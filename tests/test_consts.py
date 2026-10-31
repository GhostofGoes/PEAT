from pathlib import PurePosixPath

import pytest

from peat import consts

convert_params = [
    (None, None),
    (True, True),
    (1, 1),
    (2.0, 2.0),
    ("testing123", "testing123"),
    (b"testing123", "testing123"),
    (bytearray("123", "utf-8"), "123"),
    ([b"m340", 6.6], ["m340", 6.6]),
    (Exception(), ""),
    ({}, {}),
    ({"test": 0}, {"test": 0}),
    ({"test": "snek"}, {"test": "snek"}),
    ({"D.Va": b"OP"}, {"D.Va": "OP"}),
    ({"t": [b"m340", 6.6]}, {"t": ["m340", 6.6]}),
]


@pytest.mark.parametrize(("val", "cmp"), convert_params)
def test_convert(val, cmp):
    assert consts.convert(val) == cmp


@pytest.mark.parametrize(("val", "cmp"), convert_params)
def test_convert_idempotent(val, cmp):
    converted = consts.convert(val)
    assert converted == cmp
    assert consts.convert(converted) == cmp
    assert consts.convert(converted) == cmp
    assert consts.convert(consts.convert(converted)) == cmp


def test_get_platform_info():
    info = consts.get_platform_info()
    assert info["hostname"]
    assert info["tcpdump"] is not None
    assert info == consts.SYSINFO


def test_platform_flags():
    # Exactly one of the platform families should be detected
    assert sum([consts.WINDOWS, consts.LINUX, consts.MACOS]) == 1
    if consts.MACOS:
        assert consts.POSIX
        assert not consts.WSL


def test_get_platform_info_macos(mocker):
    mocker.patch.object(consts, "LINUX", False)
    mocker.patch.object(consts, "MACOS", True)
    mocker.patch("platform.system", return_value="Darwin")
    mocker.patch("platform.release", return_value="24.3.0")
    mocker.patch("platform.mac_ver", return_value=("15.3.1", ("", "", ""), "arm64"))
    info = consts.get_platform_info()
    assert info["os_family"] == "darwin"
    assert info["os_ver"] == "15.3.1"
    assert info["os_full"] == "Darwin 24.3.0 (macOS 15.3.1)"


def test_lower_dict():
    assert consts.lower_dict({}) == {}
    assert consts.lower_dict({}, children=False) == {}

    input_data = {"HI": "Hello", "yup": "yO", "sUb_Dict": {"Sub1": "s1", "sUB2": "S2"}}

    assert consts.lower_dict(input_data, children=True) == {
        "hi": "Hello",
        "yup": "yO",
        "sub_dict": {"sub1": "s1", "sub2": "S2"},
    }

    assert consts.lower_dict(input_data, children=False) == {
        "hi": "Hello",
        "yup": "yO",
        "sub_dict": {"Sub1": "s1", "sUB2": "S2"},
    }


def test_str_to_bool():
    with pytest.raises(ValueError):
        consts.str_to_bool("invalidstring")
    assert consts.str_to_bool("false") is False
    assert consts.str_to_bool("true") is True
    assert consts.str_to_bool("TRUE") is True


def test_sanitize_filepath():
    assert consts.sanitize_filepath("") == ""
    assert (
        consts.sanitize_filepath("system/api/1/hardware-info.html")
        == "system/api/1/hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("./system/api/1/hardware-info.html")
        == "system/api/1/hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("/system/api/1/hardware-info.html")
        == "system/api/1/hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("/system/api/1/01:01:01-hardware-info.html")
        == "system/api/1/01_01_01-hardware-info.html"
    )
    assert (
        consts.sanitize_filepath("/system/api/1/02:02:02/01:01:01-hardware-info.html")
        == "system/api/1/02_02_02/01_01_01-hardware-info.html"
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("../../escape.txt", "escape.txt"),
        ("/tmp/abs/escape.txt", "tmp/abs/escape.txt"),
        ("a/../../b/./c.txt", "a/b/c.txt"),
        ("..\\..\\windows\\escape.txt", "windows/escape.txt"),
        ("//server/share/x.txt", "server/share/x.txt"),
        ("C:/Windows/x.txt", "C_/Windows/x.txt"),
        ("../..", "unnamed"),
        ("/", "unnamed"),
    ],
)
def test_sanitize_filepath_untrusted(path, expected):
    result = consts.sanitize_filepath(path)
    assert result == expected
    assert not PurePosixPath(result).is_absolute()
    assert ".." not in PurePosixPath(result).parts


def test_sanitize_filename():
    assert consts.sanitize_filename("") == ""
    assert consts.sanitize_filename("hardware-info.html") == "hardware-info.html"
    assert consts.sanitize_filename("01:01:01-hardware-info.html") == "01_01_01-hardware-info.html"
