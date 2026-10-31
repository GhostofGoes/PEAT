import io
import json
import sys
import tarfile
from datetime import datetime
from pathlib import Path
from platform import python_version

import pytest

from peat import config, utils


def test_convert_to_snake_case():
    assert utils.convert_to_snake_case("CamelCase") == "camel_case"
    assert utils.convert_to_snake_case("snake_case") == "snake_case"


def test_clean_replace():
    assert utils.clean_replace(" some$bad$@string", " ", "@$") == "some bad  string"


def test_fmt_duration():
    assert utils.fmt_duration(0) == "0 seconds"
    assert utils.fmt_duration(59) == "59 seconds"
    assert utils.fmt_duration(60) == "1 minute [60.00 seconds]"
    assert utils.fmt_duration(120) == "2 minutes [120.00 seconds]"


def test_fmt_size():
    assert utils.fmt_size(0) == "0 bytes [0 bytes]"
    assert utils.fmt_size(1024) == "1.02 KB [1024 bytes]"


def test_sort():
    assert utils.sort({"5": 1, "4": 1, "3": 1}) == {"3": 1, "4": 1, "5": 1}


def test_move_item():
    obj = ["x", "y", "z"]
    utils.move_item(obj, 1, "z")
    assert obj == ["x", "z", "y"]


def test_move_file(tmp_path):
    t_dir = tmp_path / "test_move_file_dir"
    t_dir.mkdir(exist_ok=True, parents=True)
    t_src = tmp_path / "test_move_file_file.txt"
    t_src.write_text("some data")

    assert t_src.is_file()
    assert t_dir.is_dir()

    res = utils.move_file(t_src, t_dir)
    assert not t_src.is_file()
    assert res == Path(t_dir, t_src.name)
    assert res.is_file()

    t_src.write_text("some data")
    res = utils.move_file(t_src, t_dir)

    assert res == Path(t_dir, f"{t_src.name}.1")
    assert res.is_file()


def test_merge():
    with pytest.raises(ValueError):
        utils.merge(None, None)

    assert utils.merge(None, {"d2": 2}) == {"d2": 2}
    assert utils.merge({"d1": 1}, None) == {"d1": 1}
    assert utils.merge({"d1": 1}, {"d2": 2}) == {"d1": 1, "d2": 2}


def test_parse_date():
    data = "nov 1 2019 12:26:51"
    iso_expected = "2019-11-01T12:26:51"
    datetime_expected = datetime(2019, 11, 1, 12, 26, 51)

    assert utils.parse_date(data) == datetime_expected
    assert utils.parse_date(data).isoformat() == iso_expected
    assert utils.parse_date(iso_expected).isoformat() == iso_expected
    assert utils.parse_date(iso_expected) == datetime_expected
    assert utils.parse_date(b"nov 1 2019 12:26:51") == datetime_expected  # type: ignore
    assert not utils.parse_date("")
    assert not utils.parse_date(b"")
    assert not utils.parse_date(None)


def test_get_formatted_platform_str():
    assert python_version() in utils.get_formatted_platform_str()


def test_get_debug_string():
    assert utils.get_debug_string() != ""


def test_get_resource():
    with pytest.raises(FileNotFoundError):
        utils.get_resource("peat", "TESTINGDOESNOTEXIST")
    with pytest.raises(ValueError):
        utils.get_resource("", "TESTINGDOESNOTEXIST")
    with pytest.raises(ModuleNotFoundError):
        utils.get_resource("TESTINGDOESNOTEXIST", "TESTINGDOESNOTEXIST")
    assert utils.get_resource("peat.parsing.plc_open.core_modules", "iec_std.csv")


def test_check_file(mocker, datapath):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    assert utils.check_file(".") == Path(".").resolve()

    dpth = datapath("dummy_text_file.txt")
    assert utils.check_file(dpth) == dpth
    assert utils.check_file(dpth, ext=".txt") == dpth
    assert utils.check_file(dpth, ext=[".txt"]) == dpth
    assert utils.check_file(dpth, ext="nope") == dpth
    assert utils.check_file("-") == "-"

    if hasattr(sys.stdin, "isatty"):
        mocker.patch("sys.stdin.isatty", return_value=True)
        assert utils.check_file("-") is None
        assert utils.check_file(None) is None


def test_file_perms_to_octal():
    assert not utils.file_perms_to_octal("")
    assert not utils.file_perms_to_octal("rwx")
    assert utils.file_perms_to_octal("rwxrwxr--") == "0774"
    assert utils.file_perms_to_octal("r--r--r--") == "0444"
    assert utils.file_perms_to_octal("rw------x") == "0601"


def test_write_temp_file_none_ext(tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": None})
    assert utils.write_temp_file({}, "") is None

    mocker.patch.dict(config["CONFIG"], {"TEMP_DIR": tmp_path})
    pth = utils.write_temp_file("data", "test-ext-label.test")
    assert pth.is_file()
    assert "test-ext-label" in pth.name
    assert pth.suffix == ".test"


def test_write_file_general(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "OUT_DIR": tmp_path,
            "RUN_DIR": tmp_path,
        },
    )
    file = tmp_path / "pathtest12345"
    text = "write_file_path12345 1.0"

    assert utils.write_file(text, file) is True
    assert file.is_file()
    assert file.read_text(encoding="utf-8") == text
    assert utils.write_file(None, None) is False


def test_write_file_str_path(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "OUT_DIR": tmp_path,
            "RUN_DIR": tmp_path,
        },
    )
    file_name = "strpathtest12345"
    pth = tmp_path / file_name

    assert utils.write_file("teststring", file_name) is False
    assert not pth.is_file()


def test_write_file_json(tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})
    file = tmp_path / "jsontest12345"

    assert utils.write_file({}, file) is True

    assert file.is_file()
    assert file.read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize(
    ("invalid_name", "valid_name"),
    [
        ("CON", "CON_"),
        ("some_file?i=1.html", "some_file_i=1.html"),
    ],
)
def test_write_file_filename_validation(tmp_path, mocker, invalid_name, valid_name):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    invalid_path = tmp_path / invalid_name
    valid_path = tmp_path / valid_name
    test_string = f"testing123+{invalid_name}+{valid_name}"

    assert utils.write_file(test_string, invalid_path) is True

    assert not invalid_path.is_file()
    assert valid_path.is_file()
    assert valid_path.read_text(encoding="utf-8") == test_string


def test_write_file_merge_existing(tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    test_path = tmp_path / "test_dict.json"
    test_dict = {1: "one", "two": 2}
    assert utils.write_file(data=test_dict, file=test_path)
    assert utils.write_file(data={3: "three"}, file=test_path, merge_existing=True)
    assert json.loads(test_path.read_text(encoding="utf-8")) == {
        "1": "one",
        "two": 2,
        "3": "three",
    }

    assert utils.write_file(data={4: "four"}, file=test_path, merge_existing=False)
    assert json.loads(test_path.read_text(encoding="utf-8")) == {
        "1": "one",
        "two": 2,
        "3": "three",
    }

    # TODO: expand this test to cover all possible cases for merge_existing


filehash_compares = [
    ("md5", "7F2ABABA423061C509F4923DD04B6CF1"),
    ("sha1", "4C0D2B951FFABD6F9A10489DC40FC356EC1D26D5"),
    ("sha256", "B822F1CD2DCFC685B47E83E3980289FD5D8E3FF3A82DEF24D7D1D68BB272EB32"),
    (
        "sha512",
        "4120117B3190BA5E24044732B0B09AA9ED50EB1567705ABCBFA78431A4E0A96B1152ED7F4925966B1C82325E186A8100E692E6D2FCB6702572765820D25C7E9E",
    ),
]


@pytest.mark.parametrize(("algo", "cmp"), filehash_compares)
def test_calc_hash(datapath, algo, cmp):
    assert utils.calc_hash(datapath("hashtest.txt"), algo) == cmp


def test_gen_hashes_path(datapath):
    """Operate on the file path (Path input)."""
    f_result = utils.gen_hashes(datapath("hashtest.txt"))

    assert f_result["md5"] == filehash_compares[0][1]
    assert f_result["sha1"] == filehash_compares[1][1]
    assert f_result["sha256"] == filehash_compares[2][1]
    assert f_result["sha512"] == filehash_compares[3][1]


def test_gen_hashes_text(text_data):
    """Operating on raw text data (str input)."""
    t_result = utils.gen_hashes(text_data("hashtest.txt"))

    assert t_result["md5"] == filehash_compares[0][1]
    assert t_result["sha1"] == filehash_compares[1][1]
    assert t_result["sha256"] == filehash_compares[2][1]
    assert t_result["sha512"] == filehash_compares[3][1]


def test_utc_now():
    """
    Not really a comprehensive test, but ensures it's timezone-aware and UTC.
    """
    assert str(utils.utc_now().tzinfo) == "UTC"


def test_time_now():
    assert utils.time_now()
    assert isinstance(utils.time_now(), str)


def test_deep_get():
    data = {"1": {"2": {"3": "hi"}}}

    assert utils.deep_get(data, "1.2.3") == "hi"
    assert utils.deep_get(data, "1")
    assert not utils.deep_get(data, "1.2.3.4")
    assert not utils.deep_get(data, "1.2.3.hi")
    assert not utils.deep_get(data, "")


def test_is_ip_address():
    assert utils.is_ip("192.168.0.1")
    assert utils.is_ip("fe80::457f:9ce8:afa1:2118")

    assert not utils.is_ip("")
    assert not utils.is_ip("fe80:::")
    assert not utils.is_ip("192.168.")
    assert not utils.is_ip("192.168.168.168.168")


def test_is_email():
    assert utils.is_email("example@example.com")

    assert not utils.is_email("")
    assert not utils.is_email("google.com")


def test_is_mac():
    assert utils.is_mac("00:00:00:00:00:00")
    assert utils.is_mac("00:A0:A9:A8:12:A1")
    assert utils.is_mac("00:b0:b9:08:12:01")

    assert not utils.is_mac("")
    assert not utils.is_mac("01:02:03:04:05:0")


@pytest.mark.parametrize(
    ("untrusted", "expected"),
    [
        (("a.txt",), "a.txt"),
        (("sub", "a.txt"), "sub/a.txt"),
        (("../../escape.txt",), "escape.txt"),
        (("/etc/passwd",), "etc/passwd"),
        (("..\\..\\escape.txt",), "escape.txt"),
        (("a/../../b.txt",), "a/b.txt"),
        (("",), ""),
        (("C:/Windows/x.txt",), "Windows/x.txt"),
        (("..\\..\\D:\\x.txt",), "x.txt"),
        (("a", "C:x.txt"), "a/x.txt"),
        (("//server/share/x.txt",), "server/share/x.txt"),
    ],
)
def test_safe_join(tmp_path, untrusted, expected):
    result = utils.safe_join(tmp_path, *untrusted)
    assert result == (tmp_path.joinpath(*expected.split("/")) if expected else tmp_path)
    assert result.resolve().is_relative_to(tmp_path.resolve())


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks require privileges on Windows")
def test_safe_join_symlink_escape(tmp_path):
    base = tmp_path / "base"
    outside = tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    (base / "link").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="outside of"):
        utils.safe_join(base, "link", "x.txt")


def _tar_info(name: str, typ: bytes = tarfile.REGTYPE, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = typ
    info.linkname = linkname
    return info


@pytest.mark.parametrize(
    ("member", "expected_name"),
    [
        (_tar_info("dir/file.txt"), "dir/file.txt"),
        (_tar_info("/abs/file.txt"), "abs/file.txt"),
        (_tar_info("../../escape.txt"), None),
        (_tar_info("dir/../../escape.txt"), None),
        (_tar_info("link", tarfile.SYMTYPE, "/etc/passwd"), None),
        (_tar_info("hard", tarfile.LNKTYPE, "dir/file.txt"), None),
        (_tar_info("dev", tarfile.CHRTYPE), None),
        (_tar_info("fifo", tarfile.FIFOTYPE), None),
        (_tar_info("dir", tarfile.DIRTYPE), None),
    ],
)
def test_check_tar_member(tmp_path, member, expected_name):
    result = utils.check_tar_member(member, tmp_path)
    if expected_name is None:
        assert result is None
    else:
        assert result is not None
        assert result.name == expected_name


def test_check_tar_member_allow_dirs(tmp_path):
    member = _tar_info("dir", tarfile.DIRTYPE)
    result = utils.check_tar_member(member, tmp_path, allow_dirs=True)
    assert result is not None
    assert result.name == "dir"


@pytest.mark.parametrize("name", ["../dirup", "dir/../../dirup"])
def test_check_tar_member_unsafe_dir(tmp_path, name):
    member = _tar_info(name, tarfile.DIRTYPE)
    assert utils.check_tar_member(member, tmp_path, allow_dirs=True) is None


@pytest.mark.parametrize("name", ["../dirup", "/abs/dir", "../escape.txt"])
def test_check_tar_member_unsafe_without_data_filter(monkeypatch, tmp_path, name):
    # Python 3.11.0 - 3.11.3 have no PEP 706 extraction filters
    monkeypatch.delattr(tarfile, "data_filter")
    typ = tarfile.REGTYPE if name.endswith(".txt") else tarfile.DIRTYPE
    member = _tar_info(name, typ)
    assert utils.check_tar_member(member, tmp_path, allow_dirs=True) is None


def test_tarfile_default_extraction_filter(tmp_path):
    import peat  # noqa: F401  (importing peat sets the default filter)

    archive = tmp_path / "evil.tar"
    with tarfile.open(archive, "w") as tar:
        data = b"pwned"
        info = tarfile.TarInfo("../escape.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    dest = tmp_path / "dest"
    with tarfile.open(archive) as tar:
        with pytest.raises(tarfile.FilterError):
            tar.extractall(dest)
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only")
def test_fix_file_owners_does_not_follow_symlinks(mocker, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("owned by root", encoding="utf-8")
    run_dir = tmp_path / "run"
    (run_dir / "sub").mkdir(parents=True)
    (run_dir / "sub" / "file.txt").write_text("x", encoding="utf-8")
    (run_dir / "sub" / "link.txt").symlink_to(outside)
    (run_dir / "dirlink").symlink_to(tmp_path, target_is_directory=True)

    calls = []

    def fake_chown(path, uid, gid, *, dir_fd=None, follow_symlinks=True):  # noqa: ARG001
        calls.append((Path(path), follow_symlinks))

    mocker.patch("os.chown", side_effect=fake_chown)
    mocker.patch("os.geteuid", return_value=0)
    mocker.patch("os.getegid", return_value=0)
    mocker.patch.dict("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000"})

    assert utils.fix_file_owners(run_dir) is True
    chowned = {p for p, _ in calls}
    assert run_dir / "sub" / "file.txt" in chowned
    for path, follow_symlinks in calls:
        assert path.is_relative_to(run_dir), path
        assert not (path.is_symlink() and follow_symlinks), path


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks require privileges on Windows")
def test_clean_empty_dirs_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    (outside / "empty").mkdir(parents=True)
    to_clean = tmp_path / "to_clean"
    (to_clean / "empty").mkdir(parents=True)
    (to_clean / "link").symlink_to(outside, target_is_directory=True)

    utils.clean_empty_dirs(to_clean)
    assert not (to_clean / "empty").exists()
    assert (outside / "empty").is_dir()
