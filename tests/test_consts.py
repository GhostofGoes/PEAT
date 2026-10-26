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


MARKER = "Marker-PW-8c1e"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            f"https://elastic:{MARKER}@localhost:9200/",
            "https://elastic:<redacted>@localhost:9200/",
        ),
        (f"http://{MARKER}@host/mapi/opensearch", "http://<redacted>@host/mapi/opensearch"),
        (f"http://user:{MARKER}@host", "http://user:<redacted>@host"),
        # The password may contain "@"
        (f"http://user:a@{MARKER}@host/", "http://user:<redacted>@host/"),
        ("http://localhost:9200/", "http://localhost:9200/"),
        ("http://host/path@notuserinfo", "http://host/path@notuserinfo"),
        ("user@example.com", "user@example.com"),
        ("", ""),
    ],
)
def test_redact_url(url, expected):
    assert consts.redact_url(url) == expected


def test_redact_url_without_scheme():
    url = f"elastic:{MARKER}@localhost:9200"
    assert consts.redact_url(url) == url
    assert consts.redact_url(url, require_scheme=False) == "elastic:<redacted>@localhost:9200"


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["peat", "encrypt", "-p", MARKER], ["peat", "encrypt", "-p", "<redacted>"]),
        (
            ["peat", "encrypt", "--password", MARKER],
            ["peat", "encrypt", "--password", "<redacted>"],
        ),
        (
            ["peat", "encrypt", f"--password={MARKER}"],
            ["peat", "encrypt", "--password=<redacted>"],
        ),
        (["peat", "encrypt", f"--pass={MARKER}"], ["peat", "encrypt", "--pass=<redacted>"]),
        (["peat", "encrypt", "--pass", MARKER], ["peat", "encrypt", "--pass", "<redacted>"]),
        (["peat", "encrypt", f"-p{MARKER}"], ["peat", "encrypt", "-p<redacted>"]),
        (
            ["peat", "scan", "-e", f"elastic:{MARKER}@localhost:9200"],
            ["peat", "scan", "-e", "elastic:<redacted>@localhost:9200"],
        ),
        (
            ["peat", "scan", f"--elastic-server=http://elastic:{MARKER}@localhost:9200"],
            ["peat", "scan", "--elastic-server=http://elastic:<redacted>@localhost:9200"],
        ),
        (
            ["peat", "heat", "--heat-elastic-server", f"https://u:{MARKER}@h/"],
            ["peat", "heat", "--heat-elastic-server", "https://u:<redacted>@h/"],
        ),
        (
            ["peat", "pull", f"ftp://user:{MARKER}@192.0.2.1/"],
            ["peat", "pull", "ftp://user:<redacted>@192.0.2.1/"],
        ),
        # Other arguments aren't changed
        (
            ["peat", "pull", "-i", "192.0.2.1", "--pull-skip-scan", "-d", "sel"],
            ["peat", "pull", "-i", "192.0.2.1", "--pull-skip-scan", "-d", "sel"],
        ),
        (["peat", "pillage", "-P", "/dev/sdb"], ["peat", "pillage", "-P", "/dev/sdb"]),
    ],
)
def test_redact_argv(argv, expected):
    original = list(argv)
    assert consts.redact_argv(argv) == expected
    assert argv == original  # not modified


def test_omit_secrets():
    data = {
        "DEVICE_OPTIONS": {
            "ssh": {"user": "admin", "pass": MARKER, "port": 22, "passphrase": ""},
            "snmp": {"community": MARKER, "communities": [MARKER, MARKER]},
            "sel": {"creds": [["acc", MARKER], ("2ac", MARKER)], "passwords": [MARKER]},
            "telnet": {"meter_pass": 1234, "Password": MARKER},
        },
        "HOSTS": [{"identifier": "192.0.2.1", "options": {"web": {"pass": MARKER}}}],
        "ELASTIC_SERVER": f"https://elastic:{MARKER}@localhost:9200/",
        "OTHER_SERVER": f"https://{MARKER}@localhost:9200/",
        "DEBUG": 1,
        "VERBOSE": True,
        "PILLAGE": None,
    }

    result, omitted = consts.omit_secrets(data)

    assert MARKER not in str(result)
    assert consts.REDACTED not in str(result)
    assert MARKER in str(data)  # not modified
    assert result["DEVICE_OPTIONS"] == {
        "ssh": {"user": "admin", "port": 22},
        "snmp": {},
        "sel": {},
        "telnet": {},
    }
    assert result["HOSTS"] == [{"identifier": "192.0.2.1", "options": {"web": {}}}]
    assert result["ELASTIC_SERVER"] == "https://elastic@localhost:9200/"
    assert result["OTHER_SERVER"] == "https://localhost:9200/"
    assert result["DEBUG"] == 1
    assert result["VERBOSE"] is True
    assert result["PILLAGE"] is None
    assert omitted == [
        "DEVICE_OPTIONS.ssh.pass",
        "DEVICE_OPTIONS.ssh.passphrase",
        "DEVICE_OPTIONS.snmp.community",
        "DEVICE_OPTIONS.snmp.communities",
        "DEVICE_OPTIONS.sel.creds",
        "DEVICE_OPTIONS.sel.passwords",
        "DEVICE_OPTIONS.telnet.meter_pass",
        "DEVICE_OPTIONS.telnet.Password",
        "HOSTS[0].options.web.pass",
        "ELASTIC_SERVER (password)",
        "OTHER_SERVER (password)",
    ]


def test_drop_redacted():
    r = consts.REDACTED
    data = {
        "sel": {"pass": r, "user": "acc", "creds": [["a", r], ("b", "pw"), ["c", "d"]]},
        "snmp": {"communities": [r, r], "port": 161},
        "ssh": {"pass": r},
        "url": f"http://elastic:{r}@host:9200/",
        "token_url": f"https://{r}@host/",
        "other": f"not a URL {r}@",
        "empty": {},
    }
    result, dropped = consts.drop_redacted(data)
    assert result == {
        "sel": {"user": "acc", "creds": [("b", "pw"), ["c", "d"]]},
        "snmp": {"port": 161},
        "other": f"not a URL {r}@",
        "empty": {},
    }
    assert dropped == [
        "sel.pass",
        "sel.creds[0]",
        "snmp.communities[0]",
        "snmp.communities[1]",
        "ssh.pass",
        "url",
        "token_url",
    ]
    assert consts.drop_redacted(r) == (consts.DROPPED, [""])
    assert consts.drop_redacted([r]) == (consts.DROPPED, ["[0]"])
    assert consts.drop_redacted("value") == ("value", [])
    assert consts.drop_redacted(data["empty"]) == ({}, [])


def test_platform_info_redacts_argv(mocker):
    mocker.patch.object(
        consts.sys,
        "argv",
        ["peat", "encrypt", "-f", "c.yaml", "-p", MARKER, "-e", f"http://e:{MARKER}@h:9200"],
    )
    info = consts.get_platform_info()
    assert MARKER not in str(info)
    assert info["cli_arguments"] == "encrypt -f c.yaml -p <redacted> -e http://e:<redacted>@h:9200"
