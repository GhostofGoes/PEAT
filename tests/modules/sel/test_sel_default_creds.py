"""
Tests for the default credentials of SEL devices (peat/modules/sel/sel_default_creds.py),
and how SELRelay and SELAscii use them.

The expected passwords are the factory defaults in the tables of public SEL
instruction manuals: SEL-351S IM 20171023 Table 10.21, SEL-421 IM 20130627
Table 4.4, SEL-751A IM 20130329 Table 7.34, SEL-700G IM 20150521 Table 7.37,
and SEL-2032 IM 20120126 Table 3.1.
"""

from unittest.mock import MagicMock

import pytest

from peat import SEL3620, DeviceData, SELRelay, Service, config, datastore
from peat.modules.sel import sel_relay
from peat.modules.sel.sel_ascii import SELAscii
from peat.modules.sel.sel_default_creds import (
    MAX_DEFAULT_FTP_ATTEMPTS,
    Credential,
    configured_option,
    default_passwords,
    ftp_candidates,
    model_family,
    normalize_model,
    resolve_level_passwords,
    web_candidates,
)
from peat.modules.sel.sel_http import SELHTTP
from peat.modules.sel.sel_telnet import SELTelnet

from .fake_sel_relay import FID_451, FakeSELRelay, TCPRelayServer


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(SELAscii, "FIRST_COMMAND_QUIET", 0.0)
    mocker.patch.object(SELAscii, "_failed_passwords", {})
    mocker.patch.object(SELAscii, "_good_passwords", {})


def _passwords(model: str, **kwargs) -> dict[str, list[str]]:
    return {
        level: [c.password for c in creds]
        for level, creds in default_passwords(model, **kwargs).items()
    }


# ---------------------------------------------------------------------------
# Models and families
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "model", "family"),
    [
        ("SEL-451-5-R324-V1-Z027013-D20201009", "451", "400"),  # FID
        ("SEL-351S-7-R516-V2-Z106105-D20190111", "351S", "300"),
        ("SEL-700G", "700G", "700"),  # DEVID
        ("sel-700g", "700G", "700"),
        ("0351S61H4455421", "351S", "300"),  # Part numbers
        ("035152B3A11XX1", "351", "300"),
        ("751A01A1ACALA7LAF30", "751A", "700"),
        ("0700G12B1B1B7281A230", "700G", "700"),
        ("071001B5X1X7X86020X", "710", "700"),
        ("0241101A3A2X0X0X0130", "2411", ""),
        ("0700G", "700G", "700"),  # RELAYTYPE
        ("0487E", "487E", "400"),
        ("411L", "411L", "400"),
        ("SEL-2032-R115-V1-Z003001-D20151028", "2032", "2030"),
        ("SEL-3530", "3530", ""),  # RTAC
        ("SEL-351R", "351R", "300"),  # Not the SEL-351
        ("SEL-351RS", "351R", "300"),
        ("SEL-651R", "651R", ""),
        ("SEL-5030", "5030", ""),  # Not the 503
        ("SEL-734B", "734B", ""),  # Meters: no table was checked
        ("SEL-735", "735", ""),
        ("7101B5X", "710", "700"),  # Part number without the leading 0
        ("551", "551", "300"),
        ("749M", "749M", "700"),
        ("787", "787", "700"),
        ("", "", ""),
        (None, "", ""),
        ("not a model", "", ""),
    ],
)
def test_normalize_model_and_family(value, model, family):
    assert normalize_model(value) == model
    assert model_family(value) == family


# ---------------------------------------------------------------------------
# Default passwords (from the manual tables)
# ---------------------------------------------------------------------------


def test_300_series_defaults():
    # SEL-351S IM 20171023 Table 10.21: levels 1, B, 2, and C
    assert _passwords("351S") == {
        "acc": ["OTTER"],
        "bac": ["EDITH"],
        "2ac": ["TAIL"],
        "cal": ["CLARKE"],
    }


def test_400_series_defaults():
    # SEL-421 IM 20130627 Table 4.4: levels 1, B, P, A, O, 2, and C
    assert _passwords("451") == {
        "acc": ["OTTER"],
        "bac": ["EDITH"],
        "pac": ["AMPERE"],
        "aac": ["VOLTA"],
        "oac": ["WATT"],
        "2ac": ["TAIL"],
        "cal": ["Sel-1"],
    }
    # CLARKE isn't documented for the 400 series: only if it's enabled
    assert _passwords("451", cal_fallback=True)["cal"] == ["Sel-1", "CLARKE"]
    assert _passwords("351S", cal_fallback=True)["cal"] == ["CLARKE"]


@pytest.mark.parametrize("model", ["751A", "700G", "751", "787"])
def test_700_series_defaults(model):
    # SEL-751A IM Table 7.34, SEL-700G IM Table 7.37: no level B
    assert _passwords(model) == {"acc": ["OTTER"], "2ac": ["TAIL"], "cal": ["CLARKE"]}


def test_other_defaults():
    # SEL-2032 IM 20120126 Table 3.1
    assert _passwords("2032") == {"acc": ["OTTER"], "2ac": ["TAIL"], "cal": ["CLARKE"]}
    # SEL-551 IM 20151105: levels 1, 2, and C
    assert _passwords("551") == {"acc": ["OTTER"], "2ac": ["TAIL"], "cal": ["CLARKE"]}
    # SEL-749M IM 20080918 Table 7.35: levels 1 and 2
    assert _passwords("749M") == {"acc": ["OTTER"], "2ac": ["TAIL"]}
    # Unknown model: PEAT's previous defaults
    assert _passwords("2411") == {
        "acc": ["OTTER"],
        "bac": ["EDITH"],
        "2ac": ["TAIL"],
        "cal": ["CLARKE"],
    }
    assert _passwords("") == _passwords("2411")


def test_default_credentials_are_level_commands():
    creds = default_passwords("451")
    assert creds["acc"][0].user == "ACC"
    assert creds["2ac"][0].user == "2AC"
    assert creds["cal"][0].source == "SEL-400 series default"


def test_credential_repr_hides_password():
    cred = Credential("2AC", "TopSecret", "configured")
    assert "TopSecret" not in repr(cred)
    assert "TopSecret" not in str(cred)
    assert "2AC" in str(cred)
    assert "configured" in repr(cred)


def test_configured_passwords_win():
    resolved = resolve_level_passwords(
        "451", {"ACC": "mine-1", "cal": ["c1", "c2"], "2ac": "", "bac": None}
    )
    assert [c.password for c in resolved["acc"]] == ["mine-1"]
    assert resolved["acc"][0].source == "configured"
    assert [c.password for c in resolved["cal"]] == ["c1", "c2"]
    # Empty values are not set
    assert resolved["2ac"][0].password == "TAIL"
    assert resolved["bac"][0].password == "EDITH"


# ---------------------------------------------------------------------------
# FTP and web candidates
# ---------------------------------------------------------------------------


def _ftp(model, **kwargs):
    lp = resolve_level_passwords(model, kwargs.pop("configured", None))
    return [(c.user, c.password) for c in ftp_candidates(model, lp, **kwargs)]


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("351S", [("FTPUSER", "TAIL")]),
        ("700G", [("FTPUSER", "TAIL")]),
        ("751", [("FTPUSER", "TAIL")]),
        ("351", [("FTP", "TAIL"), ("FTPUSER", "TAIL")]),
        ("SEL-351R", [("FTPUSER", "TAIL")]),  # Not the SEL-351 FTP user
        ("451", [("2AC", "TAIL"), ("ACC", "OTTER")]),
        ("487E", [("2AC", "TAIL"), ("ACC", "OTTER")]),
        ("2032", [("2AC", "TAIL"), ("ACC", "OTTER")]),
        ("", [("FTPUSER", "TAIL"), ("2AC", "TAIL"), ("FTP", "TAIL")]),
    ],
)
def test_ftp_candidates(model, expected):
    candidates = _ftp(model)
    assert candidates == expected
    assert len(candidates) <= MAX_DEFAULT_FTP_ATTEMPTS


def test_ftp_candidates_settings_and_cap():
    # FTPUSER from the settings first, with the level 2 password
    assert _ftp("751", ftp_user="RELAYFTP")[0] == ("RELAYFTP", "TAIL")
    # The configured level 2 password is the FTP password
    assert _ftp("751", configured={"2ac": "L2-pass"}) == [("FTPUSER", "L2-pass")]

    # Anonymous only if the settings say it's enabled, and within the cap
    assert ("anonymous", "anonymous@") not in _ftp("")
    candidates = _ftp("", ftp_user="RELAYFTP", anonymous_enabled=True)
    assert len(candidates) == MAX_DEFAULT_FTP_ATTEMPTS
    assert candidates[-1] == ("anonymous", "anonymous@")
    assert candidates[0] == ("RELAYFTP", "TAIL")


def test_web_candidates():
    # Only levels 1 and 2: reading the web interface doesn't need level B or C,
    # and each wrong login is a failed password attempt
    assert [(c.user, c.password) for c in web_candidates(resolve_level_passwords("451"))] == [
        ("acc", "OTTER"),
        ("2ac", "TAIL"),
    ]
    assert [c.user for c in web_candidates(resolve_level_passwords("751A"))] == ["acc", "2ac"]
    assert [c.user for c in web_candidates(resolve_level_passwords("749M"))] == ["acc", "2ac"]
    # Configured passwords are used
    configured = resolve_level_passwords("351S", {"acc": "Web-1", "cal": "Cal-1"})
    assert [(c.user, c.password, c.source) for c in web_candidates(configured)] == [
        ("acc", "Web-1", "configured"),
        ("2ac", "TAIL", "SEL-300 series default"),
    ]


# ---------------------------------------------------------------------------
# Configured options
# ---------------------------------------------------------------------------


def test_configured_option(mocker):
    dev = DeviceData(ip="192.0.2.50")
    dev._module = SELRelay
    # Module defaults aren't configured values
    assert dev.options["sel"]["creds"]["acc"] == "OTTER"
    assert configured_option(dev, "sel", "creds") is None
    assert configured_option(dev, "ftp", "creds") is None

    # The example config has empty values, which aren't set
    mocker.patch.dict(datastore.global_options, {"ftp": {"creds": []}, "sel": {"creds": {}}})
    assert configured_option(dev, "ftp", "creds") is None
    assert configured_option(dev, "sel", "creds") is None

    mocker.patch.dict(datastore.global_options, {"sel": {"creds": {"acc": "global"}}})
    dev._host_option_overrides.update({"sel": {"creds": {"2ac": "host"}}})
    assert configured_option(dev, "sel", "creds") == {"acc": "global", "2ac": "host"}

    dev._runtime_options["sel"] = {"creds": {"acc": "runtime"}}
    assert configured_option(dev, "sel", "creds") == {"acc": "runtime", "2ac": "host"}
    assert SELRelay._configured_ascii_creds(dev) == {"acc": "runtime", "2ac": "host"}


# ---------------------------------------------------------------------------
# SELRelay logins
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ftp(mocker):
    client = MagicMock()
    client.__enter__.return_value = client
    client.login.return_value = False
    client.getwelcome.return_value = "220 Welcome"
    mocker.patch.object(sel_relay, "FTP", return_value=client)
    return client


def _ftp_dev(model: str) -> DeviceData:
    dev = datastore.get("192.0.2.51", "ip")
    dev.description.model = model
    dev.store("service", Service(port=21, transport="tcp", status="open"), lookup="port")
    return dev


@pytest.mark.parametrize("model", ["451", "411L", "487E", "351S", "700G", "351", "2032", ""])
def test_setup_ftp_attempts_are_capped(mock_ftp, model):
    dev = _ftp_dev(model)
    assert SELRelay._setup_ftp(dev) is False
    # 451, 411L, and 487E used to get 6 attempts (more than the 5-attempt lockout)
    assert 1 <= mock_ftp.login.call_count <= MAX_DEFAULT_FTP_ATTEMPTS
    users = [c.args[0] for c in mock_ftp.login.call_args_list]
    assert "anonymous" not in users


def test_setup_ftp_prefers_ftpuser_setting(mock_ftp):
    dev = _ftp_dev("751")
    dev.store(
        "service",
        Service(
            protocol="ftp", port=21, extra={"user": "SUBFTP", "anonymous_login_enabled": True}
        ),
        lookup="protocol",
    )
    mock_ftp.login.side_effect = lambda user, _passwd: user == "anonymous"

    assert SELRelay._setup_ftp(dev) is True
    calls = [c.args for c in mock_ftp.login.call_args_list]
    assert calls == [("SUBFTP", "TAIL"), ("FTPUSER", "TAIL"), ("anonymous", "anonymous@")]
    assert dev.options["ftp"]["user"] == "anonymous"
    assert "anonymous" in dev.related.user


def test_setup_ftp_user_creds_untouched(mock_ftp, mocker):
    configured = [["a", "1"], ["b", "2"], ["c", "3"], ["d", "4"], ["e", "5"], ["f", "6"]]
    mocker.patch.dict(datastore.global_options, {"ftp": {"creds": configured}})
    dev = _ftp_dev("451")
    mock_ftp.login.side_effect = lambda user, _passwd: user == "f"

    assert SELRelay._setup_ftp(dev) is True
    # In the configured order, and all of them (they're the user's choice)
    assert [c.args for c in mock_ftp.login.call_args_list] == [tuple(c) for c in configured]
    assert dev.options["ftp"]["user"] == "f"
    assert dev.options["ftp"]["pass"] == "6"


def test_verify_http_uses_model_defaults(mocker):
    login = mocker.patch.object(SELHTTP, "login", return_value=False)
    dev = datastore.get("192.0.2.52", "ip")
    dev.description.model = "451"
    dev._runtime_options["web"] = {"user": "", "pass": ""}

    assert SELRelay._verify_http(dev) is False
    # Not CAL ("Sel-1" on the 400 series) or BAC: at most two failed logins
    assert [c.args[:2] for c in login.call_args_list] == [("acc", "OTTER"), ("2ac", "TAIL")]

    login.reset_mock()
    dev.description.model = "751A"
    assert SELRelay._verify_http(dev) is False
    assert [c.args[0] for c in login.call_args_list] == ["acc", "2ac"]


def test_pull_http_default_login(mocker):
    login = mocker.patch.object(SELHTTP, "login", return_value=False)
    dev = datastore.get("192.0.2.53", "ip")
    dev._runtime_options["web"] = {"user": "", "pass": ""}
    mocker.patch.dict(datastore.global_options, {"sel": {"creds": {"acc": "Web-Pass1"}}})

    assert SELRelay.pull_http(dev) is False
    assert login.call_args.args[:2] == ("ACC", "Web-Pass1")


def test_sel3620_has_its_own_web_passwords():
    # Before, the SEL-3620 got them from the SELRTAC defaults
    assert SEL3620.default_options["web"]["passwords"] == ["admin", "rtac"]
    dev = DeviceData(ip="192.0.2.54")
    dev._module = SEL3620
    assert list(dev.options["web"]["passwords"]) == ["admin", "rtac"]


def test_selhttp_login_default_password():
    assert SELHTTP.login.__defaults__[:2] == ("ACC", "OTTER")


# ---------------------------------------------------------------------------
# SELAscii logins against the scripted relay
# ---------------------------------------------------------------------------


@pytest.fixture
def relay_server():
    servers = []

    def _make(factory) -> TCPRelayServer:
        server = TCPRelayServer(factory)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def test_elevate_uses_model_defaults(relay_server):
    server = relay_server(
        lambda: FakeSELRelay(
            fid=FID_451, passwords={"acc": "OTTER", "2ac": "TAIL", "cal": "Sel-1"}
        )
    )
    tn = SELTelnet("127.0.0.1", server.port, timeout=2.0)
    tn.model = "451"
    assert tn.elevate(3) is True
    assert server.relays[0].password_attempts["cal"] == ["Sel-1"]
    tn.disconnect()


def test_model_from_id_selects_defaults(relay_server):
    server = relay_server(
        lambda: FakeSELRelay(
            fid=FID_451, passwords={"acc": "OTTER", "2ac": "TAIL", "cal": "Sel-1"}
        )
    )
    tn = SELTelnet("127.0.0.1", server.port, timeout=2.0)
    assert tn.get_id()["FID"] == FID_451
    assert tn.elevate(3) is True
    tn.disconnect()


def test_cal_fallback_on_separate_connections(relay_server):
    # A 400 series relay with CLARKE as the level C password: the documented
    # default is tried first, then the opt-in fallback on a new connection
    server = relay_server(
        lambda: FakeSELRelay(
            fid=FID_451, passwords={"acc": "OTTER", "2ac": "TAIL", "cal": "CLARKE"}
        )
    )

    def connect() -> SELTelnet:
        tn = SELTelnet("127.0.0.1", server.port, timeout=2.0)
        tn.model = "451"
        tn.cal_fallback = True
        return tn

    tn = connect()
    assert tn.elevate(3) is False
    assert tn.access_level == "2"
    assert server.relays[0].password_attempts["cal"] == ["Sel-1"]
    tn.disconnect()

    tn = connect()
    assert tn.elevate(3) is True
    assert server.relays[1].password_attempts["cal"] == ["CLARKE"]
    tn.disconnect()


def test_no_cal_fallback_by_default(relay_server):
    server = relay_server(
        lambda: FakeSELRelay(
            fid=FID_451, passwords={"acc": "OTTER", "2ac": "TAIL", "cal": "CLARKE"}
        )
    )
    for _ in range(2):
        tn = SELTelnet("127.0.0.1", server.port, timeout=2.0)
        tn.model = "451"
        assert tn.elevate(3) is False
        tn.disconnect()
    # Sel-1 once, and nothing on the second connection
    assert server.relays[0].password_attempts["cal"] == ["Sel-1"]
    assert "cal" not in server.relays[1].password_attempts
    assert b"CAL" not in server.relays[1].lines
