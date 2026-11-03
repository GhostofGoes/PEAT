"""
Tests for SELRelay: factory default credentials, known defaults, CID file
claiming and SCL parsing, file inventory (peat/modules/sel/sel_relay.py,
sel_comms.py, sel_defaults.py, sel_ascii.py).
"""

import io
import zlib
from pathlib import Path, PurePosixPath

import pytest

from peat import IEC61850SCL, DeviceData, SELRelay, Service, datastore
from peat.api.parse_api import parsable_file_by_pattern, parsable_file_by_signature
from peat.data.baseline import compare_device, split_path
from peat.modules.sel import sel_comms
from peat.modules.sel.relay_parse import process_cid_file
from peat.modules.sel.sel_ascii import hours_to_utc_offset
from peat.modules.sel.sel_defaults import (
    SEL_RELAY_FACTORY_DEFAULTS,
    SEL_RELAY_FTP_DEFAULTS,
    SEL_RELAY_VENDOR_RECOMMENDED,
    credential_security,
)

SCD_PATH = (
    Path(__file__).resolve().parents[2]
    / "parsing"
    / "data_files"
    / "scl"
    / "synthetic_substation.scd"
)


@pytest.fixture(autouse=True)
def _clean_datastore(mocker):
    mocker.patch.object(datastore, "objects", [])


@pytest.fixture(scope="module")
def scl_raw() -> bytes:
    # SELRelay's CID signature also requires the text "IEC 61850" in the content
    # LF line endings whatever the checkout (CRLF on Windows)
    return (
        SCD_PATH.read_bytes()
        .replace(b"\r\n", b"\n")
        .replace(b'toolID="PEAT synthetic fixture"', b'toolID="PEAT IEC 61850 fixture"')
    )


def _claims(module, path: Path) -> bool:
    name = path.as_posix()
    return parsable_file_by_pattern(name, module) or parsable_file_by_signature(name, module)


# ----------------------------------------------------------------------------- #
# Default credentials
# ----------------------------------------------------------------------------- #
def test_factory_default_credentials_declared():
    assert {("ACC", "OTTER"), ("BAC", "EDITH"), ("2AC", "TAIL"), ("CAL", "CLARKE")} <= (
        SELRelay.factory_default_credentials
    )
    assert {("FTPUSER", "TAIL"), ("FTP", "TAIL")} <= SELRelay.factory_default_credentials
    assert SELRelay.is_factory_default_credential("acc", "OTTER")  # user case-insensitive
    assert not SELRelay.is_factory_default_credential("acc", "otter")  # password exact


def test_credential_security_outcomes():
    anon = credential_security(SELRelay, "anonymous", "anonymous@")
    assert anon.anonymous_access is True
    assert anon.authentication_required is False
    assert anon.default_credentials is None

    default = credential_security(SELRelay, "FTPUSER", "TAIL")
    assert default.default_credentials is True
    assert default.authentication_required is True

    # A site credential, factory defaults not (all) tried: unknown
    site = credential_security(SELRelay, "FTPUSER", "s1te-pass", [("2AC", "TAIL")])
    assert site.default_credentials is None
    assert site.authentication_required is True

    # Every factory default of the service was tried and rejected
    rejected = sorted(SEL_RELAY_FTP_DEFAULTS)
    no_default = credential_security(
        SELRelay, "FTPUSER", "s1te-pass", rejected, SEL_RELAY_FTP_DEFAULTS
    )
    assert no_default.default_credentials is False


class _FakeFTP:
    """Accepts only the credentials in ``valid``."""

    valid: tuple[str, str] = ("FTPUSER", "TAIL")

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def login(self, user, passwd):
        return (user, passwd) == self.valid

    def getwelcome(self):
        return "220 FTP"


@pytest.mark.parametrize(
    ("valid", "expected_default", "expected_anonymous"),
    [
        (("FTPUSER", "TAIL"), True, None),
        (("anonymous", "anonymous"), None, True),
    ],
)
def test_setup_ftp_records_security(mocker, valid, expected_default, expected_anonymous):
    fake = type("FakeFTP", (_FakeFTP,), {"valid": valid})
    mocker.patch("peat.modules.sel.sel_relay.FTP", fake)
    mocker.patch("peat.modules.sel.sel_relay.time.sleep")
    dev = DeviceData(ip="192.0.2.10")
    dev.store("service", Service(protocol="ftp", port=21, status="open"))
    assert SELRelay._setup_ftp(dev) is True

    ftp = dev.retrieve("service", {"protocol": "ftp"})
    assert ftp.status == "verified"
    assert ftp.security.default_credentials is expected_default
    assert ftp.security.anonymous_access is expected_anonymous
    dumped = str(dev.export())
    assert "TAIL" not in dumped  # the password is never stored


def test_ascii_login_security(mocker):
    from peat.modules.sel.sel_telnet import SELTelnet

    tn = mocker.MagicMock(spec=SELTelnet)
    tn.successful_usernames = {"acc"}
    tn.DEFAULT_CREDS = SELTelnet.DEFAULT_CREDS
    dev = DeviceData(ip="192.0.2.10")

    SELRelay._store_ascii_login_security(dev, tn, {"acc": "OTTER", "2ac": "TAIL"})
    telnet = dev.retrieve("service", {"protocol": "telnet"})
    assert telnet.security.default_credentials is True
    assert telnet.security.authentication_required is True

    dev2 = DeviceData(ip="192.0.2.11")
    SELRelay._store_ascii_login_security(dev2, tn, {"acc": "site-pass"})
    assert dev2.retrieve("service", {"protocol": "telnet"}).security.default_credentials is None


# ----------------------------------------------------------------------------- #
# Known defaults
# ----------------------------------------------------------------------------- #
def test_known_defaults_declared_and_parse():
    baselines = {b.id: b for b in SELRelay.get_known_defaults()}
    assert set(baselines) == {"sel-relay-factory-defaults", "sel-relay-vendor-recommended"}
    assert baselines["sel-relay-factory-defaults"].kind == "factory_default"
    assert baselines["sel-relay-vendor-recommended"].kind == "vendor_recommended"
    for baseline in baselines.values():
        assert baseline.selector.vendor_id == "SEL"
        assert baseline.selector.device_type == "Relay"
        assert baseline.expected is None
        for rule in baseline.rules:
            assert split_path(rule.path)
    factory = baselines["sel-relay-factory-defaults"]
    assert all(r.severity == "info" for r in factory.rules)


def _relay(**kwargs) -> DeviceData:
    dev = DeviceData(type="Relay", **kwargs)
    dev.description.vendor.id = "SEL"
    return dev


def test_known_defaults_evaluate_factory_device():
    dev = _relay(name="FEEDER 1")
    dev.extra["terminal_id"] = "STATION A"
    dev.store("service", Service(protocol="telnet", port=23, transport="tcp", enabled=True))
    dev.store("service", Service(protocol="ftp", port=21, enabled=True))
    dev.service[1].security.default_credentials = True

    factory = {f.rule_id: f for f in compare_device(dev, SEL_RELAY_FACTORY_DEFAULTS)}
    assert all(f.result == "pass" for f in factory.values()), factory

    vendor = {f.rule_id: f for f in compare_device(dev, SEL_RELAY_VENDOR_RECOMMENDED)}
    assert vendor["sel.service.ftp.disabled"].result == "fail"
    assert vendor["sel.service.telnet.absent"].result == "fail"
    assert vendor["sel.service.telnet.open"].result == "pass"
    assert vendor["sel.accounts.default-credentials"].result == "fail"
    assert vendor["sel.identity.rid-changed"].result == "fail"
    assert vendor["sel.identity.tid-changed"].result == "fail"


def test_known_defaults_evaluate_hardened_device():
    dev = _relay(name="SUB7 FDR 12")
    dev.extra["terminal_id"] = "SUB7"
    dev.store("service", Service(protocol="ftp", port=2121, enabled=False))
    # ETELNET=N: relay_parse stores a disabled Telnet service
    dev.store("service", Service(protocol="telnet", port=23, transport="tcp", enabled=False))
    factory = {f.rule_id: f for f in compare_device(dev, SEL_RELAY_FACTORY_DEFAULTS)}
    assert factory["sel.default.rid"].result == "fail"
    assert factory["sel.default.ftp-port"].result == "fail"
    vendor = {f.rule_id: f for f in compare_device(dev, SEL_RELAY_VENDOR_RECOMMENDED)}
    for rule_id in (
        "sel.service.ftp.disabled",
        "sel.service.telnet.absent",
        "sel.service.telnet.open",
        "sel.identity.rid-changed",
        "sel.identity.tid-changed",
    ):
        assert vendor[rule_id].result == "pass", rule_id


def test_known_defaults_telnet_found_by_scan_is_exposed():
    dev = _relay(name="SUB7 FDR 12")
    dev.store("service", Service(protocol="telnet", port=23, transport="tcp", status="open"))
    vendor = {f.rule_id: f for f in compare_device(dev, SEL_RELAY_VENDOR_RECOMMENDED)}
    assert vendor["sel.service.telnet.absent"].result == "pass"  # no settings
    assert vendor["sel.service.telnet.open"].result == "fail"
    assert vendor["sel.service.telnet.open"].severity == "low"


# ----------------------------------------------------------------------------- #
# CID files
# ----------------------------------------------------------------------------- #
def test_cid_filename_patterns_removed():
    assert not any(p.lower().endswith(".cid") for p in SELRelay.filename_patterns)


@pytest.mark.parametrize("level", [1, 6, 9])  # zlib headers 7801, 789C, 78DA
def test_zlib_cid_claimed_only_by_selrelay(tmp_path, scl_raw, level):
    path = tmp_path / "SET_61850.CID"
    path.write_bytes(zlib.compress(scl_raw, level))
    assert _claims(SELRelay, path)
    assert not _claims(IEC61850SCL, path)


def test_plain_xml_cid_not_claimed_by_selrelay(tmp_path, scl_raw):
    path = tmp_path / "PROT1.cid"
    path.write_bytes(scl_raw)
    assert not _claims(SELRelay, path)
    assert _claims(IEC61850SCL, path)


def test_zlib_without_scl_not_claimed(tmp_path):
    path = tmp_path / "SET_61850.CID"
    path.write_bytes(zlib.compress(b"not an SCL file"))
    assert not _claims(SELRelay, path)


def test_process_cid_file_parses_scl(mocker, tmp_path, scl_raw):
    write = mocker.patch.object(DeviceData, "write_file", return_value=tmp_path / "x")
    dev = DeviceData(ip="192.0.2.10")
    extracted = process_cid_file(
        zlib.compress(scl_raw), PurePosixPath("/SETTINGS/SET_61850.CID"), dev
    )
    assert extracted.startswith("<?xml")
    assert write.call_args.args[1] == "SET_61850_decompressed.xml"

    # First IED of the fixture
    assert dev.iec61850.ied_name == "PROT1"
    assert dev.iec61850.scl_file == "/SETTINGS/SET_61850.CID"
    assert dev.iec61850.header.file_type == "CID"
    assert {"mms", "goose"} <= {s.protocol for s in dev.service}
    types = {r.type for r in dev.relationships}
    assert {"publishes_to", "subscribes_to", "reports_to"} <= types
    assert not dev.interface  # populate_interfaces=False

    (cid,) = dev.files
    assert cid.path.as_posix() == "/SETTINGS/SET_61850.CID"
    assert cid.category == {"configuration", "iec61850"}


def test_extract_cid_content_bounded(mocker):
    from peat.modules.sel.relay_parse import extract_cid_content
    from peat.parsing import scl

    mocker.patch.object(scl, "MAX_DECOMPRESSED_SIZE", 1024)
    bomb = zlib.compress(b"<SCL>" + b" " * 4096)
    with pytest.raises(scl.ParseError):
        extract_cid_content(bomb)
    assert extract_cid_content(zlib.compress(b"\xef\xbb\xbf<SCL/>")) == "<SCL/>"
    assert extract_cid_content(b"<SCL/>") == "<SCL/>"

    write = mocker.patch.object(DeviceData, "write_file")
    dev = DeviceData(ip="192.0.2.10")
    assert process_cid_file(bomb, PurePosixPath("/SETTINGS/SET_61850.CID"), dev) == ""
    write.assert_not_called()


def test_is_cid_bounded(mocker, scl_raw):
    """A CID larger than the parser's limit (zlib bomb) is not inflated or claimed (R2-11)."""
    from peat.parsing import scl

    big = zlib.compress(scl_raw + b"<!--" + b" " * (2 * len(scl_raw)) + b"-->", 9)
    assert SELRelay.is_cid(io.BytesIO(big)) is True
    mocker.patch.object(scl, "MAX_DECOMPRESSED_SIZE", len(scl_raw))
    decompressobj = mocker.spy(zlib, "decompressobj")
    assert SELRelay.is_cid(io.BytesIO(big)) is False
    decompressobj.assert_called_once()


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"x",
        b"<?xml version='1.0'?><SCL/>",
        b"x\x00not zlib: bad header check bits",
        b"x\x9c garbage that looks like zlib",
    ],
)
def test_is_cid_rejects_non_zlib(mocker, data):
    decompressobj = mocker.spy(zlib, "decompressobj")
    assert SELRelay.is_cid(io.BytesIO(data)) is False
    if data[:2] != b"x\x9c":
        decompressobj.assert_not_called()  # invalid zlib header: not read or inflated


def test_is_cid_truncated(scl_raw):
    data = zlib.compress(scl_raw)
    assert SELRelay.is_cid(io.BytesIO(data)) is True
    assert SELRelay.is_cid(io.BytesIO(data[:-8])) is False


def test_zlib_bomb_not_claimed(mocker, tmp_path, scl_raw):
    from peat.parsing import scl

    path = tmp_path / "firmware.bin"
    path.write_bytes(zlib.compress(scl_raw + b"<!--" + b" " * 8192 + b"-->"))
    assert _claims(SELRelay, path)
    mocker.patch.object(scl, "MAX_DECOMPRESSED_SIZE", 4096)
    assert not _claims(SELRelay, path)


def test_parse_zlib_cid_any_name(mocker, tmp_path, scl_raw):
    mocker.patch.object(DeviceData, "write_file", return_value=tmp_path / "x")
    path = tmp_path / "relay_61850_export.bin"
    path.write_bytes(zlib.compress(scl_raw, 1))
    dev = SELRelay.parse(path)
    assert dev is not None
    assert dev.iec61850.ied_name == "PROT1"


def test_id_name_fallback_reads_iec61850(mocker):
    comm = mocker.MagicMock()
    comm.all_output = ["=>"]
    comm.type = "Telnet"
    dev = DeviceData(ip="192.0.2.10")
    dev.iec61850.ied_name = "PROT1"
    assert SELRelay._selascii_verify_post_process(dev, comm) is True
    assert dev.name == "PROT1"


# ----------------------------------------------------------------------------- #
# File inventory
# ----------------------------------------------------------------------------- #
class _FakeComms:
    address = "192.0.2.10"
    listings = {
        None: ["CFG.TXT", "SETTINGS", "EVENTS"],
        "SETTINGS": ["SET_1.TXT", "SET_P5.TXT", "SET_61850.CID"],
        "EVENTS": ["HISTORY.TXT", "E1001.CEV"],
    }

    def list_files(self, directory=None):
        return list(self.listings[directory])


def test_populate_file_listing():
    dev = DeviceData(ip="192.0.2.10")
    sel_comms.populate_file_listing(dev, _FakeComms())

    files = {f.path.as_posix(): f for f in dev.files}
    assert files["/SETTINGS"].type == "dir"
    assert files["/EVENTS"].type == "dir"
    assert files["/CFG.TXT"].category == {"configuration"}
    assert files["/SETTINGS/SET_1.TXT"].category == {"settings", "configuration"}
    assert files["/SETTINGS/SET_61850.CID"].category == {"configuration", "iec61850"}
    assert files["/EVENTS/HISTORY.TXT"].category == {"log"}
    assert files["/EVENTS/E1001.CEV"].category == {"event_record"}
    assert all(f.peat_module == "SELRelay" for f in dev.files)

    assert dev._cache["file_listing"]["SETTINGS"] == ["SET_1.TXT", "SET_P5.TXT", "SET_61850.CID"]
    assert dev.extra["settings_root_directory"] == "SETTINGS"
    for key in (
        "file_listing",
        "all_dirs_on_device",
        "all_files_on_device",
        "num_directories_on_device",
        "num_files_on_device",
    ):
        assert key not in dev.extra


def test_pull_files_merges_downloads(mocker, tmp_path):
    local = tmp_path / "SET_1.TXT"
    local.write_text("[1]\nRID,FEEDER 1\n")

    def _download(*_args, **_kwargs):
        return {
            "SET_1.TXT": {
                "name": "SET_1.TXT",
                "data": local.read_text(),
                "raw_path": "SETTINGS SET_1.TXT",
                # download_files() drops the directory of Telnet/serial paths
                "device_path": PurePosixPath("/SET_1.TXT"),
                "local_path": local,
            }
        }

    mocker.patch.object(sel_comms, "_method_name", return_value="Telnet")
    mocker.patch.object(sel_comms, "download_files", side_effect=_download)
    dev = DeviceData(ip="192.0.2.10")
    sel_comms.pull_files(dev, _FakeComms())

    matches = [f for f in dev.files if f.path.as_posix() == "/SETTINGS/SET_1.TXT"]
    assert len(matches) == 1
    set1 = matches[0]
    assert set1.local_path == local
    assert set1.size == len(local.read_text())
    assert set1.category == {"settings", "configuration"}
    assert set1.mtime is None  # local copy metadata is not the device's (R32)
    assert not [f for f in dev.files if f.path.as_posix() == "/SET_1.TXT"]
    assert dev._cache["all_files"]["SET_1.TXT"]["device_path"] == PurePosixPath(
        "/SETTINGS/SET_1.TXT"
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("-08.0", "-08:00"),
        ("5.5", "+05:30"),
        ("0.0", "+00:00"),
        ("x", ""),
        ("-12", "-12:00"),
        ("14.0", "+14:00"),
        # not a real UTC offset: would crash the time parse or export (R2-22)
        ("nan", ""),
        ("inf", ""),
        ("-inf", ""),
        ("1e400", ""),
        ("30", ""),
        ("-30.0", ""),
        ("99999", ""),
        ("14.5", ""),
        ("-12.5", ""),
    ],
)
def test_hours_to_utc_offset(raw, expected):
    assert hours_to_utc_offset(raw) == expected


ETH_LINES = [
    "MAC: 00-30-A7-00-00-01",
    "IP ADDRESS: 192.0.2.10/24",
    "NETMODE: FAILOVER",
    "ACTIVE PORT: PORT 5A",
    "PORT 5A   UP      100M    FULL    TX",
    "PORT 5B   DOWN    ---     ---     FX",
    "   SENT     RCVD         SENT       RCVD      SENT    RCVD",
    "     10       20            300        400         0       0",
]


def test_pull_more_commands_maps_outputs(mocker):
    from datetime import datetime

    from peat.modules.sel.sel_telnet import SELTelnet

    comms = mocker.MagicMock(spec=SELTelnet)
    comms.show_ser.return_value = []
    comms.show_his.return_value = []
    comms.get_sta.return_value = {
        "device_time": datetime(2026, 11, 2, 11, 59, 58),
        "time_source": "IRIG-B",
        "self_tests": [{"name": "RAM", "value": "OK", "health": "normal"}],
        "relay_enabled": True,
    }
    comms.get_device_time.return_value = datetime(2026, 11, 2, 11, 59, 59)
    comms.get_active_group.return_value = "1"
    comms.show_mac.return_value = {
        "ip_mac": "00:30:A7:00:00:01",
        "goose_mac": "00:30:A7:00:00:02",
    }
    comms.show_eth.return_value = ETH_LINES
    for name in ("show_bre", "show_eve", "show_sum", "show_status"):
        getattr(comms, name).return_value = []
    mocker.patch.object(DeviceData, "write_file")

    dev = DeviceData(ip="192.0.2.10")
    dev.description.model = "451"
    assert SELRelay.pull_more_commands(dev, comms) is True

    assert dev.clock.time == datetime(2026, 11, 2, 11, 59, 59)
    assert dev.clock.observed is not None
    assert dev.clock.source == "irig_b"
    assert dev.health == "normal"
    port5 = next(i for i in dev.interface if i.name == "Port 5")
    assert port5.mac == "00:30:A7:00:00:01"
    assert port5.statistics.ingress.packets == 20
    assert dev.iec61850.extra["goose_source_mac"] == "00:30:A7:00:00:02"
    for key in ("device_time", "time_source", "ip_mac", "goose_mac", "communications"):
        assert key not in dev.extra
    assert "additional_command_outputs" not in dev.extra
    assert dev.extra["active_settings_group"] == "1"
