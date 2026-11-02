"""
Tests for hashing and recording the files PEAT downloads from SEL devices
or derives from them (``peat/modules/sel/sel_files.py`` and its callers).

The relays are fakes that serve files from memory. The sources and
licenses of the data files are in data_files/relay/README.md.
"""

import hashlib
import json
import shutil
import zlib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest
from requests import Response

from peat import DeviceData, SELRelay, config, datastore, utils
from peat.modules.sel import sel_comms, sel_files, sel_relay
from peat.modules.sel.relay_parse import parse_rdb_relays, read_rdb_streams
from peat.modules.sel.sel_files import record_downloaded_file, write_and_record_file
from peat.modules.sel.sel_http import SELHTTP
from peat.modules.sel.sel_serial import SELSerial
from peat.modules.sel.sel_telnet import SELTelnet
from peat.protocols import FTP, HTTP

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"
STREAMS_DIR = RELAY_DIR / "sel-710_rdb_streams"
CERT_PATH = Path(__file__).resolve().parents[2] / "protocols" / "data_files"


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(HTTP, "page_cache", {})
    return tmp_path


@pytest.fixture
def no_device_dir(mocker):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None})


def _hashes(data: bytes) -> dict[str, str]:
    return {
        algo: getattr(hashlib, algo)(data).hexdigest().upper()
        for algo in ["md5", "sha1", "sha256", "sha512"]
    }


def _file(dev, name, source=None):
    matches = [
        f for f in dev.files if f.name == name and (not source or f.extra["source"] == source)
    ]
    assert len(matches) == 1, f"{len(matches)} files named {name}: {dev.files}"
    return matches[0]


def _assert_recorded(file_obj, data: bytes, dev):
    assert file_obj.hash.dict(exclude_none=True) == _hashes(data)
    assert file_obj.size == len(data)
    assert set(_hashes(data).values()) <= dev.related.hash
    if file_obj.local_path:
        assert file_obj.local_path.read_bytes() == data


class FakeFTP(FTP):
    """A relay's FTP server, with the files in memory."""

    def __init__(self, files: dict[str, bytes], ip: str = "192.0.2.10") -> None:
        super().__init__(ip)
        self.files = files  # {"SETTINGS/SET_1.TXT": b"...", "CFG.TXT": b"..."}

    def nlst_files(self, directory: str | None = None) -> list[str]:
        if not directory:
            return sorted({path.split("/")[0] for path in self.files})
        return sorted(
            path.split("/", 1)[1] for path in self.files if path.startswith(f"{directory}/")
        )

    def download_binary(self, filename, save_path=None, save_to_file=True) -> bytes | None:  # noqa: ARG002
        return self.files.get(filename)


class FakeTelnet(SELTelnet):
    """A relay's Telnet interface. FILE SHOW returns text with the framing removed."""

    def __init__(self, files: dict[str, str], ip: str = "192.0.2.11") -> None:
        super().__init__(ip)
        self.files = files  # {"SETTINGS SET_1.TXT": "..."}

    def can_download_files(self) -> bool:
        return True

    def download_binary(self, filename, save_to_file=True) -> str | None:  # noqa: ARG002
        return self.files.get(filename)


class FakeSerial(SELSerial):
    """A relay's serial port, which may or may not support FILE SHOW."""

    def __init__(self, files: dict[str, bytes], port: str, supports_show: bool) -> None:
        super().__init__(port)
        self.files = files
        self._show = supports_show

    @property
    def supports_show(self) -> bool:
        # The real property sends "file show" to the relay if it isn't cached
        raise AssertionError("recording a file must not send commands to the relay")

    def download_binary(self, filename, save_to_file=True) -> bytes | None:  # noqa: ARG002
        self._supports_show = self._show  # The real download caches this
        return self.files.get(filename)


def _relay_files() -> dict[str, bytes]:
    """The SEL-710 settings, laid out like files on a relay without a SET_ALL.TXT."""
    files = {"CFG.TXT": (STREAMS_DIR / "Misc" / "Cfg.txt").read_bytes()}
    for path in STREAMS_DIR.glob("set_*.txt"):
        files[f"SETTINGS/{path.name.upper()}"] = path.read_bytes()
    return files


# ---------------------------------------------------------------------------
# record_downloaded_file() and write_and_record_file()
# ---------------------------------------------------------------------------


def test_record_downloaded_file_hashes_raw_bytes():
    dev = datastore.get("192.0.2.1", "ip")
    data = b'[1]\r\nRID,"FEEDER \xb0 1"\r\n'  # Not valid UTF-8

    file_obj = record_downloaded_file(
        dev,
        data,
        "SET_1.TXT",
        device_path="\\SETTINGS\\SET_1.TXT",
        transport="ftp",
        peat_module="SELRelay",
        extra={"file_transfer": "ftp"},
    )

    assert dev.files == [file_obj]
    _assert_recorded(file_obj, data, dev)
    assert file_obj.path == PurePosixPath("/SETTINGS/SET_1.TXT")
    assert file_obj.directory == "/SETTINGS/"
    assert file_obj.type == "file"
    assert file_obj.extension == "txt"
    assert file_obj.peat_module == "SELRelay"
    assert file_obj.device == "192.0.2.1"
    assert file_obj.local_path is None
    assert file_obj.extra == {"transport": "ftp", "source": "download", "file_transfer": "ftp"}
    assert "/SETTINGS/SET_1.TXT" in dev.related.files


def test_record_downloaded_file_text_is_utf8():
    dev = datastore.get("192.0.2.1", "ip")
    file_obj = record_downloaded_file(dev, 'RID,"FEEDER °"\r\n', "SET_1.TXT")
    _assert_recorded(file_obj, 'RID,"FEEDER °"\r\n'.encode(), dev)


def test_record_downloaded_file_same_file_twice():
    dev = datastore.get("192.0.2.1", "ip")

    first = record_downloaded_file(dev, b"one", "HISTORY.TXT", device_path="/EVENTS/HISTORY.TXT")
    again = record_downloaded_file(dev, b"one", "HISTORY.TXT", device_path="/EVENTS/HISTORY.TXT")
    assert again is first
    assert len(dev.files) == 1

    # Same name, different directory or contents
    record_downloaded_file(dev, b"one", "HISTORY.TXT", device_path="/REPORTS/HISTORY.TXT")
    record_downloaded_file(dev, b"two", "HISTORY.TXT", device_path="/EVENTS/HISTORY.TXT")
    assert len(dev.files) == 3


def test_record_downloaded_file_local_path(tmp_path, caplog):
    dev = datastore.get("192.0.2.1", "ip")
    local = tmp_path / "SET_1.TXT"
    local.write_bytes(b"settings")

    recorded = record_downloaded_file(dev, b"settings", "SET_1.TXT", local_path=local)
    assert recorded.local_path == local.resolve()

    # The file doesn't have the data that was hashed, e.g. "NAME.1" was written instead
    stale = record_downloaded_file(dev, b"new settings", "SET_1.TXT", local_path=local)
    assert stale.local_path is None
    assert stale.hash.dict(exclude_none=True) == _hashes(b"new settings")
    assert "differ from the data that was hashed" in caplog.text

    # DeviceData.write_file() returns the bare filename if file output is disabled
    assert record_downloaded_file(dev, b"x", "x.txt", local_path=Path("x.txt")).local_path is None
    missing = record_downloaded_file(dev, b"y", "y.txt", local_path=tmp_path / "y.txt")
    assert missing.local_path is None


def test_write_and_record_file_existing_name(env):
    # utils.write_file() writes "<name>.1" if the file exists, the recorded local_path must follow
    dev = datastore.get("192.0.2.1", "ip")

    first = write_and_record_file(dev, "first", "combined_SET_ALL.txt")
    second = write_and_record_file(dev, "second", "combined_SET_ALL.txt")

    out_dir = env / "devices" / "192.0.2.1"
    assert first.local_path == (out_dir / "combined_SET_ALL.txt").resolve()
    assert second.local_path == (out_dir / "combined_SET_ALL.txt.1").resolve()
    _assert_recorded(first, b"first", dev)
    _assert_recorded(second, b"second", dev)
    assert first.extra["source"] == "derived"
    assert first.name == second.name == "combined_SET_ALL.txt"


def test_write_and_record_file_json(env, mocker):
    dev = datastore.get("192.0.2.1", "ip")
    data = {"ser": {"timestamp": datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC), "result": {"b", "a"}}}

    written = write_and_record_file(dev, data, "additional-command-outputs.json")
    raw = (env / "devices" / "192.0.2.1" / "additional-command-outputs.json").read_bytes()
    assert written.local_path is not None
    _assert_recorded(written, raw, dev)

    # Same hash when nothing is written
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None})
    other = datastore.get("192.0.2.2", "ip")
    in_memory = write_and_record_file(other, data, "additional-command-outputs.json")
    assert in_memory.local_path is None
    assert in_memory.hash == written.hash


def test_write_and_record_file_sub_dir(env):
    dev = datastore.get("192.0.2.1", "ip")
    page = write_and_record_file(dev, b"<html/>", "http_files/protected/N1/ver.html")

    assert page.name == "ver.html"
    out_dir = env / "devices" / "192.0.2.1"
    assert page.local_path == (out_dir / "http_files/protected/N1/ver.html").resolve()
    _assert_recorded(page, b"<html/>", dev)


@pytest.mark.usefixtures("no_device_dir")
def test_write_and_record_file_without_device_dir(env):
    dev = datastore.get("192.0.2.1", "ip")
    file_obj = write_and_record_file(dev, "settings", "extracted_SET_ALL.txt")

    assert file_obj.local_path is None
    assert file_obj.name == "extracted_SET_ALL.txt"
    _assert_recorded(file_obj, b"settings", dev)
    assert not (env / "devices").exists()


def test_annotate_settings_classes():
    dev = datastore.get("192.0.2.1", "ip")
    set_1 = record_downloaded_file(dev, b"1", "SET_1.TXT", device_path="/SETTINGS/SET_1.TXT")
    set_p1 = record_downloaded_file(dev, b"p1", "set_p1.txt")
    other = record_downloaded_file(dev, b"2", "SER.TXT")

    sel_files.annotate_settings_classes(
        {
            "1": {
                "class": "1",
                "name": "Group 1",
                "file": "/SETTINGS/SET_1.TXT",
                "hex_id": "a9dd3ac2",
            },
            "P1": {"class": "P1", "name": "Port 1"},
            "SAVE_INFO": ["Saved on 2/16/2023 at 10:14:22 PM"],
        },
        dev.files,
    )

    assert set_1.extra["settings_class"] == {
        "class": "1",
        "name": "Group 1",
        "checksum": "a9dd3ac2",
    }
    assert set_p1.extra["settings_class"] == {"class": "P1", "name": "Port 1"}
    assert "settings_class" not in other.extra

    sel_files.annotate_settings_classes(None, dev.files)  # No [CLASSES] section


# ---------------------------------------------------------------------------
# Relay file downloads (sel_comms)
# ---------------------------------------------------------------------------


def test_pull_files_ftp(env):
    served = {
        "CFG.TXT": b"[INFO]\r\nRELAYTYPE=0700G\r\n",
        "SETTINGS/SET_1.TXT": b'[1]\r\nRID,"\xb0"\r\n',  # Not valid UTF-8
        "SETTINGS/SET_61850.CID": zlib.compress(b"<SCL/>"),
        "EVENTS/HISTORY.TXT": b"events history\r\n",
        "REPORTS/HISTORY.TXT": b"reports history\r\n",
    }
    dev = datastore.get("192.0.2.10", "ip")

    all_files = sel_comms.pull_files(dev, FakeFTP(served))

    relay_files = env / "devices" / "192.0.2.10" / "relay_files"
    assert len(dev.files) == len(served)
    for path, data in served.items():
        file_obj = next(f for f in dev.files if f.path == PurePosixPath(f"/{path}"))
        _assert_recorded(file_obj, data, dev)
        assert file_obj.local_path == (relay_files / path).resolve()
        assert file_obj.peat_module == "SELRelay"
        assert file_obj.extra == {"transport": "ftp", "file_transfer": "ftp", "source": "download"}

    # Both HISTORY.TXT files are kept, the one in REPORTS is used by name
    by_path = dev._cache["all_files_by_path"]
    assert set(by_path) == {f"/{path}" for path in served}
    assert all_files["HISTORY.TXT"]["device_path"] == PurePosixPath("/REPORTS/HISTORY.TXT")
    assert all_files["HISTORY.TXT"]["data"] == "reports history\r\n"
    assert by_path["/EVENTS/HISTORY.TXT"]["data"] == "events history\r\n"

    # The data is decoded, the saved file and the hashes are of the raw bytes
    assert all_files["SET_1.TXT"]["data"] == '[1]\r\nRID,"\xb0"\r\n'
    assert all_files["SET_1.TXT"]["hash"] == _hashes(served["SETTINGS/SET_1.TXT"])
    assert all_files["SET_1.TXT"]["file"] in dev.files
    assert isinstance(all_files["SET_61850.CID"]["data"], bytes)


def test_pull_files_same_name_last_dir_wins():
    # Same precedence as before files were keyed by path: the last directory wins
    served = {"DIAGNOSTICS/NOTES.TXT": b"first", "STATUS/NOTES.TXT": b"second"}
    dev = datastore.get("192.0.2.10", "ip")

    all_files = sel_comms.pull_files(dev, FakeFTP(served))

    assert all_files["NOTES.TXT"]["data"] == "second"
    assert len(dev.files) == 2


@pytest.mark.usefixtures("no_device_dir")
def test_pull_files_without_device_dir(env):
    served = {"CFG.TXT": b"[INFO]\r\n", "SETTINGS/SET_1.TXT": b"[1]\r\n"}
    dev = datastore.get("192.0.2.10", "ip")

    all_files = sel_comms.pull_files(dev, FakeFTP(served))

    assert set(all_files) == {"CFG.TXT", "SET_1.TXT"}
    for path, data in served.items():
        file_obj = _file(dev, path.split("/")[-1])
        _assert_recorded(file_obj, data, dev)
        assert file_obj.local_path is None
    assert all_files["SET_1.TXT"]["local_path"] == ""
    assert not (env / "devices").exists()


def test_pull_files_twice(env):
    # e.g. a FTP pull followed by a Telnet pull with "sel.force_telnet_file_download"
    dev = datastore.get("192.0.2.10", "ip")
    sel_comms.pull_files(dev, FakeFTP({"SETTINGS/SET_1.TXT": b"old"}))
    sel_comms.pull_files(dev, FakeFTP({"SETTINGS/SET_1.TXT": b"new"}))

    settings = env / "devices" / "192.0.2.10" / "relay_files" / "SETTINGS"
    old, new = sorted(dev.files, key=lambda f: f.local_path.name)
    assert old.local_path == (settings / "SET_1.TXT").resolve()
    assert new.local_path == (settings / "SET_1.TXT.1").resolve()
    _assert_recorded(old, b"old", dev)
    _assert_recorded(new, b"new", dev)


def test_download_files_telnet():
    tn = FakeTelnet({"SETTINGS SET_1.TXT": '[1]\r\nRID,"FEEDER 1"\r\n', "SET_ALL.TXT": "=>"})
    dev = datastore.get("192.0.2.11", "ip")

    files = sel_comms.download_files(["SETTINGS SET_1.TXT", "SET_ALL.TXT"], tn, None, dev=dev)

    set_1 = files["SET_1.TXT"]["file"]
    assert set_1.path == PurePosixPath("/SETTINGS/SET_1.TXT")
    assert set_1.extra == {
        "transport": "telnet",
        "file_transfer": "file_show",
        "source": "download",
    }
    _assert_recorded(set_1, b'[1]\r\nRID,"FEEDER 1"\r\n', dev)

    # Only the prompt was received: nothing is saved or hashed but the empty file
    set_all = files["SET_ALL.TXT"]
    assert set_all["data"] == "=>"
    assert set_all["file"].size == 0
    assert "mis-parse" in set_all["file"].description


@pytest.mark.parametrize(("supports_show", "transfer"), [(True, "file_show"), (False, "ymodem")])
def test_download_files_serial(supports_show, transfer):
    ser = FakeSerial({"SETTINGS SET_1.TXT": b"[1]\r\n"}, f"/dev/ttyFAKE{transfer}", supports_show)
    dev = datastore.get("192.0.2.12", "ip")

    files = sel_comms.download_files(["SETTINGS SET_1.TXT"], ser, None, dev=dev)

    file_obj = files["SET_1.TXT"]["file"]
    assert file_obj.extra["transport"] == "serial"
    assert file_obj.extra["file_transfer"] == transfer
    _assert_recorded(file_obj, b"[1]\r\n", dev)


def test_download_files_directory():
    # Older relays: PEAT changes to the directory and downloads the bare filename
    dev = datastore.get("192.0.2.10", "ip")
    ftp = FakeFTP({"SET_1.TXT": b"[1]\r\n"})

    files = sel_comms.download_files(["SET_1.TXT"], ftp, None, dev=dev, directory="SETTINGS")
    assert files["SET_1.TXT"]["device_path"] == PurePosixPath("/SETTINGS/SET_1.TXT")

    # Without a device, the hashes are still returned
    files = sel_comms.download_files(["SET_1.TXT"], ftp, None)
    assert files["SET_1.TXT"]["hash"] == _hashes(b"[1]\r\n")
    assert files["SET_1.TXT"]["size"] == 5
    assert "file" not in files["SET_1.TXT"]


# ---------------------------------------------------------------------------
# SELRelay pulls
# ---------------------------------------------------------------------------


def test_pull_configs_settings_files():
    served = _relay_files()
    # A [CLASSES] line with the file and checksum, like on a relay (docs/sel.rst)
    served["CFG.TXT"] = served["CFG.TXT"].replace(
        b'1,"Group 1"', b'1,"Group 1","\\SETTINGS\\SET_1.TXT","a9dd3ac2"'
    )
    dev = datastore.get("192.168.1.2", "ip")

    assert SELRelay.pull_configs(dev, FakeFTP(served, ip="192.168.1.2")) is True

    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in dev.logic.parsed
    for path, data in served.items():
        _assert_recorded(_file(dev, path.split("/")[-1], "download"), data, dev)

    # Reconstructed SET_ALL.TXT, since there isn't one
    combined = _file(dev, "combined_SET_ALL.txt")
    assert combined.extra["source"] == "derived"
    assert combined.path == combined.local_path  # Not a file on the relay
    assert "CFG.TXT" in combined.extra["derived_from"]
    assert "SET_P1.TXT" in combined.extra["derived_from"]
    _assert_recorded(combined, combined.local_path.read_bytes(), dev)

    # Settings classes from CFG.TXT
    assert _file(dev, "SET_1.TXT").extra["settings_class"] == {
        "class": "1",
        "name": "Group 1",
        "checksum": "a9dd3ac2",
    }
    assert _file(dev, "SET_P1.TXT").extra["settings_class"] == {"class": "P1", "name": "Port 1"}


def test_pull_configs_cid():
    scl = (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n<SCL xmlns="http://www.iec.ch/61850/2003/SCL"/>'
    )
    compressed = zlib.compress(scl.encode(), 1)
    dev = datastore.get("192.0.2.13", "ip")

    SELRelay.pull_configs(dev, FakeFTP({"SETTINGS/SET_61850.CID": compressed}, ip="192.0.2.13"))

    _assert_recorded(_file(dev, "SET_61850.CID"), compressed, dev)
    decompressed = _file(dev, "SET_61850_decompressed.xml")
    _assert_recorded(decompressed, scl.encode(), dev)
    assert decompressed.extra["source"] == "derived"
    assert decompressed.extra["derived_from"] == ["SET_61850.CID"]


def test_pull_more_commands(mocker):
    tn = FakeTelnet({}, ip="192.0.2.14")
    mocker.patch.object(tn, "elevate", return_value=True)
    for name in ["show_ser", "show_his", "get_sta", "get_device_time", "show_mac"]:
        mocker.patch.object(tn, name, return_value=None)
    for name in ["show_eth", "show_bre", "show_eve", "show_sum", "show_status"]:
        mocker.patch.object(tn, name, return_value=[f"{name} output"])
    mocker.patch.object(tn, "get_active_group", return_value="1")
    dev = datastore.get("192.0.2.14", "ip")

    assert SELRelay.pull_more_commands(dev, tn) is True

    outputs = _file(dev, "additional-command-outputs.json")
    assert outputs.extra["source"] == "command_output"
    assert outputs.extra["transport"] == "telnet"
    assert outputs.peat_module == "SELRelay"
    _assert_recorded(outputs, outputs.local_path.read_bytes(), dev)
    assert b"show_eth output" in outputs.local_path.read_bytes()


# ---------------------------------------------------------------------------
# Web interface downloads (SELHTTP)
# ---------------------------------------------------------------------------


def _response(url: str, content: bytes, headers: dict | None = None) -> Response:
    resp = Response()
    resp.status_code = 200
    resp.url = url
    resp._content = content
    resp.encoding = "utf-8"
    resp.headers.update(headers or {})
    return resp


class FakeSession:
    """Responses from a device's web server, keyed by URL (without the query)."""

    def __init__(self, pages: dict[str, tuple[bytes, dict]]) -> None:
        self.pages = pages

    def _respond(self, url: str) -> Response:
        content, headers = self.pages[url]
        return _response(url, content, headers)

    def get(self, url: str, **kwargs) -> Response:  # noqa: ARG002
        return self._respond(url)

    def post(self, url: str, **kwargs) -> Response:  # noqa: ARG002
        return self._respond(url)

    def close(self) -> None:
        pass


def test_selhttp_relay_pages(env, mocker):
    session_url = "http://192.0.2.20:80/protected/N7f3a/"
    ver_url = f"{session_url}static_command.html?cmd=ver"
    ver_page = b"<html><body><pre>FID=SEL-351S-7-R516\r\n</pre></body></html>"
    http = SELHTTP("192.0.2.20", 80)
    http._session = FakeSession({ver_url: (ver_page, {})})
    http._session_url = session_url

    assert http._get_page(ver_url) == "FID=SEL-351S-7-R516\n"

    dev = datastore.get("192.0.2.20", "ip")
    page = _file(dev, "static_command_cmd=ver.html")
    _assert_recorded(page, ver_page, dev)
    assert (
        page.local_path
        == (
            env / "devices/192.0.2.20/http_files/protected/session/static_command_cmd=ver.html"
        ).resolve()
    )
    assert page.extra == {
        "transport": "http",
        "source": "web_page",
        "page": "static_command.html?cmd=ver",
    }

    # Logic settings pages
    mocker.patch("peat.modules.sel.sel_http.sleep")
    mocker.patch.object(http, "read_page", return_value="TR      =51P1T + 51G1T\n")
    http._logic_page_style = "351S"
    assert http.get_logic_data(dev) is True

    logic_1 = _file(dev, "raw_logic_group_1.txt")
    assert logic_1.extra["source"] == "command_output"
    _assert_recorded(logic_1, b"TR      =51P1T + 51G1T", dev)
    assert len([f for f in dev.files if f.name.startswith("raw_logic_group_")]) == 6


def test_selhttp_rtac_soe_log(env):
    soe = b'"timestamp","message"\r\n'
    http = SELHTTP("192.0.2.21", 443, protocol="https")
    http._session = FakeSession({"https://192.0.2.21:443/soe.csv": (soe, {})})
    dev = datastore.get("192.0.2.21", "ip")

    http.view_syslog(dev)

    soe_file = _file(dev, "soe.csv")
    _assert_recorded(soe_file, soe, dev)
    assert soe_file.local_path == (env / "devices/192.0.2.21/http_files/soe.csv").resolve()
    assert soe_file.path == PurePosixPath("/soe.csv")
    assert soe_file.peat_module == "SELRTAC"
    assert soe_file.extra == {"transport": "https", "source": "web_download"}


def test_sel3620_certificate_export(env):
    cert = (CERT_PATH / "sel_3530_certificate.cert").read_bytes()
    listing = b'<html><a class="listButton" href="/X509_export.sel?id=1">Export</a></html>'
    http = SELHTTP("192.0.2.22", 443, protocol="https")
    http._session = FakeSession(
        {
            "https://192.0.2.22:443/X509.sel": (listing, {}),
            "https://192.0.2.22:443/X509_export.sel?id=1": (
                cert,
                {"content-disposition": 'attachment; filename="web_server.pem"'},
            ),
        }
    )
    dev = datastore.get("192.0.2.22", "ip")

    result = http.gateway_cert_export(dev)

    assert "web_server.pem" in result["x509_certificates"]
    pem = _file(dev, "web_server.pem")
    _assert_recorded(pem, cert, dev)
    assert pem.local_path == (env / "devices/192.0.2.22/http_files/web_server.pem").resolve()
    assert pem.peat_module == "SEL3620"
    assert pem.extra == {
        "transport": "https",
        "source": "web_download",
        "page": "/X509_export.sel?id=1",
    }


# ---------------------------------------------------------------------------
# SELRelay parsing
# ---------------------------------------------------------------------------


def test_parse_rdb(env):
    rdb_path = RELAY_DIR / "sel-710_Relay710.rdb"
    rdb_data = rdb_path.read_bytes()

    dev = SELRelay.parse(rdb_path)

    rdb = _file(dev, "sel-710_Relay710.rdb")
    _assert_recorded(rdb, rdb_data, dev)
    assert rdb.extra["source"] == "parse_input"

    streams = read_rdb_streams(rdb_data)["New Settings 2"]
    recorded = [f for f in dev.files if f.extra["source"] == "rdb_stream"]
    assert len(recorded) == len(streams)
    for stream_path, data in streams.items():
        stream = next(f for f in recorded if f.extra["rdb_stream"] == stream_path)
        _assert_recorded(stream, data, dev)
        assert stream.path == PurePosixPath(f"Relays/New Settings 2/{stream_path}")
        assert stream.extra["rdb_relay_name"] == "New Settings 2"
        assert stream.extra["derived_from"] == ["sel-710_Relay710.rdb"]

    # The streams in data_files/ were extracted from the RDB without changes
    set_1 = next(f for f in recorded if f.extra["rdb_stream"] == "set_1.txt")
    assert set_1.hash.dict(exclude_none=True) == _hashes((STREAMS_DIR / "set_1.txt").read_bytes())

    extracted = _file(dev, "extracted_SET_ALL.txt")
    assert extracted.extra["source"] == "derived"
    assert extracted.local_path.parent == (env / "devices" / dev.get_id()).resolve()
    _assert_recorded(extracted, extracted.local_path.read_bytes(), dev)

    # The files and their hashes are exported
    full = json.loads((env / "devices" / dev.get_id() / "device-data-full.json").read_text())
    exported = {f["name"]: f for f in full["files"]}
    assert exported["set_1.txt"]["hash"] == set_1.hash.dict(exclude_none=True)
    assert exported["set_1.txt"]["extra"]["source"] == "rdb_stream"
    assert set_1.hash.sha256 in full["related"]["hash"]


@pytest.mark.usefixtures("no_device_dir")
def test_parse_rdb_without_device_dir():
    dev = SELRelay.parse(RELAY_DIR / "sel-710_Relay710.rdb")

    extracted = _file(dev, "extracted_SET_ALL.txt")
    assert extracted.local_path is None
    assert extracted.size > 0
    assert len([f for f in dev.files if f.extra["source"] == "rdb_stream"]) > 10


def test_parse_rdb_streams_outside_relays(monkeypatch):
    # Two relays with the SEL-710 settings, and a stream outside the "Relays" storage
    rdb_path = RELAY_DIR / "sel-710_Relay710.rdb"
    rdb_data = rdb_path.read_bytes()
    streams = read_rdb_streams(rdb_data)["New Settings 2"]
    set_all = parse_rdb_relays(rdb_data)["New Settings 2"]
    rdb_streams = {"A": streams, "B": streams, "": {"Project.txt": b"project"}}
    monkeypatch.setattr(sel_relay, "read_rdb_streams", lambda _data: rdb_streams)
    monkeypatch.setattr(sel_relay, "parse_rdb_relays", lambda _data: {"A": set_all, "B": set_all})

    dev_a = SELRelay.parse(rdb_path)
    dev_b = next(d for d in datastore.objects if d.extra.get("rdb_relay_name") == "B")

    # Each relay's streams are recorded for that relay, and the stream that
    # isn't in a relay's storage is recorded for both relays
    for dev, name in ((dev_a, "A"), (dev_b, "B")):
        recorded = [f for f in dev.files if f.extra["source"] == "rdb_stream"]
        assert {str(f.path) for f in recorded} == {
            *(f"Relays/{name}/{path}" for path in streams),
            "Project.txt",
        }
        project = next(f for f in recorded if f.name == "Project.txt")
        _assert_recorded(project, b"project", dev)
        assert project.extra == {
            "source": "rdb_stream",
            "rdb_stream": "Project.txt",
            "derived_from": ["sel-710_Relay710.rdb"],
        }


def test_parse_rdb_without_relay_layout(monkeypatch):
    # No relay in the file has settings, so the settings are from every stream
    rdb_path = RELAY_DIR / "sel-710_Relay710.rdb"
    rdb_data = rdb_path.read_bytes()
    streams = read_rdb_streams(rdb_data)["New Settings 2"]
    set_all = parse_rdb_relays(rdb_data)["New Settings 2"]
    monkeypatch.setattr(sel_relay, "parse_rdb_relays", lambda _data: {"": set_all})

    dev = SELRelay.parse(rdb_path)

    recorded = [f for f in dev.files if f.extra["source"] == "rdb_stream"]
    assert len(recorded) == len(streams)
    for stream_path, data in streams.items():
        stream = next(f for f in recorded if f.extra["rdb_stream"] == stream_path)
        _assert_recorded(stream, data, dev)
        assert stream.path == PurePosixPath(f"Relays/New Settings 2/{stream_path}")
        assert stream.extra["rdb_relay_name"] == "New Settings 2"


def test_parse_relay_files_dir(tmp_path):
    relay = tmp_path / "relay"
    (relay / "SETTINGS").mkdir(parents=True)
    shutil.copyfile(STREAMS_DIR / "Misc" / "Cfg.txt", relay / "CFG.TXT")
    for path in STREAMS_DIR.glob("set_*.txt"):
        shutil.copyfile(path, relay / "SETTINGS" / path.name.upper())

    dev = SELRelay.parse(relay)

    inputs = [f for f in dev.files if f.extra["source"] == "parse_input"]
    assert {f.local_path for f in inputs} == {p.resolve() for p in relay.rglob("*.TXT")}
    for file_obj in inputs:
        _assert_recorded(file_obj, file_obj.local_path.read_bytes(), dev)

    combined = _file(dev, "combined_SET_ALL.txt")
    assert combined.extra["source"] == "derived"
    assert sorted(combined.extra["derived_from"])[:2] == ["CFG.TXT", "SET_1.TXT"]
    assert combined.local_path.read_text(encoding="utf-8").startswith("[INFO]")

    assert _file(dev, "SET_1.TXT").extra["settings_class"] == {"class": "1", "name": "Group 1"}


def test_parse_cid(tmp_path):
    scl = '<?xml version="1.0"?>\n<SCL xmlns="http://www.iec.ch/61850/2003/SCL"/>'
    cid = tmp_path / "SET_61850.CID"
    cid.write_bytes(zlib.compress(scl.encode(), 9))

    dev = SELRelay.parse(cid)

    _assert_recorded(_file(dev, "SET_61850.CID"), cid.read_bytes(), dev)
    _assert_recorded(_file(dev, "SET_61850_decompressed.xml"), scl.encode(), dev)


def test_parse_set_all_file():
    path = RELAY_DIR / "sel-710_SET_ALL.TXT"
    dev = SELRelay.parse(path)

    set_all = _file(dev, "sel-710_SET_ALL.TXT")
    _assert_recorded(set_all, path.read_bytes(), dev)
    assert dev.logic.file.hash == set_all.hash
    assert utils.gen_hashes(path)["sha256"] in dev.related.hash


@pytest.mark.usefixtures("env")
def test_download_files_keeps_file_if_recording_fails(monkeypatch):
    def _fail(**_kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(sel_comms, "record_downloaded_file", _fail)
    dev = datastore.get("192.0.2.10", "ip")

    all_files = sel_comms.pull_files(dev, FakeFTP({"SETTINGS/SET_1.TXT": b"[1]\r\n"}))

    assert all_files["SET_1.TXT"]["data"] == "[1]\r\n"
    assert "hash" not in all_files["SET_1.TXT"]


@pytest.mark.usefixtures("env")
def test_write_and_record_file_unserializable_json():
    dev = datastore.get("192.0.2.10", "ip")

    assert write_and_record_file(dev, {("a", "b"): 1}, "bad.json") is None


def test_record_no_local_path_different_transfer():
    dev = DeviceData()
    for transport, transfer in (("ftp", "ftp"), ("telnet", "file_show")):
        record_downloaded_file(
            dev=dev,
            data=b"same",
            name="SET_1.TXT",
            device_path="SETTINGS/SET_1.TXT",
            transport=transport,
            extra={"file_transfer": transfer},
        )

    assert len(dev.files) == 2
