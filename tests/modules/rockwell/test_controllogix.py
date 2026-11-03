from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from peat import ControlLogix, DeviceData, config, datastore
from peat.modules.rockwell.clx_http import ClxHTTP


# TODO: test input file is validated for push (file extension, contents)
def test_controllogix_push_firmware_invalid_content_localhost(mocker):
    mocker.patch.object(datastore, "objects", [])

    dev = datastore.get("127.0.0.6")
    dev._runtime_options["timeout"] = 0.01

    assert ControlLogix.push(dev, b"xyz", "config") is False
    assert ControlLogix.push(dev, b"xyz", "firmware") is False
    assert ControlLogix.push(dev, b"", "firmware") is False
    # TODO: pytest fixture /w firmware content (see test_rest_api)


class FakeFTP:
    """Stand-in for peat.protocols.FTP with a VxWorks EWEB-like file listing."""

    LISTING = (
        ["ReadMe.txt", "1756-EWEB.eds", "WEB"],
        [
            {
                "type": "file",
                "permissions": "rwxrwxrwx",
                "size": 1200,
                "modified": datetime(2011, 1, 21),
                "name": "ReadMe.txt",
                "path": "ReadMe.txt",
                "parent": "",
            },
            {
                "type": "file",
                "permissions": "rw-r--r--",
                "size": 4096,
                "modified": datetime(2011, 1, 21),
                "name": "1756-EWEB.eds",
                "path": "1756-EWEB.eds",
                "parent": "",
            },
            {
                "type": "dir",
                "permissions": "rwxrwxrwx",
                "size": 8192,
                "modified": datetime(1970, 1, 1),
                "name": "WEB",
                "path": "WEB",
                "parent": "",
            },
        ],
    )

    def __init__(self, *_args, **_kwargs):
        self.ftp = SimpleNamespace(getwelcome=lambda: "220 VxWorks (5.4) FTP server ready")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def process_vxworks_ftp_welcome(self, welcome: str, dev: DeviceData) -> None:
        dev.extra["ftp_welcome"] = welcome

    def login(self, user: str, passwd: str) -> bool:
        return user == "Administrator" and passwd == ""

    def dir(self, _directory=None):
        return self.LISTING

    def download_binary(self, filename: str, save_to_file: bool = True) -> bytes:
        assert not save_to_file
        assert filename != "WEB", "directories must not be downloaded"
        return f"contents of {filename}".encode()


@pytest.fixture
def out_config(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


@pytest.mark.usefixtures("out_config")
def test_controllogix_ftp_files(mocker):
    mocker.patch("peat.modules.rockwell.controllogix.FTP", FakeFTP)
    dev = datastore.get("192.0.2.10")

    assert ControlLogix._verify_ftp(dev) is True
    assert ControlLogix.pull_ftp(dev) is True

    for key in ("ftp_files", "ftp_file_metadata", "ftp_metadata"):
        assert key not in dev.extra

    files = {str(f.path): f for f in dev.files}
    assert set(files) == {"ReadMe.txt", "1756-EWEB.eds", "WEB"}
    assert files["WEB"].type == "dir"
    assert files["WEB"].local_path is None
    readme = files["ReadMe.txt"]
    assert readme.type == "file"
    assert readme.size == 1200
    assert readme.mode == "0777"
    assert readme.mtime == datetime(2011, 1, 21)
    assert readme.peat_module == "ControlLogix"
    assert readme.local_path is not None
    assert readme.local_path.read_bytes() == b"contents of ReadMe.txt"
    assert readme.hash.sha256

    # Factory default credentials (Administrator, empty password) were accepted
    ftp = dev.retrieve("service", {"protocol": "ftp"})
    assert ftp.security.default_credentials is True
    assert ftp.security.encrypted is False


@pytest.mark.usefixtures("out_config")
def test_controllogix_ftp_file_cannot_escape(mocker, tmp_path):
    """A device file name with "../" is written inside of ftp_files, nowhere else."""
    listing = (
        ["escaped.txt"],
        [
            {
                "type": "file",
                "permissions": "rw-r--r--",
                "size": 10,
                "modified": datetime(2011, 1, 21),
                "name": "escaped.txt",
                "path": "../../../../escaped.txt",
                "parent": "",
            }
        ],
    )
    mocker.patch.object(FakeFTP, "LISTING", listing)
    mocker.patch("peat.modules.rockwell.controllogix.FTP", FakeFTP)
    dev = datastore.get("192.0.2.10")

    assert ControlLogix.pull_ftp(dev) is True
    ftp_dir = dev.get_sub_dir("ftp_files")
    written = list(tmp_path.rglob("escaped.txt"))
    assert written == [ftp_dir / "escaped.txt"]
    assert dev.files[0].local_path == ftp_dir / "escaped.txt"


class FakeSNMP:
    """Stand-in for peat.protocols.SNMP with one EN2T interface."""

    VALUES = {
        ("SNMPv2-MIB", "sysUpTime", 0): {"value_encoded": 360000, "value_string": ""},
        ("IF-MIB", "ifNumber", 0): {"value_encoded": 1, "value_string": "1"},
        ("IF-MIB", "ifDescr", 1): {"value_encoded": "", "value_string": "Ethernet Port 1"},
        ("IF-MIB", "ifOperStatus", 1): {"value_encoded": 1, "value_string": "up"},
        ("IF-MIB", "ifLastChange", 1): {"value_encoded": 1234, "value_string": ""},
    }

    def __init__(self, values: dict | None = None):
        self.values = dict(self.VALUES) if values is None else values

    def get(self, oid):
        value = self.values.get(oid)
        return [value] if value else []


def test_controllogix_snmp_if_last_change_is_not_uptime():
    dev = DeviceData(ip="192.0.2.10")
    dev._cache["snmp_object"] = FakeSNMP()

    assert ControlLogix.pull_snmp(dev) is True
    assert dev.uptime == timedelta(hours=1)
    iface = dev.interface[0]
    assert iface.name == "Ethernet Port 1"
    assert iface.connected is True
    assert iface.uptime is None
    assert iface.extra["if_last_change"] == 1234

    # A missing ifLastChange doesn't abort the pull
    values = dict(FakeSNMP.VALUES)
    del values[("IF-MIB", "ifLastChange", 1)]
    dev = DeviceData(ip="192.0.2.11")
    dev._cache["snmp_object"] = FakeSNMP(values)
    assert ControlLogix.pull_snmp(dev) is True
    assert "if_last_change" not in dev.interface[0].extra


def test_controllogix_pull_http_records_web_login(mocker):
    def fake_get_all(self, _dev):
        self.web_login_succeeded = True
        return True

    mocker.patch.object(ClxHTTP, "get_all", fake_get_all)
    dev = DeviceData(ip="192.0.2.10")
    dev._runtime_options["timeout"] = 0.01
    assert ControlLogix.pull_http(dev) is True

    http = dev.retrieve("service", {"protocol": "http"})
    assert http.port == dev.options["http"]["port"]
    assert http.security.default_credentials is True
