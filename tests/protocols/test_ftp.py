import ftplib

import pytest

from peat import CommError, DeviceData, config, datastore
from peat.protocols import FTP
from peat.protocols import ftp as ftp_module


def test_ftp_class():
    with pytest.raises(CommError):
        with FTP("127.0.0.1", 0, 0.01) as obj:
            obj.ftp.quit()
    inst = FTP("127.0.0.1")
    inst.ftp = ftplib.FTP()
    inst.disconnect()
    assert str(inst) == "127.0.0.1"
    assert "127.0.0.1" in repr(inst)


@pytest.mark.parametrize(
    ("welcome", "expected_version"),
    [
        ("220 VxWorks FTP server (VxWorks VxWorks5.5) ready.", "5.5"),
        ("220 VxWorks FTP server (VxWorks 6) ready.", "6"),
        ("220 Wind River FTP server 6.8 ready.", "6.8"),
    ],
)
def test_ftp_process_vxworks_ftp_welcome(welcome, expected_version):
    dev = DeviceData(ip="127.0.0.1")
    inst = FTP("127.0.0.1")

    assert inst.process_vxworks_ftp_welcome(welcome, dev) == expected_version
    assert dev.extra["ftp_welcome"] == welcome
    assert dev.os.version == expected_version
    assert dev.os.name == "VxWorks"
    assert dev.os.vendor.name == "Wind River Systems"
    assert dev.os.vendor.id == "WindRiver"


def test_ftp_process_vxworks_ftp_welcome_bad_arg():
    dev = DeviceData(ip="127.0.0.1")
    inst = FTP("127.0.0.1")

    assert inst.process_vxworks_ftp_welcome("", dev) is None
    assert dev.extra["ftp_welcome"] == ""

    assert inst.process_vxworks_ftp_welcome("bad welcome", dev) is None
    assert dev.extra["ftp_welcome"] == "bad welcome"

    assert inst.process_vxworks_ftp_welcome("") is None
    assert inst.process_vxworks_ftp_welcome("bad welcome") is None


class _FakeFTPLib:
    """Stands in for ftplib.FTP, returning fixed data for every RETR."""

    def retrbinary(self, cmd, callback, *_args, **_kwargs):
        callback(b"file data from " + cmd.encode())

    def retrlines(self, cmd, callback):
        callback(f"line from {cmd}")


@pytest.fixture
def fake_ftp(mocker, tmp_path):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    inst = FTP("127.0.0.1")
    inst.ftp = _FakeFTPLib()
    return inst


def test_ftp_download_files_contained(fake_ftp, tmp_path):
    local_dir = tmp_path / "devices" / "127.0.0.1" / "ftp_files"
    # Listing entries as produced by FTP.dir() from a hostile LIST response
    listing = [
        {"type": "file", "path": "/ata0a/../../../../../../OUTSIDE_FTP/pwned.txt"},
        {"type": "file", "path": "/../../../../ftp_abs_escape.txt"},
        {"type": "file", "path": "/ata0a/rtusetup.xml"},
    ]
    fake_ftp.download_files(local_dir, listing)

    written = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert written
    for path in written:
        assert path.is_relative_to(local_dir), path
    assert (local_dir / "ata0a" / "rtusetup.xml").is_file()
    assert (local_dir / "ata0a" / "OUTSIDE_FTP" / "pwned.txt").is_file()


@pytest.mark.parametrize("method", ["download_binary", "download_text"])
def test_ftp_download_default_path_contained(fake_ftp, tmp_path, method):
    getattr(fake_ftp, method)("../../../ftp_dl_escape.txt")
    getattr(fake_ftp, method)("/tmp/../../ftp_dl_escape2.txt")

    ftp_dir = tmp_path / "devices" / "127.0.0.1" / "ftp_files"
    written = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert len(written) == 2
    for path in written:
        assert path.is_relative_to(ftp_dir), path


def test_ftp_login_password_registered_as_secret(mocker):
    from peat import log_utils

    inst = FTP("127.0.0.1")
    inst.ftp = mocker.Mock()
    assert inst.login("Admin", "FTP-late-pw-7f3a")
    inst.ftp.login.assert_called_once_with("Admin", "FTP-late-pw-7f3a")
    assert log_utils.redact_secrets("pw FTP-late-pw-7f3a") == "pw <redacted>"


class _FakeListFTPLib:
    """Stands in for ftplib.FTP, returning a fixed LIST response for every directory."""

    def __init__(self, lines):
        self.lines = lines
        self.listed = []

    def dir(self, *args):
        *directory, callback = args
        self.listed.append(directory[0] if directory else None)
        for line in self.lines:
            callback(line)


def test_ftp_dir_skips_malformed_lines(mocker):
    mocker.patch.object(datastore, "objects", [])
    inst = FTP("127.0.0.1")
    inst.ftp = _FakeListFTPLib(
        [
            "garbage",
            "",
            "total 8",
            "-rw-r--r-- 1 0 0 NOTANUMBER JAN 01 1970 bad_size.txt",
            "-rwxrwxrwx   1 0      0          437824 JAN 21  2011 FILE.SYS",
        ]
    )

    names, metadata = inst.dir("/")
    assert names == ["bad_size.txt", "FILE.SYS"]
    assert metadata[0]["size"] == -1
    assert metadata[1]["size"] == 437824
    assert metadata[1]["path"] == "/FILE.SYS"


def test_ftp_rdir_depth_limited(mocker, log_messages):
    mocker.patch.object(datastore, "objects", [])
    inst = FTP("127.0.0.1")
    # Every directory contains another directory, forever
    inst.ftp = _FakeListFTPLib(["drwxrwxrwx   5 0      0            8192 JAN 01  1970 d"])

    assert inst.rdir("/")  # Previously, RecursionError
    assert len(inst.ftp.listed) == ftp_module.MAX_RDIR_DEPTH + 1
    assert any("directories deep" in m for m in log_messages)

    inst.ftp.listed.clear()
    _, metadata = inst.rdir("/", max_depth=5)
    assert len(inst.ftp.listed) == 6
    assert len(metadata) == 6
