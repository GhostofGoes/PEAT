import ftplib
import io
import posixpath

import pytest

import peat
from peat import CommError, DeviceData
from peat.protocols import FTP
from peat.protocols.cache import data_cache


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


class _FakeDataConn:
    def __init__(self, data: bytes, server: "FakeFTPServer", stor_path: str | None) -> None:
        self._data = data
        self._server = server
        self._stor_path = stor_path

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        pass

    def recv(self, _size: int) -> bytes:
        data, self._data = self._data, b""
        return data

    def makefile(self, *_args, **_kwargs):
        return io.StringIO(self._data.decode())

    def sendall(self, data: bytes) -> None:
        self._server.files[self._stor_path] = self._server.files.get(self._stor_path, b"") + data

    def close(self) -> None:
        pass


class FakeFTPServer:
    """Simulates a FTP server by replacing the network methods of ftplib.FTP."""

    WELCOME = "220 VxWorks FTP server (VxWorks 6) ready."

    def __init__(self, mocker) -> None:
        self.home = "/home"
        self.cwd = self.home
        self.dirs = {"/", "/home", "/home/a", "/home/b", "/etc"}
        self.files: dict[str, bytes] = {}
        self.commands: list[str] = []
        server = self

        def connect(ftp, host="", port=0, timeout=-999, source_address=None):  # noqa: ARG001
            ftp.host, ftp.port = host, port
            ftp.welcome = server.WELCOME
            return ftp.welcome

        def transfercmd(ftp, cmd, rest=None):  # noqa: ARG001
            return server.transfer(ftp, cmd)

        mocker.patch.object(ftplib.FTP, "connect", connect)
        mocker.patch.object(ftplib.FTP, "sendcmd", side_effect=server.handle, autospec=False)
        mocker.patch.object(ftplib.FTP, "voidcmd", side_effect=server.handle, autospec=False)
        mocker.patch.object(ftplib.FTP, "voidresp", return_value="226 Transfer complete")
        mocker.patch.object(ftplib.FTP, "transfercmd", transfercmd)

    def resolve(self, path: str) -> str:
        return posixpath.normpath(posixpath.join(self.cwd, path))

    def retr_count(self) -> int:
        return sum(1 for c in self.commands if c.startswith("RETR"))

    def handle(self, cmd: str) -> str:
        self.commands.append(cmd)
        verb, _, arg = cmd.partition(" ")
        if verb == "USER":
            return "331 Password required"
        if verb == "PASS":
            self.cwd = self.home
            return "230 Logged in"
        if verb == "CWD":
            target = self.resolve(arg)
            if target not in self.dirs:
                raise ftplib.error_perm("550 No such directory")
            self.cwd = target
            return "250 OK"
        if verb == "CDUP":
            self.cwd = posixpath.dirname(self.cwd) or "/"
            return "250 OK"
        if verb in ("DELE", "RNTO", "RMD"):
            self.files.pop(self.resolve(arg), None)
            return "250 OK"
        if verb == "RNFR":
            return "350 Ready"
        if verb in ("MKD", "PWD"):
            return f'257 "{self.cwd}"'
        return "200 OK"

    def transfer(self, ftp, cmd: str) -> _FakeDataConn:
        ftp.sendcmd(cmd)  # like ftplib's ntransfercmd()
        verb, _, arg = cmd.partition(" ")
        path = self.resolve(arg)
        if verb == "RETR":
            if path not in self.files:
                raise ftplib.error_perm("550 No such file")
            return _FakeDataConn(self.files[path], self, None)
        self.files[path] = b""  # STOR replaces the file
        return _FakeDataConn(b"", self, path)


@pytest.fixture
def ftp_server(mocker):
    mocker.patch.object(peat.data.datastore, "get")  # don't write files
    server = FakeFTPServer(mocker)
    server.files = {
        "/home/a/x.bin": b"\x00\x01home-a-x",
        "/home/b/x.bin": b"home-b-x",
        "/home/top.txt": b"line1\r\nline2\r\n",
        "/etc/conf.txt": b"conf",
        "/home/empty.bin": b"",
    }
    return server


def logged_in_ftp(user: str = "admin", passwd: str = "pass") -> FTP:
    inst = FTP("192.0.2.21")
    assert inst.login(user, passwd)
    return inst


@pytest.mark.usefixtures("ftp_server")
def test_welcome_captured_on_connect():
    assert FTP.cached_welcome("192.0.2.21") is None
    inst = FTP("192.0.2.21")
    assert inst.ftp.welcome == FakeFTPServer.WELCOME
    assert FTP.cached_welcome("192.0.2.21") == FakeFTPServer.WELCOME
    assert FTP.cached_welcome("192.0.2.21", 2121) is None
    assert FTP.cached_welcome("192.0.2.22") is None
    assert inst.process_vxworks_ftp_welcome(FTP.cached_welcome("192.0.2.21")) == "6"
    inst.disconnect()


def test_download_binary_cached_by_user_and_path(ftp_server, tmp_path):
    first = logged_in_ftp()
    assert first.cd("a")
    assert first.download_binary("x.bin") == b"\x00\x01home-a-x"
    assert ftp_server.retr_count() == 1

    # Same user and file from another instance: no RETR, file is still saved
    second = logged_in_ftp()
    assert second.cd("a")
    save_path = tmp_path / "saved.bin"
    assert second.download_binary("x.bin", save_path=save_path) == b"\x00\x01home-a-x"
    assert ftp_server.retr_count() == 1
    assert save_path.read_bytes() == b"\x00\x01home-a-x"

    # The same path relative to the home directory
    assert second.cd("..")
    assert second.download_binary("a/x.bin") == b"\x00\x01home-a-x"
    assert ftp_server.retr_count() == 1

    # A different user downloads it again
    other_user = logged_in_ftp("guest", "guest")
    other_user.cd("a")
    other_user.download_binary("x.bin")
    assert ftp_server.retr_count() == 2

    # Text and binary downloads are cached separately
    assert first.download_text("x.bin") == "\x00\x01home-a-x"
    assert ftp_server.retr_count() == 3

    # use_cache=False always downloads
    first.download_binary("x.bin", use_cache=False)
    assert ftp_server.retr_count() == 4


def test_download_text_cached(ftp_server):
    first = logged_in_ftp()
    assert first.download_text("top.txt") == "line1\nline2"
    assert logged_in_ftp().download_text("top.txt") == "line1\nline2"
    assert ftp_server.retr_count() == 1


def test_relative_path_resolution_with_tracked_cd(ftp_server):
    inst = logged_in_ftp()
    assert inst.cd("a")
    inst.download_binary("x.bin")
    assert inst.cd("../b")
    assert inst.download_binary("x.bin") == b"home-b-x"
    assert ftp_server.retr_count() == 2
    assert inst._file_key("x.bin", "binary").resource == "binary:~/b/x.bin"

    # A rejected CWD doesn't change the tracked directory
    assert not inst.cd("missing")
    assert inst._file_key("x.bin", "binary").resource == "binary:~/b/x.bin"

    # Absolute paths
    assert inst.download_binary("/etc/conf.txt") == b"conf"
    assert inst._file_key("/etc/../etc/conf.txt", "binary").resource == "binary:/etc/conf.txt"
    assert logged_in_ftp().download_binary("/etc/conf.txt") == b"conf"
    assert ftp_server.retr_count() == 3


@pytest.mark.usefixtures("ftp_server")
def test_going_above_home_disables_caching():
    inst = logged_in_ftp()
    assert inst.cd("..")  # the home directory is unknown, so "above home" is too
    assert inst._file_key("x.bin", "binary") is None
    assert inst._file_key("/etc/conf.txt", "binary") is not None
    # An absolute CWD makes the directory known again
    assert inst.cd("/etc")
    assert inst._file_key("conf.txt", "binary").resource == "binary:/etc/conf.txt"


def test_untracked_cwd_disables_caching(ftp_server):
    inst = logged_in_ftp()
    inst.download_binary("top.txt")
    inst.ftp.cwd("a")  # raw ftplib call, not tracked
    assert inst._file_key("x.bin", "binary") is None
    inst.download_binary("x.bin")
    inst.download_binary("x.bin")
    assert ftp_server.retr_count() == 3

    raw = logged_in_ftp()
    raw.cmd("CWD a")
    assert raw._file_key("x.bin", "binary") is None


def test_untracked_login_disables_caching(ftp_server):
    inst = FTP("192.0.2.21")
    inst.ftp.login("admin", "pass")  # raw ftplib call, not tracked
    assert inst._file_key("top.txt", "binary") is None
    inst.download_binary("top.txt")
    inst.download_binary("top.txt")
    assert ftp_server.retr_count() == 2


@pytest.mark.usefixtures("ftp_server")
def test_not_logged_in_or_plain_ftplib_disables_caching():
    inst = FTP("192.0.2.21")
    assert inst._file_key("/etc/conf.txt", "binary") is None
    logged_in = logged_in_ftp()
    logged_in.ftp = ftplib.FTP()  # setter used by some tests and modules
    assert logged_in._file_key("/etc/conf.txt", "binary") is None


@pytest.mark.usefixtures("ftp_server")
def test_failed_login_disables_caching(mocker):
    inst = logged_in_ftp()
    assert inst._file_key("top.txt", "binary") is not None
    mocker.patch.object(ftplib.FTP, "login", side_effect=ftplib.error_perm("530 denied"))
    assert not inst.login("bad", "creds")
    assert inst._file_key("top.txt", "binary") is None


def test_modifying_commands_invalidate_files(ftp_server):
    inst = logged_in_ftp()
    inst.download_binary("/etc/conf.txt")
    inst.download_binary("top.txt")
    assert len(data_cache) == 3  # 2 files and the welcome message

    inst.upload_binary("/etc/conf.txt", b"new conf")
    assert ftp_server.files["/etc/conf.txt"] == b"new conf"
    assert len(data_cache) == 1
    assert inst.download_binary("/etc/conf.txt") == b"new conf"

    inst.file_delete("/etc/other.txt")
    assert len(data_cache) == 1
    inst.download_binary("/etc/conf.txt")
    inst.file_rename("/etc/conf.txt", "/etc/conf.bak")
    inst.download_binary("top.txt")
    inst.mkdir("new")
    inst.rmdir("new")
    inst.cmd("DELE top.txt")
    inst.upload_text("x.txt", "text")
    assert len(data_cache) == 1  # only the welcome message
    assert FTP.cached_welcome("192.0.2.21") == FakeFTPServer.WELCOME


def test_empty_file_not_cached(ftp_server):
    inst = logged_in_ftp()
    assert inst.download_binary("empty.bin") == b""
    assert inst.download_binary("empty.bin") == b""
    assert ftp_server.retr_count() == 2


def test_download_error_not_cached(ftp_server):
    inst = logged_in_ftp()
    with pytest.raises(ftplib.error_perm):
        inst.download_binary("missing.bin")
    ftp_server.files["/home/missing.bin"] = b"now it exists"
    assert inst.download_binary("missing.bin") == b"now it exists"
