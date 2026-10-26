import socket
import stat
import sys
import threading
import time
from pathlib import Path

import paramiko
import pytest

from peat import CommError, config, datastore
from peat.protocols import ssh
from peat.protocols.ssh import SSH, host_key_fingerprint, save_host_key


class _FakeSFTP:
    """Stands in for paramiko.SFTPClient, writing fixed data for every get()."""

    def __init__(self):
        self.fetched = []

    def get(self, remotepath, localpath):
        self.fetched.append(remotepath)
        Path(localpath).write_bytes(b"sftp data")


def test_sftp_download_files_contained(tmp_path):
    local_dir = tmp_path / "out" / "sftp_files"
    ssh = SSH("127.0.0.1")
    ssh.sftp_conn = _FakeSFTP()
    # Listing entries as built from a hostile listdir_attr() response
    files = [
        {"path": "/../../sftp_escape.txt"},
        {"path": "/flash/../../../../sftp_escape2.txt"},
        {"path": "/flash/config.xml"},
    ]

    assert ssh.sftp_download_files(local_dir, files) is True
    assert len(ssh.sftp_conn.fetched) == 3

    written = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    assert len(written) == 3
    for path in written:
        assert path.is_relative_to(local_dir), path
    assert (local_dir / "flash" / "config.xml").is_file()


class _ServerInterface(paramiko.ServerInterface):
    def __init__(self, creds: list) -> None:
        self.creds = creds

    def check_auth_password(self, username, password):
        self.creds.append((username, password))
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):  # noqa: ARG002
        return "password"


class _FakeSSHServer:
    """In-process SSH server whose host key can be swapped between connections."""

    def __init__(self) -> None:
        self.host_key = paramiko.RSAKey.generate(1024)
        self.creds: list[tuple[str, str]] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.host_key)
        try:
            transport.start_server(server=_ServerInterface(self.creds))
            deadline = time.monotonic() + 10
            while transport.is_active() and time.monotonic() < deadline:
                time.sleep(0.05)
        except (paramiko.SSHException, EOFError, OSError):
            pass
        finally:
            transport.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(2)
        self.sock.close()


@pytest.fixture
def ssh_server():
    server = _FakeSSHServer()
    yield server
    server.close()


@pytest.fixture
def known_hosts(mocker, tmp_path) -> Path:
    path = tmp_path / "peat" / "known_hosts"
    mocker.patch.dict(config["CONFIG"], {"SSH_KNOWN_HOSTS": path})
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(ssh, "_session_host_keys", paramiko.HostKeys())
    mocker.patch.object(ssh, "_known_hosts_warned", set())
    return path


def _connect(server: _FakeSSHServer, **kwargs) -> SSH:
    client = SSH("127.0.0.1", server.port, timeout=5, username="Admin", password="pw-1", **kwargs)
    try:
        assert client.comm
    finally:
        client.disconnect()
    return client


def test_ssh_new_host_key_saved(ssh_server, known_hosts, log_messages):
    _connect(ssh_server)

    saved = paramiko.HostKeys(str(known_hosts))
    entry = saved.lookup(f"[127.0.0.1]:{ssh_server.port}")
    assert entry is not None
    assert entry["ssh-rsa"] == ssh_server.host_key
    fingerprint = host_key_fingerprint(ssh_server.host_key)
    assert any("New SSH host key" in m and fingerprint in m for m in log_messages)

    # Second connection uses the saved key, no new warning
    log_messages.clear()
    _connect(ssh_server)
    assert not any("New SSH host key" in m for m in log_messages)
    assert len(ssh_server.creds) == 2


def test_ssh_changed_host_key_rejected(ssh_server, known_hosts):
    _connect(ssh_server)
    assert len(ssh_server.creds) == 1

    ssh_server.host_key = paramiko.RSAKey.generate(1024)  # e.g. a MITM
    with pytest.raises(CommError, match="has CHANGED") as exc_info:
        _connect(ssh_server)
    assert host_key_fingerprint(ssh_server.host_key) in str(exc_info.value)
    assert str(known_hosts) in str(exc_info.value)
    assert len(ssh_server.creds) == 1  # no credentials were sent


def test_ssh_trust_new_host_key(ssh_server, known_hosts):
    _connect(ssh_server)
    new_key = paramiko.RSAKey.generate(1024)
    ssh_server.host_key = new_key

    _connect(ssh_server, trust_new_host_key=True)
    saved = paramiko.HostKeys(str(known_hosts))
    assert saved.lookup(f"[127.0.0.1]:{ssh_server.port}")["ssh-rsa"] == new_key
    assert len(saved) == 1

    _connect(ssh_server)  # the new key is now the known key


def test_ssh_pinned_host_key(ssh_server, known_hosts):
    _connect(ssh_server, host_key_fingerprint=host_key_fingerprint(ssh_server.host_key))
    assert not known_hosts.exists()  # pinned keys aren't saved

    md5 = ssh_server.host_key.get_fingerprint().hex()
    _connect(ssh_server, host_key_fingerprint=":".join(md5[i : i + 2] for i in range(0, 32, 2)))
    assert len(ssh_server.creds) == 2

    other = host_key_fingerprint(paramiko.RSAKey.generate(1024))
    with pytest.raises(CommError, match="does not match the pinned"):
        _connect(ssh_server, host_key_fingerprint=other)
    assert len(ssh_server.creds) == 2  # no credentials were sent


def test_ssh_host_key_options_from_device(ssh_server, known_hosts):  # noqa: ARG001
    dev = datastore.get("127.0.0.1")
    other = host_key_fingerprint(paramiko.RSAKey.generate(1024))
    dev._runtime_options["ssh"] = {"host_key_fingerprint": other}

    with pytest.raises(CommError, match="does not match the pinned"):
        _connect(ssh_server)

    # Options passed as paramiko kwargs (e.g. by SageSSH) aren't given to paramiko
    client = SSH(
        "127.0.0.1",
        ssh_server.port,
        kwargs={"host_key_fingerprint": host_key_fingerprint(ssh_server.host_key)},
    )
    assert "host_key_fingerprint" not in client.kwargs
    assert client.host_key_fingerprint == host_key_fingerprint(ssh_server.host_key)
    assert len(ssh_server.creds) == 0


def test_ssh_write_sensitive_not_logged(mocker, log_messages):
    client = SSH("127.0.0.1")
    client.POST_WRITE_SLEEP = 0
    client.channel = mocker.Mock()

    client.write("ls")
    client.write("SSH-UNIQUE-pw-1", sensitive=True)
    client.channel.sendall.assert_called_with(b"SSH-UNIQUE-pw-1\n")

    assert any("Writing SSH command: ls" in m for m in log_messages)
    assert not any("SSH-UNIQUE-pw-1" in m for m in log_messages)


def test_ssh_password_registered_as_secret():
    from peat import log_utils

    # e.g. a module's default credentials, which aren't in the config
    SSH("127.0.0.1", username="Admin", password="SSH-late-pw-7f3a")
    assert log_utils.redact_secrets("pw SSH-late-pw-7f3a") == "pw <redacted>"


def test_known_hosts_never_read_partially_written(tmp_path):
    path = tmp_path / "known_hosts"
    key = paramiko.RSAKey.generate(1024)
    host_keys = paramiko.HostKeys()
    for i in range(1500):
        host_keys.add(f"10.0.{i // 250}.{i % 250}", "ssh-rsa", key)
    host_keys.add("known.example", "ssh-rsa", key)
    host_keys.save(str(path))

    stop = threading.Event()

    def writer() -> None:
        n = 0
        while not stop.is_set():
            save_host_key(path, f"new-{n}", key)
            n += 1

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        missing = 0
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            # Not under the lock, like a different PEAT process reading the file
            loaded = paramiko.HostKeys(str(path))
            if loaded.lookup("known.example") is None:
                missing += 1
    finally:
        stop.set()
        thread.join(5)
    assert missing == 0


def test_save_host_key_atomic(mocker, tmp_path):
    path = tmp_path / "known_hosts"
    key = paramiko.RSAKey.generate(1024)
    save_host_key(path, "first.example", key)
    original = path.read_bytes()
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    # A failed write leaves the existing file as it was, and no temporary file
    mocker.patch.object(paramiko.HostKeys, "save", side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        save_host_key(path, "second.example", key)
    assert path.read_bytes() == original
    assert [p.name for p in tmp_path.iterdir()] == ["known_hosts"]


@pytest.mark.parametrize("problem", ["unwritable", "corrupt"])
def test_ssh_known_hosts_errors(ssh_server, known_hosts, log_messages, mocker, problem):
    if problem == "unwritable":
        # e.g. a read-only or missing home directory
        known_hosts.parent.write_text("not a directory", encoding="utf-8")
        known_hosts = known_hosts.parent / "known_hosts"
        mocker.patch.dict(config["CONFIG"], {"SSH_KNOWN_HOSTS": known_hosts})
    else:
        known_hosts.parent.mkdir()
        # Invalid UTF-8 (a UnicodeDecodeError on POSIX) and, where the locale
        # encoding accepts those bytes (Windows), a line with a bad key
        corrupt = b"\xff\xfe not a known_hosts file\nhost ssh-rsa not-a-key\n"
        known_hosts.write_bytes(corrupt)
    original = known_hosts.parent.read_bytes() if problem == "unwritable" else b""

    # Connections still work, with a single warning about the file
    _connect(ssh_server)
    _connect(ssh_server)
    assert len(ssh_server.creds) == 2
    warnings = [m for m in log_messages if f"SSH known_hosts file '{known_hosts}'" in m]
    assert len([m for m in warnings if 'ssh_known_hosts: ""' in m]) == 1

    # The file isn't overwritten
    if problem == "unwritable":
        assert known_hosts.parent.read_bytes() == original
    else:
        assert known_hosts.read_bytes() == corrupt

    # A key that changes during the run is still refused
    ssh_server.host_key = paramiko.RSAKey.generate(1024)
    with pytest.raises(CommError, match="has CHANGED"):
        _connect(ssh_server)
    assert len(ssh_server.creds) == 2


class _FakeChannel:
    """Stands in for paramiko.Channel, with the behavior of a hostile or broken device."""

    def __init__(self, data: bytes = b"", endless: bool = False, closed: bool = False):
        self.data = data
        self.endless = endless  # recv() always returns more data
        self.closed = closed
        self.recv_calls = 0

    def settimeout(self, timeout):
        pass

    def exit_status_ready(self):
        return self.closed

    def recv_ready(self):
        return self.endless or bool(self.data)

    def recv(self, nbytes):
        self.recv_calls += 1
        if self.endless:
            return self.data[:nbytes]
        # Like paramiko: b"" (no exception) once the remote side closed the channel
        part, self.data = self.data[:nbytes], self.data[nbytes:]
        return part


def _run_with_watchdog(func, seconds: float = 10.0):
    """Run func in a thread, so a hang fails the test instead of hanging it."""
    result = {}

    def _target():
        try:
            result["value"] = func()
        except Exception as ex:
            result["error"] = ex

    thread = threading.Thread(target=_target, daemon=True)
    start = time.monotonic()
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"still running after {seconds} seconds"
    return result, time.monotonic() - start


def test_ssh_read_silent_device_times_out():
    ssh = SSH("127.0.0.1", timeout=0.5)
    ssh.channel = _FakeChannel()  # never sends anything
    result, duration = _run_with_watchdog(lambda: ssh.read(delay=0))
    assert isinstance(result.get("error"), CommError)
    assert "within 0.5 seconds" in str(result["error"])
    assert duration < 5


def test_ssh_read_closed_channel():
    ssh = SSH("127.0.0.1", timeout=60.0)
    ssh.channel = _FakeChannel(closed=True)
    result, duration = _run_with_watchdog(lambda: ssh.read(delay=0))
    assert isinstance(result.get("error"), CommError)
    assert "closed" in str(result["error"])
    assert duration < 5


def test_ssh_read_endless_data_limited():
    ssh = SSH("127.0.0.1", timeout=60.0)
    ssh.MAX_READ_SIZE = 50_000
    ssh.channel = _FakeChannel(b"A" * 1000, endless=True)
    result, _ = _run_with_watchdog(lambda: ssh.read(delay=0, sleep_between_recvs=False))
    assert 50_000 <= len(result["value"]) < 52_000


def test_ssh_read_normal():
    ssh = SSH("127.0.0.1", timeout=1.0)
    ssh.channel = _FakeChannel(b"  hello\r\n")
    assert ssh.read(delay=0, sleep_between_recvs=False) == "hello"
    ssh.channel = _FakeChannel(b"login: ok\r\n# ")
    assert ssh.read_until("# ", delay=0) == "login: ok\r\n#"


def test_ssh_read_until_closed_channel():
    ssh = SSH("127.0.0.1", timeout=60.0)
    channel = _FakeChannel(b"partial output", closed=True)
    ssh.channel = channel
    result, duration = _run_with_watchdog(lambda: ssh.read_until("#", delay=0))
    assert result["value"] == "partial output"
    assert duration < 5
    assert channel.recv_calls == 2  # previously a busy loop: millions of calls


def test_ssh_read_until_never_matches():
    """A device sending data that never matches must not keep the read going forever."""
    ssh = SSH("127.0.0.1", timeout=0.5)
    ssh.channel = _FakeChannel(b".", endless=True)
    result, duration = _run_with_watchdog(lambda: ssh.read_until("#", delay=0))
    assert set(result["value"]) == {"."}
    assert duration < 5

    ssh = SSH("127.0.0.1", timeout=60.0)
    ssh.MAX_READ_SIZE = 50_000
    ssh.channel = _FakeChannel(b"A" * 1000, endless=True)
    result, _ = _run_with_watchdog(lambda: ssh.read_until("#", delay=0))
    assert 50_000 <= len(result["value"]) < 52_000
