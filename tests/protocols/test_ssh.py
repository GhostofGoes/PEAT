import socket
import threading
import time
from pathlib import Path

import paramiko
import pytest

from peat import CommError, config, datastore
from peat.protocols.ssh import SSH, host_key_fingerprint


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
