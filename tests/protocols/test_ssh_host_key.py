"""
Tests for :func:`peat.protocols.ssh.fetch_ssh_host_key`, against a local SSH
server (paramiko in server mode) that doesn't allow anyone to log in.
"""

import base64
import hashlib
import socket
import threading
import time

import paramiko
import pytest

from peat.protocols import ssh
from peat.protocols.ssh import SSHHostKey, fetch_ssh_host_key


class _NoLoginServer(paramiko.ServerInterface):
    """SSH server that rejects every login and channel."""

    def __init__(self, stats: dict):
        self.stats = stats

    def get_allowed_auths(self, _username):
        return "password"

    def check_auth_password(self, _username, _password):
        self.stats["auth_attempts"] += 1
        return paramiko.AUTH_FAILED

    def check_channel_request(self, _kind, _chanid):
        self.stats["channels"] += 1
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


@pytest.fixture
def local_server():
    """
    Run a local TCP server in a thread. Each accepted connection is passed to
    the handler. Returns the port and a dict with the number of connections.
    """
    servers = []

    def _start(handler):
        lsock = socket.create_server(("127.0.0.1", 0))
        lsock.settimeout(0.1)
        stop = threading.Event()
        stats = {"connections": 0, "auth_attempts": 0, "channels": 0}

        def _run():
            while not stop.is_set():
                try:
                    conn, _ = lsock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                stats["connections"] += 1
                conn.settimeout(5.0)
                try:
                    handler(conn, stop, stats)
                except (OSError, EOFError, paramiko.SSHException):
                    pass  # the client closed or aborted the connection
                finally:
                    conn.close()

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        servers.append((lsock, stop, thread))
        return lsock.getsockname()[1], stats

    yield _start

    for lsock, stop, thread in servers:
        stop.set()
        thread.join(timeout=5.0)
        lsock.close()


@pytest.fixture(scope="module")
def host_key() -> paramiko.PKey:
    return paramiko.ECDSAKey.generate()


def ssh_handler(key: paramiko.PKey):
    def _handle(conn, stop, stats):
        transport = paramiko.Transport(conn)
        transport.add_server_key(key)
        try:
            transport.start_server(server=_NoLoginServer(stats))
            # Wait for the client to close the connection
            deadline = time.monotonic() + 5.0
            while transport.is_active() and not stop.is_set() and time.monotonic() < deadline:
                time.sleep(0.02)
        finally:
            transport.close()

    return _handle


def test_fetch_ssh_host_key(local_server, host_key):
    port, stats = local_server(ssh_handler(host_key))

    result = fetch_ssh_host_key("127.0.0.1", port, timeout=5.0)

    assert isinstance(result, SSHHostKey)
    blob = host_key.asbytes()
    assert result.key_type == "ecdsa-sha2-nistp256"
    assert result.bits == 256
    assert result.public_key == f"ecdsa-sha2-nistp256 {host_key.get_base64()}"
    assert result.md5 == hashlib.md5(blob).hexdigest().upper()
    assert result.sha256 == hashlib.sha256(blob).hexdigest().upper()
    assert result.banner.startswith("SSH-2.0-")
    # The format of "ssh-keygen -l"
    expected = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert result.fingerprint == f"SHA256:{expected}"

    # One connection, and no login or channel was attempted
    assert stats["connections"] == 1
    assert stats["auth_attempts"] == 0
    assert stats["channels"] == 0


def test_fetch_ssh_host_key_not_ssh(local_server):
    def _http_handler(conn, _stop, _stats):
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")

    port, _ = local_server(_http_handler)
    assert fetch_ssh_host_key("127.0.0.1", port, timeout=2.0) is None


def test_fetch_ssh_host_key_silent_server(local_server):
    def _silent_handler(_conn, stop, _stats):
        stop.wait(3.0)

    port, _ = local_server(_silent_handler)
    start = time.monotonic()
    assert fetch_ssh_host_key("127.0.0.1", port, timeout=0.5) is None
    assert time.monotonic() - start < 3.0


def test_fetch_ssh_host_key_connection_refused(mocker):
    connect = mocker.patch.object(
        ssh.socket, "create_connection", side_effect=ConnectionRefusedError("refused")
    )
    assert fetch_ssh_host_key("192.0.2.10", 8001, timeout=1.0) is None
    connect.assert_called_once_with(("192.0.2.10", 8001), timeout=1.0)


def test_ssh_host_key_fingerprint():
    key = SSHHostKey(
        key_type="ssh-ed25519",
        bits=256,
        public_key="ssh-ed25519 AAAA",
        md5="00" * 16,
        sha256="FF" * 32,
    )
    assert key.fingerprint == "SHA256:" + base64.b64encode(b"\xff" * 32).decode().rstrip("=")
