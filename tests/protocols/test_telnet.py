import socket

import pytest

from peat import config
from peat.protocols import telnet


def test_telnet_class(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path})
    ip = "127.0.0.1"
    tn = telnet.Telnet(ip)
    assert str(tn) == ip
    assert not tn.connected


def connect_socketpair(tn) -> socket.socket:
    """
    Connect a Telnet-based instance to one end of a socket pair
    (instead of a real device), returning the other end.
    """
    client, peer = socket.socketpair()
    peer.settimeout(5)
    tn._comm.sock = client
    tn.connected = True
    tn.PRE_WRITE_SLEEP = 0
    tn.POST_WRITE_SLEEP = 0
    return peer


@pytest.mark.parametrize("command", ["Hunter2-UNIQUE-pw", b"Hunter2-UNIQUE-pw"])
def test_telnet_write_sensitive_not_logged(mocker, log_messages, command):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": None})
    tn = telnet.Telnet("127.0.0.1")
    peer = connect_socketpair(tn)

    tn.write("show version")
    tn.write(command, sensitive=True)
    assert peer.recv(1024).endswith(b"Hunter2-UNIQUE-pw\r\n")  # sent to the device

    assert any("show version" in m for m in log_messages)  # normal commands are logged
    assert any("<redacted>" in m for m in log_messages)
    assert not any("Hunter2-UNIQUE-pw" in m for m in log_messages)
    peer.close()
