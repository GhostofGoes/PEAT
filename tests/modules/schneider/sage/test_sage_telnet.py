import socket

from peat import config
from peat.modules.schneider.sage.sage_telnet import SageTelnet


def test_sage_telnet_login_password_not_logged(mocker, log_messages):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": None, "DEVICE_DIR": None})
    tn = SageTelnet("127.0.0.1")
    client, peer = socket.socketpair()
    peer.settimeout(5)
    tn._comm.sock = client
    tn.connected = True
    tn.PRE_WRITE_SLEEP = tn.POST_WRITE_SLEEP = tn.READ_DELAY = 0

    peer.sendall(b"login: Password: \r\n-> ")
    assert tn.login("Admin", "Hunter2-UNIQUE-7f3a") is True

    sent = peer.recv(1024)
    assert b"Hunter2-UNIQUE-7f3a" in sent  # the password was sent to the device
    assert any("Writing command: Admin" in m for m in log_messages)
    assert not any("Hunter2-UNIQUE-7f3a" in m for m in log_messages)
    client.close()
    peer.close()
