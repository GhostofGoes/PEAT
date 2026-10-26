import socket

from peat import config
from peat.modules.sel.sel_telnet import SELTelnet
from peat.protocols import Telnet


def test_sel_elevate_passwords_not_logged(mocker, log_messages):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": None, "DEVICE_DIR": None})
    sel = SELTelnet("127.0.0.1")
    sel.PRE_WRITE_SLEEP = sel.READ_DELAY = 0
    sel.comm = Telnet("127.0.0.1")
    client, peer = socket.socketpair()
    peer.settimeout(5)
    sel.comm._comm.sock = client
    sel.comm.connected = True
    sel.comm.PRE_WRITE_SLEEP = sel.comm.POST_WRITE_SLEEP = sel.comm.READ_DELAY = 0

    creds = {"acc": "L1-UNIQUE-pw", "2ac": "L2-UNIQUE-pw", "cal": "CAL-UNIQUE-pw"}
    assert sel.elevate(3, creds) is True

    sent = b""
    while len(sent) < 50:
        sent += peer.recv(1024)
    for password in creds.values():
        assert password.encode() in sent  # the passwords were sent to the device
        assert not any(password in m for m in log_messages)
        assert password.encode() + b"\r\n" not in sel.all_writes
    assert b"acc\r\n" in sel.all_writes
    client.close()
    peer.close()
