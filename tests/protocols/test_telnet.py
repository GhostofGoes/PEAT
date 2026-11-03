from peat import config
from peat.protocols import telnet


def test_telnet_class(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path})
    ip = "127.0.0.1"
    tn = telnet.Telnet(ip)
    assert str(tn) == ip
    assert not tn.connected


def test_write_secret_never_logged(caplog, mocker):
    """Bug fix: passwords written to Telnet were logged (and saved in telnet.log)."""
    caplog.set_level(0)
    tn = telnet.Telnet("192.0.2.70")
    tn.PRE_WRITE_SLEEP = tn.POST_WRITE_SLEEP = 0
    sock = mocker.MagicMock()
    tn._comm.sock = sock
    tn.connected = True
    try:
        tn.write("admin")
        tn.write("TelnetCanaryPw1", secret=True)
    finally:
        tn.connected = False

    # The password is still sent to the device
    assert [c.args[0] for c in sock.sendall.call_args_list] == [
        b"admin\r\n",
        b"TelnetCanaryPw1\r\n",
    ]
    assert "Writing command: admin" in caplog.text
    assert "<redacted>" in caplog.text
    assert "TelnetCanaryPw1" not in caplog.text
