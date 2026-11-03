"""
Passwords sent by the SEL ASCII elevation commands are never logged or saved.
"""

from peat import config
from peat.modules.sel.sel_serial import SELSerial
from peat.modules.sel.sel_telnet import SELTelnet

CREDS = {"acc": "SelAccCanary7", "2ac": "Sel2acCanary7", "cal": "SelCalCanary7"}


def _assert_no_creds(caplog, log_dir, sent: list[bytes]) -> None:
    # The passwords are still sent to the device
    for password in CREDS.values():
        assert f"{password}\r\n".encode() in sent
    assert "<redacted>" in caplog.text

    saved = list(log_dir.rglob("selascii-protocol-data_*.json"))
    assert len(saved) == 1
    assert "<redacted>" in saved[0].read_text(encoding="utf-8")

    files = [p for p in log_dir.rglob("*") if p.is_file()]
    for password in CREDS.values():
        assert password not in caplog.text
        for path in files:
            assert password not in path.read_text(encoding="utf-8", errors="ignore"), path


def test_telnet_elevate_never_logs_or_saves_passwords(caplog, mocker, tmp_path):
    """Bug fix: Telnet passwords were in the logs and the selascii protocol data file."""
    caplog.set_level(0)
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path, "OUT_DIR": tmp_path})
    sock = mocker.MagicMock()

    with SELTelnet("192.0.2.71") as sel:
        sel.PRE_WRITE_SLEEP = sel.POST_WRITE_SLEEP = 0
        sel.comm.connected = True
        sel.comm._comm.sock = sock
        mocker.patch.object(sel, "read", return_value="=>")
        try:
            assert sel.elevate(3, CREDS)
        finally:
            sel.comm.connected = False

    _assert_no_creds(caplog, tmp_path, [c.args[0] for c in sock.sendall.call_args_list])


def test_serial_elevate_never_logs_or_saves_passwords(caplog, mocker, tmp_path):
    """Bug fix: serial passwords were in the logs and the selascii protocol data file."""
    caplog.set_level(0)
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path, "OUT_DIR": tmp_path})
    port = mocker.MagicMock()

    with SELSerial("/dev/ttyPEATTEST71") as sel:
        sel.PRE_WRITE_SLEEP = sel.POST_WRITE_SLEEP = 0
        sel.comm = port
        mocker.patch.object(sel, "read", return_value="=>")
        assert sel.elevate(3, CREDS)

    _assert_no_creds(caplog, tmp_path, [c.args[0] for c in port.write.call_args_list])
