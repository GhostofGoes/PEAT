import subprocess
from pathlib import Path

import pytest

from peat import config
from peat.modules.sel.sel_serial import SELSerial


@pytest.fixture
def serial_relay(mocker, tmp_path):
    """SELSerial with a regular file standing in for the serial port."""
    mocker.patch.dict(config["CONFIG"], {"OUT_DIR": tmp_path, "TEMP_DIR": tmp_path / "temp"})
    port = tmp_path / "ttyUSB0; touch pwned"  # Shell metacharacters in the port name
    port.write_bytes(b"")
    relay = SELSerial(str(port))
    relay.__dict__["rz_path"] = "/usr/bin/rz"
    relay.__dict__["sz_path"] = "/usr/bin/sz"
    relay._comm = mocker.Mock()
    mocker.patch.object(relay, "_ensure_priv")
    mocker.patch.object(relay, "write")
    mocker.patch.object(relay, "read", return_value="Ready to send file")
    mocker.patch.object(relay, "restart_device", return_value=True)
    mocker.patch.object(relay, "disconnect")
    mocker.patch("peat.modules.sel.sel_serial.sleep")
    return relay


def _check_serial_call(call, port: str) -> None:
    assert not call.kwargs.get("shell")
    assert isinstance(call.args[0], list)
    assert Path(call.kwargs["stdin"].name) == Path(port)
    assert Path(call.kwargs["stdout"].name) == Path(port)


def test_ymodem_read_file_no_shell(serial_relay, mocker):
    def fake_rz(cmd, cwd, **_kwargs):
        (Path(cwd) / "set_1.txt").write_bytes(b"settings\x1a\x1a")
        return subprocess.CompletedProcess(cmd, 0, stderr=b"")

    run = mocker.patch("peat.modules.sel.sel_serial.subprocess.run", side_effect=fake_rz)

    assert serial_relay.ymodem_read_file("SETTINGS SET_1.TXT") == b"settings"
    assert run.call_count == 1
    _check_serial_call(run.call_args, serial_relay.address)
    assert run.call_args.args[0] == ["/usr/bin/rz", "--ymodem", "--quiet", "--restrict"]


def test_ymodem_push_configs_no_shell(serial_relay, mocker, tmp_path):
    run = mocker.patch(
        "peat.modules.sel.sel_serial.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0),
    )
    configs_dir = tmp_path / "configs"
    configs_dir.mkdir()

    assert serial_relay.ymodem_push_configs(["SET_1.TXT", "-x;touch pwned"], configs_dir)
    assert run.call_count == 4
    for call in run.call_args_list:
        _check_serial_call(call, serial_relay.address)
        assert call.kwargs["cwd"] == configs_dir
    assert run.call_args_list[0].args[0] == [
        "/usr/bin/sz",
        "--ymodem",
        "-vv",
        "-b",
        "--",
        "SET_1.TXT",
    ]
    assert run.call_args_list[2].args[0][-2:] == ["--", "-x;touch pwned"]
