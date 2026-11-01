"""
Tests for restarting SEL relays (SELAscii.restart_device and SELRelay.restart_relay),
against the scripted relay in fake_sel_relay.py, with the TCP port checks mocked.

The STA C dialog is the one in the SEL-351S Instruction Manual (20171023), STA command:
"Reboot the relay and clear status" / "Are you sure (Y/N) ?" / "Rebooting the relay".
"""

import threading

import pytest

from peat import SELRelay, config, datastore
from peat.modules.sel import sel_relay, sel_serial
from peat.modules.sel.sel_ascii import RestartResult, SELAscii
from peat.modules.sel.sel_telnet import SELTelnet

from .fake_sel_relay import FID_351S, FID_751, FakeSELRelay, FakeSerialPort, TCPRelayServer


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(SELAscii, "FIRST_COMMAND_QUIET", 0.0)
    mocker.patch.object(SELAscii, "_failed_passwords", {})
    mocker.patch.object(SELAscii, "_good_passwords", {})
    mocker.patch.object(SELRelay, "restart_poll_interval", 0.01)
    mocker.patch.object(SELRelay, "restart_down_timeout", 0.5)
    mocker.patch.object(SELRelay, "restart_reboot_timeout", 0.3)


@pytest.fixture
def relay_server():
    servers = []

    def _make(factory=None, **kwargs) -> TCPRelayServer:
        server = TCPRelayServer(factory or FakeSELRelay, **kwargs)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def _telnet(server: TCPRelayServer) -> SELTelnet:
    return SELTelnet("127.0.0.1", server.port, timeout=1.0)


def _dev(server: TCPRelayServer, model: str = "351S", **sel_options):
    dev = datastore.get("127.0.0.1", "ip")
    dev.description.model = model
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 1.0}
    dev._runtime_options["sel"] = {"restart_timeout": 2.0, **sel_options}
    return dev


# ---------------------------------------------------------------------------
# SELAscii.restart_device()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        ("close", "said it's restarting"),
        ("silent", "closed the connection"),
        ("hang", "stopped responding"),
    ],
)
def test_restart_initiated(relay_server, mode, reason):
    server = relay_server(lambda: FakeSELRelay(sta_c=mode))
    tn = _telnet(server)

    result = tn.restart_device(reboot_timeout=0.5)

    assert isinstance(result, RestartResult)
    assert result  # "truthy", like the bool returned before
    assert result.initiated
    assert result.status == "initiated"
    assert reason in result.reason
    assert result.fid == FID_351S
    assert result.device_time.year == 2009  # DAT and TIM before the restart
    assert result.initiated_at is not None
    assert "Are you sure (Y/N) ?" in result.transcript[0]
    assert result.to_dict()["status"] == "initiated"

    relay = server.relays[0]
    assert relay.restarted
    tn.disconnect()
    # Nothing is sent after the restart (no QUIT or EXIT)
    assert relay.lines[-4:] == [b"date", b"time", b"STA C", b"Y"]


def test_restart_requires_verified_level_2(relay_server):
    # PEAT thinks it's at level 2, but the relay's prompt says level 1
    server = relay_server(lambda: FakeSELRelay(level="1"))
    tn = _telnet(server)
    tn.priv_level = 2
    tn.access_level = "2"

    result = tn.restart_device()
    assert not result
    assert result.status == "failed"
    assert "isn't at access level 2" in result.reason
    assert b"STA C" not in server.relays[0].lines
    tn.disconnect()


def test_restart_elevation_fails(relay_server):
    # MAXACC 1 on the port: 2AC is refused
    server = relay_server(lambda: FakeSELRelay(maxacc="1"))
    tn = _telnet(server)
    result = tn.restart_device()
    assert result.status == "failed"
    assert "elevate" in result.reason
    assert b"STA C" not in server.relays[0].lines
    tn.disconnect()


def test_restart_invalid_access_level(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="2"))
    tn = _telnet(server)
    tn.sync_access_level()
    server.relays[0].level = "1"  # e.g. the session timed out
    tn.priv_level = 2
    tn.access_level = "2"
    tn.sync_access_level = lambda: tn.access_level  # skip the check

    result = tn.restart_device()
    assert result.status == "failed"
    assert "Invalid Access Level" in result.reason
    tn.disconnect()


def test_restart_answered_with_prompt(relay_server):
    server = relay_server(lambda: FakeSELRelay(sta_c="prompt"))
    tn = _telnet(server)
    result = tn.restart_device()
    assert result.status == "failed"
    assert "prompt after Y" in result.reason
    assert tn.access_level == "2"
    tn.disconnect()
    assert server.relays[0].lines[-2:] == [b"quit", b"exit"]


def test_restart_without_confirmation_question(relay_server):
    server = relay_server(lambda: FakeSELRelay(sta_c="no_confirm"))
    tn = _telnet(server)
    result = tn.restart_device()
    assert result.status == "failed"
    assert "without asking for confirmation" in result.reason
    assert b"Y" not in server.relays[0].lines
    tn.disconnect()


def test_restart_no_response(relay_server):
    server = relay_server(lambda: FakeSELRelay(sta_c="ignore"))
    tn = _telnet(server)
    result = tn.restart_device(confirm_timeout=0.3)
    assert result.status == "failed"
    assert "didn't ask for confirmation" in result.reason
    relay = server.relays[0]
    assert b"Y" not in relay.lines
    assert relay.cancels == 1  # The dialog was cancelled with CAN
    tn.disconnect()


def test_restart_connection_lost_before_confirmation(relay_server):
    server = relay_server(lambda: FakeSELRelay(sta_c="drop"))
    tn = _telnet(server)
    result = tn.restart_device()
    assert not result
    assert result.status == "unknown"
    tn.disconnect()


def test_restart_never_confirms_hardware_question(relay_server):
    # SEL-400 series relays may ask to accept a new hardware configuration
    server = relay_server(lambda: FakeSELRelay(sta_c="hardware"))
    tn = _telnet(server)
    result = tn.restart_device()
    assert result.status == "failed"
    assert "answered N" in result.reason
    relay = server.relays[0]
    assert b"N" in relay.lines
    assert b"Y" not in relay.lines
    assert not relay.restarted
    tn.disconnect()


def test_restart_unsupported_on_2032():
    tn = SELTelnet("192.0.2.40")
    tn.model = "2032"
    result = tn.restart_device()
    assert result.status == "unsupported"
    assert tn._comm is None  # Nothing was sent


# ---------------------------------------------------------------------------
# SELRelay.restart_relay() via Telnet
# ---------------------------------------------------------------------------


def _port_checks(mocker, values):
    values = list(values)

    def check(ip, port, timeout=None, reset=False):  # noqa: ARG001
        return values.pop(0) if len(values) > 1 else values[0]

    return mocker.patch.object(sel_relay, "check_tcp_port", side_effect=check)


def test_restart_relay_verified(relay_server, mocker):
    server = relay_server()
    dev = _dev(server)
    checks = _port_checks(mocker, [True, False, False, True])

    assert SELRelay.restart_relay(dev, comm_type="telnet") is True

    record = dev.extra["restart"]
    assert record["status"] == "initiated"
    assert record["initiated"] is True
    assert record["verified"] is True
    assert record["port_went_down"] is True
    assert record["fid"] == record["fid_after"] == FID_351S
    assert record["method"] == "telnet"
    for key in ("requested_at", "initiated_at", "back_at", "duration_s"):
        assert record[key] is not None
    assert checks.call_args.kwargs["reset"] is True
    # The second connection only ran ID
    assert server.relays[0].restarted
    assert server.relays[1].lines == [b"id", b"quit", b"exit"]


def test_restart_relay_not_back(relay_server, mocker):
    server = relay_server()
    dev = _dev(server, restart_timeout=0.3)
    _port_checks(mocker, [False])

    assert SELRelay.restart_relay(dev, comm_type="telnet") is False
    assert dev.extra["restart"]["initiated"] is True
    assert dev.extra["restart"]["verified"] is False
    assert "didn't open again" in dev.extra["restart"]["reason"]
    assert len(server.relays) == 1


def test_restart_relay_fid_changed(relay_server, mocker):
    fids = iter([FID_351S, FID_751])
    server = relay_server(lambda: FakeSELRelay(fid=next(fids)))
    dev = _dev(server)
    _port_checks(mocker, [False, True])

    assert SELRelay.restart_relay(dev, comm_type="telnet") is False
    record = dev.extra["restart"]
    assert record["verified"] is False
    assert "FID changed" in record["reason"]
    assert record["fid_after"] == FID_751


def test_restart_relay_port_never_closed(relay_server, mocker):
    server = relay_server()
    dev = _dev(server)
    _port_checks(mocker, [True])

    assert SELRelay.restart_relay(dev, comm_type="telnet") is False
    record = dev.extra["restart"]
    assert record["port_went_down"] is False
    assert "wasn't confirmed" in record["reason"]


def test_restart_relay_without_verification(relay_server, mocker):
    server = relay_server()
    dev = _dev(server, restart_verify=False)
    checks = _port_checks(mocker, [True])

    assert SELRelay.restart_relay(dev, comm_type="telnet") is True
    assert checks.call_count == 0
    assert dev.extra["restart"]["verified"] is False


def test_restart_relay_login_failure_is_not_retried(relay_server, mocker):
    server = relay_server(lambda: FakeSELRelay(passwords={"acc": "OTTER", "2ac": "Changed-2"}))
    dev = _dev(server)
    _port_checks(mocker, [True])

    assert SELRelay.restart_relay(dev, comm_type="telnet") is False
    assert len(server.relays) == 1
    assert server.relays[0].password_attempts["2ac"] == ["TAIL"]
    assert not server.relays[0].restarted
    assert "elevate" in dev.extra["restart"]["reason"]


def test_restart_relay_connection_retries(relay_server, mocker):
    server = relay_server()
    dev = _dev(server, restart_verify=False)
    original = SELTelnet.test_connection
    results = iter([False, False])
    mocker.patch.object(
        SELTelnet,
        "test_connection",
        autospec=True,
        side_effect=lambda self: next(results, None) or original(self),
    )

    assert SELRelay.restart_relay(dev, comm_type="telnet") is True
    assert server.relays[-1].restarted


def test_restart_relay_unsupported_model(relay_server):
    server = relay_server()
    dev = _dev(server, model="2032")
    assert SELRelay.restart_relay(dev) is False
    assert dev.extra["restart"]["status"] == "unsupported"
    assert server.relays == []


def test_restart_relay_telnet_compatibility(mocker):
    restart = mocker.patch.object(SELRelay, "restart_relay", return_value=True)
    dev = datastore.get("192.0.2.41", "ip")
    assert SELRelay.restart_relay_telnet(dev) is True
    restart.assert_called_once_with(dev, comm_type="telnet")


# ---------------------------------------------------------------------------
# SELRelay.restart_relay() via serial
# ---------------------------------------------------------------------------


def test_restart_relay_serial(mocker):
    relay = FakeSELRelay(fid=FID_751, sta_c="hang")
    port = FakeSerialPort(relay)
    # The relay starts again after a moment, and sends its power-up message (AUTO=Y)
    relay.on_restart = lambda: threading.Timer(0.2, relay.boot).start()
    mocker.patch.object(sel_serial.serial, "Serial", return_value=port)

    dev = datastore.get("/dev/ttyFAKE2", "serial_port")
    dev.description.model = "751"
    dev._runtime_options["serial"] = {"baudrate": 9600}
    dev._runtime_options["sel"] = {"restart_timeout": 3.0}

    assert SELRelay.restart_relay(dev, comm_type="serial") is True
    record = dev.extra["restart"]
    assert record["method"] == "serial"
    assert record["verified"] is True
    assert record["fid_after"] == FID_751
    assert relay.restarted


def test_restart_relay_serial_fast_boot(mocker):
    # The relay restarts before PEAT sees "Rebooting the relay", and shows the
    # level 0 prompt (AUTO=Y)
    relay = FakeSELRelay(fid=FID_751, sta_c="hang")
    port = FakeSerialPort(relay)
    relay.on_restart = relay.boot
    mocker.patch.object(sel_serial.serial, "Serial", return_value=port)

    dev = datastore.get("/dev/ttyFAKE4", "serial_port")
    dev._runtime_options["serial"] = {"baudrate": 9600}
    dev._runtime_options["sel"] = {"restart_timeout": 2.0}

    assert SELRelay.restart_relay(dev, comm_type="serial") is True
    record = dev.extra["restart"]
    assert "level 0 prompt" in record["restart_reason"]
    assert record["verified"] is True


def test_restart_relay_serial_no_prompt(mocker):
    relay = FakeSELRelay(sta_c="hang")
    port = FakeSerialPort(relay)
    mocker.patch.object(sel_serial.serial, "Serial", return_value=port)

    dev = datastore.get("/dev/ttyFAKE3", "serial_port")
    dev._runtime_options["serial"] = {"baudrate": 9600}
    dev._runtime_options["sel"] = {"restart_timeout": 0.5}

    assert SELRelay.restart_relay(dev, comm_type="serial") is False
    assert dev.extra["restart"]["initiated"] is True
    assert "prompt" in dev.extra["restart"]["reason"]
    # PEAT sends a carriage return now and then, to get the prompt
    assert relay.lines.count(b"") >= 2


@pytest.mark.parametrize("delay", [0.0, 0.6])
def test_restart_relay_serial_back_in_selboot(mocker, delay):
    # The relay comes back in its firmware loader (right away, or after PEAT
    # stopped waiting for the reboot message): PEAT stops sending (not even ID)
    relay = FakeSELRelay(sta_c="hang")
    port = FakeSerialPort(relay)
    selboot = b"\r\nSELBOOT\r\n!>"
    relay.on_restart = lambda: threading.Timer(delay, relay.send, [selboot]).start()
    mocker.patch.object(sel_serial.serial, "Serial", return_value=port)

    dev = datastore.get(f"/dev/ttyFAKE5{int(delay * 10)}", "serial_port")
    dev._runtime_options["serial"] = {"baudrate": 9600}
    dev._runtime_options["sel"] = {"restart_timeout": 2.0}

    assert SELRelay.restart_relay(dev, comm_type="serial") is False
    record = dev.extra["restart"]
    assert record["initiated"] is True
    assert "SELBOOT" in record["reason"]
    assert relay.lines[-1] == b"Y"
