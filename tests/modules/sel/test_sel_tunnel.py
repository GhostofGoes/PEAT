"""
Tests for the RTAC engineering access tunnels (sel_tunnel.py): the description
of a path (RTACTunnel), the RTAC's dialog (login, ACC, WHO, PORT n, termination),
and the transports (Telnet, raw TCP, TLS, SSH), against the scripted RTAC in
fake_rtac.py and the scripted relay in fake_sel_relay.py. No hardware is needed,
and all data is synthetic.
"""

import json
import threading
import time

import paramiko
import pytest

from peat import CommError, config, datastore
from peat.modules.sel.sel_ascii import SELAscii
from peat.modules.sel.sel_commands import SELCommandRefused
from peat.modules.sel.sel_tunnel import (
    DEFAULT_TERMINATION,
    ENTRY_KEYS,
    RTACLoginError,
    RTACTunnel,
    SELTunnel,
    TunnelError,
    is_device_row,
    parse_termination_string,
    parse_who_output,
    safe_id,
)

from .fake_rtac import ChunkingProxy, FakeRTAC, GatewayRelay, RTACServer, make_tls_files
from .fake_sel_relay import FakeSELRelay
from .sel_command_transcripts import FID_351S


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
    # The fake RTAC's prompts aren't framed: wait less for more data after them
    mocker.patch.object(SELAscii, "PROMPT_SETTLE", 0.1)
    mocker.patch.object(SELAscii, "_failed_passwords", {})
    mocker.patch.object(SELAscii, "_good_passwords", {})
    mocker.patch.object(SELAscii, "_unsupported_commands", {})
    mocker.patch.object(SELTunnel, "_rejected_logins", {})


@pytest.fixture
def rtac_server():
    servers = []

    def _make(factory=None, **kwargs) -> RTACServer:
        server = RTACServer(factory or FakeRTAC, **kwargs)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    return make_tls_files(tmp_path_factory.mktemp("tls"))


@pytest.fixture(scope="module")
def ssh_key():
    return paramiko.RSAKey.generate(2048)


def _tunnel(server, **kwargs) -> RTACTunnel:
    entry = {"rtac_ip": "127.0.0.1", "tcp_port": server.port, "sel_port": 1, "pre_term_s": 0.25}
    entry.update(kwargs)
    return RTACTunnel.from_dict(entry)


def _session(tunnel: RTACTunnel, **kwargs) -> SELTunnel:
    kwargs.setdefault("timeout", 2.0)
    return SELTunnel(tunnel, **kwargs)


def _relay_lines(relay: FakeSELRelay) -> list[str]:
    passwords = {p for p in relay.passwords.values() if p}
    lines = [line.decode("latin-1") for line in relay.lines]
    return [line for line in lines if line and line not in passwords]


def _wait_until(condition, timeout: float = 5.0) -> bool:
    """Wait for the fake RTAC's and relay's threads to catch up (slow CI runners)."""
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


# ---------------------------------------------------------------------------
# RTACTunnel
# ---------------------------------------------------------------------------


def test_from_dict_contract_entry():
    # An entry of extra.engineering_access of a RTAC (all of the keys)
    entry = {
        "name": "Feeder1_SEL_TAP",
        "rtac_ip": "192.0.2.10",
        "tcp_port": 51001,
        "transport": "raw",
        "kind": "access_point",
        "sel_port": None,
        "device_name": "Feeder1",
        "route": "interleaved",
        "needs_rtac_login": False,
        "termination_string": None,
        "source": "export",
    }
    tunnel = RTACTunnel.from_dict(entry)
    assert tunnel.kind == "access_point"
    assert tunnel.transport == "raw"
    assert tunnel.route == "interleaved"
    assert not tunnel.may_be_direct
    assert tunnel.source == "export"
    assert tunnel.target_id == "192.0.2.10_51001"
    assert tunnel.to_dict() == {**entry, "termination_string": DEFAULT_TERMINATION}
    assert set(tunnel.to_dict()) == set(ENTRY_KEYS)


def test_from_dict_defaults():
    tunnel = RTACTunnel.from_dict({"rtac_ip": "192.0.2.10", "tcp_port": "3254", "sel_port": "2"})
    # A sel_port means a SEL server, and SEL server connections are interleaved
    assert tunnel.kind == "sel_server"
    assert tunnel.route == "interleaved"
    assert tunnel.transport == "telnet"
    assert tunnel.termination_string == "\x04"
    assert tunnel.pre_term_s == 1.0
    assert tunnel.target_id == "192.0.2.10_3254_p2"
    assert tunnel.source == "config"
    assert tunnel.describe() == "SEL server 192.0.2.10:3254 PORT 2 (telnet)"

    # Without a sel_port: an access point, whose route isn't known (it may be direct)
    ap = RTACTunnel.from_dict({"rtac_ip": "192.0.2.10", "tcp_port": 50001})
    assert ap.kind == "access_point"
    assert ap.route is None
    assert ap.may_be_direct

    # SSH always needs the RTAC login (Perform Authentication is forced)
    ssh = RTACTunnel.from_dict({"rtac_ip": "192.0.2.10", "tcp_port": 3022, "transport": "SSH"})
    assert ssh.needs_rtac_login

    # The default rtac_ip (e.g. the IP of the host in the configuration)
    assert (
        RTACTunnel.from_dict({"tcp_port": 23}, default_rtac_ip="192.0.2.9").rtac_ip == "192.0.2.9"
    )


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"tcp_port": 23}, "rtac_ip"),
        ({"rtac_ip": "192.0.2.10"}, "tcp_port"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": 70000}, "tcp_port"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": "x"}, "tcp_port"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": 23, "transport": "http"}, "transport"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": 23, "route": "sideways"}, "route"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": 23, "kind": "router"}, "kind"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": 23, "sel_port": 0}, "sel_port"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": 23, "creds": "OTTER"}, "creds"),
        ({"rtac_ip": "192.0.2.10", "tcp_port": 23, "pre_term_s": -1}, "pre_term_s"),
    ],
)
def test_from_dict_invalid(entry, message):
    with pytest.raises(ValueError, match=message):
        RTACTunnel.from_dict(entry)


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("192.0.2.10:3254:1", ("sel_server", 1, "telnet", "interleaved")),
        ("192.0.2.10:3254:2:ssh", ("sel_server", 2, "ssh", "interleaved")),
        ("192.0.2.10:3254:tls:3", ("sel_server", 3, "tls", "interleaved")),
        ("192.0.2.10:51001:raw:interleaved", ("access_point", None, "raw", "interleaved")),
        ("192.0.2.10:51001::raw:tap", ("access_point", None, "raw", "interleaved")),
        ("192.0.2.10:50001:direct", ("access_point", None, "telnet", "direct")),
        ("192.0.2.10:50001", ("access_point", None, "telnet", None)),
    ],
)
def test_from_spec(spec, expected):
    tunnel = RTACTunnel.from_spec(spec)
    assert (tunnel.kind, tunnel.sel_port, tunnel.transport, tunnel.route) == expected
    assert tunnel.rtac_ip == "192.0.2.10"
    assert ":" not in tunnel.target_id


def test_from_spec_login():
    assert not RTACTunnel.from_spec("192.0.2.10:3254:1").needs_rtac_login
    tunnel = RTACTunnel.from_spec("192.0.2.10:3254:1:login")
    assert tunnel.needs_rtac_login
    assert (tunnel.kind, tunnel.sel_port) == ("sel_server", 1)
    tunnel = RTACTunnel.from_spec("192.0.2.10:51001:raw:tap:login")
    assert tunnel.needs_rtac_login
    assert (tunnel.kind, tunnel.transport, tunnel.route) == ("access_point", "raw", "interleaved")
    with pytest.raises(ValueError):
        RTACTunnel.from_spec("192.0.2.10:3254:1:login:login")


def test_from_spec_ipv6_has_no_colon_in_the_id():
    tunnel = RTACTunnel.from_spec("[2001:db8::10]:3254:1")
    assert tunnel.rtac_ip == "2001:db8::10"
    assert tunnel.endpoint == "[2001:db8::10]:3254"
    assert tunnel.target_id == "2001-db8-10_3254_p1"
    assert ":" not in tunnel.target_id


@pytest.mark.parametrize("spec", ["192.0.2.10", ":3254", "192.0.2.10:3254:1:2", "x:23:what"])
def test_from_spec_invalid(spec):
    with pytest.raises(ValueError):
        RTACTunnel.from_spec(spec)


def test_coerce():
    tunnel = RTACTunnel.from_spec("192.0.2.10:3254:1")
    assert RTACTunnel.coerce(tunnel) is tunnel
    assert RTACTunnel.coerce("192.0.2.10:3254:1") == tunnel
    assert RTACTunnel.coerce({"rtac_ip": "192.0.2.10", "tcp_port": 3254, "sel_port": 1}) == tunnel
    assert tunnel.with_port(5, "Feeder_5").target_id == "192.0.2.10_3254_p5"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "\x04"),
        ("", "\x04"),
        ("<CTRL-D>", "\x04"),
        ("Ctrl+D", "\x04"),
        ("^D", "\x04"),
        ("^c", "\x03"),
        ("\\x04", "\x04"),
        ("\x04", "\x04"),
        ("+++", "+++"),
    ],
)
def test_parse_termination_string(value, expected):
    assert parse_termination_string(value) == expected


def test_safe_id():
    assert safe_id("SEL_351S_1") == "SEL_351S_1"
    assert safe_id("FEEDER 1") == "FEEDER-1"
    assert safe_id("a:b/c\\d") == "a-b-c-d"


def test_parse_who_output():
    # Like the WHO table in HD2014-34 (Figure 24) and LWP0018-01 (Figure 8)
    text = (
        "WHO\r\nPort#  Device                 Protocol\r\n"
        "1      Feeder_1               Client - Serial\r\n"
        "63     SEL_451_Eth            Client - Ethernet\r\n"
        "254    Remote_Access_Server   Server - Ethernet\r\n"
    )
    rows = parse_who_output(text)
    assert rows == [
        {"port": 1, "device": "Feeder_1", "protocol": "Client - Serial"},
        {"port": 63, "device": "SEL_451_Eth", "protocol": "Client - Ethernet"},
        {"port": 254, "device": "Remote_Access_Server", "protocol": "Server - Ethernet"},
    ]
    assert [is_device_row(r) for r in rows] == [True, True, False]


# ---------------------------------------------------------------------------
# SEL server
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("transport", ["raw", "telnet"])
def test_sel_server_session(rtac_server, transport):
    server = rtac_server(lambda: FakeRTAC(relays={1: FakeSELRelay(fid=FID_351S)}))
    tunnel = _tunnel(server, transport=transport)

    with _session(tunnel) as tn:
        info = tn.get_id()
        assert info["FID"] == FID_351S
        assert tn.in_device
        assert tn.access_level == "0"
        assert tn.elevate(1)
        assert tn.run_command("DAT").lines == ["02/02/09"]
        assert tn.who_rows[0] == {"port": 1, "device": "Feeder_1", "protocol": "Client - Serial"}
        assert tn.address == "127.0.0.1_" + str(server.port) + "_p1"
        assert tn.ip == "127.0.0.1"

    rtac = server.rtacs[0]
    relay = rtac.relays[1]
    # The RTAC's dialog: ACC, WHO, PORT 1, and QUI after the termination string
    assert _wait_until(lambda: rtac.commands == ["ACC", "WHO", "PORT 1", "QUI"]), rtac.commands
    # The relay got QUIT (level 0), not EXIT
    assert _wait_until(lambda: _relay_lines(relay)[-1:] == ["quit"]), _relay_lines(relay)
    assert "exit" not in _relay_lines(relay)
    # The termination string came after the idle time, and ended the connection
    assert rtac.terminations == 1
    assert rtac.early_terminations == 0
    assert not rtac.closed_while_transparent
    assert not tn.in_device


def test_sel_server_without_greeting_and_framed_prompts(rtac_server):
    # The SEL server only shows its prompt after a carriage return
    server = rtac_server(lambda: FakeRTAC(greet=False, framed=True))
    with _session(_tunnel(server)) as tn:
        assert tn.get_id()["FID"] == FID_351S
    rtac = server.rtacs[0]
    assert rtac.lines[0] == b""  # the carriage return
    assert rtac.terminations == 1


def test_sel_server_rtac_login(rtac_server):
    server = rtac_server(lambda: FakeRTAC(login=("engineer", "Rtac-Pass1")))
    creds = {"user": "engineer", "pass": "Rtac-Pass1"}
    with _session(_tunnel(server, needs_rtac_login=True), rtac_creds=creds) as tn:
        assert tn.get_id()["FID"] == FID_351S
        assert tn.session_info["rtac_login"] is True

    rtac = server.rtacs[0]
    assert rtac.login_attempts == 1
    assert rtac.login_failures == 0
    # The RTAC password isn't recorded or in the output
    assert b"Rtac-Pass1" not in b"".join(tn.all_writes)
    assert b"<redacted>\r\n" in tn.all_writes
    assert "Rtac-Pass1" not in "".join(tn.all_output)


def test_rtac_login_rejected_once(rtac_server):
    server = rtac_server(lambda: FakeRTAC(login=("engineer", "Rtac-Pass1")))
    tn = _session(_tunnel(server), rtac_creds={"user": "engineer", "pass": "wrong"})
    with pytest.raises(TunnelError, match="rejected"):
        tn.connect()
    rtac = server.rtacs[0]
    assert rtac.login_attempts == 1  # never tried again
    assert not tn.in_device
    assert tn._stream is None


def test_rejected_rtac_login_is_not_sent_again(rtac_server):
    server = rtac_server(lambda: FakeRTAC(login=("engineer", "Rtac-Pass1")))
    wrong = {"user": "engineer", "pass": "wrong"}
    tunnel = _tunnel(server)
    with pytest.raises(RTACLoginError, match="rejected the login") as error:
        _session(tunnel, rtac_creds=wrong).connect()
    assert error.value.credential == "login"
    assert SELTunnel.rejected_login(tunnel, wrong) == "the login of RTAC user 'engineer'"
    # Other paths to the RTAC with the same login (e.g. another port)
    assert SELTunnel.rejected_login(_tunnel(server, sel_port=2), wrong)
    assert not SELTunnel.rejected_login(tunnel, {"user": "engineer", "pass": "Rtac-Pass1"})
    assert not SELTunnel.rejected_login(tunnel, {})

    # Not sent again, also when the RTAC asks for it on a new connection
    with pytest.raises(RTACLoginError, match="before"):
        _session(_tunnel(server, sel_port=2), rtac_creds=wrong).connect()
    assert [rtac.login_attempts for rtac in server.rtacs] == [1, 0]
    assert server.rtacs[1].lines == []

    # A different login is tried
    with _session(tunnel, rtac_creds={"user": "engineer", "pass": "Rtac-Pass1"}) as tn:
        assert tn.get_id()["FID"] == FID_351S
    assert server.rtacs[2].login_attempts == 1

    # Until the rejected logins are forgotten (at the start of each pass)
    SELTunnel.forget_rejected_logins("127.0.0.1")
    assert not SELTunnel.rejected_login(tunnel, wrong)
    with pytest.raises(RTACLoginError):
        _session(tunnel, rtac_creds=wrong).connect()
    assert server.rtacs[3].login_attempts == 1
    assert sum(rtac.login_failures for rtac in server.rtacs) == 2


def test_late_login_prompt_does_not_get_a_carriage_return(rtac_server):
    class LateLoginRTAC(FakeRTAC):
        """Shows "login:" after more than a second (e.g. a busy RTAC)."""

        def connected(self) -> None:
            timer = threading.Timer(1.3, lambda: self.send(b"\r\nlogin: "))
            timer.daemon = True
            timer.start()

    server = rtac_server(lambda: LateLoginRTAC(login=("engineer", "Rtac-Pass1")))
    creds = {"user": "engineer", "pass": "Rtac-Pass1"}
    # The path doesn't say that the RTAC asks for a login, but a RTAC user is
    # configured: PEAT waits for the login prompt, instead of sending a carriage
    # return after a second (which would be an empty user name)
    with _session(_tunnel(server), rtac_creds=creds, timeout=3.0) as tn:
        assert tn.get_id()["FID"] == FID_351S
    rtac = server.rtacs[0]
    assert rtac.lines[0] == b"engineer"
    assert rtac.login_attempts == 1
    assert rtac.login_failures == 0


def test_rtac_login_without_creds(rtac_server):
    server = rtac_server(lambda: FakeRTAC(login=("engineer", "Rtac-Pass1")))
    tn = _session(_tunnel(server))
    with pytest.raises(TunnelError, match="rtac_tunnel_creds"):
        tn.connect()
    # Nothing was guessed
    assert server.rtacs[0].login_attempts == 0


def test_sel_server_acc_password(rtac_server):
    server = rtac_server(lambda: FakeRTAC(acc_password="SrvAcc"))
    with _session(_tunnel(server), rtac_creds={"acc": "SrvAcc"}) as tn:
        assert tn.get_id()["FID"] == FID_351S
    assert server.rtacs[0].acc_attempts == 1
    assert b"SrvAcc" not in b"".join(tn.all_writes)


def test_rejected_acc_password_is_not_sent_again(rtac_server):
    server = rtac_server(lambda: FakeRTAC(acc_password="SrvAcc"))
    wrong = {"acc": "wrong"}
    with pytest.raises(RTACLoginError, match="rejected the ACC password") as error:
        _session(_tunnel(server), rtac_creds=wrong).connect()
    assert error.value.credential == "acc"
    assert SELTunnel.rejected_login(_tunnel(server, sel_port=2), wrong) == (
        "the SEL server's ACC password"
    )
    # Access points don't have the SEL server's ACC
    access_point = _tunnel(server, sel_port=None, kind="access_point", route="interleaved")
    assert not SELTunnel.rejected_login(access_point, wrong)

    with pytest.raises(RTACLoginError, match="before"):
        _session(_tunnel(server, sel_port=2), rtac_creds=wrong).connect()
    assert [rtac.acc_attempts for rtac in server.rtacs] == [1, 0]
    # The second dialog was cancelled (CAN) without sending the password
    assert server.rtacs[1].cancels == 1
    assert "PORT 2" not in server.rtacs[1].commands


def test_sel_server_acc_password_not_configured(rtac_server):
    server = rtac_server(lambda: FakeRTAC(acc_password="SrvAcc"))
    tn = _session(_tunnel(server))
    with pytest.raises(TunnelError, match="ACC password"):
        tn.connect()
    rtac = server.rtacs[0]
    # The dialog was cancelled (CAN), and no password was guessed
    assert rtac.cancels == 1
    assert rtac.acc_attempts == 0
    assert "PORT 1" not in rtac.commands


def test_port_not_listed_by_who(rtac_server):
    server = rtac_server(FakeRTAC)
    tn = _session(_tunnel(server, sel_port=7))
    with pytest.raises(TunnelError, match="doesn't list port 7"):
        tn.connect()
    assert server.rtacs[0].commands == ["ACC", "WHO"]


def test_port_of_the_server_itself_is_refused(rtac_server):
    rows = [
        "1      Feeder_1               Client - Serial",
        "254    Remote_Access_Server   Server - Ethernet",
    ]
    relays = {1: FakeSELRelay(), 254: FakeSELRelay()}
    server = rtac_server(lambda: FakeRTAC(relays=relays, who=rows))
    tn = _session(_tunnel(server, sel_port=254))
    with pytest.raises(TunnelError, match="not a device"):
        tn.connect()
    assert "PORT 254" not in server.rtacs[0].commands


def test_port_error(rtac_server):
    server = rtac_server(lambda: FakeRTAC(port_error="Connection failed"))
    tn = _session(_tunnel(server))
    with pytest.raises(TunnelError, match="failed to open port 1"):
        tn.connect()
    assert tn._stream is None


def test_sel_server_kind_on_an_access_point(rtac_server):
    # The relay's prompt instead of the SEL server's
    server = rtac_server(lambda: FakeRTAC(kind="access_point"))
    tn = _session(_tunnel(server))
    with pytest.raises(TunnelError, match="doesn't look like a RTAC SEL server"):
        tn.connect()


def test_discovery_only(rtac_server):
    server = rtac_server(lambda: FakeRTAC(relays={1: FakeSELRelay(), 2: FakeSELRelay()}))
    with _session(_tunnel(server, sel_port=None, kind="sel_server"), enter_device=False) as tn:
        tn.connect()
        assert [r["port"] for r in tn.who_rows] == [1, 2, 254]
        assert not tn.in_device
    rtac = server.rtacs[0]
    assert rtac.commands == ["ACC", "WHO", "QUI"]
    assert rtac.terminations == 0


def test_termination_waits_for_the_idle_time(rtac_server):
    # The SEL server only takes Ctrl+D after 0.6 s without data
    server = rtac_server(lambda: FakeRTAC(pre_term_s=0.6))
    with _session(_tunnel(server, pre_term_s=0.6)) as tn:
        tn.get_id()
    assert server.rtacs[0].terminations == 1
    assert server.rtacs[0].early_terminations == 0


def test_custom_termination_string(rtac_server):
    server = rtac_server(lambda: FakeRTAC(termination=b"+++"))
    with _session(_tunnel(server, termination_string="+++")) as tn:
        tn.get_id()
    assert server.rtacs[0].terminations == 1


def test_closed_tunnel_is_not_reopened_by_a_command(rtac_server):
    server = rtac_server(FakeRTAC)
    tn = _session(_tunnel(server))
    assert tn.get_id()["FID"] == FID_351S
    tn.disconnect()
    with pytest.raises(CommError, match="closed"):
        tn.run_command("ID")
    assert server.connections == 1
    # It's opened again explicitly
    tn.connect()
    assert tn.get_id()["FID"] == FID_351S
    tn.disconnect()
    assert server.connections == 2


def test_halted_session_still_closes_the_tunnel(rtac_server):
    # The relay ignores CAN, so its password dialog can't be cancelled
    relay = FakeSELRelay(passwords={"acc": "OTTER"}, ignore_can=True)
    server = rtac_server(lambda: FakeRTAC(relays={1: relay}))
    tn = _session(_tunnel(server))
    assert not tn.elevate(1, {"acc": "WRONG"})
    assert tn.halted
    tn.disconnect()

    rtac = server.rtacs[0]
    # No QUIT to the relay (it would be taken as a password), but the tunnel was ended
    assert "quit" not in _relay_lines(relay)
    assert rtac.terminations == 1
    assert not rtac.closed_while_transparent
    # As on serial, the session stays halted: the relay's port keeps its state
    assert tn.halted
    with pytest.raises(CommError):
        tn.connect()


def test_file_transfer_needs_the_option(rtac_server):
    files = {"SETTINGS SET_1.TXT": "[1]\r\nRID=FEEDER 1\r\n"}
    server = rtac_server(lambda: FakeRTAC(relays={1: FakeSELRelay(files=files)}))

    with _session(_tunnel(server)) as tn:
        assert tn.elevate(1)
        with pytest.raises(SELCommandRefused, match="tunnel_file_transfer"):
            tn.run_command("FILE DIR")
        assert tn.list_files() == []
        assert tn.can_download_files() is False
    assert not [line for line in _relay_lines(server.rtacs[0].relays[1]) if "FIL" in line.upper()]

    with _session(_tunnel(server), allow_file_transfer=True) as tn:
        assert tn.elevate(1)
        assert tn.list_files() == ["SETTINGS"]
        assert tn.show_file("SETTINGS SET_1.TXT") == files["SETTINGS SET_1.TXT"]


def test_only_known_commands_go_to_the_rtac(rtac_server):
    server = rtac_server(FakeRTAC)
    tn = _session(_tunnel(server))
    tn.connect()
    try:
        with pytest.raises(SELCommandRefused):
            tn._gateway_write("SET 1")
        # PORT is refused for the relay (it's in the list of commands PEAT never sends)
        with pytest.raises(SELCommandRefused):
            tn.write("PORT 2")
    finally:
        tn.disconnect()


def test_protocol_log_and_raw_output_are_for_the_device(rtac_server, tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path / "logs", "OUT_DIR": tmp_path})
    server = rtac_server(FakeRTAC)
    child = datastore.get("relay-behind-rtac", "id")
    rtac_dev = datastore.get("127.0.0.1", "ip")

    with _session(_tunnel(server, transport="raw"), output_dev=child) as tn:
        tn.get_id()

    log_file = (
        tmp_path / "logs" / f"selascii-protocol-data_rtac-tunnel_127.0.0.1_{server.port}_p1.json"
    )
    data = json.loads(log_file.read_text())[0]
    assert data["class"] == "SELTunnel"
    assert data["gateway"]["type"] == "SEL RTAC"
    assert data["gateway"]["tcp_port"] == server.port
    assert data["who"][0]["device"] == "Feeder_1"

    # The raw output is in the device's directory, not the RTAC's
    raw = child.get_out_dir() / "raw-tunnel-output.json"
    assert raw.is_file()
    assert "Establishing connection" in "".join(json.loads(raw.read_text()))
    assert not (rtac_dev.get_out_dir() / "raw-tunnel-output.json").exists()


def test_telnet_raw_output_is_for_the_device(rtac_server):
    server = rtac_server(FakeRTAC)
    child = datastore.get("relay-behind-rtac", "id")
    rtac_dev = datastore.get("127.0.0.1", "ip")
    with _session(_tunnel(server, transport="telnet"), output_dev=child) as tn:
        tn.get_id()
    assert (child.get_out_dir() / "raw-telnet-output.json").is_file()
    assert not rtac_dev.get_out_dir().exists()


# ---------------------------------------------------------------------------
# Access points and transports
# ---------------------------------------------------------------------------


def test_access_point_raw_tcp_passes_0xff(rtac_server):
    # 0xFF is the Telnet IAC byte. Through a raw TCP access point, it's data.
    relay = FakeSELRelay(outputs={"VER": "\x02\r\nCHECKSUM \xff\xfe\xff\r\n\x03"})
    server = rtac_server(lambda: FakeRTAC(kind="access_point", relays={1: relay}))
    tunnel = _tunnel(server, transport="raw", sel_port=None, route="interleaved")
    assert tunnel.kind == "access_point"

    with _session(tunnel) as tn:
        assert tn.elevate(1)
        response = tn.run_command("VER")
        assert "\xff\xfe\xff" in response.body
        # Sent as they are: not doubled, as Telnet would
        tn.comm.write_raw(b"\xff\r\n")

    rtac = server.rtacs[0]
    # The relay gets QUIT last (the RTAC forwards it on another thread)
    assert _wait_until(lambda: _relay_lines(relay)[-1:] == ["quit"]), _relay_lines(relay)
    assert b"\xff\r\n" in rtac.received
    assert b"\xff\xff" not in rtac.received
    # An access point has no SEL server dialog or termination string
    assert rtac.commands == []
    assert rtac.terminations == 0


def test_access_point_with_rtac_login(rtac_server):
    server = rtac_server(lambda: FakeRTAC(kind="access_point", login=("engineer", "Rtac-Pass1")))
    tunnel = _tunnel(server, sel_port=None, route="interleaved", needs_rtac_login=True)
    with _session(tunnel, rtac_creds={"user": "engineer", "pass": "Rtac-Pass1"}) as tn:
        assert tn.get_id()["FID"] == FID_351S
    assert server.rtacs[0].login_attempts == 1


def test_access_point_password_dialog_is_cancelled(rtac_server):
    # The relay's port is still in a password dialog (e.g. left by an earlier session)
    relay = FakeSELRelay()
    relay._pending_level = "1"
    server = rtac_server(lambda: FakeRTAC(kind="access_point", relays={1: relay}))
    tunnel = _tunnel(server, sel_port=None, route="interleaved")
    with _session(tunnel) as tn:
        assert tn.get_id()["FID"] == FID_351S
    assert relay.cancels == 1


def test_tls_transport(rtac_server, tls_files):
    server = rtac_server(FakeRTAC, transport="tls", tls_files=tls_files)
    with _session(_tunnel(server, transport="tls")) as tn:
        assert tn.get_id()["FID"] == FID_351S
    assert tn.session_info["tls_version"].startswith("TLS")
    assert len(tn.session_info["tls_certificate_sha256"]) == 64
    assert server.rtacs[0].terminations == 1


def test_ssh_transport(rtac_server, ssh_key):
    server = rtac_server(FakeRTAC, transport="ssh", ssh_key=ssh_key)
    creds = {"user": "engineer", "pass": "rtac-pass"}
    with _session(_tunnel(server, transport="ssh"), rtac_creds=creds) as tn:
        assert tn.get_id()["FID"] == FID_351S
        assert tn.elevate(1)
    assert tn.session_info["ssh_host_key"]["fingerprint"].startswith("SHA256:")
    assert server.rtacs[0].commands == ["ACC", "WHO", "PORT 1", "QUI"]
    assert server.rtacs[0].terminations == 1


def test_ssh_login_rejected_once(rtac_server, ssh_key):
    server = rtac_server(FakeRTAC, transport="ssh", ssh_key=ssh_key)
    tn = _session(_tunnel(server, transport="ssh"), rtac_creds={"user": "engineer", "pass": "x"})
    with pytest.raises(RTACLoginError, match="rejected the SSH login"):
        tn.connect()
    assert server.ssh_interfaces[0].auth_attempts == 1

    # Not tried again: PEAT doesn't connect
    tn = _session(_tunnel(server, transport="ssh"), rtac_creds={"user": "engineer", "pass": "x"})
    with pytest.raises(RTACLoginError, match="before"):
        tn.connect()
    assert server.connections == 1
    assert len(server.ssh_interfaces) == 1


def test_ssh_needs_creds(rtac_server, ssh_key):
    server = rtac_server(FakeRTAC, transport="ssh", ssh_key=ssh_key)
    tn = _session(_tunnel(server, transport="ssh"))
    with pytest.raises(TunnelError, match="rtac_tunnel_creds"):
        tn.connect()
    assert server.connections == 0


def test_chunking_proxy(rtac_server):
    # The RTAC's and the relay's output arrive 2 bytes at a time
    relay = GatewayRelay(serial="2009000123", ied_name="SEL_351S_1", fid=FID_351S)
    server = rtac_server(lambda: FakeRTAC(relays={1: relay}))
    proxy = ChunkingProxy(server.port, chunk_size=2, delay=0.0005)
    try:
        tunnel = RTACTunnel.from_dict(
            {"rtac_ip": "127.0.0.1", "tcp_port": proxy.port, "sel_port": 1, "pre_term_s": 0.25}
        )
        with _session(tunnel) as tn:
            info = tn.get_id()
            assert info["FID"] == FID_351S
            assert info["SERIALNO"] == "2009000123"
            assert tn.elevate(2)
            assert tn.access_level == "2"
    finally:
        proxy.close()
    assert proxy.chunks > 100
    assert server.rtacs[0].terminations == 1
