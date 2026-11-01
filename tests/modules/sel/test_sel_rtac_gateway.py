"""
Tests for pulling SEL relays through RTAC engineering access tunnels: the opt-in
pass over gateways (peat/api/pull_api.py, DeviceModule.downstream_targets),
SELRelay.pull_via_gateway and pull_downstream (sel_gateway.py), the devices of
the relays behind a RTAC ("children"), the safety rules, and the inputs
(sel.rtac_tunnels, --rtac-tunnel). They use the scripted RTAC in fake_rtac.py
and the canned relay outputs in sel_command_transcripts.py. All data is synthetic.
"""

import json

import pytest

from peat import DeviceData, DeviceModule, SELRelay, config, datastore, module_api, state
from peat.api import pull_api
from peat.cli_args import build_argument_parser
from peat.cli_main import get_targets
from peat.init import add_rtac_tunnels
from peat.modules.sel import sel_gateway
from peat.modules.sel.sel_ascii import SELAscii
from peat.modules.sel.sel_commands import is_read_only
from peat.modules.sel.sel_comms import device_label
from peat.modules.sel.sel_tunnel import RTACTunnel, SELTunnel

from . import sel_command_transcripts as tr
from .fake_rtac import FakeRTAC, GatewayRelay, RTACServer


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "HOSTS": [],
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(datastore, "global_options", {"telnet": {"timeout": 2.0}})
    mocker.patch.object(datastore, "_data_obj", None)
    mocker.patch.dict(state["CONFIG"], {"error": False, "elastic": None})
    mocker.patch.object(SELAscii, "FIRST_COMMAND_QUIET", 0.0)
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


def _relay(serial: str = "", ied_name: str = "", **kwargs) -> GatewayRelay:
    kwargs.setdefault("fid", tr.FID_351S)
    kwargs.setdefault("outputs", tr.OUTPUTS_351S)
    return GatewayRelay(serial=serial, ied_name=ied_name, **kwargs)


def _entry(server: RTACServer, **kwargs) -> dict:
    entry = {"rtac_ip": "127.0.0.1", "tcp_port": server.port, "sel_port": 1, "pre_term_s": 0.25}
    entry.update(kwargs)
    return entry


def _sel_options(**options) -> None:
    datastore.global_options["sel"] = {**datastore.global_options.get("sel", {}), **options}


def _sent(relay) -> list[str]:
    passwords = {p for p in relay.passwords.values() if p}
    lines = [line.decode("latin-1") for line in relay.lines]
    return [line for line in lines if line and line not in passwords]


def _rtac(ip: str = "127.0.0.1") -> DeviceData:
    """The RTAC's device, as after a pull of the RTAC."""
    dev = datastore.get(ip, "ip")
    dev._is_active = True
    dev._is_verified = True
    return dev


# ---------------------------------------------------------------------------
# SELRelay.pull_via_gateway
# ---------------------------------------------------------------------------


def test_pull_via_gateway_sel_server(rtac_server):
    relay = _relay(serial="2009000123", ied_name="SEL_351S_1")
    server = rtac_server(lambda: FakeRTAC(relays={1: relay}))
    rtac = _rtac()

    child = SELRelay.pull_via_gateway(_entry(server), gateway=rtac)
    assert child is not None

    # The child: its own ID (the serial number), no IP, not the RTAC
    assert child.id == "2009000123"
    assert not child.ip
    assert child is not rtac
    assert any(obj is child for obj in datastore.objects)
    assert child._is_verified
    assert child._is_active
    assert child._module is SELRelay
    assert child.firmware.id == tr.FID_351S
    assert child.extra["iedName"] == "SEL_351S_1"
    # The RTAC's IP address, and the addresses in the relay's settings (SHO P),
    # which aren't the device's address
    assert child.related.ip == {"127.0.0.1", "192.0.2.30", "192.0.2.1"}
    assert child.interface[0].ip == "192.0.2.30"
    assert child.extra["gateway"] == {
        "type": "SEL RTAC",
        "ip": "127.0.0.1",
        "tcp_port": server.port,
        "sel_port": 1,
        "transport": "telnet",
        "kind": "sel_server",
        "route": "interleaved",
        "name": None,
        "device_name": None,
        "source": "config",
        "pull_status": "successful",
        "session": {
            "rtac_login": False,
            "who_row": {"port": 1, "device": "Feeder_1", "protocol": "Client - Serial"},
        },
    }
    assert device_label(child) == "2009000123"

    # The RTAC lists the child
    assert "2009000123" in rtac.related.hosts

    # Read-only commands at level 1: no 2AC, nothing that changes the relay
    sent = _sent(relay)
    assert sent[:2] == ["id", "ACC"]
    assert "2AC" not in sent
    assert not [c for c in sent if not is_read_only(c) and c != "quit"]
    upper = [c.upper() for c in sent]
    for command in ("STA", "SER", "HIS", "DATE", "GRO", "VER", "SHO G", "SHO 1", "SHO L 1"):
        assert command in upper
    assert not [c for c in sent if c.upper().startswith("FIL")]
    assert sent[-1] == "quit"

    # The settings come from the SHO commands
    assert child.extra["settings_source"] == "sho_commands"
    assert child.extra["raw_rid"] == "FEEDER 1"
    assert child.serial_number == "2009000123"
    assert child.part_number == "0351S7XHD3E5462"
    assert [e for e in child.event if e.dataset == "ser"]

    # The output is in the child's directory
    out_dir = config.DEVICE_DIR / "2009000123"
    assert child.get_out_dir() == out_dir
    outputs = next(f for f in child.files if f.name == "additional-command-outputs.json")
    assert outputs.local_path.parent == out_dir
    assert outputs.extra["transport"] == "rtac_tunnel"
    assert (out_dir / "ascii_commands" / "sta.txt").is_file()
    assert (out_dir / "raw-telnet-output.json").is_file()
    assert not rtac.get_out_dir().exists()

    # The tunnel was closed
    assert server.rtacs[0].terminations == 1
    assert server.rtacs[0].commands == ["ACC", "WHO", "PORT 1", "QUI"]


def test_pull_via_gateway_with_more_commands(rtac_server):
    relay = _relay(serial="2009000123")
    server = rtac_server(lambda: FakeRTAC(relays={1: relay}))
    _sel_options(attempt_more_commands=True)

    child = SELRelay.pull_via_gateway(_entry(server))
    assert child is not None
    sent = _sent(relay)
    # All of the commands of sel.attempt_more_commands, with 2AC as before
    assert "2AC" in sent
    for command in ("TIM Q", "GOO", "ETH", "MAC", "CST"):
        assert command in [c.upper() for c in sent]
    assert child.extra["gateway"]["pull_status"] == "successful"


def test_child_ids(rtac_server):
    relays = {
        1: _relay(ied_name="SEL_351S_1"),
        2: _relay(ied_name="SEL_351S_1"),  # the same IED name (e.g. a template)
        3: _relay(),
    }
    server = rtac_server(lambda: FakeRTAC(relays=relays))
    _sel_options(rtac_tunnels=[_entry(server, sel_port=n) for n in (1, 2, 3)])

    children = SELRelay.pull_downstream([])
    ids = [child.id for child in children]
    # The IED name, the device ID (DEVID) if it's used already, then the path
    assert ids == ["SEL_351S_1", "SEL-351S-7", f"127.0.0.1_{server.port}_p3"]
    for child in children:
        assert ":" not in child.id
        assert child.get_out_dir().name == child.id.lower()


def test_access_point_routes(rtac_server):
    server = rtac_server(lambda: FakeRTAC(kind="access_point", relays={1: _relay()}))

    # A direct route, or a route that isn't known, isn't used by default
    for route in ("direct", None):
        entry = _entry(server, sel_port=None, kind="access_point", route=route)
        assert SELRelay.pull_via_gateway(entry) is None
    assert server.connections == 0

    # An interleaved route (to the _TAP) is used
    entry = _entry(server, sel_port=None, kind="access_point", route="interleaved")
    child = SELRelay.pull_via_gateway(entry)
    assert child is not None
    assert child.extra["gateway"]["kind"] == "access_point"
    assert server.connections == 1

    # With sel.allow_direct_tunnels
    _sel_options(allow_direct_tunnels=True)
    entry = _entry(server, sel_port=None, kind="access_point", route="direct")
    assert SELRelay.pull_via_gateway(entry) is not None
    assert server.connections == 2


def test_relay_login_failure(rtac_server):
    relay = _relay(serial="2009000123")
    server = rtac_server(lambda: FakeRTAC(relays={1: relay}))

    # The path's own passwords for the relay (here a wrong one)
    child = SELRelay.pull_via_gateway(_entry(server, creds={"acc": "WRONG"}))
    assert child is not None
    assert child.extra["gateway"]["pull_status"] == "login failed"
    assert relay.password_attempts == {"acc": ["WRONG"]}
    assert server.rtacs[0].terminations == 1


def test_tunnel_failure(rtac_server):
    server = rtac_server(lambda: FakeRTAC(port_error="Connection failed"))
    assert SELRelay.pull_via_gateway(_entry(server)) is None
    assert datastore.objects == []
    assert not config.DEVICE_DIR.exists()
    assert SELRelay.pull_via_gateway("not a tunnel") is None


def test_rejected_rtac_login_is_tried_once_per_rtac(rtac_server):
    relays = {n: _relay(serial=f"100{n}") for n in (1, 2, 3)}
    server = rtac_server(lambda: FakeRTAC(relays=relays, login=("admin", "right")))
    _sel_options(
        rtac_tunnel_creds={"user": "admin", "pass": "WRONG"},
        # Two ports, and the SEL server without a port (expanded with WHO)
        rtac_tunnels=[
            _entry(server, sel_port=1),
            _entry(server, sel_port=2),
            _entry(server, sel_port=None),
        ],
    )

    assert SELRelay.pull_downstream([]) == []
    # One failed login, not one per path (a RTAC may lock the account)
    assert server.connections == 1
    assert sum(rtac.login_attempts for rtac in server.rtacs) == 1
    assert sum(rtac.login_failures for rtac in server.rtacs) == 1
    assert datastore.objects == []

    # A later pass tries once more
    assert SELRelay.pull_downstream([]) == []
    assert server.connections == 2
    assert sum(rtac.login_failures for rtac in server.rtacs) == 2

    # pull_via_gateway doesn't try it again either
    assert SELRelay.pull_via_gateway(_entry(server, sel_port=3)) is None
    assert server.connections == 2


def test_rejected_acc_password_is_tried_once_per_rtac(rtac_server):
    relays = {n: _relay(serial=f"100{n}") for n in (1, 2, 3)}
    server = rtac_server(lambda: FakeRTAC(relays=relays, acc_password="SrvAcc"))
    _sel_options(
        rtac_tunnel_creds={"acc": "WRONG"},
        rtac_tunnels=[_entry(server, sel_port=n) for n in (1, 2, 3)],
    )
    assert SELRelay.pull_downstream([]) == []
    assert server.connections == 1
    assert sum(rtac.acc_attempts for rtac in server.rtacs) == 1


def test_file_transfer_option(rtac_server):
    set_1 = '[1]\r\nRID,"FEEDER 1"\r\nTID,"STATION A"\r\n'
    relay = _relay(serial="2009000123", files={"SETTINGS SET_1.TXT": set_1})
    server = rtac_server(lambda: FakeRTAC(relays={1: relay}))

    child = SELRelay.pull_via_gateway(_entry(server))
    assert not [line for line in _sent(relay) if line.upper().startswith("FIL")]

    _sel_options(tunnel_file_transfer=True)
    child = SELRelay.pull_via_gateway(_entry(server))
    assert any(line.upper().startswith("FIL") for line in _sent(relay))
    downloaded = next(f for f in child.files if f.name == "SET_1.TXT")
    assert downloaded.extra["transport"] == "rtac_tunnel"
    assert downloaded.extra["file_transfer"] == "file_show"
    assert downloaded.local_path.is_relative_to(child.get_out_dir())
    assert child.get_out_dir() == config.DEVICE_DIR / "sel-351s-7"


# ---------------------------------------------------------------------------
# The pass over gateways (pull_api.pull_downstream)
# ---------------------------------------------------------------------------


class FakeGatewayModule(DeviceModule):
    """A module of a gateway, like SELRTAC with its engineering access entries."""

    entries: list[dict] = []

    @classmethod
    def downstream_targets(cls, dev: DeviceData) -> list[dict]:  # noqa: ARG003
        return [dict(e) for e in cls.entries]

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:  # noqa: ARG003
        return True


def test_default_downstream_targets():
    assert DeviceModule.downstream_targets(DeviceData(ip="192.0.2.1")) == []
    assert SELRelay.downstream_targets(DeviceData(ip="192.0.2.1")) == []


def test_nothing_configured_does_nothing(rtac_server):
    server = rtac_server()
    gateway = _rtac()
    assert pull_api.pull_downstream([gateway]) == []
    assert server.connections == 0


def test_discovered_targets_need_the_option(rtac_server, mocker):
    server = rtac_server(lambda: FakeRTAC(relays={1: _relay(serial="2009000123")}))
    entry = {
        "name": "Feeder_1",
        "rtac_ip": "127.0.0.1",
        "tcp_port": server.port,
        "transport": "telnet",
        "kind": "sel_server",
        "sel_port": 1,
        "device_name": "Feeder_1",
        "route": "interleaved",
        "needs_rtac_login": False,
        "termination_string": "\x04",
        "source": "export",
    }
    mocker.patch.object(FakeGatewayModule, "entries", [entry])
    gateway = _rtac()
    gateway._module = FakeGatewayModule

    # Off by default: the RTAC's paths aren't used
    assert pull_api.pull_downstream([gateway]) == []
    assert server.connections == 0

    # sel.rtac_pull_downstream for the RTAC
    gateway._runtime_options["sel"] = {"rtac_pull_downstream": True}
    children = pull_api.pull_downstream([gateway])
    assert [c.id for c in children] == ["2009000123"]
    assert children[0].extra["gateway"]["source"] == "export"
    assert children[0].extra["gateway"]["device_name"] == "Feeder_1"
    assert "2009000123" in gateway.related.hosts


def test_configured_paths_need_the_selrelay_module(rtac_server, mocker):
    relays = {1: _relay(serial="1001"), 2: _relay(serial="1002")}
    server = rtac_server(lambda: FakeRTAC(relays=relays))
    _sel_options(rtac_tunnels=[_entry(server, sel_port=2)])

    # e.g. "peat pull -d clx" with sel.rtac_tunnels in a shared configuration file
    assert pull_api.pull_downstream([], ["clx"]) == []
    assert server.connections == 0
    assert pull_api.pull([], "unicast_ip", ["clx"]) is None
    assert server.connections == 0

    # The paths of a RTAC that was pulled (-d selrtac) are governed by its options
    mocker.patch.object(FakeGatewayModule, "entries", [{**_entry(server), "source": "export"}])
    gateway = _rtac()
    gateway._module = FakeGatewayModule
    gateway._runtime_options["sel"] = {"rtac_pull_downstream": True}
    children = pull_api.pull_downstream([gateway], ["selrtac"])
    assert [(c.id, c.extra["gateway"]["sel_port"]) for c in children] == [("1001", 1)]
    assert server.connections == 1

    # With SELRelay selected (or all modules, the default), the configured path too
    children = pull_api.pull_downstream([], ["selrelay"])
    assert [c.id for c in children] == ["1002"]
    assert server.connections == 2


def test_single_string_option_and_subclasses(rtac_server, mocker):
    server = rtac_server(lambda: FakeRTAC(relays={1: _relay(serial="2009000123")}))
    # One path as a string instead of a list
    _sel_options(rtac_tunnels=_entry(server))

    class OtherRelay(SELRelay):
        """e.g. a third-party module based on SELRelay"""

    mocker.patch.object(
        type(module_api),
        "classes",
        new_callable=mocker.PropertyMock,
        return_value=[SELRelay, OtherRelay],
    )
    spy = mocker.spy(sel_gateway, "pull_through_tunnel")
    children = pull_api.pull_downstream([])
    # SELRelay.pull_downstream runs once, not again for the subclass
    assert [c.id for c in children] == ["2009000123"]
    assert children[0]._module is SELRelay
    assert spy.call_count == 1
    assert server.connections == 1

    # Only the subclass is selected: it pulls the relays (once)
    children = pull_api.pull_downstream([], [OtherRelay])
    assert len(children) == 1
    assert children[0]._module is OtherRelay
    assert spy.call_count == 2


def test_who_expansion_and_one_session_at_a_time(rtac_server):
    relays = {1: _relay(serial="1001"), 2: _relay(serial="1002"), 3: _relay(serial="1003")}
    server = rtac_server(lambda: FakeRTAC(relays=relays))
    # A SEL server without a port: the relays WHO lists (not the server itself)
    _sel_options(rtac_tunnels=[_entry(server, sel_port=None, kind="sel_server")])

    children = pull_api.pull_downstream([])
    assert [c.id for c in children] == ["1001", "1002", "1003"]
    assert [c.extra["gateway"]["device_name"] for c in children] == [
        "Feeder_1",
        "Feeder_2",
        "Feeder_3",
    ]
    # WHO, then one connection per relay, never two at the same time
    assert server.connections == 4
    assert server.max_open == 1
    assert server.rtacs[0].commands == ["ACC", "WHO", "QUI"]
    assert "PORT 254" not in [c for rtac in server.rtacs for c in rtac.commands]
    for rtac in server.rtacs[1:]:
        assert rtac.terminations == 1


def test_one_path_per_relay(rtac_server, mocker):
    relays = {1: _relay(serial="1001"), 2: _relay(serial="1001")}
    server = rtac_server(lambda: FakeRTAC(relays=relays))
    configured = _entry(server, sel_port=1)
    _sel_options(rtac_tunnels=[configured, dict(configured), f"127.0.0.1:{server.port}:1"])
    # The same path from the RTAC's configuration, and another port with the same name
    mocker.patch.object(
        FakeGatewayModule,
        "entries",
        [
            {**configured, "source": "export"},
            {**_entry(server, sel_port=2), "device_name": "Feeder_1", "source": "export"},
        ],
    )
    gateway = _rtac()
    gateway._module = FakeGatewayModule
    gateway._runtime_options["sel"] = {"rtac_pull_downstream": True}

    jobs = sel_gateway.plan_jobs([(gateway, FakeGatewayModule.downstream_targets(gateway))])
    assert [(j.tunnel.sel_port, j.explicit) for j in jobs] == [(1, True), (2, False)]

    # Port 2 has the same serial number as port 1: it isn't pulled twice
    children = pull_api.pull_downstream([gateway])
    assert [c.id for c in children] == ["1001"]
    assert server.connections == 2


def test_device_name_dedupe_prefers_paths_that_are_not_direct(rtac_server):
    server = rtac_server()
    sel_server_path = _entry(server, sel_port=1, device_name="Feeder_1")
    ap_path = _entry(
        server, sel_port=None, kind="access_point", device_name="Feeder_1", tcp_port=1
    )
    _sel_options(rtac_tunnels=[ap_path, sel_server_path])
    jobs = sel_gateway.plan_jobs([])
    assert [j.tunnel.kind for j in jobs] == ["sel_server"]


def test_host_options(rtac_server):
    relay = _relay(serial="2009000123")
    server = rtac_server(lambda: FakeRTAC(relays={1: relay}, login=("engineer", "Rtac-Pass1")))
    # A host in the configuration file: the RTAC, with its tunnels, its web
    # login (the RTAC user), and the passwords of the relays behind it
    host = DeviceData(ip="127.0.0.1")
    host._host_option_overrides.update(
        {
            "sel": {
                "rtac_tunnels": [
                    {"tcp_port": server.port, "sel_port": 1, "pre_term_s": 0.25},
                    "not:a:tunnel",
                ],
                "creds": {"acc": "OTTER"},
            },
            "web": {"user": "engineer", "pass": "Rtac-Pass1"},
        }
    )
    datastore.objects.append(host)

    children = pull_api.pull_downstream([])
    assert [c.id for c in children] == ["2009000123"]
    assert server.rtacs[0].login_attempts == 1
    assert relay.password_attempts == {"acc": ["OTTER"]}
    assert "2009000123" in host.related.hosts

    # The relay has the host's options for relays, not the ones for the RTAC
    child = children[0]
    assert child._host_option_overrides == {"sel": {"creds": {"acc": "OTTER"}}}
    assert child.options["sel"]["rtac_tunnels"] == []
    # So the relay isn't a host with paths of its own on a later pass
    assert [dev for _, dev in sel_gateway._configured_entries()] == [host, host]
    assert [t.target_id for t, _ in sel_gateway.configured_tunnels()] == [
        f"127.0.0.1_{server.port}_p1"
    ]


def test_invalid_configured_tunnels_are_skipped():
    entry = {"rtac_ip": "192.0.2.10", "creds": {"acc": "S3cret"}}
    _sel_options(rtac_tunnels=[entry, "192.0.2.10:3254:1"])
    assert [t for t, _ in sel_gateway.configured_tunnels()] == [
        RTACTunnel.from_spec("192.0.2.10:3254:1")
    ]
    # The entry is logged without its passwords
    assert sel_gateway._safe_entry(entry) == {"rtac_ip": "192.0.2.10", "creds": "<redacted>"}


def test_children_are_not_merged_with_the_rtac(rtac_server):
    server = rtac_server(lambda: FakeRTAC(relays={1: _relay(serial="2009000123")}))
    rtac = _rtac()
    rtac._module = FakeGatewayModule
    child = SELRelay.pull_via_gateway(_entry(server), gateway=rtac)

    datastore.deduplicate(prune_inactive=True)
    assert any(obj is child for obj in datastore.objects)
    assert any(obj is rtac for obj in datastore.objects)
    assert not rtac.is_duplicate(child)
    assert not child.is_duplicate(rtac)
    assert rtac.ip == "127.0.0.1"
    assert not child.ip


# ---------------------------------------------------------------------------
# pull_api.pull and the CLI
# ---------------------------------------------------------------------------


def test_pull_without_targets(rtac_server):
    server = rtac_server(lambda: FakeRTAC(relays={1: _relay(serial="2009000123")}))
    add_rtac_tunnels([f"127.0.0.1:{server.port}:1"])
    # The pre-termination timeout of the fake RTAC is shorter than the default
    datastore.global_options["sel"]["rtac_tunnels"] = [_entry(server)]

    summary = pull_api.pull([], "unicast_ip", ["selrelay"])
    assert summary is not None
    assert summary["pull_devices"] == ["2009000123"]
    assert summary["num_pull_results"] == 1
    result = summary["pull_results"][0]
    assert result["id"] == "2009000123"
    assert result["extra"]["gateway"]["type"] == "SEL RTAC"
    assert "ip" not in result
    assert not state.error
    saved = json.loads(next((config.SUMMARIES_DIR).glob("pull-summary*.json")).read_text())
    assert saved["pull_devices"] == ["2009000123"]


def test_pull_without_targets_or_tunnels():
    assert pull_api.pull([], "unicast_ip", ["selrelay"]) is None
    assert state.error


def test_pull_refreshes_the_gateway_results(rtac_server, mocker):
    server = rtac_server(lambda: FakeRTAC(relays={1: _relay(serial="2009000123")}))
    rtac = _rtac()
    rtac._module = FakeGatewayModule
    mocker.patch.object(FakeGatewayModule, "entries", [_entry(server)])
    rtac._runtime_options["sel"] = {"rtac_pull_downstream": True}
    mocker.patch.object(pull_api, "scan", return_value={"hosts_verified": 1, "scan_targets": []})

    summary = pull_api.pull(["127.0.0.1"], "unicast_ip", ["selrtac"])
    assert summary["pull_devices"] == ["127.0.0.1", "2009000123"]
    results = {r["id"]: r for r in summary["pull_results"]}
    assert "2009000123" in results["127.0.0.1"]["related"]["hosts"]
    assert "127.0.0.1" in results["2009000123"]["related"]["ip"]
    assert "ip" not in results["2009000123"]


def test_cli_argument():
    parser = build_argument_parser()
    args = parser.parse_args(
        [
            "pull",
            "-d",
            "selrelay",
            "--rtac-tunnel",
            "192.0.2.10:3254:1",
            "192.0.2.10:51001:raw:tap",
            "192.0.2.10:3254:2:tls:interleaved:login",
        ]
    )
    assert args.rtac_tunnels == [
        "192.0.2.10:3254:1",
        "192.0.2.10:51001:raw:tap",
        "192.0.2.10:3254:2:tls:interleaved:login",
    ]
    assert parser.parse_args(["pull", "-i", "192.0.2.1"]).rtac_tunnels is None
    with pytest.raises(SystemExit):
        parser.parse_args(["pull", "--rtac-tunnel", "192.0.2.10"])


def test_cli_targets_with_only_tunnels():
    args = {
        "device_types": ["selrelay"],
        "rtac_tunnels": ["192.0.2.10:3254:1"],
        "host_file": None,
        "host_list": None,
        "broadcast_list": None,
        "port_list": None,
    }
    targets, comm_type, modules = get_targets(args)
    assert targets == []
    assert comm_type == "unicast_ip"
    assert modules == ["SELRelay"]


def test_add_rtac_tunnels():
    datastore.global_options["sel"] = {
        "rtac_tunnels": ["192.0.2.10:3254:1"],
        "creds": {"acc": "x"},
    }
    add_rtac_tunnels(["192.0.2.10:3254:1", "192.0.2.10:3254:2"])
    assert datastore.global_options["sel"] == {
        "rtac_tunnels": ["192.0.2.10:3254:1", "192.0.2.10:3254:2"],
        "creds": {"acc": "x"},
    }
    tunnels = [t for t, _ in sel_gateway.configured_tunnels()]
    assert tunnels == [
        RTACTunnel.from_spec("192.0.2.10:3254:1"),
        RTACTunnel.from_spec("192.0.2.10:3254:2"),
    ]
