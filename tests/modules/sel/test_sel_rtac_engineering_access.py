"""
Tests for the discovery of the engineering access paths of a SEL RTAC
(access points, access point routers and SEL servers), from project exports
and from the RTAC database, and for the opt-in probe of the TLS and SSH ports.

The project export in ``data_files/rtac/synthetic-engineering-access/`` is
synthetic (refer to the ``README.md`` there). The database tables are
synthetic too: the column names of the RTAC's tables are not public, so they
are the snake case setting names, like the columns PEAT already reads from
other RTAC tables (e.g. ``server_ip_port``).
"""

import hashlib
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta

import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from loguru import logger

from peat import SELRTAC, DeviceData, config, datastore
from peat.modules.sel import rtac_engineering_access as rea
from peat.modules.sel import rtac_parse, sel_rtac
from peat.protocols.ssh import SSHHostKey
from peat.protocols.tls import PeerCertificate

RTAC_IP = "192.0.2.10"


@pytest.fixture
def rtac_path(datapath):
    def _rtac_path(filename: str):
        return datapath(f"rtac/{filename}")

    return _rtac_path


def _isolate(mocker, tmp_path) -> None:
    """Device output in a temporary directory, and an empty datastore."""
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch.object(datastore, "objects", [])


@pytest.fixture
def isolated(mocker, tmp_path):
    _isolate(mocker, tmp_path)


def make_dev(ip: str = RTAC_IP) -> DeviceData:
    device = DeviceData(ip=ip)
    device._module = SELRTAC
    return device


@pytest.fixture
def dev(mocker, tmp_path) -> DeviceData:
    _isolate(mocker, tmp_path)
    return make_dev()


@pytest.fixture
def log_text():
    """Text of the WARNING and higher messages that PEAT logs during the test."""
    messages = []
    handler_id = logger.add(
        lambda msg: messages.append(f"{msg.record['level'].name}: {msg.record['message']}"),
        level="WARNING",
    )
    yield lambda: "\n".join(messages)
    logger.remove(handler_id)


def entry(**values) -> dict:
    """An engineering access entry, with the values that most entries have."""
    result = {
        "name": None,
        "rtac_ip": RTAC_IP,
        "tcp_port": None,
        "transport": None,
        "kind": "access_point",
        "sel_port": None,
        "device_name": None,
        "route": None,
        "needs_rtac_login": False,
        "termination_string": None,
        "source": "export",
    }
    assert set(values) <= set(result)
    result.update(values)
    return result


def services_by_port(dev: DeviceData) -> dict:
    return {service.port: service for service in dev.service}


# ---------- Value conversion ----------


def test_normalize_and_get_setting():
    assert rea.normalize("Pre-Termination Timeout") == "preterminationtimeout"
    assert rea.normalize("local_port_number") == rea.normalize("Local Port Number")

    settings = {"LOCAL_PORT_NUMBER": 8001, "Network Connection Type": "  ", "Mode": "SSH"}
    assert rea.get_setting(settings, ["Local Port Number"]) == 8001
    # Empty values are skipped
    assert rea.get_setting(settings, ["Network Connection Type", "Mode"]) == "SSH"
    assert rea.get_setting(settings, ["Missing"], default=1) == 1
    assert rea.get_setting(None, ["Missing"]) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (8001, 8001),
        ("3254", 3254),
        (" 23 ", 23),
        (3254.0, 3254),
        (65535, 65535),
        (0, None),
        ("0", None),
        (65536, None),
        (-1, None),
        (True, None),
        ("Raw TCP", None),
        (None, None),
    ],
)
def test_to_port(value, expected):
    assert rea.to_port(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        ("True", True),
        ("Y", True),
        ("t", True),
        (1, True),
        (False, False),
        ("False", False),
        ("N", False),
        (0, False),
        ("maybe", None),
        (None, None),
    ],
)
def test_to_bool(value, expected):
    assert rea.to_bool(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Telnet", "telnet"),
        ("Raw TCP", "raw"),
        ("TCP", "raw"),
        ("SSH", "ssh"),
        ("SSL/TLS", "tls"),
        ("TLS", "tls"),
        ("UDP Incoming", "udp"),
        ("Something else", None),
        ("", None),
        (3, None),  # e.g. the ID of the mode in the database
        (None, None),
    ],
)
def test_transport_from_text(value, expected):
    assert rea.transport_from_text(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("<CTRL-D>", "\x04"),
        ("<ctrl-c>", "\x03"),
        ("< CTRL - D >", "\x04"),
        ("^D", "\x04"),
        ("<CTRL-D><CR>", "\x04\r"),
        ("QUIT<CR><LF>", "QUIT\r\n"),
        ("<ESC>x", "\x1bx"),
        ("BYE", "BYE"),
        ("", None),
        (None, None),
        (4, None),
    ],
)
def test_parse_termination_string(value, expected):
    assert rea.parse_termination_string(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, 1),
        (254, 254),
        ("3", 3),
        ("Com_01", 1),
        ("COM3", 3),
        ("Port 12", 12),
        ("Serial_02", 2),
        ("Com_00", None),
        (0, None),
        (1000, None),
        ("/dev/ttyS0", None),
        (True, None),
        (None, None),
    ],
)
def test_port_number(value, expected):
    assert rea.port_number(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("TAP", "interleaved"),
        ("tap", "interleaved"),
        ("AP", "direct"),
        ("Interleaved", "interleaved"),
        ("Direct Transparent", "direct"),
        ("Transparent", "interleaved"),
        ("Engineering", None),
        ("", None),
        (None, None),
    ],
)
def test_route_from_type(value, expected):
    assert rea.route_from_type(value) == expected


def test_client_ips():
    assert rea.client_ips("192.0.2.100, 192.0.2.101;bad") == ["192.0.2.100", "192.0.2.101"]
    assert rea.client_ips("") == []
    assert rea.client_ips(None) == []


def test_merge_entries():
    first = entry(name="A", tcp_port=9001, transport="telnet", device_name="R1")
    second = entry(name="B", tcp_port=8001, transport="ssh", device_name="R1")
    merged = rea.merge_entries([first], [second, dict(first)])
    assert merged == [second, first]  # no duplicates, sorted by port
    assert merged[1] is not first  # copies


# ---------- Project exports ----------

# Expected results for the synthetic export in data_files/rtac/synthetic-engineering-access
SYNTHETIC_ENTRIES = [
    entry(
        name="Remote_Access_Server",
        tcp_port=3254,
        transport="tls",
        kind="sel_server",
        sel_port=1,
        device_name="Feeder_1",
        route="interleaved",
        needs_rtac_login=True,
        termination_string="\x04",
    ),
    entry(
        name="Remote_Access_Server",
        tcp_port=3254,
        transport="tls",
        kind="sel_server",
        sel_port=63,
        device_name="Feeder_2",
        route="interleaved",
        needs_rtac_login=True,
        termination_string="\x04",
    ),
    # EA_Transparent_APR: the destination is "Feeder_1" with the type "TAP"
    entry(
        name="Feeder_1",
        tcp_port=8001,
        transport="ssh",
        device_name="Feeder_1",
        route="interleaved",
        needs_rtac_login=True,  # SSH always needs a login
    ),
    # EA_Direct_APR: the destination is "Feeder_1_SEL_AP"
    entry(
        name="Feeder_1_SEL_AP",
        tcp_port=9001,
        transport="telnet",
        device_name="Feeder_1",
        route="direct",
    ),
    # EA_Raw_APR has the source and destination the other way around
    entry(
        name="Feeder_2_SEL_TAP",
        tcp_port=9002,
        transport="raw",
        device_name="Feeder_2",
        route="interleaved",
    ),
]


@pytest.mark.usefixtures("isolated")
def test_parse_synthetic_export(rtac_path, log_text):
    dev = SELRTAC.parse(rtac_path("synthetic-engineering-access"))

    assert dev.ip == RTAC_IP  # from "Ethernet Settings.xml"
    assert dev.extra["engineering_access"] == SYNTHETIC_ENTRIES
    for result in dev.extra["engineering_access"]:
        assert tuple(result) == rea.ENGINEERING_ACCESS_KEYS
    assert "engineering_access_devices" not in dev.extra
    assert SELRTAC.downstream_targets(dev) == SYNTHETIC_ENTRIES

    services = services_by_port(dev)
    assert set(services) == {3254, 7300, 8001, 9001, 9002}  # not the DNP3 server (20000)

    server = services[3254]
    assert (server.protocol, server.transport, server.role) == ("tls", "tcp", "engineering_access")
    assert server.configured_port == 3254
    assert server.enabled is True
    assert server.status == ""  # from the configuration, not verified
    assert server.extra["kind"] == "sel_server"
    assert server.extra["termination_string"] == "\x04"
    assert server.extra["termination_string_setting"] == "<CTRL-D>"
    assert server.extra["perform_authentication"] is True
    assert server.extra["enable_port_command"] is True
    assert server.extra["virtual_port_number"] == 254
    assert server.extra["allow_anonymous_clients"] is False
    assert server.extra["allowed_client_ips"] == ["192.0.2.100", "192.0.2.101"]
    assert server.extra["pre_termination_timeout"] == 1
    assert server.extra["destinations"] == [
        {"name": "Feeder_1", "device_name": "Feeder_1", "route": "interleaved", "sel_port": 1},
        {"name": "Feeder_2", "device_name": "Feeder_2", "route": "interleaved", "sel_port": 63},
    ]

    ssh_ap = services[8001]
    assert (ssh_ap.protocol, ssh_ap.transport, ssh_ap.role) == ("ssh", "tcp", "engineering_access")
    assert ssh_ap.extra["name"] == "EA_Transparent"
    assert ssh_ap.extra["connection_type"] == "SSH"
    assert ssh_ap.extra["destinations"] == [
        {
            "name": "Feeder_1",
            "device_name": "Feeder_1",
            "route": "interleaved",
            "router": "EA_Transparent_APR",
            "legacy_port_command": False,
            "legacy_port_command_id": 1,
        }
    ]
    assert services[9001].protocol == "telnet"
    assert services[9001].extra["destinations"][0]["route"] == "direct"
    # Raw TCP has no protocol name of its own
    assert (services[9002].protocol, services[9002].transport) == ("", "tcp")

    # A UDP access point with no router isn't engineering access
    udp = services[7300]
    assert (udp.protocol, udp.transport, udp.role) == ("", "udp", "access_point")
    assert "destinations" not in udp.extra

    # The services are on the interface with the RTAC's IP address
    eth_01 = next(iface for iface in dev.interface if iface.name == "Eth_01")
    assert {service.port for service in eth_01.services} == set(services)

    assert {3254, 7300, 8001, 9001, 9002} <= dev.related.ports
    assert {"ssh", "telnet", "tls"} <= dev.related.protocols
    # Access points are not hosts, the devices are
    assert {"Feeder_1", "Feeder_2"} <= dev.related.hosts
    assert not {"EA_Transparent", "EA_Direct", "EA_Raw", "Logic_UDP"} & dev.related.hosts

    # The raw parsed data is unchanged
    assert dev.extra["AccessPointRouters"]["EA_Raw_APR"]["Source"]["device_name"] == (
        "Feeder_2_SEL_TAP"
    )
    assert "WARNING" not in log_text()


@pytest.mark.usefixtures("isolated")
def test_parse_public_export_without_engineering_access(rtac_path, log_text):
    """The public EPHCC export only has UDP access points with no router."""
    dev = SELRTAC.parse(rtac_path("ephcc-microgrid-rtac.tar.gz"))

    assert "engineering_access" not in dev.extra
    assert SELRTAC.downstream_targets(dev) == []
    udp = {s.port: s for s in dev.service if s.role == "access_point"}
    assert set(udp) == {7200, 7201}
    assert all(s.transport == "udp" and s.protocol == "" for s in udp.values())
    assert udp[7200].extra["name"] == "BansheeUDP"
    # Unchanged from before (no protocol is added for UDP access points)
    assert dev.related.protocols == {"modbus", "iec61850"}
    assert dev.related.ports == {502, 7200, 7201, 10507}
    assert "WARNING" not in log_text()


def _ap(port, conn_type="Telnet", **settings) -> dict:
    return {
        "Manufacturer": "Any",
        "Model": "Other",
        "Protocol": "AccessPointServer",
        "Connection Type": "Ethernet",
        "Settings": {"Network Connection Type": conn_type, "Local Port Number": port, **settings},
    }


def _sel_client(connection_type="Ethernet", **settings) -> dict:
    return {"Protocol": "SELClient", "Connection Type": connection_type, "Settings": settings}


def _sel_server(**settings) -> dict:
    return {
        "Protocol": "SELServer",
        "Connection Type": "Ethernet Tunneled Serial",
        "Settings": {"Server IP Port": 3254, "Serial Tunneling Mode": "Telnet", **settings},
    }


def _router(source, destination, destinations=None, **settings) -> dict:
    def _endpoint(value):
        if isinstance(value, str):
            value = (value, "", "")
        name, protocol, typ = value
        return {"device_name": name, "device_protocol": protocol, "type": typ}

    result = {"Source": _endpoint(source), "Destination": _endpoint(destination)}
    if destinations:
        result["Destinations"] = [_endpoint(d) for d in destinations]
    result["Settings"] = settings
    return result


def test_export_router_like_pr21_test_data():
    """
    The access point is found whether it's the source or the destination
    (the router in the tests of the export parser has it as the destination).
    """
    info = {
        "Devices": {"Relay1": _sel_client(), "AP1": _ap(9100, "Raw TCP")},
        "AccessPointRouters": {
            "APR1": _router(
                ("Relay1", "SEL", "Engineering"), "AP1", Enable_Legacy_Port_Command=False
            )
        },
    }
    discovery = rea.discover_from_export(info)
    assert discovery.warnings == []
    assert discovery.entries(RTAC_IP) == [
        entry(name="Relay1", tcp_port=9100, transport="raw", device_name="Relay1")
    ]


def test_export_router_multiple_destinations():
    info = {
        "Devices": {
            "EA": _ap(9001),
            "Relay1": _sel_client(),
            "Relay2": _sel_client(),
        },
        "AccessPointRouters": {
            "APR": _router(
                "EA_AP",
                "Relay1_SEL_TAP",
                destinations=["Relay1_SEL_TAP", "Relay2_SEL_AP"],
            )
        },
    }
    entries = rea.discover_from_export(info).entries(None)
    assert entries == [
        entry(
            name="Relay1_SEL_TAP",
            rtac_ip=None,
            tcp_port=9001,
            transport="telnet",
            device_name="Relay1",
            route="interleaved",
        ),
        entry(
            name="Relay2_SEL_AP",
            rtac_ip=None,
            tcp_port=9001,
            transport="telnet",
            device_name="Relay2",
            route="direct",
        ),
    ]


def test_export_router_to_unknown_device():
    """A destination that isn't a device in the export is kept, without its suffix."""
    info = {
        "Devices": {"EA": _ap(9001)},
        "AccessPointRouters": {"APR": _router("EA", "Other_Relay_SEL_TAP")},
    }
    assert rea.discover_from_export(info).entries(RTAC_IP) == [
        entry(
            name="Other_Relay_SEL_TAP",
            tcp_port=9001,
            transport="telnet",
            device_name="Other_Relay_SEL",
            route="interleaved",
        )
    ]


def test_export_router_between_access_points():
    """A route from a network access point to an access point on a serial port."""
    serial_ap = {"Protocol": "AccessPointServer", "Connection Type": "Serial", "Settings": {}}
    info = {
        "Devices": {"EA": _ap(9003, "Raw TCP"), "Serial_AP": serial_ap},
        "AccessPointRouters": {"APR": _router("EA", "Serial_AP")},
    }
    discovery = rea.discover_from_export(info)
    assert discovery.warnings == []
    assert discovery.entries(RTAC_IP) == [
        entry(name="Serial_AP", tcp_port=9003, transport="raw", device_name="Serial_AP")
    ]


def test_export_router_to_access_points_of_devices():
    """
    The access points of devices ("<Device>_<Protocol>_TAP" and "_AP") may be
    devices in the export too. A route to one of them is a route to the device.
    """
    device_ap = {"Protocol": "AccessPointServer", "Connection Type": "Ethernet", "Settings": {}}
    info = {
        "Devices": {
            "EA_Direct": _ap(9001, "Telnet"),
            "EA_Transparent": _ap(8001, "SSH"),
            "Feeder_1": _sel_client(),
            "Feeder_1_SEL_TAP": device_ap,
            "Feeder_1_SEL_AP": device_ap,
            # An access point of the RTAC (not of a device) with the "_AP" suffix
            "Other_AP": device_ap,
        },
        "AccessPointRouters": {
            "Direct_APR": _router("EA_Direct", "Feeder_1_SEL_AP"),
            # The other way around, like in the tests of the export parser
            "Transparent_APR": _router("Feeder_1_SEL_TAP", "EA_Transparent"),
            "Other_APR": _router("EA_Direct", "Other_AP"),
        },
    }
    discovery = rea.discover_from_export(info)
    assert discovery.warnings == []
    assert discovery.entries(RTAC_IP) == [
        entry(
            name="Feeder_1_SEL_TAP",
            tcp_port=8001,
            transport="ssh",
            device_name="Feeder_1",
            route="interleaved",
            needs_rtac_login=True,
        ),
        entry(
            name="Feeder_1_SEL_AP",
            tcp_port=9001,
            transport="telnet",
            device_name="Feeder_1",
            route="direct",
        ),
        entry(name="Other_AP", tcp_port=9001, transport="telnet", device_name="Other_AP"),
    ]

    # The database has the same results for the same configuration
    tables = {
        "access_points": [
            {"access_point_id": 1, "name": "EA_Direct", "network_connection_type": "Telnet",
             "local_port_number": 9001},
            {"access_point_id": 2, "name": "Feeder_1_SEL_AP"},
        ],
        "access_point_routers": [
            {"name": "Direct_APR", "source_access_point_id": 1, "destination_access_point_id": 2},
        ],
        "sel_client_common_settings": [{"connection_id": 10, "virtual_port_number": 1}],
        "connections": [{"connection_id": 10, "name": "Feeder_1"}],
    }  # fmt: skip
    [result] = rea.discover_from_postgres(tables).entries(RTAC_IP)
    assert (result["device_name"], result["route"]) == ("Feeder_1", "direct")


def test_export_router_problems():
    info = {
        "Devices": {"EA": _ap(9001), "Relay1": _sel_client()},
        "AccessPointRouters": {
            # The access point isn't in the export
            "Missing_APR": _router("Missing_AP", "Relay1_SEL_TAP"),
            # The access point is there, but has no destination
            "Empty_APR": {"Source": {"device_name": "EA"}, "Destination": {}, "Settings": {}},
            # Not a dict
            "Bad_APR": "bad",
        },
    }
    discovery = rea.discover_from_export(info)
    assert discovery.entries(RTAC_IP) == []
    assert len(discovery.warnings) == 2
    assert (
        "'Missing_APR' doesn't have a known access point (source 'Missing_AP')"
        in (discovery.warnings[0])
    )
    assert "'Empty_APR' doesn't have a destination" in discovery.warnings[1]


def test_export_access_point_settings_missing():
    """The access point is a device in the export, but without its settings."""
    info = {
        "Devices": {
            "EA": {"Protocol": "AccessPointServer", "Settings": {}},
            "Relay1": _sel_client(),
        },
        "AccessPointRouters": {"APR": _router("EA", "Relay1_SEL_TAP")},
    }
    discovery = rea.discover_from_export(info)
    assert discovery.entries(RTAC_IP) == []
    assert discovery.listeners[0].port is None
    # It's still the access point of the router, so there's no warning about it


def test_export_access_points_not_listening():
    info = {
        "Devices": {
            "Out": _ap(9001, "TCP Outgoing"),
            "Unknown": _ap(9002, "Carrier Pigeon"),
            "Relay1": _sel_client(),
        },
        "AccessPointRouters": {
            "APR1": _router("Out", "Relay1_SEL_TAP"),
            "APR2": _router("Unknown", "Relay1_SEL_TAP"),
        },
    }
    discovery = rea.discover_from_export(info)
    assert [lst.name for lst in discovery.listeners] == ["Unknown"]
    assert discovery.listeners[0].transport is None
    assert discovery.entries(RTAC_IP) == []
    assert any("Unknown connection type 'Carrier Pigeon'" in w for w in discovery.warnings)
    assert any(
        "'APR1': its access point (Out) isn't a port the RTAC listens on" in w
        for w in discovery.warnings
    )


def test_export_access_point_authentication():
    info = {
        "Devices": {"EA": _ap(9001, "Telnet", **{"Perform Authentication": "True"})},
    }
    listener = rea.discover_from_export(info).listeners[0]
    assert listener.needs_rtac_login is True
    assert listener.settings == {"perform_authentication": True}
    assert listener.entries(RTAC_IP) == []  # no router


def test_export_sel_server_variants():
    info = {
        "Devices": {
            # SSH always needs the RTAC login, even if authentication is off
            "SSH_Server": _sel_server(
                **{
                    "Server IP Port": 3022,
                    "Serial Tunneling Mode": "SSH",
                    "Perform Authentication": False,
                    "Termination String": "QUIT<CR>",
                }
            ),
            # The PORT command is disabled, so it doesn't reach any devices
            "No_Port_Server": _sel_server(
                **{"Server IP Port": 3001, "Enable Port Command": False}
            ),
            # Port 0 doesn't listen
            "Off_Server": _sel_server(**{"Server IP Port": 0}),
            "Unknown_Server": _sel_server(**{"Server IP Port": 3002, "Serial Tunneling Mode": 7}),
            # SEL devices: the serial port number of serial devices
            "Relay_Serial": _sel_client("Serial", **{"Serial Port": "Com_03"}),
            "Relay_Serial_VPN": _sel_client("Serial", **{"Virtual Port Number": 5}),
            "Relay_Eth": _sel_client("Ethernet", **{"Virtual Port Number": 63}),
            "Relay_No_Port": _sel_client("Ethernet"),
            # Not a SEL server
            "DNP": {
                "Protocol": "DNPServer",
                "Connection Type": "Ethernet",
                "Settings": {"Server IP Port": 20000, "Serial Tunneling Mode": "SSL/TLS"},
            },
        }
    }
    discovery = rea.discover_from_export(info)
    listeners = {lst.name: lst for lst in discovery.listeners}
    assert set(listeners) == {"SSH_Server", "No_Port_Server", "Unknown_Server"}
    assert discovery.warnings == [
        "Unknown tunneling mode 7 of the SEL server 'Unknown_Server' (port 3002)"
    ]

    assert listeners["No_Port_Server"].gives_access is False
    assert listeners["No_Port_Server"].entries(RTAC_IP) == []
    assert listeners["Unknown_Server"].entries(RTAC_IP) == []

    ssh_entries = listeners["SSH_Server"].entries(RTAC_IP)
    assert [(e["device_name"], e["sel_port"]) for e in ssh_entries] == [
        ("Relay_Serial", 3),
        ("Relay_Serial_VPN", 5),
        ("Relay_Eth", 63),
        ("Relay_No_Port", None),
    ]
    for result in ssh_entries:
        assert result["needs_rtac_login"] is True
        assert result["termination_string"] == "QUIT\r"
        assert result["kind"] == "sel_server"
        assert result["transport"] == "ssh"


def test_export_sel_server_without_tunneling_mode(dev, log_text):
    """A SEL server without a tunneling mode (e.g. for an HMI) isn't engineering access."""
    info = {
        "Devices": {
            "HMI_SEL": {
                "Protocol": "SEL",
                "Connection Type": "Server - Ethernet",
                "Settings": {"Server IP Port": 702},
            },
            "Relay1": _sel_client(**{"Virtual Port Number": 1}),
        }
    }
    discovery = rea.discover_from_export(info)
    assert discovery.entries(RTAC_IP) == []
    assert discovery.warnings == []
    assert discovery.notes == [
        "The SEL server 'HMI_SEL' (port 702) doesn't have a tunneling mode, "
        "so it isn't used for engineering access"
    ]

    assert SELRTAC._process_engineering_access(dev, discovery) == []
    assert "WARNING" not in log_text()
    [service] = dev.service
    assert (service.port, service.role, service.protocol) == (702, "sel_server", "")
    assert "destinations" not in service.extra  # it doesn't reach the SEL devices


def test_export_sel_server_without_devices():
    """WHO lists the devices, so a server with no known devices still has an entry."""
    info = {
        "Devices": {
            "Server": {
                "Protocol": "SEL",
                "Connection Type": "Server - Ethernet",
                "Settings": {"Server IP Port": "3254", "Serial Tunneling Mode": "Raw TCP"},
            }
        }
    }
    assert rea.discover_from_export(info).entries(RTAC_IP) == [
        entry(
            name="Server",
            tcp_port=3254,
            transport="raw",
            kind="sel_server",
            route="interleaved",
            termination_string="\x04",
        )
    ]


@pytest.mark.usefixtures("isolated")
def test_export_eng_access_names():
    dev = make_dev()
    info = {
        "Devices": {
            "Eng_Access_40": {"Protocol": "SomethingInternal", "Settings": {}},
            "Relay1": _sel_client(),
        }
    }
    SELRTAC._process_export(dev, info)
    assert dev.extra["engineering_access_devices"] == ["Eng_Access_40"]
    assert "Eng_Access_40" not in dev.related.hosts
    assert "Relay1" in dev.related.hosts


def test_export_bad_input():
    assert rea.discover_from_export({}).listeners == []
    assert rea.discover_from_export({"Devices": "bad", "AccessPointRouters": []}).listeners == []
    assert rea.discover_from_export({"Devices": {"X": "bad"}}).listeners == []


def test_parse_accesspointrouters_multiple_destinations():
    info = {}
    rtac_parse.parse_accesspointrouters(
        rtac_parse.ET.fromstring(
            "<RTACModule><AccessPointRouter><Name>APR1</Name>"
            "<Source><DeviceName>EA</DeviceName></Source>"
            "<Destinations>"
            "<Destination><DeviceName>R1</DeviceName><type>TAP</type></Destination>"
            "<Destination><DeviceName>R2</DeviceName><type>TAP</type></Destination>"
            "</Destinations></AccessPointRouter></RTACModule>"
        ),
        info,
    )
    router = info["AccessPointRouters"]["APR1"]
    # The first destination is also "Destination", like a router with one destination
    assert router["Destination"] == {"device_name": "R1", "device_protocol": "", "type": "TAP"}
    assert [d["device_name"] for d in router["Destinations"]] == ["R1", "R2"]
    assert router["Settings"] == {}


# ---------- Database ----------


def pg_tables() -> dict[str, list[dict]]:
    """
    Synthetic RTAC database tables, with the setting names as snake case
    column names. The real column names are not public.
    """
    return {
        "access_points": [
            {"access_point_id": 1, "name": "EA_Transparent"},
            {"access_point_id": 2, "name": "Feeder_1_SEL_TAP"},
            {"access_point_id": 3, "name": "Feeder_1_SEL_AP"},
            {"access_point_id": 4, "name": "EA_Direct"},
            {"access_point_id": 5, "name": "Serial_AP"},  # no port
        ],
        # The first column is the same for both rows (they'd overwrite each
        # other in pulled-postgres-config.json, but not in the list of rows)
        "access_point_ethernet_settings": [
            {"project_id": 1, "access_point_id": 1, "Network_Connection_Type": "SSH",
             "LOCAL_PORT_NUMBER": 8001},
            {"project_id": 1, "access_point_id": 4, "network_connection_type": "Telnet",
             "local_port_number": "9001"},
        ],
        "access_point_routers": [
            {"access_point_router_id": 1, "name": "EA_Transparent_APR",
             "source_access_point_id": 1, "destination_access_point_id": 2,
             "enable_legacy_port_command": False},
            {"access_point_router_id": 2, "name": "EA_Direct_APR",
             "source_access_point_id": 4, "destination_access_point_id": [3]},
        ],
        "connections": [
            {"connection_id": 10, "name": "Feeder_1", "remote_device_id": 5},
            {"connection_id": 20, "name": "Remote_Access_Server", "remote_device_id": 6},
        ],
        "remote_devices": [
            {"remote_device_id": 5, "project_id": 1, "name": "Feeder_1", "model": "351S"},
            {"remote_device_id": 6, "project_id": 1, "name": "Remote_Access_Server"},
            {"remote_device_id": 40, "project_id": 1, "name": "Eng_Access_40"},
        ],
        "sel_server_ethernet_settings": [
            {"connection_id": 20, "server_ip_port": 3254, "serial_tunneling_mode": "Telnet"},
        ],
        "sel_server_common_settings": [
            {"connection_id": 20, "perform_authentication": True,
             "termination_string": "<CTRL-D>", "enable_port_command": True,
             "virtual_port_number": 254},
        ],
        "sel_client_common_settings": [{"connection_id": 10, "virtual_port_number": 1}],
    }  # fmt: skip


PG_ENTRIES = [
    entry(
        name="Remote_Access_Server",
        tcp_port=3254,
        transport="telnet",
        kind="sel_server",
        sel_port=1,
        device_name="Feeder_1",
        route="interleaved",
        needs_rtac_login=True,
        termination_string="\x04",
        source="postgres",
    ),
    entry(
        name="Feeder_1_SEL_TAP",
        tcp_port=8001,
        transport="ssh",
        device_name="Feeder_1",
        route="interleaved",
        needs_rtac_login=True,
        source="postgres",
    ),
    entry(
        name="Feeder_1_SEL_AP",
        tcp_port=9001,
        transport="telnet",
        device_name="Feeder_1",
        route="direct",
        source="postgres",
    ),
]


def test_discover_from_postgres():
    discovery = rea.discover_from_postgres(pg_tables())
    assert discovery.warnings == []
    assert discovery.entries(RTAC_IP) == PG_ENTRIES
    assert discovery.engineering_access_devices == ["Eng_Access_40"]

    listeners = {lst.name: lst for lst in discovery.listeners}
    assert set(listeners) == {"EA_Transparent", "EA_Direct", "Remote_Access_Server"}
    destination = listeners["EA_Transparent"].destinations[0]
    assert destination.router == "EA_Transparent_APR"
    assert destination.extra == {"legacy_port_command": False}
    assert listeners["Remote_Access_Server"].settings["virtual_port_number"] == 254


def test_discover_from_postgres_json_format():
    """The format of pulled-postgres-config.json: rows keyed by their first column."""
    tables = {
        name: {str(index): row for index, row in enumerate(rows)}
        for name, rows in pg_tables().items()
    }
    assert rea.discover_from_postgres(tables).entries(RTAC_IP) == PG_ENTRIES


def test_discover_from_postgres_name_columns():
    """Routers with names instead of IDs, and types in their own columns."""
    tables = {
        "access_points_mview": [
            {"name": "EA", "network_connection_type": "Raw TCP", "local_port_number": 9002},
        ],
        "access_point_routers": [
            {"name": "APR", "source_name": "EA", "destination_name": "Relay2_SEL",
             "destination_type": "TAP", "source_protocol": "ignored"},
        ],
        "sel_client_ethernet_settings": [{"connection_id": 30, "virtual_port_number": 63}],
        "connections": [{"connection_id": 30, "name": "Relay2_SEL"}],
    }  # fmt: skip
    assert rea.discover_from_postgres(tables).entries(RTAC_IP) == [
        entry(
            name="Relay2_SEL",
            tcp_port=9002,
            transport="raw",
            device_name="Relay2_SEL",
            route="interleaved",
            source="postgres",
        )
    ]


def test_discover_from_postgres_serial_device():
    """A serial SEL device gets the serial port number for the PORT command."""
    tables = {
        "sel_server_ethernet_settings": [
            {"connection_id": 20, "name": "Server", "server_ip_port": 3254,
             "serial_tunneling_mode": "SSH"},
        ],
        "sel_client_common_settings": [
            {"connection_id": 10, "name": "Relay_Serial", "virtual_port_number": 9},
        ],
        "serial_port_connections": [{"connection_id": 10, "serial_port_id": 3}],
        "serial_ports": [{"serial_port_id": 3, "serial_port_number": 3, "baud_rate": 19200}],
    }  # fmt: skip
    entries = rea.discover_from_postgres(tables).entries(RTAC_IP)
    assert [(e["device_name"], e["sel_port"], e["needs_rtac_login"]) for e in entries] == [
        ("Relay_Serial", 3, True)
    ]


def test_discover_from_postgres_unknown_values():
    """IDs instead of names can't be interpreted, the warning has the column names."""
    tables = {
        "access_point_ethernet_settings": [
            {"access_point_id": 1, "network_connection_type_id": 2, "local_port_number": 8001},
        ],
        "access_points": [{"access_point_id": 1, "name": "EA"}],
        "sel_server_ethernet_settings": [
            {"connection_id": 20, "server_ip_port": 3254, "serial_tunneling_mode": 4},
        ],
        "connections": [{"connection_id": 20, "name": "Server"}],
    }  # fmt: skip
    discovery = rea.discover_from_postgres(tables)
    assert discovery.entries(RTAC_IP) == []
    assert len(discovery.warnings) == 2
    assert "access point 'EA' (port 8001)" in discovery.warnings[0]
    assert (
        "columns: accesspointid, localportnumber, name, networkconnectiontypeid"
        in (discovery.warnings[0])
    )
    assert (
        "Unknown tunneling mode 4 of the SEL server 'Server' (port 3254)"
        in (discovery.warnings[1])
    )


def test_discover_from_postgres_generic_id_columns():
    """Router columns like "source_id" are looked up in the access point IDs."""
    tables = {
        "access_points": [
            {"access_point_id": 7, "name": "EA", "network_connection_type": "Telnet",
             "local_port_number": 9001},
            {"access_point_id": 8, "name": "R1_SEL_TAP"},
        ],
        "access_point_routers": [
            {"name": "APR", "source_id": 7, "destination_id": 8, "dest_other_id": 99},
        ],
    }  # fmt: skip
    discovery = rea.discover_from_postgres(tables)
    assert discovery.warnings == []
    assert discovery.entries(RTAC_IP) == [
        entry(
            name="R1_SEL_TAP",
            tcp_port=9001,
            transport="telnet",
            device_name="R1_SEL",
            route="interleaved",
            source="postgres",
        )
    ]


@pytest.mark.parametrize(
    ("row", "other", "expected"),
    [
        ({"accesspointid": 1}, {"accesspointid": 1}, True),
        ({"accesspointid": 1}, {"accesspointid": "1"}, True),
        ({"accesspointid": 1}, {"accesspointid": 2}, False),
        # A column that may be the same in every row doesn't join rows...
        ({"deviceid": 1}, {"deviceid": 1}, False),
        ({"accesspointid": 1, "deviceid": 1}, {"accesspointid": 2, "deviceid": 1}, False),
        # ...but rows with different values in it are not joined
        ({"accesspointid": 1, "deviceid": 1}, {"accesspointid": 1, "deviceid": 2}, False),
        ({"accesspointid": 1, "deviceid": 1}, {"accesspointid": 1, "deviceid": 1}, True),
        # All of the join columns that both rows have must be the same
        ({"connectionid": 10, "serialportid": 3}, {"connectionid": 10, "serialportid": 4}, False),
        ({"connectionid": 10}, {"connectionid": 10, "serialportid": 4}, True),
        (
            {"connectionid": None, "accesspointid": 1},
            {"connectionid": 5, "accesspointid": 1},
            True,
        ),
        # Generic columns don't join rows
        ({"id": 1, "projectid": 1}, {"id": 1, "projectid": 1}, False),
        ({}, {}, False),
    ],
)
def test_postgres_row_joins(row, other, expected):
    assert rea._joins(row, other) is expected
    assert rea._joins(other, row) is expected


def test_discover_from_postgres_conflicting_ids():
    """Rows with the same value in a generic column, but different IDs, are not joined."""
    tables = {
        "access_points_mview": [
            {"access_point_id": 1, "device_id": 1, "name": "A"},
            {"access_point_id": 2, "device_id": 1, "name": "B"},
        ],
        "access_point_ethernet_settings": [
            {"access_point_id": 2, "device_id": 1, "network_connection_type": "Telnet",
             "local_port_number": 9001},
            {"access_point_id": 1, "device_id": 1, "network_connection_type": "SSH",
             "local_port_number": 8001},
            {"access_point_id": 3, "device_id": 1, "network_connection_type": "Raw TCP",
             "local_port_number": 9003},
        ],
        # A record doesn't get its name or port from a row that only has the
        # same generic column
        "connections": [{"connection_id": 10, "device_id": 1, "name": "Feeder_1"}],
        "access_points": [{"access_point_id": 3, "device_id": 1}],
        "local_tcp_network_ports": [{"device_id": 1, "port_number": 7000}],
    }  # fmt: skip
    discovery = rea.discover_from_postgres(tables)
    assert discovery.warnings == []
    assert sorted((lst.name, lst.port, lst.transport) for lst in discovery.listeners) == [
        ("A", 8001, "ssh"),
        ("B", 9001, "telnet"),
        ("access_point_2", 9003, "raw"),
    ]


def test_discover_from_postgres_only_sel_devices():
    """
    The serial port tables have rows for other devices and unused ports,
    which are not SEL devices of the SEL server.
    """
    tables = {
        "sel_server_ethernet_settings": [
            {"connection_id": 20, "name": "Server", "server_ip_port": 3254,
             "serial_tunneling_mode": "Telnet"},
        ],
        "sel_client_common_settings": [
            {"connection_id": 10, "virtual_port_number": 5},
        ],
        "sel_virtual_ports": [
            {"connection_id": 20, "virtual_port_number": 254},  # the SEL server
            {"connection_id": 10, "virtual_port_number": 5},
        ],
        "serial_port_connections": [
            {"serial_port_id": 3, "connection_id": 30},  # a DNP3 device
            {"serial_port_id": 1, "connection_id": 10},
        ],
        "serial_ports": [
            {"serial_port_id": 1, "name": "Com_01", "serial_port_number": 1},
            {"serial_port_id": 3, "name": "Com_03", "serial_port_number": 3},
            {"serial_port_id": 4, "name": "Com_04", "serial_port_number": 4},  # unused
        ],
        "connections": [
            {"connection_id": 10, "name": "Relay1"},
            {"connection_id": 30, "name": "DNP_Meter"},
        ],
    }  # fmt: skip
    entries = rea.discover_from_postgres(tables).entries(RTAC_IP)
    assert [(e["name"], e["device_name"], e["sel_port"]) for e in entries] == [
        ("Server", "Relay1", 1),  # on the serial port Com_01
    ]


def test_discover_from_postgres_local_tcp_ports():
    """
    The local TCP port tables add the port of access points and SEL servers
    that don't have one in their settings. Ports of other servers are not used.
    """
    tables = {
        "sel_server_ethernet_settings": [
            {"connection_id": 20, "name": "Server", "serial_tunneling_mode": "SSH"},
        ],
        "access_points": [
            {"access_point_id": 1, "name": "EA", "network_connection_type": "Raw TCP"},
            {"access_point_id": 2, "name": "EA_Settings", "network_connection_type": "Telnet",
             "local_port_number": 9002},
            {"access_point_id": 3, "name": "R1_SEL_TAP"},
        ],
        "access_point_routers": [
            {"name": "APR", "source_access_point_id": 1, "destination_access_point_id": 3},
        ],
        "local_tcp_network_port_connections": [
            {"local_tcp_network_port_id": 1, "connection_id": 20},
            {"local_tcp_network_port_id": 2, "connection_id": 40},  # a DNP3 server
            {"local_tcp_network_port_id": 3, "access_point_id": 1},
            {"local_tcp_network_port_id": 4, "access_point_id": 2},
        ],
        "local_tcp_network_ports": [
            {"local_tcp_network_port_id": 1, "port_number": 3254},
            {"local_tcp_network_port_id": 2, "port_number": 20000},
            {"local_tcp_network_port_id": 3, "port_number": 9001},
            {"local_tcp_network_port_id": 4, "port_number": 1234},
        ],
    }  # fmt: skip
    discovery = rea.discover_from_postgres(tables)
    assert discovery.warnings == []
    assert sorted((lst.name, lst.port, lst.transport) for lst in discovery.listeners) == [
        ("EA", 9001, "raw"),
        ("EA_Settings", 9002, "telnet"),  # the port in the settings is used
        ("Server", 3254, "ssh"),
    ]
    assert [(e["tcp_port"], e["device_name"]) for e in discovery.entries(RTAC_IP)] == [
        (3254, None),
        (9001, "R1_SEL"),  # R1 isn't a SEL device in the database
    ]


def test_discover_from_postgres_mode_columns():
    """
    A connection type or tunneling mode in a column with another name (e.g. an
    ID) is used, and the warning has its value. SEL servers without a
    tunneling mode only get a note.
    """
    tables = {
        "sel_server_ethernet_settings": [
            {"connection_id": 20, "name": "Server", "server_ip_port": 3254,
             "serial_tunneling_mode_id": 2},
            {"connection_id": 21, "name": "SCADA_Server", "server_ip_port": 3255},
        ],
        "access_points": [
            {"access_point_id": 1, "name": "EA", "network_connection_type_name": "SSH",
             "local_port_number": 8001},
        ],
    }  # fmt: skip
    discovery = rea.discover_from_postgres(tables)
    listeners = {lst.name: lst for lst in discovery.listeners}
    assert listeners["EA"].transport == "ssh"
    assert discovery.warnings == [
        "Unknown tunneling mode 2 of the SEL server 'Server' (port 3254) in the RTAC "
        "database (columns: connectionid, name, serialtunnelingmodeid, serveripport)"
    ]
    assert len(discovery.notes) == 1
    assert "'SCADA_Server' (port 3255) doesn't have a tunneling mode" in discovery.notes[0]


def test_discover_from_postgres_no_tables():
    discovery = rea.discover_from_postgres({})
    assert discovery.listeners == []
    assert discovery.entries(RTAC_IP) == []
    assert rea.discover_from_postgres({"access_points": "bad"}).listeners == []


class FakeCursor:
    """psycopg2 cursor that returns rows of some tables, and nothing for the others."""

    def __init__(self, tables: dict[str, list[dict]]):
        self.tables = tables
        self.description = None
        self._rows = []

    def execute(self, statement, _args=()):
        table = statement.removeprefix("SELECT * from ").rstrip(";")
        rows = self.tables.get(table)
        if not rows:
            self.description = None
            self._rows = []
            return
        columns = list(dict.fromkeys(col for row in rows for col in row))
        self.description = [(col,) for col in columns]
        self._rows = [tuple(row.get(col) for col in columns) for row in rows]

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class FakeConnection:
    def commit(self):
        pass

    def close(self):
        pass


def test_pull_postgres_engineering_access(dev, log_text):
    tables = pg_tables()
    dev._cache["pg_conn"] = FakeConnection()
    dev._cache["pg_cursor"] = FakeCursor(tables)

    pulled = SELRTAC.pull_postgres(dev)

    # Only one of the rows with the same first column is in the pulled data...
    assert len(pulled["access_point_ethernet_settings"]) == 1
    # ...but the discovery uses all of them
    assert dev.extra["engineering_access"] == PG_ENTRIES
    assert dev.extra["engineering_access_devices"] == ["Eng_Access_40"]
    assert SELRTAC.downstream_targets(dev) == PG_ENTRIES

    assert set(services_by_port(dev)) == {3254, 8001, 9001}
    assert {"Feeder_1", "Remote_Access_Server"} <= dev.related.hosts
    assert "Eng_Access_40" not in dev.related.hosts
    assert (dev.get_out_dir() / "pulled-postgres-config.json").is_file()
    assert "WARNING" not in log_text()


def test_pull_postgres_engineering_access_error(dev, mocker, log_text):
    """An error in the discovery doesn't stop the pull."""
    mocker.patch.object(sel_rtac, "discover_from_postgres", side_effect=KeyError("bad"))
    dev._cache["pg_conn"] = FakeConnection()
    dev._cache["pg_cursor"] = FakeCursor(pg_tables())

    pulled = SELRTAC.pull_postgres(dev)

    assert pulled["remote_devices"]
    assert "engineering_access" not in dev.extra
    assert (dev.get_out_dir() / "pulled-postgres-config.json").is_file()
    assert "Failed to process the engineering access settings of 192.0.2.10" in log_text()


def test_remote_device_without_name(dev):
    tables = {"remote_devices": [{"remote_device_id": 1, "name": None}, {"remote_device_id": 2}]}
    dev._cache["pg_conn"] = FakeConnection()
    dev._cache["pg_cursor"] = FakeCursor(tables)
    SELRTAC.pull_postgres(dev)  # doesn't raise
    assert not dev.related.hosts


def test_process_engineering_access_warnings(dev, log_text):
    info = {
        "Devices": {
            "EA": _ap(9002, "Carrier Pigeon"),
            "Serial_AP": {"Protocol": "AccessPointServer", "Settings": {}},
        }
    }
    assert SELRTAC._process_engineering_access(dev, rea.discover_from_export(info)) == []

    assert "Unknown connection type 'Carrier Pigeon' of the access point 'EA'" in log_text()
    assert "engineering_access" not in dev.extra
    # The access point without a port has no service
    assert len(dev.service) == 1
    service = dev.service[0]
    assert (service.port, service.protocol, service.transport) == (9002, "", "")
    assert service.role == "access_point"
    assert service.extra["connection_type"] == "Carrier Pigeon"
    assert "tunnel_transport" not in service.extra


@pytest.mark.usefixtures("isolated")
def test_export_and_postgres_are_merged(rtac_path):
    dev = SELRTAC.parse(rtac_path("synthetic-engineering-access"))
    service_count = len(dev.service)

    SELRTAC._process_engineering_access(dev, rea.discover_from_postgres(pg_tables()))

    entries = dev.extra["engineering_access"]
    # Both sources are kept, without duplicates
    assert all(e in entries for e in SYNTHETIC_ENTRIES + PG_ENTRIES)
    assert len(entries) == len(SYNTHETIC_ENTRIES) + len(PG_ENTRIES)
    assert entries == rea.merge_entries([], entries)  # sorted
    # The ports are the same, so the services are merged
    assert len(dev.service) == service_count

    # Processing the same data again doesn't add anything
    SELRTAC._process_engineering_access(dev, rea.discover_from_postgres(pg_tables()))
    assert dev.extra["engineering_access"] == entries
    assert len(dev.service) == service_count

    # The paths to Feeder_1 on 8001 and 9001 are in both sources (with different
    # names), and are only once in the targets. The SEL server paths have
    # different transports (TLS in the export, Telnet in the database).
    targets = SELRTAC.downstream_targets(dev)
    assert len(targets) == len(entries) - 2
    assert [(t["tcp_port"], t["source"]) for t in targets if t["tcp_port"] in (8001, 9001)] == [
        (8001, "export"),
        (9001, "export"),
    ]


def test_downstream_targets(dev):
    assert SELRTAC.downstream_targets(dev) == []
    dev.extra["engineering_access"] = "bad"
    assert SELRTAC.downstream_targets(dev) == []

    complete = entry(name="R1", tcp_port=9001, transport="telnet")
    dev.extra["engineering_access"] = [complete, entry(rtac_ip=None, tcp_port=9001), "bad"]
    targets = SELRTAC.downstream_targets(dev)
    assert targets == [complete]
    # Changing the results doesn't change the device data
    targets[0]["tcp_port"] = 1
    assert dev.extra["engineering_access"][0]["tcp_port"] == 9001
    # Duck-typed hook for gateway pulls
    assert getattr(SELRTAC, "downstream_targets", None) is not None


def test_downstream_targets_one_per_path(dev):
    export = entry(
        name="R1_SEL_TAP", tcp_port=9001, transport="telnet", device_name="R1", route="interleaved"
    )
    postgres = dict(export, name="R1", needs_rtac_login=True, source="postgres")
    other_route = dict(export, route="direct")
    dev.extra["engineering_access"] = [export, postgres, other_route]

    targets = SELRTAC.downstream_targets(dev)

    # The first entry of the path, with the RTAC login if any of its entries need it
    assert targets == [dict(export, needs_rtac_login=True), other_route]
    assert dev.extra["engineering_access"][0]["needs_rtac_login"] is False  # unchanged


def test_unique_paths_fills_in_values():
    first = entry(tcp_port=3254, transport="ssh", kind="sel_server", sel_port=1)
    second = dict(first, name="Server", termination_string="\x04", source="postgres")
    assert rea.unique_paths([first, second]) == [
        dict(first, name="Server", termination_string="\x04")
    ]
    assert rea.unique_paths([]) == []


# ---------- Probing the TLS and SSH ports ----------


@pytest.fixture
def local_server():
    """
    Run a local TCP server in a thread. Each accepted connection is passed
    to the handler. Returns the port, and a dict with the number of connections.
    """
    servers = []

    def _start(handler):
        lsock = socket.create_server(("127.0.0.1", 0))
        lsock.settimeout(0.1)
        stop = threading.Event()
        stats = {"connections": 0}

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
                    handler(conn, stop)
                except (OSError, EOFError, ssl.SSLError, paramiko.SSHException):
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


@pytest.fixture
def tls_cert(tmp_path):
    """A self-signed certificate like the factory-default one of a SEL-3530-4."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "SEL-3530-4 RTAC"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "Automation and Integration Engineering"
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "Schweitzer Engineering Laboratories, Inc."
            ),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, cert_path, key_path


def tls_handler(cert_path, key_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    def _handle(conn, _stop):
        with context.wrap_socket(conn, server_side=True) as tls:
            # The client must not send anything (it doesn't open the tunnel)
            tls.settimeout(1.0)
            try:
                assert tls.recv(1) == b""
            except TimeoutError:
                pass

    return _handle


class _NoLoginServer(paramiko.ServerInterface):
    def get_allowed_auths(self, _username):
        return "password"


def ssh_handler(host_key):
    def _handle(conn, stop):
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        try:
            transport.start_server(server=_NoLoginServer())
            deadline = time.monotonic() + 5.0
            while transport.is_active() and not stop.is_set() and time.monotonic() < deadline:
                time.sleep(0.02)
        finally:
            transport.close()

    return _handle


@pytest.mark.usefixtures("isolated")
def test_probe_tls_port(local_server, tls_cert):
    cert, cert_path, key_path = tls_cert
    port, stats = local_server(tls_handler(cert_path, key_path))
    der = cert.public_bytes(serialization.Encoding.DER)
    der_sha256 = hashlib.sha256(der).hexdigest().upper()

    dev = make_dev("127.0.0.1")
    dev.extra["engineering_access"] = [
        entry(rtac_ip="127.0.0.1", tcp_port=port, transport="tls", kind="sel_server",
              sel_port=1, route="interleaved"),
        entry(rtac_ip="127.0.0.1", tcp_port=port, transport="tls", kind="sel_server",
              sel_port=2, route="interleaved"),
    ]  # fmt: skip
    dev.extra["ssl_certificate"] = {"fingerprints": {"sha256": der_sha256}}

    results = SELRTAC.probe_tunnel_ports(dev)

    key = f"tcp/{port}"
    assert set(results) == {key}
    assert dev.extra["engineering_access_probes"] == results
    assert stats["connections"] == 1  # one connection for both entries of the port

    result = results[key]
    assert result["transport"] == "tls"
    assert result["tls_version"].startswith("TLSv1.")
    assert result["legacy_tls"] is False
    assert result["fingerprints"]["sha256"] == der_sha256
    assert result["default_sel_certificate"] is True
    assert result["self_signed"] is True
    assert result["same_as_web_certificate"] is True
    assert result["expired"] is False
    assert "CN=SEL-3530-4 RTAC" in result["subject"]
    assert der_sha256 in dev.related.hash

    pem_name = f"engineering-access-tcp-{port}-certificate.pem"
    pem_path = dev.get_out_dir() / pem_name
    assert pem_path.read_text() == cert.public_bytes(serialization.Encoding.PEM).decode()
    recorded = next(f for f in dev.files if f.name == pem_name)
    assert recorded.extra == {"source": "tls_certificate", "transport": "tls"}

    service = services_by_port(dev)[port]
    assert (service.protocol, service.transport, service.status) == ("tls", "tcp", "verified")
    assert service.extra["certificate_sha256"] == der_sha256


@pytest.mark.usefixtures("isolated")
def test_probe_ssh_port(local_server):
    host_key = paramiko.ECDSAKey.generate()
    port, stats = local_server(ssh_handler(host_key))

    dev = make_dev("127.0.0.1")
    dev.extra["engineering_access"] = [
        entry(rtac_ip="127.0.0.1", tcp_port=port, transport="ssh", route="interleaved"),
    ]
    # The service from the configuration is updated
    SELRTAC._store_engineering_access_service(
        dev,
        rea.Listener(kind="access_point", name="EA", port=port, transport="ssh"),
    )

    results = SELRTAC.probe_tunnel_ports(dev)

    blob_sha256 = hashlib.sha256(host_key.asbytes()).hexdigest().upper()
    result = results[f"tcp/{port}"]
    assert result["transport"] == "ssh"
    assert result["key_type"] == "ecdsa-sha2-nistp256"
    assert result["sha256"] == blob_sha256
    assert result["fingerprint"].startswith("SHA256:")
    assert result["banner"].startswith("SSH-2.0-")
    assert stats["connections"] == 1

    assert len(dev.ssh_keys) == 1
    ssh_key = dev.ssh_keys[0]
    assert ssh_key.type == "public"
    assert ssh_key.host == "127.0.0.1"
    assert ssh_key.original == f"ecdsa-sha2-nistp256 {host_key.get_base64()}"
    assert ssh_key.id == result["fingerprint"]
    assert blob_sha256 in dev.related.hash

    assert len(dev.service) == 1
    service = dev.service[0]
    assert service.status == "verified"
    assert service.role == "access_point"  # kept from the configuration
    assert service.extra["host_key_fingerprint"] == result["fingerprint"]
    assert service.extra["name"] == "EA"


def test_probe_only_safe_tls_and_ssh_ports(dev, mocker):
    fetch_cert = mocker.patch.object(sel_rtac, "fetch_peer_certificate", return_value=None)
    fetch_key = mocker.patch.object(sel_rtac, "fetch_ssh_host_key", return_value=None)
    dev.extra["engineering_access"] = [
        # A port with a direct route is never probed
        entry(tcp_port=9001, transport="tls", route="direct"),
        entry(tcp_port=9001, transport="tls", route="interleaved"),
        entry(tcp_port=9002, transport="ssh", route="direct"),
        # Neither is a port with a route that isn't known (it may be direct)
        entry(tcp_port=9006, transport="ssh", route=None),
        entry(tcp_port=9007, transport="ssh", route="interleaved"),
        entry(tcp_port=9007, transport="ssh", route=None, device_name="R2"),
        # Or a port with different transports (e.g. in an export and the database)
        entry(tcp_port=9008, transport="tls", route="interleaved"),
        entry(tcp_port=9008, transport="telnet", route="interleaved", source="postgres"),
        # Telnet and raw TCP ports have nothing to collect
        entry(tcp_port=9003, transport="telnet", route="interleaved"),
        entry(tcp_port=9004, transport="raw", route="interleaved"),
        # Another RTAC
        entry(rtac_ip="192.0.2.99", tcp_port=9005, transport="tls", route="interleaved"),
        # Only SEL servers and interleaved routes are probed
        entry(tcp_port=3254, transport="tls", kind="sel_server", route="interleaved"),
        entry(tcp_port=3255, transport="tls", kind="sel_server", route=None),
        entry(tcp_port=8001, transport="ssh", route="interleaved"),
    ]

    assert SELRTAC.probe_tunnel_ports(dev) == {}  # the fetches failed

    timeout = dev.options["https"]["timeout"]
    assert fetch_cert.call_args_list == [
        mocker.call(RTAC_IP, 3254, timeout),
        mocker.call(RTAC_IP, 3255, timeout),
    ]
    fetch_key.assert_called_once_with(RTAC_IP, 8001, dev.options["ssh"]["timeout"])
    assert "engineering_access_probes" not in dev.extra


def test_probe_skips_routes_to_device_access_points(dev, mocker):
    """
    A route to the "_AP" access point of a device is a direct route, also
    if the export has the access points of the devices as devices.
    """
    fetch_key = mocker.patch.object(sel_rtac, "fetch_ssh_host_key", return_value=None)
    device_ap = {"Protocol": "AccessPointServer", "Connection Type": "Ethernet", "Settings": {}}
    info = {
        "Devices": {
            "EA": _ap(8001, "SSH"),
            "Feeder_1": _sel_client(),
            "Feeder_1_SEL_AP": device_ap,
        },
        "AccessPointRouters": {"APR": _router("EA", "Feeder_1_SEL_AP")},
    }
    SELRTAC._process_engineering_access(dev, rea.discover_from_export(info))
    assert dev.extra["engineering_access"][0]["route"] == "direct"

    assert SELRTAC.probe_tunnel_ports(dev) == {}
    fetch_key.assert_not_called()


def test_probe_without_entries(dev, mocker):
    fetch_cert = mocker.patch.object(sel_rtac, "fetch_peer_certificate")
    assert SELRTAC.probe_tunnel_ports(dev) == {}
    fetch_cert.assert_not_called()


def test_probe_invalid_certificate(dev, mocker, log_text):
    mocker.patch.object(
        sel_rtac, "fetch_peer_certificate", return_value=PeerCertificate(der=b"not a cert")
    )
    dev.extra["engineering_access"] = [entry(tcp_port=3254, transport="tls", route="interleaved")]
    assert SELRTAC.probe_tunnel_ports(dev) == {}
    assert "Failed to parse the TLS certificate from 192.0.2.10:3254" in log_text()


def test_probe_results_are_kept(dev, mocker):
    host_key = SSHHostKey(
        key_type="ssh-ed25519",
        bits=256,
        public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA",
        md5="11" * 16,
        sha256="22" * 32,
    )
    mocker.patch.object(sel_rtac, "fetch_ssh_host_key", return_value=host_key)
    dev.extra["engineering_access"] = [entry(tcp_port=8001, transport="ssh", route="interleaved")]
    dev.extra["engineering_access_probes"] = {"tcp/22": {"transport": "ssh"}}

    results = SELRTAC.probe_tunnel_ports(dev)

    assert set(results) == {"tcp/8001"}
    assert set(dev.extra["engineering_access_probes"]) == {"tcp/22", "tcp/8001"}
    assert results["tcp/8001"]["banner"] == ""
    assert "ssh_banner" not in dev.service[0].extra


@pytest.mark.parametrize("enabled", [False, True])
def test_pull_config_probe_option(dev, mocker, enabled):
    mocker.patch.object(SELRTAC, "pull_ssl_certificate")
    mocker.patch.object(SELRTAC, "pull_web")
    mocker.patch.object(SELRTAC, "pull_postgres")
    probe = mocker.patch.object(SELRTAC, "probe_tunnel_ports")
    dev.options["sel"]["rtac_probe_tunnel_ports"] = enabled

    SELRTAC.pull_config(dev)

    assert probe.called is enabled


def test_pull_config_probe_error(dev, mocker, log_text):
    mocker.patch.object(SELRTAC, "pull_ssl_certificate")
    mocker.patch.object(SELRTAC, "pull_web")
    mocker.patch.object(SELRTAC, "pull_postgres")
    mocker.patch.object(SELRTAC, "probe_tunnel_ports", side_effect=OSError("boom"))
    mocker.patch.dict(sel_rtac.state["CONFIG"], {"error": False})
    dev.options["sel"]["rtac_probe_tunnel_ports"] = True

    SELRTAC.pull_config(dev)  # doesn't raise

    assert "failed to probe the engineering access ports of 192.0.2.10" in log_text()
    assert sel_rtac.state.error is True


def test_probe_option_default_off():
    assert DeviceData().options["sel"]["rtac_probe_tunnel_ports"] is False
