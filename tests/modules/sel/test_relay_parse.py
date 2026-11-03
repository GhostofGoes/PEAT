"""
Unit tests for the pure parsing functions of the SEL relay module
(peat/modules/sel/relay_parse.py), with synthetic inputs derived from
the formats documented in the code comments.
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from peat import DeviceData, datastore
from peat.modules.sel.relay_parse import (
    ansi_meaning,
    apply_device_time,
    apply_eth_output,
    apply_mac_output,
    device_file_path,
    front_panel_indicators,
    history_event_details,
    normalize_serial_protocol,
    normalize_time_source,
    parse_and_process_events,
    parse_eth_output,
    parse_self_tests,
    parse_status_output,
    process_cid_file,
    process_info_classes,
    process_info_into_dev,
    process_port_settings,
    sel_file_categories,
    sel_led_colors,
    split_lines,
)

T0 = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)

# ETH output (format of the sel_http.get_communications() code comments,
# "$" = overflowed counter)
ETH_FAILOVER = """\
SEL-451                         Date: 03/15/2021  Time: 14:22:01.123
STATION A                       Serial Number: 1234567890

MAC: 00-30-A7-00-00-01
IP ADDRESS: 192.0.2.10/24
DEFAULT GATEWAY: 192.0.2.1

NETMODE: FAILOVER
PRIMARY PORT: PORT 5A
ACTIVE PORT: PORT 5B

          LINK    SPEED   DUPLEX  MEDIA
PORT 5A   UP      100M    FULL    TX
PORT 5B   DOWN    ---     ---     FX

     PACKETS                 BYTES               ERRORS
   SENT     RCVD         SENT       RCVD      SENT    RCVD
$$$$$$$  $$$$$$$   1463657022 1664082074         0       0
"""

ETH_PRP = """\
MAC 1: 00-30-A7-00-00-01
MAC 2: 00-30-A7-00-00-02
IP ADDRESS: 192.0.2.20/16
DEFAULT GATEWAY: 0.0.0.0
NETMODE: PRP

PORT 1A   UP      1G      FULL    FX
PORT 1B   UP      1G      FULL    FX

     PACKETS                 BYTES               ERRORS
   SENT     RCVD         SENT       RCVD      SENT    RCVD
   1200     3400          56000      78000         1       2
"""

# STA output (identity lines from the parse_status_output() comments, self-tests
# in the documented "column names / values" layout)
STA_ENABLED = """\
SEL-351S                                 Date: 03/15/2021  Time: 14:22:01.123
FEEDER 1                                 Time Source: IRIG-B
FID=SEL-351S-7-R516-V2-Z106105-D20190111   CID=F029
SELF TESTS (W=Warn, F=Fail)
         IA     IB     IC     IN
OS       2      2      1      1
         +5V_PS  +5V_REG  -5V_REG
PS       5.05    5.07     -5.03
         TEMP   RAM   ROM   A/D   CR_RAM
         24.0   OK    OK    OK    OK
Relay Enabled
"""

STA_DISABLED_FAILED = """\
SEL-351S                                 Date: 03/15/2021  Time: 14:22:01.123
FEEDER 1                                 Time Source: Internal
FID=SEL-351S-7-R516-V2-Z106105-D20190111   CID=F029
SELF TESTS (W=Warn, F=Fail)
         TEMP   RAM   ROM    A/D   CR_RAM
         24.0   OK    FAIL   W     OK
Relay Disabled
"""

# HISTORY.TXT (header from the parse_history() comments)
HISTORY = """\
SEL-351-5                                Date: 01/15/2021  Time: 17:10:00.000
FEEDER 1

#  REF  DATE      TIME          EVENT   CURR  FREQ   TARGETS
1  10001 01/15/21  17:09:45.504  Trip    1.00  60.00  11000000
2  10002 01/14/21  10:00:00.000  ER      0.50  60.00  00000000
"""

# SER.TXT (rows from the parse_ser() comments)
SER = """\
SEL-351-5                                Date: 01/15/2021  Time: 17:10:00.000
FEEDER 1

#    DATE        TIME             ELEMENT                      STATE
1024 12/09/2020  18:08:43.048    SALARM                       Deasserted
1025 12/09/2020  18:09:00.000    51G                          Asserted
213  01/15/2021  17:09:45.504    Relay Powered Up
214  01/16/2021  10:00:00.000    Settings changed             Class P 5
215  01/16/2021  10:01:00.000    Group change                 Group 2
"""


@pytest.fixture(autouse=True)
def _clean_datastore(mocker):
    mocker.patch.object(datastore, "objects", [])


def _dev(**kwargs) -> DeviceData:
    return DeviceData(**kwargs)


def _iface(dev: DeviceData, name: str):
    return next(i for i in dev.interface if i.name == name)


# ----------------------------------------------------------------------------- #
# ETH
# ----------------------------------------------------------------------------- #
def test_parse_eth_output_failover():
    eth = parse_eth_output(ETH_FAILOVER)
    assert eth["macs"] == ["00:30:A7:00:00:01"]
    assert eth["ip"] == "192.0.2.10"
    assert eth["subnet_mask"] == "255.255.255.0"
    assert eth["gateway"] == "192.0.2.1"
    assert eth["network_mode"] == "FAILOVER"
    assert eth["primary_port"] == "5A"
    assert eth["active_port"] == "5B"
    assert eth["ports"] == {
        "5A": {"link": "up", "speed": 100, "duplex": "full", "media": "TX"},
        "5B": {"link": "down", "speed": None, "duplex": "", "media": "FX"},
    }
    stats = eth["statistics"]
    assert stats["packets_sent"] is None
    assert stats["packets_received"] is None
    assert stats["bytes_sent"] == 1463657022
    assert stats["bytes_received"] == 1664082074
    assert stats["errors_sent"] == 0
    assert stats["errors_received"] == 0
    assert stats["overflowed"] == ["packets_sent", "packets_received"]


def test_parse_eth_output_prp_and_empty():
    eth = parse_eth_output(ETH_PRP)
    assert eth["macs"] == ["00:30:A7:00:00:01", "00:30:A7:00:00:02"]
    assert eth["subnet_mask"] == "255.255.0.0"
    assert eth["ports"]["1A"]["speed"] == 1000
    assert eth["statistics"]["overflowed"] == []
    assert parse_eth_output("") == {}
    assert parse_eth_output("garbage\nIP ADDRESS: not-an-ip") == {}


def test_apply_eth_output_failover():
    dev = _dev(ip="192.0.2.10")
    apply_eth_output(parse_eth_output(ETH_FAILOVER), dev, timestamp=T0)

    ip_iface = _iface(dev, "Port 5")  # derived from port names 5A/5B
    assert ip_iface.ip == "192.0.2.10"
    assert ip_iface.subnet_mask == "255.255.255.0"
    assert ip_iface.gateway == "192.0.2.1"
    assert ip_iface.mac == "00:30:A7:00:00:01"
    assert ip_iface.statistics.timestamp == T0
    assert ip_iface.statistics.ingress.bytes == 1664082074
    assert ip_iface.statistics.egress.bytes == 1463657022
    assert ip_iface.statistics.ingress.packets is None
    assert ip_iface.statistics.ingress.errors == 0
    assert ip_iface.statistics.extra["overflowed"] == ["egress.packets", "ingress.packets"]
    assert ip_iface.redundancy.protocol == "failover"
    assert ip_iface.redundancy.mode == "failover"
    assert ip_iface.redundancy.members == ["5A", "5B"]
    assert ip_iface.redundancy.extra["primary_port"] == "5A"
    assert not ip_iface.parent

    port_a, port_b = _iface(dev, "5A"), _iface(dev, "5B")
    assert port_a.physical
    assert port_a.connected is True
    assert port_a.speed == 100
    assert port_a.duplex == "full"
    assert port_a.description.description == "TX"
    assert port_b.connected is False
    assert port_b.speed is None
    assert port_a.redundancy.state == "standby"
    assert port_b.redundancy.state == "active"
    assert not port_a.parent
    assert not port_b.parent
    assert "00:30:A7:00:00:01" in dev.related.mac
    assert "communications" not in dev.extra


def test_apply_eth_output_prp_uses_existing_interface():
    dev = _dev()
    process_port_settings("1", {"EPORT": "Y", "IPADDR": "192.0.2.20/16"}, dev)
    apply_eth_output(parse_eth_output(ETH_PRP), dev, timestamp=T0)

    ip_iface = _iface(dev, "Port 1")
    assert ip_iface.mac == "00:30:A7:00:00:01"
    assert ip_iface.extra["mac_addresses"] == ["00:30:A7:00:00:01", "00:30:A7:00:00:02"]
    assert not ip_iface.gateway  # 0.0.0.0 is not a gateway
    assert ip_iface.redundancy.protocol == "prp"
    assert ip_iface.statistics.ingress.packets == 3400
    assert ip_iface.statistics.egress.errors == 1
    assert "overflowed" not in ip_iface.statistics.extra
    for port in ("1A", "1B"):
        red = _iface(dev, port).redundancy
        assert red.protocol == "prp"
        assert red.state == "active"
        assert red.lan == ""
    assert len([i for i in dev.interface if i.name == "Port 1"]) == 1


def test_apply_eth_output_switched_has_no_port_state():
    text = ETH_FAILOVER.replace("NETMODE: FAILOVER", "NETMODE: SWITCHED")
    dev = _dev()
    apply_eth_output(parse_eth_output(text), dev, timestamp=T0)
    assert _iface(dev, "Port 5").redundancy.mode == "switched"
    assert _iface(dev, "Port 5").redundancy.protocol == ""
    assert _iface(dev, "5A").redundancy.state == ""


def test_baseline_ignores_active_port_and_time_source_switches():
    """A failover port switch and a lost IRIG-B signal are live state, not drift (R3-15)."""
    from peat.data.baseline import compare_device
    from peat.data.models import Baseline

    def pull(sta: str = STA_ENABLED, eth: str = ETH_FAILOVER) -> DeviceData:
        dev = _dev(ip="192.0.2.10", id="192.0.2.10")
        process_info_into_dev(parse_status_output(sta.splitlines()), dev, observed=T0)
        apply_eth_output(parse_eth_output(eth), dev, timestamp=T0)
        return dev

    baseline = Baseline(id="relay", kind="first_observed", expected=pull())
    assert compare_device(pull(), baseline) == []
    lost = pull(sta=STA_ENABLED.replace("Time Source: IRIG-B", "Time Source: Internal"))
    assert lost.clock.source == "internal"
    assert compare_device(lost, baseline) == []
    switched = pull(eth=ETH_FAILOVER.replace("ACTIVE PORT: PORT 5B", "ACTIVE PORT: PORT 5A"))
    assert _iface(switched, "5A").redundancy.state == "active"
    assert compare_device(switched, baseline) == []
    # the network mode (configuration) is still compared
    prp = pull(eth=ETH_FAILOVER.replace("NETMODE: FAILOVER", "NETMODE: PRP"))
    diffs = {(f.difference, f.path) for f in compare_device(prp, baseline)}
    assert ("change", "interface[name=Port 5].redundancy.protocol") in diffs


def test_apply_mac_output():
    dev = _dev(ip="192.0.2.10")
    process_port_settings("5", {"IPADDR": "192.0.2.10/24"}, dev)
    apply_mac_output({"ip_mac": "00:30:A7:00:00:01", "goose_mac": "00:30:A7:00:00:02"}, dev)
    assert _iface(dev, "Port 5").mac == "00:30:A7:00:00:01"
    assert dev.iec61850.extra["goose_source_mac"] == "00:30:A7:00:00:02"
    assert {"00:30:A7:00:00:01", "00:30:A7:00:00:02"} <= dev.related.mac
    assert "ip_mac" not in dev.extra
    assert "goose_mac" not in dev.extra


# ----------------------------------------------------------------------------- #
# Port settings
# ----------------------------------------------------------------------------- #
P5_SETTINGS = {
    "EPORT": "Y",
    "IPADDR": "192.0.2.10/24",
    "DEFRTR": "192.0.2.1",
    "EDNP": "Y",
    "DNPNUM": "20000",
    "DNPADR": "10",
    "DNPIP1": "192.0.2.50",
    "DNPTR1": "TCP",
    "REPADR1": "1",
    "DNPMAP1": "1",
    "DNPINA1": "120",
    "DNPCL1": "Y",
    "DNPIP2": "192.0.2.51",
    "DNPTR2": "UDP",
    "DNPUDP2": "REQ",
    "REPADR2": "2",
    "EMODBUS": "Y",
    "MODIP1": "192.0.2.60",
    "MTIMEO1": "15",
    "ESNTP": "UNICAST",
    "SNTPPSIP": "192.0.2.1",
    "SNTPBSIP": "192.0.2.2",
    "SNTPRATE": "60",
    "SNTPTO": "5",
    "E61850": "Y",
    "EGSE": "N",
    "EPMIP": "Y",
    "PMOTS1": "UDP_T",
    "PMOIPA1": "192.0.2.70",
    "PMOTCP1": "4712",
    "PMOUDP1": "4713",
    "ETELNET": "Y",
    "TPORT": "1023",
    "EHTTP": "Y",
    "HTTPPOR": "80",
    "FTPSERV": "Y",
    "FTPANMS": "Y",
    "FTPUSER": "FTPUSER",
}


@pytest.fixture
def p5_dev() -> DeviceData:
    dev = _dev(ip="192.0.2.10")
    process_port_settings("5", P5_SETTINGS, dev)
    dev.populate_fields()
    return dev


def _svc(dev, protocol):
    return next(s for s in dev.service if s.protocol == protocol)


def _rels(dev, protocol):
    return [r for r in dev.relationships if r.protocol == protocol]


def test_port_settings_services(p5_dev):
    protocols = {s.protocol for s in p5_dev.service}
    assert {"mms", "goose", "dnp3", "modbus_tcp", "sntp", "c37_118"} <= protocols
    assert "iec61850" not in protocols
    assert "c37.118" not in protocols
    mms = _svc(p5_dev, "mms")
    assert (mms.transport, mms.port, mms.enabled) == ("tcp", 102, True)
    assert _svc(p5_dev, "goose").enabled is False
    assert _svc(p5_dev, "telnet").configured_port == 1023
    assert _svc(p5_dev, "telnet").port == 1023
    assert _svc(p5_dev, "http").configured_port == 80
    assert _svc(p5_dev, "dnp3").configured_port == 20000
    assert _svc(p5_dev, "sntp").enabled is True  # ESNTP=UNICAST
    ftp = _svc(p5_dev, "ftp")
    assert ftp.security.anonymous_access is True
    assert ftp.security.authentication_required is False
    assert "anonymous_login_enabled" not in ftp.extra
    for svc in p5_dev.service:
        for key in ("dnp3_stations", "modbus_endpoints", "c37_endpoints", "sntp_primary_ip"):
            assert key not in svc.extra


def test_port_settings_dnp3_relationships(p5_dev):
    rels = sorted(_rels(p5_dev, "dnp3"), key=lambda r: r.remote.ip)
    assert len(rels) == 2
    tcp, udp = rels
    assert tcp.type == "communicates_with"
    assert tcp.direction == "ingress"
    assert tcp.transport == "tcp"
    assert tcp.local.interface == "Port 5"
    assert tcp.local.port == 20000
    assert tcp.local.role == "outstation"
    assert tcp.local.protocol_address == "10"
    assert tcp.remote.ip == "192.0.2.50"
    assert tcp.remote.role == "master"
    assert tcp.remote.protocol_address == "1"
    assert tcp.enabled is True
    assert tcp.evidence == {"config"}
    assert tcp.extra == {
        "station_num": 1,
        "session_map": "1",
        "heartbeat_timeout": 120,
        "control_operations_enabled": True,
    }
    assert udp.transport == "udp"
    assert udp.extra["udp_response_port"] == "REQ"
    assert tcp.id
    assert tcp.id != udp.id


def test_port_settings_dnp3_session_count():
    """EDNP is "Enable DNP Sessions (0-5)" on SEL-751/351 class relays."""
    settings = {"IPADDR": "192.0.2.10/24", "EDNP": "2", "DNPNUM": "20000", "DNPADR": "10"}
    for n in (1, 2, 3):
        settings |= {f"DNPIP{n}": f"192.0.2.5{n}", f"DNPTR{n}": "TCP", f"REPADR{n}": str(n)}
    dev = _dev()
    process_port_settings("5", settings, dev)
    (svc,) = [s for s in dev.service if s.protocol == "dnp3"]
    assert svc.enabled is True
    assert svc.extra["sessions"] == 2
    enabled = {r.remote.ip: r.enabled for r in _rels(dev, "dnp3")}
    assert enabled == {"192.0.2.51": True, "192.0.2.52": True, "192.0.2.53": False}

    dev = _dev()
    process_port_settings("5", settings | {"EDNP": "0"}, dev)
    assert [s.enabled for s in dev.service if s.protocol == "dnp3"] == [False]
    assert {r.enabled for r in _rels(dev, "dnp3")} == {False}


def test_port_settings_dnp3_sessions_from_one_master():
    """Two sessions with one master IP are one edge: both sessions are kept."""
    settings = {"IPADDR": "192.0.2.10/24", "EDNP": "3", "DNPNUM": "20000", "DNPADR": "10"}
    settings |= {"DNPIP1": "192.0.2.51", "DNPTR1": "TCP", "REPADR1": "1", "DNPMAP1": "1"}
    settings |= {"DNPIP2": "192.0.2.51", "DNPTR2": "TCP", "REPADR2": "2", "DNPMAP2": "2"}
    settings |= {"DNPIP3": "192.0.2.53", "DNPTR3": "UDP", "REPADR3": "3"}
    dev = _dev()
    process_port_settings("5", settings, dev)
    dev.populate_fields()
    rels = {r.remote.ip: r for r in _rels(dev, "dnp3")}
    assert set(rels) == {"192.0.2.51", "192.0.2.53"}

    shared = rels["192.0.2.51"]
    assert shared.remote.protocol_address == ""  # the sessions report to different addresses
    assert (shared.transport, shared.enabled) == ("tcp", True)
    assert shared.extra == {
        "sessions": [
            {
                "station_num": 1,
                "session_map": "1",
                "remote_protocol_address": "1",
                "transport": "tcp",
                "enabled": True,
            },
            {
                "station_num": 2,
                "session_map": "2",
                "remote_protocol_address": "2",
                "transport": "tcp",
                "enabled": True,
            },
        ]
    }
    single = rels["192.0.2.53"]
    assert single.remote.protocol_address == "3"
    assert single.extra == {"station_num": 3}


def test_port_settings_modbus_c37_sntp(p5_dev):
    (mb,) = _rels(p5_dev, "modbus_tcp")
    assert (mb.direction, mb.transport, mb.local.port) == ("ingress", "tcp", 502)
    assert (mb.local.role, mb.remote.role, mb.remote.ip) == ("server", "client", "192.0.2.60")
    assert mb.extra["allow_list"] is True
    assert mb.extra["timeout"] == 15.0

    (pmu,) = _rels(p5_dev, "c37_118")
    assert (pmu.transport, pmu.direction) == ("udp", "egress")
    assert (pmu.local.role, pmu.remote.role) == ("pmu", "pdc")
    assert (pmu.remote.ip, pmu.remote.port) == ("192.0.2.70", 4713)
    assert pmu.extra["transport_scheme"] == "UDP_T"
    assert pmu.extra["tcp_local_port"] == 4712

    sources = sorted(p5_dev.clock.sources, key=lambda s: s.priority)
    assert [(s.protocol, s.address, s.priority) for s in sources] == [
        ("sntp", "192.0.2.1", 1),
        ("sntp", "192.0.2.2", 2),
    ]
    assert sources[0].extra == {"mode": "unicast", "poll_rate": 60, "timeout": 5.0}
    # Derived by populate_fields()
    assert {r.remote.ip for r in p5_dev.relationships if r.type == "syncs_time_from"} == {
        "192.0.2.1",
        "192.0.2.2",
    }


def test_port_settings_c37_tcp_and_sntp_broadcast():
    dev = _dev()
    settings = {
        "IPADDR": "192.0.2.10/24",
        "EPMIP": "Y",
        "PMOTS1": "TCP",
        "PMOIPA1": "192.0.2.70",
        "PMOTCP1": "4712",
        "ESNTP": "BROADCAST",
        "SNTPRATE": "60",
    }
    process_port_settings("5", settings, dev)
    (pmu,) = _rels(dev, "c37_118")
    assert (pmu.transport, pmu.direction, pmu.local.port) == ("tcp", "ingress", 4712)
    assert dev.clock.sources == []
    assert dev.clock.extra == {"sntp_mode": "broadcast", "sntp_poll_rate": 60}


def test_port_settings_serial():
    dev = _dev()
    process_port_settings("3", {"EPORT": "Y", "PROTO": "MBT", "SPEED": "9600", "TXID": "1"}, dev)
    process_port_settings("2", {"EPORT": "Y", "PROTO": "DNP", "SPEED": "19200"}, dev)
    process_port_settings("1", {"PROTO": "MOD", "SPEED": "9600", "COMMINF": "485"}, dev)
    process_port_settings("F", {"SPEED": "9600"}, dev)

    assert _iface(dev, "Port 3").application == "mirrored_bits"
    assert _iface(dev, "Port 3").type == "serial"
    assert _iface(dev, "Port 2").application == "dnp3"
    assert _iface(dev, "Port 1").application == "modbus_rtu"
    assert _iface(dev, "Port 1").type == "rs_485"
    assert _iface(dev, "Port F").application == "sel"
    assert _iface(dev, "Port F").type == "rs_232"

    (link,) = [r for r in dev.relationships if r.type == "physical_link"]
    assert link.protocol == "mirrored_bits"
    assert link.local.serial_port == "Port 3"
    assert link.local.role == "peer"
    assert link.remote.role == "peer"
    assert link.evidence == {"config"}
    assert link.extra == {"tx_id": "1"}
    assert link.medium == "serial"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("MBA", "mirrored_bits"),
        ("MB8B", "mirrored_bits"),
        ("MBT", "mirrored_bits"),
        ("DNP", "dnp3"),
        ("MOD", "modbus_rtu"),
        ("SEL", "sel"),
        ("LMD", "lmd"),
    ],
)
def test_normalize_serial_protocol(raw, expected):
    assert normalize_serial_protocol(raw) == expected


# ----------------------------------------------------------------------------- #
# STA / clock / id
# ----------------------------------------------------------------------------- #
def test_parse_self_tests_enabled():
    result = parse_self_tests(split_lines(STA_ENABLED))
    assert result["relay_enabled"] is True
    tests = {t["name"]: t for t in result["self_tests"]}
    assert tests["OS_IA"]["value"] == "2"
    assert tests["OS_IA"]["health"] == ""
    assert tests["PS_+5V_PS"]["value"] == "5.05"
    assert tests["PS_-5V_REG"]["value"] == "-5.03"
    assert tests["TEMP"]["value"] == "24.0"
    assert tests["RAM"]["health"] == "normal"
    assert len(tests) == 4 + 3 + 5


def test_parse_self_tests_failures_list_and_none():
    lines = [
        "SELF TESTS",
        "Failures",
        "No Failures",
        "",
        "Warnings",
        "Clock Battery",
        "",
        "Relay Enabled",
    ]
    result = parse_self_tests(lines)
    assert result["self_tests"] == [
        {"name": "Clock Battery", "value": "WARN", "health": "maintenance_required"}
    ]
    assert parse_self_tests(["FEEDER 1", "Relay Disabled"]) == {
        "self_tests": [],
        "relay_enabled": False,
    }
    assert parse_self_tests([]) == {"self_tests": [], "relay_enabled": None}


def test_status_output_to_dev_enabled():
    info = parse_status_output(split_lines(STA_ENABLED))
    assert info["time_source"] == "IRIG-B"
    assert info["device_time"] == datetime(2021, 3, 15, 14, 22, 1, 123000)
    dev = _dev()
    process_info_into_dev(info, dev, observed=T0)

    assert dev.health == "normal"
    assert dev.status == "Relay Enabled"
    assert dev.clock.source == "irig_b"
    assert dev.clock.extra["time_source_raw"] == "IRIG-B"
    assert dev.clock.time == datetime(2021, 3, 15, 14, 22, 1, 123000)  # naive, device-local
    assert dev.clock.observed == T0
    assert not dev.clock.utc_offset
    for key in ("device_time", "time_source", "self_tests", "relay_enabled"):
        assert key not in dev.extra
    ram = next(i for i in dev.indicators if i.name == "RAM")
    assert (ram.type, ram.category, ram.health, ram.value) == (
        "status_flag",
        "self_test",
        "normal",
        "OK",
    )
    assert ram.timestamp == T0
    enabled = next(i for i in dev.indicators if i.name == "relay_enabled")
    assert enabled.state == "on"
    dev.annotate()
    assert dev.clock.offset is None  # naive device time: no offset is computed


def test_status_output_to_dev_disabled_failed():
    info = parse_status_output(split_lines(STA_DISABLED_FAILED))
    dev = _dev()
    process_info_into_dev(info, dev, observed=T0)
    assert dev.health == "failure"  # failure wins over "disabled"
    assert dev.status == "Relay Disabled"
    assert dev.clock.source == "internal"
    rom = next(i for i in dev.indicators if i.name == "ROM")
    assert rom.health == "failure"
    assert next(i for i in dev.indicators if i.name == "A/D").health == "maintenance_required"

    # Disabled without a failed self-test -> check_function
    dev2 = _dev()
    process_info_into_dev({"relay_enabled": False}, dev2, observed=T0)
    assert dev2.health == "check_function"


def test_device_time_with_utc_offset():
    dev = _dev()
    tz = timezone(timedelta(hours=-8))
    observed = datetime(2023, 2, 9, 22, 35, 25, tzinfo=UTC)
    apply_device_time(dev, datetime(2023, 2, 9, 14, 35, 20, tzinfo=tz), observed)
    assert dev.clock.utc_offset == "-08:00"
    dev.clock.annotate(dev)
    assert dev.clock.offset == -5.0

    # A parsed file (no observed time) does not overwrite a live reading
    apply_device_time(dev, datetime(2020, 1, 1), None)
    assert dev.clock.observed == observed
    assert dev.clock.time.year == 2023


def test_id_command_iec61850_identity():
    dev = _dev()
    process_info_into_dev(
        {
            "FID": "SEL-700G-R200-V0-Z006003-D20180629",
            "iedName": "PROT1",
            "configVersion": "R1",
            "LIB61850ID": "5C9A14CB",
            "DEVID": "SEL-700G",
        },
        dev,
    )
    assert dev.iec61850.ied_name == "PROT1"
    assert dev.iec61850.config_version == "R1"
    assert dev.iec61850.extra["lib61850_id"] == "5C9A14CB"
    for key in ("iedName", "configVersion", "LIB61850ID"):
        assert key not in dev.extra
    assert dev.extra["DEVID"] == "SEL-700G"

    # Empty values ("iedName=") are dropped, not stored in extra
    dev2 = _dev()
    process_info_into_dev({"iedName": "", "configVersion": ""}, dev2)
    assert not dev2.iec61850.ied_name
    assert "iedName" not in dev2.extra


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("IRIG", "irig_b"),
        ("IRIG-B", "irig_b"),
        ("HIRIG", "irig_b"),
        ("PTP", "ptp"),
        ("SNTP", "sntp"),
        ("Internal", "internal"),
        ("GPS Clock", "gps_clock"),
    ],
)
def test_normalize_time_source(raw, expected):
    assert normalize_time_source(raw) == expected


# ----------------------------------------------------------------------------- #
# Events
# ----------------------------------------------------------------------------- #
def test_history_events():
    dev = _dev(name="FEEDER 1")
    events, _ = parse_and_process_events(HISTORY, "HISTORY.TXT", dev)
    assert len(events) == 2
    trip = next(e for e in dev.event if e.sequence == 10001)
    assert trip.action == "trip"
    assert "alert" in trip.kind
    assert trip.reason == "Trip; targets 11000000"
    assert trip.message == "Trip 11000000 (Current: 1.0 - Frequency: 60.0)"
    other = next(e for e in dev.event if e.sequence == 10002)
    assert other.action == "er"
    assert "alert" not in other.kind
    assert other.reason == "ER; targets 00000000"


def test_history_event_details():
    assert history_event_details("Trip", "11000000") == (
        "trip",
        "Trip; targets 11000000",
        {"alert"},
    )
    assert history_event_details("TRIG", "") == ("trig", "TRIG", {"event"})


def test_ser_events_reasons():
    dev = _dev(name="FEEDER 1")
    parse_and_process_events(SER, "SER.TXT", dev)
    by_seq = {e.sequence: e for e in dev.event}
    assert by_seq[214].reason == "Class P 5"
    assert "configuration" in by_seq[214].category
    assert by_seq[215].reason == "Group 2"
    assert by_seq[1025].action == "asserted-51g"
    assert by_seq[1025].reason == "51G Ground Time Overcurrent"
    assert by_seq[1024].reason == ""  # SALARM has no ANSI device number
    assert by_seq[213].reason == ""
    assert all(e.module == "SELRelay" for e in dev.event)


def test_ansi_meaning():
    assert ansi_meaning("51G") == "Ground Time Overcurrent"
    assert ansi_meaning("51X") == ansi_meaning("51")
    assert ansi_meaning("21G") == "Ground Distance"
    assert ansi_meaning("79LO")
    assert ansi_meaning("OUT101") == ""
    assert ansi_meaning("SALARM") == ""


# ----------------------------------------------------------------------------- #
# Front panel (SHO F / SET F)
# ----------------------------------------------------------------------------- #
def test_front_panel_indicators():
    settings = {
        "T01_LED": {"value": "51P1T OR 51G1T", "comment": "TIME OC"},
        "T01LEDL": {"value": "Y", "comment": ""},
        "T01LEDC": {"value": "RO", "comment": ""},
        "T02_LED": "50P1",
        "T02LEDC": "OG",
        "T03_LED": "79LO",
        "T03LEDC": "XY",
        "PB1_LED": {"value": "!LT01", "comment": "RECLOSE OFF"},
        "PB1LEDL": "N",
        "PB1LEDC": "a",
        "FP_TO": {"value": "15", "comment": ""},
    }
    indicators, remaining = front_panel_indicators(settings)
    by_name = {i.name: i for i in indicators}
    t01 = by_name["T01"]
    assert (t01.type, t01.category) == ("led", "target")
    assert t01.equation == "51P1T OR 51G1T"
    assert t01.latched is True
    assert t01.color == "red"  # asserted color of "RO"
    assert t01.extra == {"deasserted_color": "off"}
    assert t01.label == "TIME OC"
    assert t01.state == ""
    assert t01.timestamp is None
    assert by_name["T02"].equation == "50P1"
    assert by_name["T02"].latched is None
    assert by_name["T02"].color == ""  # off when asserted
    assert by_name["T02"].extra == {"deasserted_color": "green"}
    assert by_name["T03"].color == ""
    assert by_name["T03"].extra == {"color_code": "XY"}
    assert by_name["PB1"].color == "amber"
    assert by_name["PB1"].extra == {}
    pb1 = by_name["PB1"]
    assert (pb1.type, pb1.category, pb1.latched) == ("pushbutton", "pushbutton", False)
    assert pb1.label == "RECLOSE OFF"
    assert remaining == {"FP_TO": {"value": "15", "comment": ""}}


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("RO", ("red", "off")),
        ("ag", ("amber", "green")),
        (" G ", ("green", "")),
        ("OR", ("off", "red")),
        ("", None),
        ("RED", None),
        ("XY", None),
    ],
)
def test_sel_led_colors(code, expected):
    assert sel_led_colors(code) == expected


SET_ALL = """\
[INFO]
RELAYTYPE=0351
FID=SEL-351-5-R510-V0-Z103103-D20110429
[F]
T1_LED,"51P1T","","","","Target LED 1"
T1LEDL,"Y","","","",""
FP_TO,"15","","","",""
[P5]
IPADDR,"192.0.2.10/24","","","",""
EDNP,"Y","","","",""
DNPIP1,"192.0.2.50","","","",""
[1]
RID,"FEEDER 1","","","",""
TID,"STATION A","","","",""
"""


def test_parse_set_all_front_panel_and_relationships():
    from peat.modules.sel.relay_parse import parse_set_all

    _, dev = parse_set_all(SET_ALL)
    t1 = next(i for i in dev.indicators if i.name == "T1")
    assert t1.equation == "51P1T"
    assert t1.latched is True
    assert [r.remote.ip for r in dev.relationships if r.protocol == "dnp3"] == ["192.0.2.50"]


# ----------------------------------------------------------------------------- #
# Files
# ----------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/SETTINGS/SET_1.TXT", {"settings", "configuration"}),
        ("SET_P5.TXT", {"settings", "configuration"}),
        ("/CFG.TXT", {"configuration"}),
        ("/SER.TXT", {"log"}),
        ("/REPORTS/CHISTORY.TXT", {"log"}),
        ("/EVENTS/E1234.CEV", {"event_record"}),
        ("/SETTINGS/SET_61850.CID", {"configuration", "iec61850"}),
        ("/HMI/IMAGE.BMP", set()),
    ],
)
def test_sel_file_categories(path, expected):
    assert sel_file_categories(path) == expected


def test_device_file_path():
    assert device_file_path("\\SETTINGS\\SET_1.TXT").as_posix() == "/SETTINGS/SET_1.TXT"
    assert device_file_path("SETTINGS SET_1.TXT").as_posix() == "/SETTINGS/SET_1.TXT"
    assert device_file_path("CFG.TXT").as_posix() == "/CFG.TXT"


def test_files_from_classes():
    dev = _dev()
    configs = {
        "INFO": {"FID": "SEL-351-5-R510-V0-Z103103-D20110429"},
        "CLASSES": {
            "SAVE_INFO": ["Saved on 2/16/2023 at 10:14:22 PM"],
            "1": {"class": "1", "name": "Group 1", "file": "/SETTINGS/SET_1.TXT", "hex_id": "a1"},
            "P5": {"class": "P5", "name": "Port 5", "file": "SET_P5.TXT"},
        },
    }
    process_info_classes(configs, dev)
    files = {f.path.as_posix(): f for f in dev.files}
    assert set(files) == {"/SETTINGS/SET_1.TXT", "/SET_P5.TXT"}
    set1 = files["/SETTINGS/SET_1.TXT"]
    assert set1.category == {"settings", "configuration"}
    assert set1.description == "Group 1"
    assert set1.peat_module == "SELRelay"
    assert set1.extra == {"settings_class": "1", "hex_id": "a1"}
    assert "files_from_classes" not in dev.extra
    assert dev.extra["SAVE_INFO_FROM_CLASSES"] == ["Saved on 2/16/2023 at 10:14:22 PM"]
    assert dev.logic.last_updated == datetime(2023, 2, 16, 22, 14, 22)


# ----------------------------------------------------------------------------- #
# CID
# ----------------------------------------------------------------------------- #
def test_process_cid_file_bad_scl_keeps_file(tmp_path, mocker):
    import zlib
    from pathlib import PurePosixPath

    dev = _dev()
    write = mocker.patch.object(DeviceData, "write_file", return_value=tmp_path / "x")
    data = zlib.compress(b"<?xml version='1.0'?><NotSCL/>")
    out = process_cid_file(data, PurePosixPath("/SETTINGS/SET_61850.CID"), dev)
    assert out.startswith("<?xml")
    write.assert_called_once()
    (cid,) = dev.files
    assert cid.path.as_posix() == "/SETTINGS/SET_61850.CID"
    assert cid.category == {"configuration", "iec61850"}
    assert not dev.iec61850.ied_name  # SCL parse failed, the file is kept
