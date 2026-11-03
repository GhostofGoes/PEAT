"""
Tests for the GE UR relay and D25 RTU modules with synthetic inputs in the shape
of the parsed web pages (``parse_ge_html()``) and Telnet menus.
"""

import pytest

from peat import DeviceData, GERelay, config, datastore, utils
from peat.modules.ge import ge_relay, ge_rtu


@pytest.fixture
def out_config(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


def _page_tables() -> dict:
    return {
        "routing": {
            "port_status": [
                {
                    "port": "1",
                    "ip_address": "192.0.2.30",
                    "subnet_mask": "255.255.255.0",
                    "function": "Enabled",
                    "link_status": "UP",
                    "redundancy": "Failover",
                    "active_if_redundancy": "Yes",
                },
                {
                    "port": "2",
                    "function": "Enabled",
                    "link_status": "DOWN",
                    "redundancy": "Failover",
                    "active_if_redundancy": "No",
                },
                {
                    "port": "3",
                    "function": "Disabled",
                    "link_status": "DOWN",
                    "redundancy": "None",
                },
            ],
            "ipv4_routing_table": [
                {"destination": "0.0.0.0/0", "gateway": "192.0.2.1", "if": "fei0", "flags": "UG"},
                {"destination": "192.0.2.5", "gateway": "00:11:22:33:44:55", "if": "fei0"},
                {"destination": "127.0.0.1", "gateway": "127.0.0.1", "if": "lo0"},
            ],
            "arp_table": [
                {"internet_address": "192.0.2.5", "physical_address": "00-11-22-33-44-55"},
            ],
            "ipv6_routing_table": [{"destination": "::1"}],
        },
        "mb_map_administrator": {
            "admin": [
                {"name": "GDOI KDC IP", "value": "192.0.2.50"},
                {"name": "OCSP Server IP", "value": "0.0.0.0"},
                {"name": "SCEP Server IP", "value": "192.0.2.52"},
            ]
        },
        "usb_stats": {
            "usb": {
                "usb_initialized": "Yes",
                "rx_frame_count": "120",
                "tx_frame_count": "98",
                "usb_speed": "Full Speed: 12Mbit/s",
            }
        },
        "event_recorder": {
            "events": [
                {
                    "event_number": "12",
                    "time_and_date": "2024-01-02 03:04:05",
                    "event_cause": "PHASE IOC1 OP",
                },
            ]
        },
    }


def test_security_servers_on_one_host_stay_separate():
    dev = DeviceData(ip="192.0.2.30")
    for name in ("GDOI KDC IP", "OCSP Server IP", "SCEP Server IP"):
        dev.store(
            "relationships",
            ge_relay.security_server_relationship({"name": name, "value": "10.0.0.5"}),
        )
    roles = {r.protocol: r.remote.role for r in dev.relationships}
    assert roles == {"gdoi": "gdoi_kdc", "ocsp": "ocsp_responder", "scep": "scep_server"}
    assert ge_relay.security_server_relationship({"name": "Other", "value": "10.0.0.5"}) is None


@pytest.mark.usefixtures("out_config")
def test_process_pages():
    dev = DeviceData(ip="192.0.2.30")
    GERelay._process_pages(dev, _page_tables())

    ifaces = {i.name: i for i in dev.interface}
    assert ifaces["1"].redundancy.protocol == "failover"
    assert ifaces["1"].redundancy.state == "active"
    assert ifaces["2"].redundancy.state == "standby"
    assert "redundancy" not in ifaces["1"].extra
    assert ifaces["3"].redundancy.protocol == ""
    assert ifaces["3"].extra["redundancy"] == "None"
    assert ifaces["lo0"].type == "loopback"

    usb = next(i for i in dev.interface if i.type == "usb")
    assert usb.statistics.ingress.messages == 120
    assert usb.statistics.egress.messages == 98
    assert usb.statistics.timestamp is not None
    assert usb.speed == 12
    assert "rx_frame_count" not in usb.extra

    routes = {r.destination: r for r in dev.routes}
    assert routes["0.0.0.0/0"].gateway == "192.0.2.1"
    assert routes["0.0.0.0/0"].interface == "fei0"
    assert routes["0.0.0.0/0"].flags == "UG"
    assert routes["192.0.2.5/32"].gateway == ""
    assert routes["192.0.2.5/32"].extra["gateway_mac"] == "00:11:22:33:44:55"
    assert routes["192.0.2.5/32"].type == "connected"
    assert "00:11:22:33:44:55" in dev.related.mac

    rels = {(r.type, r.remote.ip): r for r in dev.relationships}
    arp = rels[("neighbor_of", "192.0.2.5")]
    assert arp.remote.mac == "00:11:22:33:44:55"
    assert arp.evidence == {"arp"}
    assert rels[("depends_on", "192.0.2.50")].remote.role == "gdoi_kdc"
    assert rels[("depends_on", "192.0.2.50")].protocol == "gdoi"
    assert rels[("depends_on", "192.0.2.52")].remote.role == "scep_server"
    assert rels[("depends_on", "192.0.2.52")].protocol == "scep"
    assert ("depends_on", "0.0.0.0") not in rels

    event = dev.event[0]
    assert event.reason == "PHASE IOC1 OP"
    assert event.action == "phase-ioc1-op"

    assert "usb_stats" not in dev.extra
    assert dev.extra["routing"] == {"ipv6_routing_table": [{"destination": "::1"}]}


@pytest.mark.usefixtures("out_config")
def test_baseline_ignores_arp_host_routes():
    """An expired ARP-cloned host route (MAC next hop) is not a missing route (R3-16)."""
    from peat.data.baseline import compare_device
    from peat.data.models import Baseline

    def pull(tables: dict) -> DeviceData:
        dev = DeviceData(ip="192.0.2.30", id="192.0.2.30")
        GERelay._process_pages(dev, tables)
        return dev

    baseline = Baseline(id="ur", kind="previous_observed", expected=pull(_page_tables()))
    expired = _page_tables()
    routing = expired["routing"]
    routing["arp_table"] = []
    routing["ipv4_routing_table"] = [
        r for r in routing["ipv4_routing_table"] if r["destination"] != "192.0.2.5"
    ]
    assert compare_device(pull(expired), baseline) == []
    # the other routes are still compared
    routing["ipv4_routing_table"] = [
        r for r in routing["ipv4_routing_table"] if r["destination"] != "0.0.0.0/0"
    ]
    diffs = {(f.difference, f.path) for f in compare_device(pull(expired), baseline)}
    assert diffs == {("missing", "routes[destination=0.0.0.0/0,gateway=192.0.2.1,interface=fei0]")}


def test_port_redundancy():
    assert ge_relay.port_redundancy({"redundancy": "PRP"}).protocol == "prp"
    assert ge_relay.port_redundancy({"redundancy": "Independent"}) is None
    unknown = ge_relay.port_redundancy({"redundancy": "LLA"})
    assert unknown.protocol == ""
    assert unknown.mode == "lla"
    assert unknown.extra == {"redundancy": "LLA"}


def test_split_error_log_entry():
    assert ge_rtu.split_error_log_entry("1A2B N0: IP=192.0.2.5, can't connect, ") == (
        "1A2B",
        "N0: IP=192.0.2.5, can't connect",
    )
    assert ge_rtu.split_error_log_entry("no code") == ("", "no code")


def test_process_error_log():
    dev = DeviceData(ip="192.0.2.40")
    ge_rtu.GERTU.process_error_log(dev, {"1": "0C21 N0: IP=192.0.2.5, can't open socket"})
    event = dev.event[0]
    assert event.code == "0C21"
    assert event.reason == "N0: IP=192.0.2.5, can't open socket"
    assert event.outcome == "failure"
    assert "192.0.2.5" in dev.related.ip


def test_internet_stats_to_statistics(mocker):
    ip = ge_rtu.internet_stats_to_statistics(
        {"in_receives": "1000", "out_requests": "900", "in_discards": "3", "frag_ok": "7"},
        "ip",
    )
    assert ip.type == "ipv4"
    assert ip.transport == ""
    assert ip.ingress.packets == 1000
    assert ip.egress.packets == 900
    assert ip.ingress.dropped == 3
    assert ip.extra == {"frag_ok": 7}
    assert ip.timestamp.tzinfo is not None

    tcp = ge_rtu.internet_stats_to_statistics(
        {"tcp_curr_estab": "2", "in_segs": "50", "retrans_t/o": "1", "state": "n/a"}, "tcp"
    )
    assert tcp.transport == "tcp"
    assert tcp.connections.active == 2
    assert tcp.ingress.packets == 50
    assert tcp.extra == {"retrans_t_o": 1, "state": "n/a"}

    # Both samples get the same timestamp (as with a coarse clock, e.g. on Windows):
    # the sample stored later wins
    mocker.patch.object(utils, "utc_now", return_value=ip.timestamp)
    dev = DeviceData()
    for kind, stats in [("ip", {"in_receives": "1"}), ("udp", {"in_datagrams": "5"})]:
        dev.store("protocol_statistics", ge_rtu.internet_stats_to_statistics(stats, kind))
    dev.store(
        "protocol_statistics", ge_rtu.internet_stats_to_statistics({"in_receives": "2"}, "ip")
    )
    assert len(dev.protocol_statistics) == 2
    ip_stats = next(s for s in dev.protocol_statistics if s.type == "ipv4")
    assert ip_stats.ingress.packets == 2  # newest sample wins
    assert ip_stats.timestamp == ip.timestamp
