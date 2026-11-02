from copy import deepcopy
from datetime import UTC, datetime, timedelta

from peat import DeviceData, Interface, Service
from peat.modules.rockwell.clx_http import ClxHTTP


def test_clxhttp_clean_data():
    assert ClxHTTP._clean_data({}) == {}
    assert ClxHTTP._clean_data({" some key ": "   evil \t   value     "}) == {
        "some key": "evil value"
    }


def test_clxhttp_add_padding():
    assert ClxHTTP.add_padding("01") == "00000001"
    assert ClxHTTP.add_padding("1034") == "00001034"
    assert ClxHTTP.add_padding("b9d29221") == "b9d29221"


def test_clxhttp_parse_uptime():
    assert ClxHTTP._parse_uptime("") is None
    assert ClxHTTP._parse_uptime("bogus string") is None
    assert ClxHTTP._parse_uptime("28 days, 15h:43m:33.775s") == timedelta(
        days=28, hours=15, minutes=43, seconds=33, milliseconds=775
    )
    assert ClxHTTP._parse_uptime("28 days, 16h:53m:45s") == timedelta(
        days=28, hours=16, minutes=53, seconds=45
    )


# Synthetic "advancedDiags" tables, in the shape returned by parse_statistics()
# ({label: value}) and parse_net_table() ([{column: value}]). The labels follow
# the MIB-II (RFC 1213) object names; no captured device pages exist in the repo.
NETWORK_INFO = {
    "arp_table": [
        {"Net Address": "192.0.2.1", "Physical Address": "00-00-5E-00-53-01", "Type": "dynamic"},
        {"Net Address": "192.0.2.10", "Physical Address": "00-00-BC-00-00-0A", "Type": "local"},
        {"Net Address": "192.0.2.50", "Physical Address": "00-00-5E-00-53-32", "Type": "None"},
    ],
    "if_statistics": {
        "Description": "Ethernet Port 1",
        "MAC address": "00:00:BC:00:00:0A",
        "MTU": "1500",
        "In Octets": "123456",
        "In Ucast Packets": "1000",
        "In Discards": "2",
        "In Errors": "1",
        "In Unknown Protos": "0",
        "Out Octets": "654321",
        "Out Discards": "0",
        "Out Errors": "0",
    },
    "ip_statistics": {
        "In Receives": "5000",
        "In Discards": "3",
        "In Unknown Protos": "4",
        "Out Discards": "1",
    },
    "icmp_statistics": {"In Msgs": "10", "Out Msgs": "12", "In Errors": "0"},
    "tcp_statistics": {
        "Active Opens": "5",
        "Passive Opens": "20",
        "Attempt Fails": "1",
        "Estab Resets": "2",
        "Curr Estab": "3",
        "In Segs": "9000",
        "Out Segs": "8000",
        "Retrans Segs": "7",
    },
    "udp_statistics": {"In Datagrams": "300", "Out Datagrams": "200", "No Ports": "6"},
    "udp_table": [
        {"Local Address": "0.0.0.0", "Local Port": "2222"},
        {"Local Address": "0.0.0.0", "Local Port": "44818"},
    ],
    "tcp_connections": [
        {
            "Local Address": "0.0.0.0",
            "Local Port": "44818",
            "Remote Address": "0.0.0.0",
            "Remote Port": "0",
            "State": "LISTEN",
        },
        {
            "Local Address": "0.0.0.0",
            "Local Port": "80",
            "Remote Address": "0.0.0.0",
            "Remote Port": "0",
            "State": "LISTEN",
        },
        # Two sessions of the same HMI
        {
            "Local Address": "192.0.2.10",
            "Local Port": "44818",
            "Remote Address": "192.0.2.50",
            "Remote Port": "50123",
            "State": "ESTABLISHED",
        },
        {
            "Local Address": "192.0.2.10",
            "Local Port": "44818",
            "Remote Address": "192.0.2.50",
            "Remote Port": "50124",
            "State": "ESTABLISHED",
        },
        # A connection the controller opened (e.g. MSG instruction to another PLC)
        {
            "Local Address": "192.0.2.10",
            "Local Port": "1050",
            "Remote Address": "192.0.2.20",
            "Remote Port": "44818",
            "State": "TIME_WAIT",
        },
    ],
    "ip_routes": [
        {"Destination": "192.0.2.0", "Mask": "0.255.255.255", "Gateway": "0.0.0.0"},
        {"Destination": "198.51.100.0", "Mask": "0.255.255.255", "Gateway": "192.0.2.1"},
        {"Destination": "bogus", "Mask": "0.255.255.255"},
    ],
}


def test_clxhttp_statistics_from_table():
    stats = ClxHTTP.statistics_from_table(NETWORK_INFO["tcp_statistics"])
    assert stats.timestamp is not None
    assert stats.timestamp.tzinfo is not None
    assert stats.connections.total == 25  # active + passive opens
    assert stats.connections.failed == 1
    assert stats.connections.resets == 2
    assert stats.connections.active == 3
    assert stats.ingress.packets == 9000
    assert stats.egress.packets == 8000
    assert stats.extra == {"retrans_segs": 7}

    # MIB object names with the table prefix, and unparsable values
    stats = ClxHTTP.statistics_from_table(
        {"ifInOctets": "10", "ifOutOctets": "1,024", "Speed": "100 Mbps", "Bad": "-5"}
    )
    assert stats.ingress.bytes == 10
    assert stats.egress.bytes == 1024
    assert stats.extra == {"speed": "100 Mbps", "bad": "-5"}

    assert not ClxHTTP.statistics_from_table({}).has_counters()


def test_clxhttp_process_network():
    dev = DeviceData(ip="192.0.2.10")
    ClxHTTP.process_network(dev, deepcopy(NETWORK_INFO))

    assert "network" not in dev.extra

    # Interface and its counters
    assert len(dev.interface) == 1
    iface = dev.interface[0]
    assert iface.name == "Ethernet Port 1"
    assert iface.mtu == 1500
    assert iface.subnet_mask == ""  # no IP known for the interface
    assert iface.statistics.ingress.bytes == 123456
    assert iface.statistics.ingress.dropped == 2
    assert iface.statistics.ingress.errors == 1
    assert iface.statistics.ingress.unknown_protocols == 0
    assert iface.statistics.egress.bytes == 654321
    assert iface.statistics.extra == {"in_ucast_packets": 1000}
    assert iface.statistics.timestamp is not None

    # Protocol statistics
    by_scope = {(s.type, s.transport): s for s in dev.protocol_statistics}
    assert set(by_scope) == {("ipv4", ""), ("", "icmp"), ("", "tcp"), ("", "udp")}
    assert by_scope[("ipv4", "")].ingress.dropped == 3
    assert by_scope[("ipv4", "")].ingress.unknown_protocols == 4
    assert by_scope[("ipv4", "")].extra == {"in_receives": 5000}
    assert by_scope[("", "icmp")].ingress.messages == 10
    assert by_scope[("", "icmp")].egress.messages == 12
    assert by_scope[("", "tcp")].connections.total == 25
    assert by_scope[("", "udp")].ingress.packets == 300
    assert by_scope[("", "udp")].extra == {"no_ports": 6}

    # Listening services (services are identified by protocol and port)
    services = {(s.protocol, s.port) for s in dev.service}
    assert services == {("cip", 44818), ("http", 80), ("enip", 2222)}

    # Connections (direction inferred from the listening services)
    conns = [r for r in dev.relationships if "netstat" in r.evidence]
    assert len(conns) == 2
    hmi = next(r for r in conns if r.remote.ip == "192.0.2.50")
    assert hmi.direction == "ingress"
    assert hmi.protocol == "cip"
    assert hmi.local.port == 44818
    assert hmi.count == 2
    assert hmi.state == "established"
    assert hmi.id
    peer = next(r for r in conns if r.remote.ip == "192.0.2.20")
    assert peer.direction == "egress"
    assert peer.remote.port == 44818
    assert peer.state == "time_wait"

    # ARP neighbors (not the device itself)
    neighbors = {r.remote.ip: r for r in dev.relationships if r.type == "neighbor_of"}
    assert set(neighbors) == {"192.0.2.1", "192.0.2.50"}
    assert neighbors["192.0.2.1"].remote.mac == "00:00:5E:00:53:01"
    assert neighbors["192.0.2.1"].evidence == {"arp"}
    assert neighbors["192.0.2.1"].extra == {"type": "dynamic"}
    assert neighbors["192.0.2.50"].extra == {}
    assert dev.mac == "00:00:BC:00:00:0A"

    # Routes (the mask is reported with the bytes in reverse order)
    routes = {r.destination: r for r in dev.routes}
    assert set(routes) == {"192.0.2.0/24", "198.51.100.0/24"}
    assert routes["192.0.2.0/24"].gateway == ""
    assert routes["198.51.100.0/24"].gateway == "192.0.2.1"
    assert "192.0.2.1" in dev.related.ip


def test_clxhttp_process_network_subnet_mask_and_unknown_interface():
    dev = DeviceData(ip="192.0.2.10")
    dev.store("interface", Interface(name="SNMP iface", ip="192.0.2.10", mac="00:00:BC:00:00:0B"))
    info = {
        "if_statistics": {"In Octets": "5", "Out Octets": "6"},
        "ip_routes": NETWORK_INFO["ip_routes"],
    }
    ClxHTTP.process_network(dev, info)
    assert dev.interface[0].subnet_mask == "255.255.255.0"
    # No MAC or description to find the interface: device totals
    assert dev.statistics.ingress.bytes == 5
    assert dev.interface[0].statistics.ingress.bytes is None


def test_clxhttp_process_syslog():
    dev = DeviceData(ip="192.0.2.10")
    ClxHTTP.process_syslog(
        dev,
        [
            {
                "Event Number": "12",
                "Time": "28 days, 15h:42m:55.588s",
                "Event String": "CipStatus: Generated on device",
                "File": "CommPortBase.cpp",
                "Line Number": "2308",
                "Param1": "0x2",
                "Param2": "0x19001e",
                "Task Name": "EncapTCP024",
                "Event Code": "0xd",
            }
        ],
    )
    event = dev.event[0]
    assert event.code == "0xd"
    assert "event_code" not in event.extra
    assert event.extra["task_name"] == "EncapTCP024"
    assert event.sequence == 12


def test_clxhttp_process_serverlog():
    dev = DeviceData(ip="192.0.2.10")
    dev.store("service", Service(protocol="http", port=80, transport="tcp"))
    rows = [
        {
            "Timestamp": "MAY 04 17:11:01 2021",
            "IP Address": "192.0.2.50",
            "URL": "/index.html",
            "HTTP Code": "200",
            "Access": "public",
        },
        {
            "Timestamp": "MAY 04 17:15:30 2021",
            "IP Address": "192.0.2.50",
            "URL": "/serverlog.asp?username=Administrator&realm=1756-EWEB",
            "HTTP Code": "401",
            "Access": "admin",
        },
        {
            "Timestamp": "MAY 03 08:00:00 2021",
            "IP Address": "192.0.2.50",
            "URL": "/home.asp",
            "HTTP Code": "200",
            "Access": "public",
        },
        {
            "Timestamp": "MAY 04 18:00:00 2021",
            "IP Address": "192.0.2.60",
            "URL": "/home.asp",
            "HTTP Code": "200",
            "Access": "public",
        },
    ]
    ClxHTTP.process_serverlog(dev, rows)

    assert len(dev.event) == 4
    clients = {r.remote.ip: r for r in dev.relationships}
    assert set(clients) == {"192.0.2.50", "192.0.2.60"}
    hmi = clients["192.0.2.50"]
    assert hmi.type == "communicates_with"
    assert hmi.protocol == "http"
    assert hmi.direction == "ingress"
    assert hmi.evidence == {"log"}
    assert hmi.count == 3
    assert hmi.first_seen == datetime(2021, 5, 3, 8, 0, 0, tzinfo=UTC)
    assert hmi.last_seen == datetime(2021, 5, 4, 17, 15, 30, tzinfo=UTC)
    assert hmi.local.port == 80  # from the device's own HTTP service
    assert clients["192.0.2.60"].count == 1
