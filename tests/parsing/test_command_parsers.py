import datetime
from pathlib import PurePosixPath

import pytest

from peat import DeviceData, config
from peat.data.models import File, HostProcess, Interface, Service
from peat.parsing import command_parsers

# to get data artifacts:
#   run the test
#   look in: /tmp/pytest-of-<username>/pytest-current/...
#   just keep tab-completing to the path that has "current" in it
#   to get to the file output for your test.


def test_command_parser_edge_cases(mocker, tmp_path, caplog):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="test_command_parser_edge_cases")

    assert not command_parsers.VarLogMessagesParser.parse_and_process("", dev)
    assert "WARNING" in caplog.text

    with pytest.raises(ValueError):
        command_parsers.NixParserBase.parse_and_process("data", dev)

    with pytest.raises(ValueError):
        assert command_parsers.NixParserBase.type()

    assert command_parsers.VarLogMessagesParser.parse("blahblah") == []
    assert not command_parsers.VarLogMessagesParser.parse_and_process("blahblah", dev)
    assert not command_parsers.VarLogMessagesParser.parse_and_process("", dev)

    assert command_parsers.VarLogMessagesParser.__name__ == "VarLogMessagesParser"
    assert command_parsers.VarLogMessagesParser.type() == "file"
    assert command_parsers.DateParser.type() == "command"

    assert command_parsers.NixParserBase.parse("") is None
    assert command_parsers.NixParserBase.process("", dev) is None


def test_parse_env(text_data, json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert command_parsers.EnvParser.parse("") == {}

    input_data = text_data("env.txt")
    results = command_parsers.EnvParser.parse(input_data)
    expected = json_data("expected_env.json")
    assert results == expected

    dev = DeviceData(id="test_parse_env")
    assert command_parsers.EnvParser.parse_and_process(input_data, dev)
    assert dev.extra["env"] == expected
    assert_no_errors()


def test_parse_proc_cmdline(mocker, tmp_path, text_data, json_data, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    assert command_parsers.ProcCmdlineParser.parse("") == {}

    results = command_parsers.ProcCmdlineParser.parse(text_data("proc_cmdline.txt"))
    assert results == json_data("expected_proc_cmdline.json")

    dev = DeviceData(id="test_parse_proc_cmdline")
    command_parsers.ProcCmdlineParser.process(results, dev)
    assert dev.extra["/proc/cmdline"] == results

    assert_no_errors()


def test_parse_proc_cpuinfo(text_data, json_data, assert_no_errors):
    assert command_parsers.ProcCpuinfoParser.parse("") == {}

    results = command_parsers.ProcCpuinfoParser.parse(text_data("proc_cpuinfo.txt"))
    assert results == json_data("expected_proc_cpuinfo.json")
    assert_no_errors()


def test_process_proc_cpuinfo(json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.ProcCpuinfoParser.process({}, DeviceData())

    dev = DeviceData(id="process_proc_cpuinfo")
    data = json_data("expected_proc_cpuinfo.json")
    command_parsers.ProcCpuinfoParser.process(data, dev)
    assert dev.hardware.cpu.model == "e500v2"
    assert dev.hardware.cpu.full == "P1020 RDB e500v2"
    assert (
        dev.hardware.cpu.description
        == "P1020 RDB e500v2 799.999992MHz revision 5.1 (pvr 8021 2051)"
    )
    assert_no_errors()


def test_parse_proc_meminfo(text_data, json_data, assert_no_errors):
    assert command_parsers.ProcMeminfoParser.parse("") == {}

    results = command_parsers.ProcMeminfoParser.parse(text_data("proc_meminfo.txt"))
    assert results == json_data("expected_proc_meminfo.json")
    assert_no_errors()


def test_process_proc_meminfo(json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.ProcMeminfoParser.process({}, DeviceData())

    dev = DeviceData(id="process_proc_meminfo")
    data = json_data("expected_proc_meminfo.json")
    command_parsers.ProcMeminfoParser.process(data, dev)
    assert dev.hardware.memory_total == 193191936
    assert dev.hardware.memory_available == 118960128
    assert_no_errors()


def test_parse_proc_modules(mocker, tmp_path, text_data, json_data, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert command_parsers.ProcModulesParser.parse("") == []

    results = command_parsers.ProcModulesParser.parse(text_data("proc_modules.txt"))
    assert results == json_data("expected_proc_modules.json")

    dev = DeviceData(id="test_parse_proc_modules")
    command_parsers.ProcModulesParser.process(results, dev)
    assert dev.extra["/proc/modules"] == results

    assert_no_errors()


def test_parse_proc_uptime(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    input_data = text_data("proc_uptime.txt")
    expected = datetime.timedelta(seconds=21165.34)

    results = command_parsers.ProcUptimeParser.parse(input_data)
    assert results == expected

    dev = DeviceData(id="test_parse_proc_uptime")
    assert command_parsers.ProcUptimeParser.parse_and_process(input_data, dev)
    assert dev.uptime == expected
    assert_no_errors()


def test_proc_net_dev_parser(text_data, json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.ProcNetDevParser.parse("")

    input_data = text_data("dev")
    expected = json_data("expected_dev.json")

    results = command_parsers.ProcNetDevParser.parse(input_data)
    assert results == expected

    dev = DeviceData(id="test_procnetdevparser")
    assert command_parsers.ProcNetDevParser.parse_and_process(input_data, dev)
    # The counters are in Interface.statistics, not duplicated in dev.extra
    assert "/proc/net/dev" not in dev.extra
    assert len(dev.interface) == 7
    assert dev.interface[0].type == "loopback"
    assert dev.interface[1].type == "ethernet"

    eth0 = dev.interface[1]
    assert eth0.name == "eth0"
    stats = eth0.statistics
    assert stats.timestamp is not None
    assert stats.timestamp.tzinfo is not None
    assert stats.ingress.bytes == 15030
    assert stats.ingress.packets == 113
    assert stats.ingress.errors == 0
    assert stats.ingress.dropped == 0
    assert stats.ingress.multicast_packets == 0
    assert stats.egress.bytes == 269699
    assert stats.egress.packets == 377
    assert stats.collisions == 0
    assert stats.extra == {
        "recv_fifo": 0,
        "recv_frame": 0,
        "recv_compressed": 0,
        "trans_fifo": 0,
        "trans_carrier": 0,
        "trans_compressed": 0,
    }
    assert "statistics" not in eth0.extra
    assert_no_errors()


def test_proc_net_dev_existing_interface_and_vlan(text_data, assert_no_errors):
    data = text_data("dev").replace("tun0:", "eth0.100:")
    dev = DeviceData(id="test_proc_net_dev_existing_interface")
    dev.store("interface", Interface(name="eth0", type="ethernet", ip="192.0.2.20"))

    command_parsers.ProcNetDevParser.process(command_parsers.ProcNetDevParser.parse(data), dev)

    # Merged into the existing interface (by name)
    assert len(dev.interface) == 7
    eth0 = dev.retrieve("interface", {"name": "eth0"})
    assert eth0.ip == "192.0.2.20"
    assert eth0.statistics.egress.bytes == 269699

    vlan_if = dev.retrieve("interface", {"name": "eth0.100"})
    assert vlan_if.parent == "eth0"
    assert vlan_if.vlan.id == "100"
    assert vlan_if.vlan.tagged is True
    assert vlan_if.statistics.ingress.packets == 92
    assert "100" in dev.related.vlans
    assert_no_errors()


def test_build_statistics():
    now = datetime.datetime.now(datetime.UTC)
    stats = command_parsers.build_statistics(
        {"rx_bytes": 10, "tx_packets": 2, "collisions": 1, "rx_frame": 3, "rx_errors": -1},
        command_parsers.IFCONFIG_STATISTICS,
        now,
    )
    assert stats.timestamp == now
    assert stats.ingress.bytes == 10
    assert stats.egress.packets == 2
    assert stats.collisions == 1
    # Unmapped counters and invalid values go to extra
    assert stats.extra == {"rx_frame": 3, "rx_errors": -1}
    assert stats.ingress.errors is None
    assert stats.has_counters()

    empty = command_parsers.build_statistics({}, command_parsers.IFCONFIG_STATISTICS, now)
    assert not empty.has_counters()


@pytest.mark.parametrize(
    ("name", "parent", "vlan_id"),
    [
        ("eth0.100", "eth0", "100"),
        ("eth0.100@eth0", "eth0", "100"),
        ("eth1.0", "eth1", "0"),
        ("eth0:1", "eth0", ""),
        ("eth0", "", ""),
        ("fei0", "", ""),
        ("br.lan", "", ""),
        ("eth0.5000", "", ""),
    ],
)
def test_set_interface_layering(name, parent, vlan_id):
    iface = Interface(name=name)
    command_parsers.set_interface_layering(iface)
    assert iface.parent == parent
    assert iface.vlan.id == vlan_id
    if vlan_id:
        assert iface.vlan.tagged is True


def test_set_interface_layering_keeps_values():
    iface = Interface(name="eth0.100", parent="bond0")
    command_parsers.set_interface_layering(iface)
    assert iface.parent == "bond0"
    assert iface.vlan.id == "100"


def test_ifconfig_vxworks(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    data = text_data("ifconfig_vxworks.txt")

    parsed = command_parsers.IfconfigParser.parse(data)
    assert set(parsed) == {"lo0", "fei0"}
    assert parsed["fei0"]["rx_bytes"] == 24000000
    assert parsed["fei0"]["unsupported_protocol"] == 7

    dev = DeviceData(id="test_ifconfig_vxworks")
    assert command_parsers.IfconfigParser.parse_and_process(data, dev)
    assert "ifconfig -a" not in dev.extra

    fei0 = dev.retrieve("interface", {"name": "fei0"})
    assert fei0.ip == "192.0.2.20"
    assert fei0.mac == "00:A0:1E:01:02:03"
    assert fei0.id == "2"
    assert fei0.mtu == 1500
    assert fei0.type == "ethernet"
    assert fei0.enabled is True
    assert fei0.connected is True
    assert fei0.description.description == "Primary interface"
    assert "statistics" not in fei0.extra
    assert fei0.extra["queue"] == "none"
    assert fei0.extra["capabilities"] == ["TXCSUM", "VLAN_MTU"]

    stats = fei0.statistics
    assert stats.timestamp is not None
    assert stats.timestamp.tzinfo is not None
    assert stats.ingress.packets == 12000
    assert stats.ingress.multicast_packets == 250
    assert stats.ingress.errors == 1
    assert stats.ingress.dropped == 3
    assert stats.ingress.bytes == 24000000
    assert stats.ingress.unknown_protocols == 7
    assert stats.egress.packets == 9000
    assert stats.egress.multicast_packets == 4
    assert stats.egress.errors == 2
    assert stats.egress.bytes == 1000000
    assert stats.collisions == 5
    assert stats.extra == {}

    lo0 = dev.retrieve("interface", {"name": "lo0"})
    assert lo0.type == "loopback"
    assert lo0.statistics.ingress.packets == 6
    assert_no_errors()


def test_ifconfig_busybox(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    data = text_data("ifconfig_busybox.txt")

    parsed = command_parsers.IfconfigParser.parse(data)
    assert set(parsed) == {"eth0", "eth0.100", "eth0:1", "lo", "tun0"}
    assert "mac" not in parsed["tun0"]  # 16-byte "HWaddr 00-00-..." is not a MAC

    dev = DeviceData(id="test_ifconfig_busybox")
    assert command_parsers.IfconfigParser.parse_and_process(data, dev)

    eth0 = dev.retrieve("interface", {"name": "eth0"})
    assert eth0.ip == "192.0.2.20"
    assert eth0.subnet_mask == "255.255.255.0"
    assert eth0.mac == "00:00:5E:00:53:01"
    assert eth0.mtu == 1500
    assert eth0.type == "ethernet"
    assert eth0.enabled is True
    assert eth0.connected is True
    assert eth0.extra["broadcast"] == "192.0.2.255"
    assert eth0.extra["txqueuelen"] == 1000
    assert eth0.statistics.ingress.packets == 113
    assert eth0.statistics.ingress.dropped == 2
    assert eth0.statistics.ingress.bytes == 15030
    assert eth0.statistics.egress.errors == 1
    assert eth0.statistics.egress.bytes == 269699
    assert eth0.statistics.collisions == 0
    assert eth0.statistics.extra == {
        "rx_overruns": 0,
        "rx_frame": 0,
        "tx_overruns": 0,
        "tx_carrier": 0,
    }

    vlan_if = dev.retrieve("interface", {"name": "eth0.100"})
    assert vlan_if.parent == "eth0"
    assert vlan_if.vlan.id == "100"
    assert vlan_if.vlan.tagged is True
    assert "100" in dev.related.vlans

    alias = dev.retrieve("interface", {"name": "eth0:1"})
    assert alias.parent == "eth0"
    assert alias.vlan.id == ""
    assert not alias.statistics.has_counters()

    lo = dev.retrieve("interface", {"name": "lo"})
    assert lo.type == "loopback"

    tun0 = dev.retrieve("interface", {"name": "tun0"})
    assert tun0.mac == ""
    assert tun0.extra["peer"] == "10.8.0.5"
    assert "10.8.0.5" in dev.related.ip
    assert_no_errors()


def test_ifconfig_down_interface_without_down_flag(assert_no_errors):
    """net-tools/BusyBox print no DOWN flag: an interface without UP is down."""
    data = (
        "eth1      Link encap:Ethernet  HWaddr 00:50:C2:B2:7F:F5\n"
        "          BROADCAST MULTICAST  MTU:1500  Metric:1\n"
        "          RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n"
        "          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n"
        "          collisions:0 txqueuelen:1000\n"
        "          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n"
        "\n"
        "eth2      Link encap:Ethernet  HWaddr 00:50:C2:B2:7F:F6\n"
        "          UP BROADCAST MULTICAST  MTU:1500  Metric:1\n"
        "          RX packets:0 errors:0 dropped:0 overruns:0 frame:0\n"
        "          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0\n"
        "          collisions:0 txqueuelen:1000\n"
        "          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)\n"
    )
    dev = DeviceData(id="test_ifconfig_down")
    command_parsers.IfconfigParser.process(command_parsers.IfconfigParser.parse(data), dev)
    eth1 = dev.retrieve("interface", {"name": "eth1"})
    assert (eth1.enabled, eth1.connected) == (False, False)
    eth2 = dev.retrieve("interface", {"name": "eth2"})
    assert (eth2.enabled, eth2.connected) == (True, False)  # up, no link
    assert_no_errors()


def test_ifconfig_then_proc_net_dev_newest_wins(text_data, mocker, assert_no_errors):
    t1 = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)
    t2 = t1 + datetime.timedelta(seconds=5)
    mocker.patch.object(command_parsers.utils, "utc_now", side_effect=[t1, t2])

    dev = DeviceData(id="test_ifconfig_then_proc_net_dev")
    parsed = command_parsers.IfconfigParser.parse(text_data("ifconfig_busybox.txt"))
    command_parsers.IfconfigParser.process(parsed, dev)
    assert dev.retrieve("interface", {"name": "eth0"}).statistics.timestamp == t1

    parsed = command_parsers.ProcNetDevParser.parse(text_data("dev"))
    command_parsers.ProcNetDevParser.process(parsed, dev)
    stats = dev.retrieve("interface", {"name": "eth0"}).statistics

    # One complete sample: the newer /proc/net/dev sample replaced the ifconfig one
    assert stats.timestamp == t2
    assert "recv_fifo" in stats.extra
    assert "rx_overruns" not in stats.extra
    assert_no_errors()


def test_arp_parser(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="test_arp_parser", ip="192.0.2.20")
    assert command_parsers.ArpParser.parse_and_process(text_data("arp_a_multi.txt"), dev)
    assert "arp -a" not in dev.extra

    # The device's own entry is not a neighbor
    rels = {r.remote.ip: r for r in dev.relationships}
    assert set(rels) == {"192.0.2.5", "192.0.2.1", "192.0.2.9"}

    for rel in rels.values():
        assert rel.type == "neighbor_of"
        assert rel.evidence == {"arp"}
        assert rel.local.interface == "eth0"
        assert rel.id
        assert not rel.direction

    assert rels["192.0.2.5"].remote.mac == "B4:96:91:51:3A:67"
    assert rels["192.0.2.5"].state == ""
    assert rels["192.0.2.1"].remote.mac == "00:A0:1E:02:03:04"
    assert rels["192.0.2.1"].remote.hostname == "gateway"
    assert rels["192.0.2.1"].state == "permanent"
    assert rels["192.0.2.9"].remote.mac == ""
    assert rels["192.0.2.9"].state == "incomplete"

    # related.* is still populated
    assert {"192.0.2.5", "192.0.2.1", "192.0.2.9"} <= dev.related.ip
    assert {"B4:96:91:51:3A:67", "00:A0:1E:02:03:04"} <= dev.related.mac
    assert "gateway" in dev.related.hosts
    assert_no_errors()


def test_arp_parser_single_line(text_data, assert_no_errors):
    dev = DeviceData(id="test_arp_parser_single_line")
    command_parsers.ArpParser.process(command_parsers.ArpParser.parse(text_data("arp_a.txt")), dev)
    assert len(dev.relationships) == 1
    rel = dev.relationships[0]
    assert rel.remote.ip == "192.168.0.111"
    assert rel.remote.mac == "B4:96:91:51:3A:67"
    assert rel.local.interface == "eth0"

    # Same entry again (e.g. a second pull): merged, not duplicated
    command_parsers.ArpParser.process(command_parsers.ArpParser.parse(text_data("arp_a.txt")), dev)
    assert len(dev.relationships) == 1
    assert_no_errors()


def test_netstat_vxworks(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="test_netstat_vxworks", ip="192.0.2.20")
    dev.store("interface", Interface(name="lo0", ip="127.0.0.1"))
    # Task listing (e.g. Sage "ti") ran before netstat
    dev.store(
        "processes",
        HostProcess(type="task", pid=0x1C8F0E0, name="tTelnetd", extra={"task_id": "0x1c8f0e0"}),
    )

    data = text_data("netstat_anP.txt")
    parsed = command_parsers.NetstatSocketsVxWorksParser.parse(data)
    assert len(parsed) == 6
    assert command_parsers.NetstatSocketsVxWorksParser.parse_and_process(data, dev)
    assert "netstat -anP" not in dev.extra

    # Tasks: merged with the existing task, one per TID
    assert len(dev.processes) == 4
    telnetd = dev.processes[0]
    assert telnetd.name == "tTelnetd"
    assert telnetd.pid == 0x1C8F0E0
    pids = {p.pid: p for p in dev.processes}
    assert pids[0x1C90000].type == "task"
    assert pids[0x1C90000].extra == {"task_id": "0x1c90000"}

    # Listening sockets -> services
    services = {(s.port, s.transport): s for s in dev.service}
    assert set(services) == {(23, "tcp"), (20000, "tcp"), (161, "udp")}
    assert services[(23, "tcp")].process_name == "tTelnetd"
    assert services[(23, "tcp")].process_pid == 0x1C8F0E0
    assert services[(23, "tcp")].listen_address == "0.0.0.0"
    assert services[(23, "tcp")].status == "open"
    assert services[(20000, "tcp")].extra["task_id"] == "0x1c90000"
    assert services[(161, "udp")].listen_address == "127.0.0.1"
    lo0 = dev.retrieve("interface", {"name": "lo0"})
    assert [s.port for s in lo0.services] == [161]

    # Other sockets -> relationships (one per peer and server port)
    rels = {r.remote.ip: r for r in dev.relationships}
    assert set(rels) == {"192.0.2.5", "192.0.2.9"}
    master = rels["192.0.2.5"]
    assert master.evidence == {"netstat"}
    assert master.direction == "ingress"  # the device listens on 20000
    assert master.protocol == "dnp3"
    assert master.transport == "tcp"
    assert master.local.port == 20000
    assert master.local.ip == "192.0.2.20"
    assert master.count == 2
    assert master.state == "established"
    modbus = rels["192.0.2.9"]
    assert modbus.direction == "egress"
    assert modbus.protocol == "modbus_tcp"
    assert modbus.remote.port == 502
    assert modbus.count == 1

    assert {"192.0.2.5", "192.0.2.9"} <= dev.related.ip
    assert {23, 161, 502, 20000} <= dev.related.ports
    assert "tTelnetd" in dev.related.process
    assert_no_errors()


def test_netstat_vxworks_bad_lines_skipped(text_data, mocker, tmp_path, assert_no_errors):
    """A corrupted socket line does not drop the rest of the socket table (R3-22)."""
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    lines = text_data("netstat_anP.txt").splitlines()
    bad = [
        # letter "O" in the listening port
        "TCP         0      0 0.0.0.0.2O            0.0.0.0.*             LISTEN      0x1c8f0e0",
        # peer port above 65535
        "TCP         0      0 192.0.2.20.1026       192.0.2.77.70000      ESTABLISHED 0x1ca0000",
        # Recv-Q is not a number
        "TCP         x      0 192.0.2.20.1027       192.0.2.78.502        ESTABLISHED 0x1ca0000",
    ]
    data = "\n".join(lines[:2] + bad + lines[2:])
    parser = command_parsers.NetstatSocketsVxWorksParser
    assert len(parser.parse(data)) == 8  # the line with the bad Recv-Q is skipped

    dev = DeviceData(id="test_netstat_vxworks_bad_lines", ip="192.0.2.20")
    assert parser.parse_and_process(data, dev)
    assert {(s.port, s.transport) for s in dev.service} == {
        (23, "tcp"),
        (20000, "tcp"),
        (161, "udp"),
    }
    assert {r.remote.ip for r in dev.relationships} == {"192.0.2.5", "192.0.2.9"}
    assert not {"192.0.2.77", "192.0.2.78"} & dev.related.ip
    assert 70000 not in dev.related.ports
    assert_no_errors()


def test_task_id_to_pid():
    assert command_parsers.task_id_to_pid("0x1c8f0e0") == 0x1C8F0E0
    assert command_parsers.task_id_to_pid("1c8f0e0") == 0x1C8F0E0
    assert command_parsers.task_id_to_pid("tNetTask") is None
    assert command_parsers.task_id_to_pid("0xffffffffffffffff") is None


def test_netstat_linux(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="test_netstat_linux", ip="192.0.2.20")
    dev.store("interface", Interface(name="eth0", ip="192.0.2.20"))
    dev.store("service", Service(protocol="ssh", port=22, status="verified"))
    dev.store("service", Service(protocol="snmp", port=161, transport="tcp"))

    data = text_data("netstat_tulnp.txt")
    parsed = command_parsers.NetstatLinuxParser.parse(data)
    assert len(parsed) == 6
    assert parsed[1]["pid"] is None
    assert parsed[1]["program"] == ""
    assert parsed[2]["local_address"] == "::"
    assert parsed[4]["state"] == ""

    assert command_parsers.NetstatLinuxParser.parse_and_process(data, dev)
    assert "netstat -tulnp" not in dev.extra

    procs = {(p.pid, p.name) for p in dev.processes}
    assert procs == {(612, "dropbear"), (640, "lighttpd"), (655, "snmpd"), (660, "ntpd")}
    assert all(p.type == "process" for p in dev.processes)

    services = {(s.port, s.transport): s for s in dev.service}
    assert set(services) == {
        (22, "tcp"),
        (161, "tcp"),
        (161, "udp"),
        (443, "tcp"),
        (5000, "tcp"),
        (123, "udp"),
    }
    # Merged with the existing ssh service (IPv4 and IPv6 listeners)
    ssh = services[(22, "tcp")]
    assert ssh.protocol == "ssh"
    assert ssh.status == "verified"
    assert ssh.process_name == "dropbear"
    assert ssh.process_pid == 612
    assert ssh.listen_address == "0.0.0.0"
    # udp/161 is not merged into the tcp/161 service
    assert services[(161, "udp")].process_name == "snmpd"
    assert services[(161, "tcp")].process_name == ""
    assert services[(5000, "tcp")].listen_address == "127.0.0.1"
    assert services[(5000, "tcp")].process_pid is None
    # Listener on a specific IP is also added to that interface
    eth0 = dev.retrieve("interface", {"name": "eth0"})
    assert [s.port for s in eth0.services] == [123]

    assert {"dropbear", "lighttpd", "snmpd", "ntpd"} <= dev.related.process
    assert {22, 123, 161, 443, 5000} <= dev.related.ports
    assert not dev.relationships
    assert_no_errors()


def test_netstat_linux_connections(assert_no_errors):
    data = (
        "Proto Recv-Q Send-Q Local Address  Foreign Address    State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22     0.0.0.0:*          LISTEN      612/dropbear\n"
        "tcp        0      0 192.0.2.20:22  192.0.2.5:50122    ESTABLISHED 700/dropbear\n"
        "tcp        0      0 192.0.2.20:22  192.0.2.5:50123    ESTABLISHED 701/dropbear\n"
        "tcp        0      0 192.0.2.20:41000 192.0.2.9:443    TIME_WAIT   -\n"
    )
    dev = DeviceData(id="test_netstat_linux_connections", ip="192.0.2.20")
    command_parsers.NetstatLinuxParser.process(command_parsers.NetstatLinuxParser.parse(data), dev)

    rels = {r.remote.ip: r for r in dev.relationships}
    assert rels["192.0.2.5"].direction == "ingress"
    assert rels["192.0.2.5"].local.port == 22
    assert rels["192.0.2.5"].count == 2
    assert rels["192.0.2.5"].evidence == {"netstat"}
    assert rels["192.0.2.9"].direction == "egress"
    assert rels["192.0.2.9"].protocol == "https"
    assert rels["192.0.2.9"].state == "time_wait"
    assert_no_errors()


def test_netstat_sessions_with_itself_are_not_relationships(assert_no_errors):
    linux = (
        "Proto Recv-Q Send-Q Local Address  Foreign Address    State       PID/Program name\n"
        "tcp        0      0 127.0.0.1:5000 0.0.0.0:*          LISTEN      700/app\n"
        "tcp        0      0 127.0.0.1:5000 127.0.0.1:41000    ESTABLISHED 700/app\n"
        "tcp        0      0 127.0.0.1:41000 127.0.0.1:5000    ESTABLISHED 701/client\n"
        "tcp        0      0 192.0.2.20:41001 192.0.2.20:22    ESTABLISHED 702/ssh\n"
        "tcp        0      0 ::1:41002      ::1:5000           ESTABLISHED 703/client\n"
        "tcp        0      0 192.0.2.20:41003 192.0.2.9:443    ESTABLISHED 704/curl\n"
    )
    dev = DeviceData(id="test_netstat_self", ip="192.0.2.20")
    command_parsers.NetstatLinuxParser.process(
        command_parsers.NetstatLinuxParser.parse(linux), dev
    )
    assert [r.remote.ip for r in dev.relationships] == ["192.0.2.9"]

    vxworks = (
        "INET sockets\n"
        "Prot   Recv-Q Send-Q Local Address         Foreign Address       State       TID\n"
        "TCP         0      0 127.0.0.1.5000        0.0.0.0.*             LISTEN      0x1c90000\n"
        "TCP         0      0 127.0.0.1.5000        127.0.0.1.1030        ESTABLISHED 0x1c90000\n"
        "TCP         0      0 127.0.0.1.1030        127.0.0.1.5000        ESTABLISHED 0x1ca0000\n"
    )
    dev = DeviceData(id="test_netstat_self_vx", ip="192.0.2.20")
    parser = command_parsers.NetstatSocketsVxWorksParser
    parser.process(parser.parse(vxworks), dev)
    assert dev.relationships == []
    assert_no_errors()


@pytest.mark.parametrize(
    ("parser", "data"),
    [
        (
            command_parsers.NetstatLinuxParser,
            "Proto Recv-Q Send-Q Local Address  Foreign Address  State   PID/Program name\n"
            "tcp        0      0 0.0.0.0:53     0.0.0.0:*        LISTEN  301/dnsmasq\n"
            "tcp        0      0 0.0.0.0:20000  0.0.0.0:*        LISTEN  412/dnp3d\n"
            "udp        0      0 0.0.0.0:53     0.0.0.0:*                301/dnsmasq\n"
            "udp        0      0 0.0.0.0:20000  0.0.0.0:*                412/dnp3d\n",
        ),
        (
            command_parsers.NetstatSocketsVxWorksParser,
            "INET sockets\n"
            "Prot   Recv-Q Send-Q Local Address    Foreign Address  State   TID\n"
            "TCP         0      0 0.0.0.0.53       0.0.0.0.*        LISTEN  0x1c80000\n"
            "TCP         0      0 0.0.0.0.20000    0.0.0.0.*        LISTEN  0x1c90000\n"
            "UDP         0      0 0.0.0.0.53       0.0.0.0.*                0x1c80000\n"
            "UDP         0      0 0.0.0.0.20000    0.0.0.0.*                0x1c90000\n",
        ),
    ],
)
def test_netstat_tcp_and_udp_listeners_on_one_port_are_exported(parser, data, assert_no_errors):
    """tcp/N and udp/N are two services in export() and elastic(), not one (R5-2)."""
    dev = DeviceData(id="test_netstat_tcp_udp", ip="192.0.2.20")
    parser.process(parser.parse(data), dev)
    expected = {(53, "tcp"), (53, "udp"), (20000, "tcp"), (20000, "udp")}
    assert {(s.port, s.transport) for s in dev.service} == expected

    exported = dev.export()["service"]
    assert len(exported) == 4
    assert {(s["port"], s["transport"]) for s in exported} == expected
    assert {(s["port"], s["transport"]) for s in dev.elastic()["service"]} == expected
    assert_no_errors()


def test_out_of_range_pid_and_metric_never_reach_elasticsearch(assert_no_errors):
    """A corrupted PID or route metric does not reject the host document (R5-10)."""
    big = "99999999999999999999"
    netstat = (
        "Proto Recv-Q Send-Q Local Address  Foreign Address  State   PID/Program name\n"
        "tcp        0      0 0.0.0.0:80     0.0.0.0:*        LISTEN  640/lighttpd\n"
        f"tcp        0      0 0.0.0.0:22     0.0.0.0:*        LISTEN  {big}/dropbear\n"
    )
    route = (
        f"default via 192.0.2.1 dev eth0 metric {big}\n"
        "192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.20\n"
    )
    dev = DeviceData(id="test_out_of_range", ip="192.0.2.20")
    parser = command_parsers.NetstatLinuxParser
    parser.process(parser.parse(netstat), dev)
    command_parsers.IpRouteParser.process(command_parsers.IpRouteParser.parse(route), dev)

    doc = dev.elastic()
    ints = []

    def walk(value):
        if isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
        elif isinstance(value, int) and not isinstance(value, bool):
            ints.append(value)

    walk(doc)
    assert ints
    assert all(-(2**63) <= v < 2**63 for v in ints)

    # The process, service and route are still stored, with the raw value in extra
    procs = {p.name: p for p in dev.processes}
    assert set(procs) == {"lighttpd", "dropbear"}
    assert procs["dropbear"].pid is None
    assert procs["dropbear"].extra["out_of_range"] == {"pid": big}
    assert procs["lighttpd"].pid == 640
    ssh = dev.retrieve("service", {"port": 22})
    assert ssh.process_pid is None
    assert ssh.extra["out_of_range"] == {"process_pid": big}
    default = {r.destination: r for r in dev.routes}["0.0.0.0/0"]
    assert (default.gateway, default.metric) == ("192.0.2.1", None)
    assert default.extra["out_of_range"] == {"metric": big}
    assert_no_errors()


def test_ip_route_parser_multipath_and_junk_lines():
    data = (
        "default proto static metric 100\n"
        "\tnexthop via 10.0.0.1 dev eth0 weight 1\n"
        "\tnexthop via 10.0.1.1 dev eth1 weight 1\n"
        "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n"
        "BusyBox v1.31.1 (2020-01-01) multi-call binary.\n"
        "root@x3:~\n"
    )
    dev = DeviceData(id="test_ip_route_multipath")
    assert command_parsers.IpRouteParser.parse_and_process(data, dev)
    routes = {r.destination: r for r in dev.routes}
    assert set(routes) == {"0.0.0.0/0", "10.0.0.0/24"}
    default = routes["0.0.0.0/0"]
    assert (default.gateway, default.interface, default.type) == ("10.0.0.1", "eth0", "static")
    assert [h["via"] for h in default.extra["nexthops"]] == ["10.0.0.1", "10.0.1.1"]
    assert routes["10.0.0.0/24"].type == "connected"

    junk = DeviceData(id="test_ip_route_junk")
    command_parsers.IpRouteParser.parse_and_process("root@x3:~\nip: can't find device 'foo'", junk)
    assert junk.routes == []


def test_ip_route_parser(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    data = text_data("ip_route.txt")

    parsed = command_parsers.IpRouteParser.parse(data)
    assert len(parsed) == 6
    assert parsed[0] == {
        "destination": "default",
        "via": "192.0.2.1",
        "dev": "eth0",
        "proto": "static",
        "metric": "100",
    }
    assert parsed[3]["flags"] == ["linkdown"]
    assert parsed[4] == {"type": "blackhole", "destination": "203.0.113.0/24"}

    dev = DeviceData(id="test_ip_route_parser")
    assert command_parsers.IpRouteParser.parse_and_process(data, dev)
    assert "ip route" not in dev.extra

    routes = {r.destination: r for r in dev.routes}
    assert len(routes) == 6
    default = routes["0.0.0.0/0"]
    assert default.gateway == "192.0.2.1"
    assert default.interface == "eth0"
    assert default.metric == 100
    assert default.protocol == "static"
    assert default.type == "static"

    connected = routes["192.0.2.0/24"]
    assert connected.gateway == ""
    assert connected.type == "connected"
    assert connected.protocol == "kernel"
    assert connected.extra == {"scope": "link", "src": "192.0.2.20"}

    assert routes["10.8.0.0/24"].type == "dynamic"
    assert routes["198.51.100.0/24"].flags == "linkdown"
    assert routes["203.0.113.0/24"].type == "blackhole"
    assert routes["203.0.113.128/25"].type == "blackhole"
    assert routes["203.0.113.128/25"].extra == {"action": "unreachable"}

    # Gateways feed related.ip
    assert {"192.0.2.1", "10.8.0.5"} <= dev.related.ip

    # Parsing the same table again does not duplicate routes
    command_parsers.IpRouteParser.process(parsed, dev)
    assert len(dev.routes) == 6
    assert_no_errors()


def test_ls_recursive_parser_store(assert_no_errors):
    listing = (
        "/etc:\n"
        "-rw-r--r--    1 0        0              194 Wed Jan 01 00:00:00 1970 interfaces\n"
        "drwxr-xr-x    2 0        0                0 Wed Jan 01 00:00:00 1970 init.d\n"
        "lrwxrwxrwx    1 0        0               12 Wed Jan 01 00:00:00 1970 "
        "mtab -> /proc/mounts\n"
    )
    dev = DeviceData(id="test_ls_recursive_parser_store")
    # A file already known (e.g. pulled) is merged by path, not duplicated
    dev.store(
        "files",
        File(path=PurePosixPath("/etc/interfaces"), description="network config"),
        lookup="path",
    )

    parsed = command_parsers.LsRecursiveParser.parse(listing)
    assert len(parsed) == 3
    command_parsers.LsRecursiveParser.process(parsed, dev)
    command_parsers.LsRecursiveParser.process(parsed, dev)  # second listing: no duplicates

    assert len(dev.files) == 3
    files = {str(f.path): f for f in dev.files}
    assert files["/etc/interfaces"].description == "network config"
    assert files["/etc/interfaces"].size == 194
    assert files["/etc/interfaces"].owner == "root"
    assert files["/etc/init.d"].type == "dir"
    assert files["/etc/mtab"].type == "symlink"
    assert str(files["/etc/mtab"].target_path) == "/proc/mounts"
    assert "/etc/interfaces" in dev.related.files
    assert_no_errors()


def test_dateparser(text_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.DateParser.parse("")

    assert command_parsers.DateParser.parse(text_data("date.txt")).year == 2019

    dev = DeviceData(id="test_dateparser")
    assert command_parsers.DateParser.parse_and_process(text_data("date.txt"), dev)
    assert dev.geo.timezone == "UTC"
    assert dev.extra["current_time"].year == 2019
    assert_no_errors()


def test_parse_etc_passwd(text_data, json_data, assert_no_errors):
    assert command_parsers.EtcPasswdParser.parse("") == []

    results = command_parsers.EtcPasswdParser.parse(text_data("etc_passwd.txt"))
    assert results == json_data("expected_etc_passwd.json")
    assert_no_errors()


def test_process_etc_passwd(json_data, mocker, tmp_path, assert_no_errors):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})

    assert not command_parsers.EtcPasswdParser.process([], DeviceData())

    dev = DeviceData(id="process_etc_passwd")
    data = json_data("expected_etc_passwd.json")
    command_parsers.EtcPasswdParser.process(data, dev)
    assert len(dev.users) == 5
    assert len(dev.related.user) == 5
    assert len(dev.related.files) == 3
    assert "/bin/sh" in dev.related.files
    assert "ftp" in dev.related.user
    assert dev.users[4].name == "admin"
    assert dev.users[4].description == "Linux User"
    assert_no_errors()


def test_etc_passwd_password_hash_never_stored(mocker, tmp_path, caplog):
    """Bug fix: a password hash in /etc/passwd was stored in dev.extra and parsed/passwd.json."""
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    dev = DeviceData(id="etc_passwd_hash")
    text = (
        "root:$1$ab$PasswdHashCanary:0:0:root:/root:/bin/sh\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "guest::100:100:Guest:/home/guest:/bin/sh\n"
        "locked:!:101:101::/home/locked:/bin/sh\n"
        "bad:BadLineCanary:5\n"
    )
    assert command_parsers.EtcPasswdParser.parse_and_process(text, dev)

    users = dev.extra["/etc/passwd"]
    assert [
        (u["login_name"], u["password_in_shadow"], u["password_set"], u["password_empty"])
        for u in users
    ] == [
        ("root", False, True, False),
        ("daemon", True, False, False),
        ("guest", False, False, True),
        ("locked", False, False, False),
    ]
    assert all("password" not in u for u in users)
    assert sorted(u.name for u in dev.users) == ["daemon", "guest", "locked", "root"]
    assert "line 5: 3 fields" in caplog.text
    assert "BadLineCanary" not in caplog.text

    assert "PasswdHashCanary" not in str(dev.export())
    parsed = tmp_path / "etc_passwd_hash" / "parsed" / "passwd.json"
    assert "PasswdHashCanary" not in parsed.read_text(encoding="utf-8")


# TODO: WIP on IpAddrParser
# def test_parse_ipaddr(text_data, json_data, assert_no_errors):
#     assert command_parsers.IpAddrParser.parse("") == {}
#
#     parsed = command_parsers.IpAddrParser.parse(text_data("ip_addr.txt"))
#     assert parsed == {}
#     # assert parsed == json_data("expected_parsed_ip_addr.json")
#     assert_no_errors()


def test_sshd_config_parser(text_data, json_data, assert_no_errors):
    assert not command_parsers.SshdConfigParser.parse("")

    results = command_parsers.SshdConfigParser.parse(text_data("sshd_config"))
    assert results == json_data("expected_sshd_config.json")
    assert_no_errors()


def test_netstat_linux_ipv4_mapped_and_ipv6_sockets(assert_no_errors):
    """R2-44/R2-43: dual-stack (::ffff:a.b.c.d) and IPv6 sockets keep the whole table."""
    data = (
        "Proto Recv-Q Send-Q Local Address  Foreign Address    State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22     0.0.0.0:*          LISTEN      612/dropbear\n"
        "tcp6       0      0 ::ffff:127.0.0.1:8005 :::*        LISTEN      700/java\n"
        "tcp        0      0 0.0.0.0:443    0.0.0.0:*          LISTEN      640/lighttpd\n"
        "tcp6       0      0 ::ffff:192.0.2.20:502 :::*        LISTEN      650/modbusd\n"
        "tcp6  0  0 ::ffff:192.0.2.20:443 ::ffff:192.0.2.60:40000 ESTABLISHED 640/lighttpd\n"
        "tcp6  0  0 ::ffff:192.0.2.20:502 ::ffff:192.0.2.20:50000 ESTABLISHED 650/modbusd\n"
        "tcp6       0      0 2001:db8::10:443 2001:db8::50:51235 ESTABLISHED 640/lighttpd\n"
    )
    dev = DeviceData(id="test_netstat_mapped")
    dev.store("interface", Interface(name="eth0", ip="192.0.2.20"))
    command_parsers.NetstatLinuxParser.process(command_parsers.NetstatLinuxParser.parse(data), dev)

    assert {s.port for s in dev.service} == {22, 443, 502, 8005}
    assert {s.listen_address for s in dev.service if s.port == 8005} == {"127.0.0.1"}
    # the mapped listen address matches the IPv4 interface
    assert [(s.port, s.listen_address) for s in dev.interface[0].services] == [(502, "192.0.2.20")]
    # the mapped session with the device itself is skipped
    assert {r.remote.ip for r in dev.relationships} == {"192.0.2.60", "2001:db8::50"}
    # mixed IPv4/IPv6 related.ip must not break the exports
    related_ip = dev.export()["related"]["ip"]
    assert related_ip.index("192.0.2.60") < related_ip.index("2001:db8::50")
    assert "2001:db8::50" in dev.elastic()["related"]["ip"]
    assert_no_errors()
