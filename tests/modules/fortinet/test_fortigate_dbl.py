"""
Tests for the FortiGate "debug log" parsers with synthetic sections.

Formats follow the Fortinet documentation: "diagnose hardware deviceinfo nic"
(FortiOS 6.2 cookbook, "Displaying detail Hardware NIC information"), "diagnose
sys top" (FortiOS 6.2.6 cookbook) and "diagnose ip arp list" (FortiOS 6.4
administration guide), and the FG100F-style "get hardware nic" output the
parser was written against. All values are made up.
"""

from datetime import timedelta

import pytest

from peat import DeviceData, config, datastore
from peat.modules.fortinet import fortigate_dbl
from peat.modules.fortinet.fortigate_dbl import (
    crashlog_reason,
    fg_file_category,
    parse_fg_debug_log,
    parse_fg_nic,
    parse_fg_top,
    process_fg_debug_log,
)

# Fortinet-documented format ("diagnose hardware deviceinfo nic lan")
NIC_DOC_FORMAT = """\
Description     :Marvell Ethernet controller
Current_HWaddr   00:09:0f:00:00:01
Permanent_HWaddr 00:09:0f:00:00:01
State            up
Link             up
Speed            100
Duplex           full
Rx_Packets=5685708
Tx_Packets=4107073
Rx_Bytes=617908014
Tx_Bytes=1269751248
Rx_Errors=0
Tx_Errors=1
Rx_Dropped=2
Tx_Dropped=0
Multicast=12
Collisions=3
Rx_Length_Errors=0
Rx_CRC_Errors=4
Tx_Window_Errors=5
"""

# FG100F-style format ("get hardware nic port1")
NIC_FG100F_FORMAT = """\
Description          :FortiASIC NP6XLITE Adapter
Driver Name          :FortiASIC NP6XLITE Driver
Current_HWaddr        00:09:0f:00:00:02
Permanent_HWaddr      00:09:0f:00:00:02
========== Link Status ==========
Admin                :up
netdev status        :up
speed_setting        :1000
duplex               :full
============ Counters ===========
rx pkts              :1000
rx bytes             :64000
tx pkts              :900
tx bytes             :57600
"""

TOP = """\
Run Time:  4 days, 5 hours and 29 minutes
1U, 0N, 0S, 99I, 0WA, 0HI, 0SI, 0ST; 1866T, 1113F
          miglogd      191      S       0.3     6.3
        ipshelper      164      S <     0.3     1.2
           newcli    16087      R       0.1     0.6
           zombie       99      Z       0.0     0.0
"""

CRASHLOG = """\
1: 2024-08-01 10:00:00 <07893> application httpsd
2: 2024-08-01 10:00:00 <07893> *** signal 11 (Segmentation fault) received ***
3: 2024-08-01 10:05:00 the killed daemon is /bin/sflowd: status=0x0
4: 2024-08-01 10:06:00 process_id=1028, process_name="httpsd" restarted
"""

ARP = """\
index=5 ifname=port1 192.0.2.1 00:09:0f:00:00:aa state=00000002 use=170 confirm=170 ref=3
index=5 ifname=port1 192.0.2.7 00:00:00:00:00:00 state=00000020 use=3 confirm=3 update=3 ref=1
index=12 ifname=vlan100 198.51.100.20 00:09:0f:00:00:bb state=00000004 use=5 ref=2
"""

RTCACHE = """\
family=02 tab=254 vrf=0 vwl_id=0 type=01 tos=0 flag=00000200
192.0.2.10@0->203.0.113.7@3(port1) gwy=192.0.2.254 prefsrc=192.0.2.10
ci: ref=0 lastused=0 expire=0 err=00000000 used=1 br=0 pmtu=1500
family=02 tab=254 vrf=0 vwl_id=0 type=01 tos=0 flag=00000200
192.0.2.10@0->192.0.2.20@3(port1) gwy=0.0.0.0 prefsrc=192.0.2.10
"""

# "fnsysctl ls -l": the modification time comes before the size
LS_TMP = """\
-rw-r--r--    1 0        0       Tue Sep  9 00:00:00 2025          12 KEY-FILE
lrwxrwxrwx    1 0        0       Tue Sep  9 00:00:00 2025          10 KEY-LINK -> KEY-FILE
drwxr-xr-x    2 0        0       Tue Sep  9 00:00:00 2025           0 log
"""


def _debug_log(**sections: str) -> str:
    out = []
    for name, text in sections.items():
        out.append(f"### {name}")
        out.append(text)
    return "\n".join(out)


def test_parse_fg_nic_both_formats():
    doc = parse_fg_nic(NIC_DOC_FORMAT.splitlines())
    assert doc["state"] == "up"
    assert doc["link"] == "up"
    assert doc["speed"] == "100"
    assert doc["rx_packets"] == "5685708"
    assert doc["current_hwaddr"] == "00:09:0f:00:00:01"

    fg100f = parse_fg_nic(NIC_FG100F_FORMAT.splitlines())
    assert fg100f["admin"] == "up"
    assert fg100f["rx pkts"] == "1000"
    assert fg100f["description"] == "FortiASIC NP6XLITE Adapter"


def test_process_fg_interfaces_documented_format():
    """Bug fix: the documented format lost the counters, speed, admin and link state."""
    dev = DeviceData()
    db_log = parse_fg_debug_log(
        _debug_log(**{"get hardware nic lan": NIC_DOC_FORMAT, "get hardware nic port1": ""})
    )
    fortigate_dbl.process_fg_interfaces(db_log, dev)

    lan = next(i for i in dev.interface if i.name == "lan")
    assert lan.enabled is True
    assert lan.connected is True
    assert lan.speed == 100
    assert lan.duplex == "full"
    assert lan.mac == "00:09:0F:00:00:01"

    stats = lan.statistics
    assert stats.timestamp is not None
    assert stats.timestamp.tzinfo is not None
    assert stats.ingress.packets == 5685708
    assert stats.egress.packets == 4107073
    assert stats.ingress.bytes == 617908014
    assert stats.egress.bytes == 1269751248
    assert stats.ingress.errors == 0
    assert stats.egress.errors == 1
    assert stats.ingress.dropped == 2
    assert stats.egress.dropped == 0
    assert stats.ingress.crc_errors == 4
    assert stats.ingress.multicast_packets == 12
    assert stats.collisions == 3
    assert stats.extra == {"rx_length_errors": 0, "tx_window_errors": 5}


def test_process_fg_interfaces_fg100f_format():
    dev = DeviceData()
    db_log = {"get hardware nic port1": NIC_FG100F_FORMAT.splitlines()}
    fortigate_dbl.process_fg_interfaces(db_log, dev)

    port1 = dev.interface[0]
    assert port1.enabled is True
    assert port1.connected is True
    assert port1.speed == 1000
    assert port1.statistics.ingress.packets == 1000
    assert port1.statistics.ingress.bytes == 64000
    assert port1.statistics.egress.packets == 900
    assert port1.statistics.egress.bytes == 57600
    for key in ("received_packets", "received_bytes", "transmitted_packets", "transmitted_bytes"):
        assert key not in port1.extra


def test_parse_fg_top():
    run_time, processes = parse_fg_top(TOP.splitlines())
    assert run_time == timedelta(days=4, hours=5, minutes=29)

    procs = {p.name: p for p in processes}
    assert set(procs) == {"miglogd", "ipshelper", "newcli", "zombie"}
    miglogd = procs["miglogd"]
    assert miglogd.pid == 191
    assert miglogd.type == "process"
    assert miglogd.state == "sleeping"
    assert miglogd.cpu_percent == 0.3
    assert miglogd.memory_percent == 6.3
    assert miglogd.extra == {"state_code": "S"}
    assert procs["ipshelper"].extra == {"state_code": "S", "high_priority": True}
    assert procs["ipshelper"].memory_percent == 1.2
    assert procs["newcli"].state == "running"
    assert procs["zombie"].state == "zombie"


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


@pytest.mark.usefixtures("out_config")
def test_process_fg_debug_log():
    dev = DeviceData()
    raw = _debug_log(
        **{
            "diagnose sys top-all 1 100 1": TOP,
            "diagnose debug crashlog read": CRASHLOG,
            "diagnose ip arp list": ARP,
            "diagnose ip rtcache list": RTCACHE,
            "fnsysctl ls -l /tmp": LS_TMP,
        }
    )
    process_fg_debug_log(parse_fg_debug_log(raw), dev)

    # top
    assert dev.uptime == timedelta(days=4, hours=5, minutes=29)
    assert len(dev.processes) == 4
    assert {"miglogd", "ipshelper", "newcli"} <= dev.related.process

    # crashlog
    events = {e.sequence: e for e in dev.event}
    assert events[2].reason == "signal 11 (Segmentation fault)"
    assert events[3].reason == "killed daemon is /bin/sflowd: status=0x0"
    assert events[1].reason == ""
    assert events[4].extra["process_id"] == 1028
    assert events[4].extra["process_name"] == "httpsd"
    assert "httpsd" in dev.related.process

    # ARP
    neighbors = {r.remote.ip: r for r in dev.relationships if r.type == "neighbor_of"}
    assert set(neighbors) == {"192.0.2.1", "192.0.2.7", "198.51.100.20"}
    gw = neighbors["192.0.2.1"]
    assert gw.evidence == {"arp"}
    assert gw.local.interface == "port1"
    assert gw.remote.mac == "00:09:0F:00:00:AA"
    assert gw.state == "reachable"
    assert gw.extra["state_code"] == "00000002"
    assert neighbors["192.0.2.7"].remote.mac == ""  # incomplete entry
    assert neighbors["192.0.2.7"].state == "failed"
    assert neighbors["198.51.100.20"].state == "stale"
    assert neighbors["198.51.100.20"].local.interface == "vlan100"

    # route cache
    routes = {r.destination: r for r in dev.routes}
    assert set(routes) == {"203.0.113.7/32", "192.0.2.20/32"}
    assert routes["203.0.113.7/32"].gateway == "192.0.2.254"
    assert routes["203.0.113.7/32"].interface == "port1"
    assert routes["203.0.113.7/32"].type == "cache"
    assert routes["192.0.2.20/32"].gateway == ""

    # files
    files = {str(f.path): f for f in dev.files}
    assert set(files) == {"/tmp/KEY-FILE", "/tmp/KEY-LINK", "/tmp/log"}
    assert files["/tmp/KEY-LINK"].type == "symlink"
    assert files["/tmp/log"].type == "dir"

    # Processing the same log again doesn't duplicate the list items
    process_fg_debug_log(parse_fg_debug_log(raw), dev)
    assert len(dev.processes) == 4
    assert len(dev.files) == 3
    assert len([r for r in dev.relationships if r.type == "neighbor_of"]) == 3


def test_crashlog_reason():
    assert crashlog_reason("*** signal 6 (Aborted) received ***") == "signal 6 (Aborted)"
    assert crashlog_reason("application httpsd") == ""
    assert crashlog_reason("Process killed due to low memory") == "killed due to low memory"


def test_fg_file_category():
    assert fg_file_category("/data/config/sys_global.conf.gz") == {"configuration"}
    assert fg_file_category("/var/log/elog") == {"log"}
    assert fg_file_category("/tmp/log/crash.txt") == {"log"}
    assert fg_file_category("/tmp/KEY-FILE") == set()
