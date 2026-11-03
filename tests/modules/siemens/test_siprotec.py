"""
Tests for the SIPROTEC 4 module with synthetic SNMP data in the shape returned
by ``Siprotec._get_snmp_data()`` (``snmp_walk()`` returns ``{object name: prettyPrint}``,
names and enumerations from the MIBs in ``peat/modules/siemens/mibs/``).
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from peat import DeviceData, Siprotec
from peat.modules.siemens import siprotec

T0 = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)


def _module_info(iec_62439: dict | None = None) -> dict:
    return {
        "sysDescr": "SIPROTEC EN100 V04.29.01_22",
        "sysName": "EN100 7SJ61",
        "sysObjectID": "1.3.6.1.4.1.22638",
        "module_firmware_version": "V04.29.01_22",
        "mac_address": "00:09:8E:01:02:03",
        "netmask": "255.255.255.0",
        "ifAdminStatus": "up",
        "ifOperStatus": "lowerLayerDown",
        "snmp_stats": {
            "snmpInBadVersions": 1,
            "snmpInBadCommunityNames": 42,
            "snmpInBadCommunityUses": 3,
        },
        "sip_ethernet": {
            "nRxTelInt": "1000",
            "nRxTelTask": "20",
            "nRxBMsg": "300",
            "nRxMMsg": "400",
            "nRxCRCErrFrm": "2",
            "nTxTel": "900",
            "nFrameLoss": "1",
            "nTxLateCollision": "0",
            "linkUpChan1": "linkUp",
            "linkUpChan2": "linkDown",
            "activChannel": "nonrelevant",
            "optLevel1": "2500",
            "optLevel2": "0",
            "rstpRoleChannel1": "root",
            "rstpRoleChannel2": "alternate",
            "rstpStatusChannel1": "forwarding",
            "rstpStatusChannel2": "discarding",
            "sntpPrimaryServer": "192.0.2.123",
            "sntpSecondaryServer": "0.0.0.0",
            "sntpClockmaster": "primary",
            "modCPUload": "12",
            "mallocSize": "2048",
        },
        "sip_goose": {"nRxMatchedTel": "5000", "nRxMismatchTel": "7"},
        "sip_optical": {
            "opMode": "switch",
            "bridgePrior": "32768",
            "rstpNeighbourPortA": "0x00098e0a0b0c",
            "rstpNeighbourPortB": "0x000000000000",
            "channel": "1",  # the index of the table is 0..1: Ch2
            "txPacket": "11",
            "rxPacket": "12",
            "filterCrcErrCnt": "1",
            "filterLenErrCnt": "0",
            "vendor": "Avago",
            "partNo": "AFBR-5803",
            "temperature": "41.5 C",
        },
        "iec_62439": iec_62439 or {},
    }


def test_process_snmp_data_rstp():
    dev = DeviceData(ip="192.0.2.60")
    system = {"system_uptime": 8640000}  # 1 day in TimeTicks (1/100 s)
    unmapped = siprotec.process_snmp_data(dev, _module_info(), system, timestamp=T0)

    # Bug fix: sysUpTime is hundredths of a second
    assert dev.uptime == timedelta(days=1)
    assert dev.start_time == T0 - timedelta(days=1)
    assert "system_uptime" not in system

    ifaces = {i.name: i for i in dev.interface}
    en100 = ifaces["EN100"]
    assert en100.ip == "192.0.2.60"
    assert en100.mac == "00:09:8E:01:02:03"
    assert en100.subnet_mask == "255.255.255.0"
    assert en100.enabled is True
    assert en100.connected is False
    assert en100.extra["oper_status"] == "lowerLayerDown"
    stats = en100.statistics
    assert stats.timestamp == T0
    assert stats.egress.packets == 900
    assert stats.ingress.broadcast_packets == 300
    assert stats.ingress.multicast_packets == 400
    assert stats.ingress.crc_errors == 2
    assert stats.ingress.dropped == 1
    assert stats.extra["n_rx_tel_int"] == 1000
    assert stats.extra["n_tx_late_collision"] == 0
    assert en100.redundancy.protocol == "rstp"
    assert en100.redundancy.members == ["Ch1", "Ch2"]

    ch1, ch2 = ifaces["Ch1"], ifaces["Ch2"]
    assert ch1.physical is True
    assert ch1.connected is True
    assert ch2.connected is False
    assert ch1.extra["optical_rx_level_mv"] == 2500
    assert ch1.redundancy.protocol == "rstp"
    assert ch1.redundancy.role == "root"
    assert ch1.redundancy.state == "forwarding"
    assert ch1.redundancy.partner == "00:09:8E:0A:0B:0C"
    assert ch2.redundancy.role == "alternate"
    assert ch2.redundancy.partner == ""
    # SipOptical table row of channel index 1 (Ch2)
    assert ch1.statistics.ingress.packets is None
    assert ch2.statistics.ingress.packets == 12
    assert ch2.statistics.egress.packets == 11
    assert ch2.statistics.ingress.crc_errors == 1
    assert ch2.statistics.extra == {"filter_len_err_cnt": 0}
    assert ch2.description.vendor.name == "Avago"
    assert ch2.extra["transceiver"] == {"temperature": "41.5 C"}

    goose = dev.retrieve("service", {"protocol": "goose"})
    assert goose.statistics.ingress.messages == 5000
    assert goose.statistics.ingress.errors is None
    assert goose.statistics.extra == {"mismatched_telegrams": 7}

    snmp = dev.retrieve("service", {"protocol": "snmp"})
    assert snmp.statistics.connections.authentication_failures == 42
    assert snmp.statistics.extra == {"bad_versions": 1, "bad_community_uses": 3}

    assert [(s.protocol, s.address, s.priority, s.selected) for s in dev.clock.sources] == [
        ("sntp", "192.0.2.123", 1, True)
    ]
    assert dev.clock.source == "sntp"

    # Moved keys are gone, identity and resources are kept
    assert set(unmapped) == {
        "sysDescr",
        "sysName",
        "sysObjectID",
        "module_firmware_version",
        "sip_ethernet",
        "sip_optical",
    }
    assert unmapped["sip_ethernet"] == {"modCPUload": "12", "mallocSize": "2048"}
    assert unmapped["sip_optical"] == {"opMode": "switch", "bridgePrior": "32768"}


def test_process_snmp_data_optical_channel_0():
    info = _module_info()
    info["sip_optical"]["channel"] = "0"
    dev = DeviceData(ip="192.0.2.60")
    unmapped = siprotec.process_snmp_data(dev, info, {}, timestamp=T0)
    ifaces = {i.name: i for i in dev.interface}
    assert ifaces["Ch1"].statistics.ingress.packets == 12
    assert ifaces["Ch1"].description.model == "AFBR-5803"
    assert ifaces["Ch1"].extra["transceiver"] == {"temperature": "41.5 C"}
    assert ifaces["Ch2"].statistics.ingress.packets is None
    assert ifaces["Ch2"].description.model == ""
    assert unmapped["sip_optical"] == {"opMode": "switch", "bridgePrior": "32768"}


def test_process_snmp_data_optical_channel_unknown():
    info = _module_info()
    info["sip_optical"]["channel"] = "2"  # not a channel index of the MIB (0..1)
    dev = DeviceData(ip="192.0.2.60")
    unmapped = siprotec.process_snmp_data(dev, info, {}, timestamp=T0)
    ifaces = {i.name: i for i in dev.interface}
    assert ifaces["Ch1"].statistics.ingress.packets is None
    assert ifaces["Ch2"].statistics.ingress.packets is None
    # The row is kept in extra
    assert unmapped["sip_optical"] == {
        "opMode": "switch",
        "bridgePrior": "32768",
        "channel": "2",
        "txPacket": "11",
        "rxPacket": "12",
        "filterCrcErrCnt": "1",
        "filterLenErrCnt": "0",
        "vendor": "Avago",
        "partNo": "AFBR-5803",
        "temperature": "41.5 C",
    }


def test_process_snmp_data_prp():
    info = _module_info(
        {
            "nodeType": "prpmode1",
            "nodeName": "SIP-1",
            "adapterActiveA": "active",
            "adapterActiveB": "notActive",
            "switchingEndNode": "prpnode",
        }
    )
    dev = DeviceData(ip="192.0.2.61")
    siprotec.process_snmp_data(dev, info, {}, timestamp=T0)
    ifaces = {i.name: i for i in dev.interface}
    assert ifaces["EN100"].redundancy.protocol == "prp"
    assert ifaces["EN100"].redundancy.mode == "prpmode1"
    assert ifaces["EN100"].redundancy.members == ["Ch1", "Ch2"]
    assert ifaces["EN100"].redundancy.extra["node_name"] == "SIP-1"
    assert (ifaces["Ch1"].redundancy.lan, ifaces["Ch1"].redundancy.state) == ("A", "active")
    assert (ifaces["Ch2"].redundancy.lan, ifaces["Ch2"].redundancy.state) == ("B", "inactive")
    assert dev.uptime is None


def test_process_snmp_data_keeps_unmapped_rstp_neighbours():
    # PRP mode: the RSTP neighbour MAC of port A is not mapped to any partner, so it
    # stays in extra; the all-zero MAC of port B holds no information and is dropped
    info = _module_info({"nodeType": "prpmode1", "adapterActiveA": "active"})
    dev = DeviceData(ip="192.0.2.63")
    unmapped = siprotec.process_snmp_data(dev, info, {}, timestamp=T0)
    assert all(i.redundancy.partner == "" for i in dev.interface)
    assert unmapped["sip_optical"] == {
        "opMode": "switch",
        "bridgePrior": "32768",
        "rstpNeighbourPortA": "0x00098e0a0b0c",
    }

    # Point-to-point mode with inactive RSTP roles: same
    info = _module_info()
    info["sip_ethernet"].update(
        {
            "rstpRoleChannel1": "nonStp",
            "rstpRoleChannel2": "nonStp",
            "activChannel": "activChannel1",
        }
    )
    unmapped = siprotec.process_snmp_data(DeviceData(ip="192.0.2.64"), info, {}, timestamp=T0)
    assert unmapped["sip_optical"]["rstpNeighbourPortA"] == "0x00098e0a0b0c"
    assert "rstpNeighbourPortB" not in unmapped["sip_optical"]


def test_process_snmp_data_point_to_point():
    info = _module_info()
    info["sip_ethernet"].update(
        {
            "rstpRoleChannel1": "nonStp",
            "rstpRoleChannel2": "nonStp",
            "activChannel": "activChannel2",
        }
    )
    dev = DeviceData(ip="192.0.2.62")
    siprotec.process_snmp_data(dev, info, {}, timestamp=T0)
    ifaces = {i.name: i for i in dev.interface}
    assert ifaces["EN100"].redundancy.protocol == "failover"
    assert ifaces["Ch1"].redundancy.state == "standby"
    assert ifaces["Ch2"].redundancy.state == "active"


def test_snmp_oids_and_status(mocker):
    """Bug fixes: SNMPv2-MIB bad community OIDs, ifOperStatus values, sysName slicing."""
    requested = []

    def _get(oid, *args, **kwargs):  # noqa: ARG001
        requested.append(oid)
        values = {
            "1.3.6.1.2.1.2.2.1.7.2": "1",
            "1.3.6.1.2.1.2.2.1.8.2": "5",
            "1.3.6.1.2.1.1.5.0": "EN100",
            "1.3.6.1.2.1.11.4.0": "9",
            "1.3.6.1.2.1.1.3.0": "100",
        }
        if isinstance(oid, str) and oid in values:
            return [{"value_string": values[oid]}]
        return []

    snmp = MagicMock()
    snmp.get.side_effect = _get
    mocker.patch.object(siprotec, "SNMP", return_value=snmp)
    mocker.patch.object(siprotec, "snmp_walk", return_value={})

    module_info, system = Siprotec._get_snmp_data("192.0.2.60", timeout=0.1)
    assert "1.3.6.1.2.1.11.4.0" in requested
    assert "1.3.6.1.2.1.11.5.0" in requested
    assert module_info["ifAdminStatus"] == "up"
    assert module_info["ifOperStatus"] == "dormant"
    assert module_info["snmp_stats"]["snmpInBadCommunityNames"] == 9

    # _pull(): sysName without a space keeps all characters
    mocker.patch.object(Siprotec, "_get_webmonitor_data", return_value=False)
    mocker.patch.object(Siprotec, "_get_snmp_data", return_value=(module_info, system))
    dev = DeviceData(ip="192.0.2.60")
    dev._runtime_options = {"snmp": {"community": "public"}}
    Siprotec._pull(dev)
    assert "module_EN100" in dev.extra
    assert dev.uptime == timedelta(seconds=1)


def test_webmonitor_version():
    parsed = Siprotec._parse_ver_txt("V04.29.01\nThu, 18 Feb 2016 10:20:30 GMT\n")
    dev = DeviceData()
    siprotec.process_webmonitor_version(dev, parsed)
    assert parsed == {}
    pkg = dev.software[0]
    assert (pkg.name, pkg.version, pkg.category) == ("WebMonitor", "04.29.01", "application")
    assert pkg.extra["build_date"] == "Thu, 18 Feb 2016 10:20:30 GMT"
    assert pkg.extra["build_timestamp"] == "2016-02-18T10:20:30"
