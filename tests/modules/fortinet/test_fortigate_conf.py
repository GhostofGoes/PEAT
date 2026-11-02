"""
Tests for the FortiGate configuration parser with synthetic configuration blocks.

The blocks follow the FortiOS CLI reference syntax ("config system interface",
"config router static", "config vpn ipsec phase1-interface", ...). They are
authored for PEAT, not captured from a device; all addresses are documentation
ranges (RFC 5737).
"""

import pytest

from peat import DeviceData, Fortigate, config, datastore
from peat.modules.fortinet.fortigate_conf import fg_conf_to_dict, process_fg_conf

SYNTHETIC_CONF = """\
#config-version=FG100F-7.2.9-FW-build1688-240509:opmode=0:vdom=0:user=admin
config system global
    set alias "FG100F-SUB1"
    set hostname "fg-sub1"
end
config system interface
    edit "port1"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping https ssh
        set type physical
        set snmp-index 1
    next
    edit "vlan100"
        set vdom "root"
        set ip 198.51.100.1 255.255.255.0
        set allowaccess ping
        set interface "port1"
        set vlanid 100
        set vlan-protocol 8021q
        set type vlan
        set snmp-index 20
    next
    edit "lag1"
        set vdom "root"
        set type aggregate
        set member "port3" "port4"
        set lacp-mode active
        set snmp-index 21
    next
    edit "red1"
        set vdom "root"
        set type redundant
        set member "port5" "port6"
        set snmp-index 22
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2xxxxxxxxxxxxxxxxxxxxxxxx
    next
end
config system dns
    set primary 192.0.2.53
    set secondary 0.0.0.0
    set source-ip 192.0.2.1
end
config system snmp sysinfo
    set status enable
    set location "Substation 1"
end
config system snmp community
    edit 1
        set name "notpublic"
        config hosts
            edit 1
                set ip 192.0.2.99 255.255.255.255
                set host-type query
            next
            edit 2
                set ip 192.0.2.98 255.255.255.255
                set host-type trap
            next
        end
    next
end
config system email-server
    set server "mail.example.com"
    set port 587
    set username "fgt"
    set password ENC xxxxxxxx
end
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "192.0.2.123"
        next
        edit 2
            set server "ntp.example.com"
        next
    end
end
config system ha
    set group-name "sub1-ha"
    set mode a-p
    set password ENC xxxxxxxx
    set hbdev "ha" 0
end
config log fortianalyzer setting
    set status enable
    set server "192.0.2.200"
    set upload-option realtime
end
config log syslogd setting
    set status enable
    set server "192.0.2.201"
    set mode reliable
    set port 6514
end
config router static
    edit 1
        set gateway 192.0.2.254
        set device "port1"
    next
    edit 2
        set dst 203.0.113.0 255.255.255.0
        set gateway 198.51.100.254
        set device "vlan100"
        set distance 20
        set status disable
        set comment "to control center"
    next
end
config vpn ipsec phase1-interface
    edit "to-cc"
        set interface "port1"
        set ike-version 2
        set peertype any
        set remote-gw 203.0.113.5
        set psksecret ENC xxxxxxxx
    next
    edit "dialup"
        set type dynamic
        set interface "port1"
        set psksecret ENC xxxxxxxx
    next
end
"""


def _dev() -> DeviceData:
    dev = DeviceData()
    process_fg_conf(fg_conf_to_dict(SYNTHETIC_CONF), dev)
    return dev


def _rels(dev: DeviceData, **kwargs) -> list:
    return [r for r in dev.relationships if all(getattr(r, k) == v for k, v in kwargs.items())]


def test_fortigate_vlan_interface():
    dev = _dev()
    ifaces = {i.name: i for i in dev.interface}

    vlan = ifaces["vlan100"]
    assert vlan.type == "vlan"
    assert vlan.vlan.id == "100"
    assert vlan.vlan.tagged is True
    assert vlan.parent == "port1"
    assert vlan.physical is False
    assert "vlanid" not in vlan.extra
    assert "interface" not in vlan.extra
    assert vlan.extra["vlan-protocol"] == "8021q"
    assert "100" in dev.related.vlans

    port1 = ifaces["port1"]
    assert port1.physical is True
    assert port1.vlan.id == ""
    assert port1.parent == ""


def test_fortigate_aggregate_interfaces():
    ifaces = {i.name: i for i in _dev().interface}

    lag = ifaces["lag1"]
    assert lag.type == "aggregate"  # FortiOS value kept
    assert lag.physical is False
    assert lag.redundancy.protocol == "lag"
    assert lag.redundancy.mode == "active"
    assert lag.redundancy.members == ["port3", "port4"]
    assert "member" not in lag.extra
    assert "lacp-mode" not in lag.extra

    red = ifaces["red1"]
    assert red.redundancy.protocol == "failover"
    assert red.redundancy.mode == ""
    assert red.redundancy.members == ["port5", "port6"]


def test_fortigate_snmp_hosts():
    """Bug fix: the SNMP manager hosts were never captured (stale loop variable)."""
    dev = _dev()
    assert {"192.0.2.99", "192.0.2.98"} <= dev.related.ip
    managers = {r.remote.ip: r for r in _rels(dev, protocol="snmp")}
    assert set(managers) == {"192.0.2.99", "192.0.2.98"}
    assert managers["192.0.2.99"].remote.role == "snmp_manager"
    assert managers["192.0.2.99"].direction == "ingress"
    assert managers["192.0.2.99"].local.port == 161  # the device's SNMP service
    assert managers["192.0.2.98"].direction == "egress"
    assert managers["192.0.2.98"].evidence == {"config"}
    # The community string is a secret
    assert "notpublic" not in dev.json()


def test_fortigate_dns_email_relationships():
    dev = _dev()
    dns = _rels(dev, protocol="dns")
    assert len(dns) == 1  # 0.0.0.0 (unset) is skipped, source-ip is not a server
    assert dns[0].type == "depends_on"
    assert dns[0].remote.ip == "192.0.2.53"
    assert dns[0].remote.role == "dns_server"

    smtp = _rels(dev, protocol="smtp")
    assert len(smtp) == 1
    assert smtp[0].type == "depends_on"
    assert smtp[0].remote.hostname == "mail.example.com"
    assert smtp[0].remote.port == 587
    assert smtp[0].remote.role == "smtp_server"


def test_fortigate_log_destinations():
    dev = _dev()
    assert "fortianalyzer" not in dev.extra

    faz = _rels(dev, protocol="fortianalyzer")
    assert len(faz) == 1
    assert faz[0].type == "logs_to"
    assert faz[0].remote.ip == "192.0.2.200"
    assert faz[0].remote.role == "log_server"
    assert faz[0].enabled is True
    assert faz[0].extra == {"upload_option": "realtime"}

    syslog = _rels(dev, protocol="syslog")
    assert len(syslog) == 1
    assert syslog[0].type == "logs_to"
    assert syslog[0].transport == "tcp"
    assert syslog[0].remote.ip == "192.0.2.201"
    assert syslog[0].remote.port == 6514
    assert syslog[0].remote.role == "log_server"
    assert syslog[0].evidence == {"config"}


def test_fortigate_static_routes():
    routes = {r.destination: r for r in _dev().routes}
    assert set(routes) == {"0.0.0.0/0", "203.0.113.0/24"}

    default = routes["0.0.0.0/0"]
    assert default.gateway == "192.0.2.254"
    assert default.interface == "port1"
    assert default.type == "static"
    assert default.enabled is True

    cc = routes["203.0.113.0/24"]
    assert cc.gateway == "198.51.100.254"
    assert cc.interface == "vlan100"
    assert cc.metric == 20
    assert cc.enabled is False
    assert cc.description == "to control center"


def test_fortigate_ntp_ipsec_ha():
    dev = _dev()

    sources = {s.address: s for s in dev.clock.sources}
    assert set(sources) == {"192.0.2.123", "ntp.example.com"}
    assert all(s.protocol == "ntp" and s.enabled is True for s in sources.values())
    assert dev.clock.extra["ntp_type"] == "custom"

    tunnels = _rels(dev, type="tunnel")
    assert len(tunnels) == 1  # the dial-up tunnel has no fixed peer
    assert tunnels[0].protocol == "ipsec"
    assert tunnels[0].remote.ip == "203.0.113.5"
    assert tunnels[0].local.interface == "port1"
    assert tunnels[0].extra["tunnel_name"] == "to-cc"

    assert dev.extra["ha"]["mode"] == "a-p"
    assert dev.extra["ha"]["group-name"] == "sub1-ha"
    assert "password" not in dev.extra["ha"]
    assert "ENC xxxxxxxx" not in dev.json()

    # Processing the configuration again doesn't duplicate list items
    process_fg_conf(fg_conf_to_dict(SYNTHETIC_CONF), dev)
    assert len(dev.clock.sources) == 2
    assert len(_rels(dev, type="tunnel")) == 1
    assert len(dev.routes) == 2


def test_fortigate_conf_without_global_or_admin():
    dev = DeviceData()
    process_fg_conf(fg_conf_to_dict("config system dns\n    set primary 192.0.2.53\nend\n"), dev)
    assert _rels(dev, protocol="dns")[0].remote.ip == "192.0.2.53"


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


def test_fortigate_parse_conf_file(out_config):
    conf = out_config / "fortigate-sub1.conf"
    conf.write_text(SYNTHETIC_CONF, encoding="utf-8")

    dev = Fortigate.parse(conf)

    assert dev.hostname == "fg-sub1"
    assert dev.name == "FG100F-SUB1"
    assert {r.destination for r in dev.routes} == {"0.0.0.0/0", "203.0.113.0/24"}
    assert all(r.id for r in dev.relationships)
    # Route gateways become "routes_via" relationships (derived by populate_fields)
    assert {r.remote.ip for r in dev.relationships if r.type == "routes_via"} == {
        "192.0.2.254",
        "198.51.100.254",
    }
    exported = dev.export()
    assert "fortianalyzer" not in exported.get("extra", {})
    assert "ENC xxxxxxxx" not in str(exported)
