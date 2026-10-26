import pytest

from peat import DeviceData
from peat.modules.fortinet import fortigate_conf
from peat.modules.fortinet.fortigate_conf import fg_conf_to_dict, process_fg_conf

# Representative FortiGate configuration (made up, in the FortiOS 7.0 format)
SAMPLE_CONF = """\
#config-version=FGT60F-7.0.12-FW-build0523-230504:opmode=0:vdom=0:user=admin
#conf_file_ver=12345
#buildno=0523
#global_vdom=1
config system global
    set alias "FGT60F-LAB"
    set hostname "fw-lab-01"
    set timezone 12
    set admintimeout 30
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set allowaccess ping https ssh
        set type physical
        set description ''
        set role wan
    next
    edit "internal"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set member "port1" "port2"
        config ipv6
            set ip6-address ::/0
        end
    next
end
config system dns
    set primary 192.0.2.53
    set secondary 192.0.2.54
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2abcdefghijklmnopqrstuvwxyz0123456789=
    next
end
"""


def test_fg_conf_to_dict():
    parsed = fg_conf_to_dict(SAMPLE_CONF)
    assert parsed == {
        "system": {
            "global": {
                "alias": "FGT60F-LAB",
                "hostname": "fw-lab-01",
                "timezone": "12",
                "admintimeout": "30",
            },
            "interface": {
                "wan1": {
                    "vdom": "root",
                    "ip": "192.0.2.1 255.255.255.0",
                    "allowaccess": "ping https ssh",
                    "type": "physical",
                    "description": "",
                    "role": "wan",
                },
                "internal": {
                    "vdom": "root",
                    "ip": "10.0.0.1 255.255.255.0",
                    "member": "port1 port2",
                    "ipv6": {"ip6-address": "::/0"},
                },
            },
            "dns": {"primary": "192.0.2.53", "secondary": "192.0.2.54"},
            "admin": {
                "admin": {
                    "accprofile": "super_admin",
                    "password": "ENC SH2abcdefghijklmnopqrstuvwxyz0123456789=",
                }
            },
        }
    }

    dev = DeviceData()
    process_fg_conf(parsed, dev)
    assert dev.hostname == "fw-lab-01"
    assert dev.name == "FGT60F-LAB"
    assert any(iface.ip == "192.0.2.1" for iface in dev.interface)


def test_fg_conf_to_dict_single_quote():
    # Previously, ValueError: the whole configuration failed to parse
    parsed = fg_conf_to_dict('config system global\n    set alias "it\'s"\nend\n')
    assert parsed == {"system": {"global": {"alias": "it's"}}}


def test_fg_conf_to_dict_no_key_injection():
    conf = "config system dns\n    set primary b', 'injected': [1, 2], 'x': 'q\nend\n"
    # Previously, {'primary': 'b', 'injected': [1, 2], 'x': 'q'}
    parsed = fg_conf_to_dict(conf)
    assert parsed == {"system": {"dns": {"primary": "b', 'injected': [1, 2], 'x': 'q"}}}


def test_fg_conf_to_dict_escaped_quotes():
    conf = (
        'config firewall address\n    edit "srv \\"main\\""\n        set subnet 1\n    next\nend\n'
    )
    assert fg_conf_to_dict(conf) == {"firewall": {"address": {"srv main": {"subnet": "1"}}}}


def test_fg_conf_to_dict_nesting_limit():
    depth = fortigate_conf.MAX_FG_CONF_DEPTH + 1
    with pytest.raises(ValueError, match="nested"):
        fg_conf_to_dict("config a\n" * depth + "end\n" * depth)
