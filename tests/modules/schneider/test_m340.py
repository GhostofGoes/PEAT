"""
Tests for the Modicon M340 module with synthetic inputs in the shape of the
data pulled by ``m340_pull.pull_network_config()`` (SNMP, FTP ``DINF``) and parsed
from the project file (``COMExchangeFile``).
"""

from unittest.mock import MagicMock

from peat import M340, DeviceData, Interface
from peat.data.baseline import compare_device, split_path
from peat.modules.schneider.m340 import m340_parse, m340_pull


def _net_config() -> dict:
    return {
        "full_model": "BMX P34 2020",
        "if_table_last_change": 4200,
        "firmware_version": "V2.70",
        "module_0": {
            "slot": 0,
            "model_name": "BMX P34 2020",
            "module_status": "nok",
            "mac_address": "00:80:F4:01:02:03",
            "configured_ipv4_address": "192.0.2.20",
            "communication_services": {"web": "supported"},
            "port_502": {
                "supported_protocol": "modbusDirectAndUnite",
                "service_status": "operational",
                "port_security": "enabled",
                "max_connections": 16,
                "total_messages_received": 1200,
                "total_messages_sent": 1190,
                "total_errors_sent": 3,
            },
            "web_server": {
                "service_status": "operational",
                "password_status": "disabled",
                "successful_attempts": 7,
                "failed_attempts": 2,
            },
            "smtp_server": {
                "service_status": "operational and running",
                "ipv4_address": "192.0.2.25",
                "mail_sent_count": 4,
                "error_count": 1,
                "link_service_status": "reachable",
                "server_check_fail_count": 2,
            },
            "led_0": {"name": "RUN", "description": "Running", "state": 2},
            "led_1": {"name": "ERR", "description": "Error", "state": 1},
        },
        "device_1": {
            "fw_loc": "0",
            "hardware_id": "0x0102",
            "fw_id": "0x0A21",
            "device": "BMX NOE 0100",
            "ir": 5,
            "description": "Ethernet module",
            "mac_address": "00:80:F4:0A:0B:0C",
        },
        "loader_status": {"state": "idle"},
        "free_space_sd_card": 1024,
    }


def test_led_indicators():
    leds = m340_parse.led_indicators(_net_config()["module_0"])
    assert [(i.name, i.label, i.value, i.position) for i in leds] == [
        ("Running", "RUN", "2", "led_0"),
        ("Error", "ERR", "1", "led_1"),
    ]
    assert all(i.type == "led" and i.state == "" for i in leds)
    assert all(i.timestamp is not None and i.timestamp.tzinfo for i in leds)
    assert leds[1].extra == {"oid_index": 1}


def test_process_network_config():
    dev = DeviceData(ip="192.0.2.20")
    dev.store("interface", Interface(ip="192.0.2.20", type="ethernet"))
    cpu = DeviceData(slot="0")
    cpu.description.product = "BMX P34 2020"
    dev.store("module", cpu, lookup="slot")
    noe = DeviceData(slot="2")
    noe.description.product = "BMX NOE 0100"
    dev.store("module", noe, lookup="slot")

    remaining = m340_parse.process_network_config(dev, _net_config())

    # Services and their counters
    modbus = dev.retrieve("service", {"protocol": "modbus_tcp"})
    assert modbus.enabled is True
    assert modbus.statistics.ingress.messages == 1200
    assert modbus.statistics.egress.messages == 1190
    assert modbus.statistics.egress.errors == 3
    assert modbus.statistics.connections.max == 16
    assert modbus.statistics.timestamp.tzinfo is not None
    assert modbus.security.extra == {"access_control": "enabled"}
    assert modbus.extra["supported_protocol"] == "modbusDirectAndUnite"

    web = dev.retrieve("service", {"protocol": "http"})
    assert web.security.authentication_required is False
    assert web.statistics.connections.authentication_successes == 7
    assert web.statistics.connections.authentication_failures == 2

    smtp = dev.retrieve("service", {"protocol": "smtp"})
    assert smtp.enabled is True
    assert smtp.role == "client"
    assert smtp.statistics.egress.messages == 4
    assert smtp.statistics.extra == {"server_check_fail_count": 2}
    rel = dev.relationships[0]
    assert (rel.protocol, rel.direction, rel.remote.ip, rel.remote.role) == (
        "smtp",
        "egress",
        "192.0.2.25",
        "server",
    )

    # Modules: status/health, MAC, firmware, LEDs
    cpu = dev.module[0]
    assert cpu.status == "nok"
    assert cpu.health == "failure"
    assert cpu.mac == "00:80:F4:01:02:03"
    assert cpu.firmware.version == "V2.70"
    assert {i.name for i in cpu.indicators} == {"Running", "Error"}
    assert dev.interface[0].mac == "00:80:F4:01:02:03"
    noe = dev.module[1]
    assert noe.firmware.id == "0x0A21"
    assert noe.hardware.id == "0x0102"
    assert noe.mac == "00:80:F4:0A:0B:0C"

    # Moved keys are not left in the remaining (dev.extra) data
    assert "port_502" not in remaining["module_0"]
    assert "led_0" not in remaining["module_0"]
    assert "module_status" not in remaining["module_0"]
    assert remaining["module_0"]["model_name"] == "BMX P34 2020"
    assert remaining["device_1"]["ir"] == 5
    assert "firmware_version" not in remaining
    assert remaining["if_table_last_change"] == 4200
    assert "system_uptime" not in remaining
    assert dev.uptime is None


def test_process_network_config_creates_missing_module():
    dev = DeviceData(ip="192.0.2.20")
    m340_parse.process_network_config(dev, {"module_3": {"slot": 3, "module_status": "ok"}})
    assert dev.module[0].slot == "3"
    assert dev.module[0].health == "normal"


def test_snmp_project_config_and_redaction():
    device_info = {
        "network_configurations": {
            "NOE": {
                "name": "NOE",
                "ntp_srv": 3221225985,  # 192.0.2.1 as an integer
                "snmp_config": {
                    "IPAddressMgr1": "192.0.2.161",
                    "IPAddressMgr2": "0.0.0.0",
                    "set": "private",
                    "get": "public",
                    "trap": "public",
                    "manager": 1,
                    "authentication": 0,
                },
            }
        }
    }
    dev = DeviceData(ip="192.0.2.20")
    m340_parse.process_project_network_config(dev, device_info["network_configurations"])
    snmp = dev.retrieve("service", {"protocol": "snmp"})
    assert snmp.security.default_credentials is True
    assert snmp.security.security_mode == "v1"
    assert [(r.remote.ip, r.remote.port, r.remote.role) for r in dev.relationships] == [
        ("192.0.2.161", 162, "snmp_manager")
    ]
    assert dev.clock.sources[0].protocol == "ntp"
    assert dev.clock.sources[0].address == "192.0.2.1"

    m340_parse.redact_snmp_communities(device_info)
    snmp_config = device_info["network_configurations"]["NOE"]["snmp_config"]
    assert not {"set", "get", "trap"} & set(snmp_config)
    assert snmp_config["IPAddressMgr1"] == "192.0.2.161"

    # Site communities -> not the factory default; small ntp_srv values are flags
    dev2 = DeviceData(ip="192.0.2.21")
    m340_parse.process_project_network_config(
        dev2, {"NOE": {"ntp_srv": 1, "snmp_config": {"get": "s1te-get", "set": "s1te-set"}}}
    )
    assert dev2.retrieve("service", {"protocol": "snmp"}).security.default_credentials is False
    assert dev2.clock.sources == []
    assert dev2.clock.extra == {"ntp_srv": 1}


def test_snmp_led_walk_tolerates_missing_column(mocker):
    """A failed or short LED column no longer aborts all SNMP data."""
    snmp = MagicMock()

    def _get(identity, single_query=True, query_limit=None):  # noqa: ARG001
        if not single_query:
            if identity.endswith("9.1.2"):  # names: 2 rows
                return [{"value_encoded": "RUN"}, {"value_encoded": "ERR"}]
            if identity.endswith("9.1.4"):  # states: 1 row
                return [{"value_encoded": 1}]
            return []  # descriptions: failed
        return [{"value_string": "2"}] if identity.endswith("3833.1.7.10.0") else []

    snmp.get.side_effect = _get
    mocker.patch.object(m340_pull, "SNMP", return_value=snmp)
    module_info, _system = m340_pull._get_snmp_metadata("192.0.2.20", max_failures=100)
    assert module_info["led_0"] == {"name": "RUN", "state": 1}
    assert module_info["led_1"] == {"name": "ERR"}
    assert "led_2" not in module_info


def test_ftp_default_credentials():
    dev = DeviceData(ip="192.0.2.20")
    M340._record_ftp_login(dev, "LOADER", "fwdownload")
    ftp = dev.retrieve("service", {"protocol": "ftp"})
    assert ftp.security.default_credentials is True
    assert ftp.security.authentication_required is True

    dev2 = DeviceData(ip="192.0.2.21")
    M340._record_ftp_login(dev2, "site", "secret", defaults_rejected=True)
    assert dev2.retrieve("service", {"protocol": "ftp"}).security.default_credentials is False

    dev3 = DeviceData(ip="192.0.2.22")
    M340._record_ftp_login(dev3, "site", "secret")
    assert dev3.retrieve("service", {"protocol": "ftp"}).security.default_credentials is None


def test_verify_ftp_records_default_credential(mocker):
    class FakeFTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def login(self, user, password):
            return (user, password) == ("loader", "fwdownload")

        def cmd(self, _command):
            return "200 FwLoc=0, Device='BMX P34 2020'"

    mocker.patch("peat.modules.schneider.m340.m340.FTP", FakeFTP)
    dev = DeviceData(ip="192.0.2.20")
    dev._runtime_options = {"ftp": {"creds": [["site", "secret"], ["loader", "fwdownload"]]}}
    assert M340._verify_ftp(dev)
    assert dev.retrieve("service", {"protocol": "ftp"}).security.default_credentials is True


def test_known_defaults():
    baselines = M340.get_known_defaults()
    assert [b.id for b in baselines] == ["m340-vendor-recommended"]
    baseline = baselines[0]
    assert baseline.kind == "vendor_recommended"
    for rule in baseline.rules:
        assert split_path(rule.path)

    dev = DeviceData(ip="192.0.2.20", type="PLC")
    dev.description.vendor.id = "Schneider"
    M340._record_ftp_login(dev, "loader", "fwdownload")
    dev.store("service", m340_parse.web_service({"password_status": "disabled"}))
    results = {f.rule_id: f for f in compare_device(dev, baseline)}
    assert results["m340.accounts.default-credentials"].result == "fail"
    assert results["m340.web.password"].result == "fail"

    ok = DeviceData(ip="192.0.2.21", type="PLC")
    ok.description.vendor.id = "Schneider"
    ok.store("service", m340_parse.web_service({"password_status": "enabled"}))
    results = {f.rule_id: f for f in compare_device(ok, baseline)}
    assert results["m340.accounts.default-credentials"].result == "pass"
    assert results["m340.web.password"].result == "pass"
