from datetime import timedelta

import pytest

from peat import CommError, DeviceData, Interface
from peat.modules.schneider.m340 import m340, m340_pull, m340_snmp
from peat.modules.schneider.m340.m340 import M340

TFE = m340_snmp.TFE_ROOT
DEV_IP = "192.0.2.10"


@pytest.fixture
def m340_entries(json_data) -> list:
    """SYNTHETIC walk of a fictitious BMX P34 2020 (refer to the file's comment)."""
    return json_data("m340_snmp_walk.json")["entries"]


@pytest.fixture
def install_fake_agent(fake_snmp_cls, m340_entries, monkeypatch):
    """Replace the SNMP class used by m340_snmp (and the fallback in m340_pull)."""

    def _install(entries: list | None = None, target=m340_snmp, **fake_kwargs) -> list:
        created = []

        def _factory(*args, **kwargs):
            inst = fake_snmp_cls(
                *args,
                entries=m340_entries if entries is None else entries,
                **fake_kwargs,
                **kwargs,
            )
            created.append(inst)
            return inst

        monkeypatch.setattr(target, "SNMP", _factory)
        return created

    return _install


@pytest.fixture
def snmp_data(install_fake_agent) -> dict:
    install_fake_agent()
    return m340_snmp.pull_snmp(DEV_IP)


def _without(entries: list, *oid_prefixes: str) -> list:
    return [e for e in entries if not any(e[0].startswith(p) for p in oid_prefixes)]


def test_decode_comm_services_lsb_first():
    assert m340_snmp.decode_comm_services(1) == {
        "port502_messaging": True,
        "io_scanning": False,
        "global_data": False,
        "web": False,
        "address_server": False,
        "time_management": False,
        "email": False,
    }
    assert all(m340_snmp.decode_comm_services(0x7F).values())
    assert not any(m340_snmp.decode_comm_services(0).values())
    only_email = m340_snmp.decode_comm_services(0x40)
    assert [k for k, v in only_email.items() if v] == ["email"]


def test_pull_snmp_structures_groups(install_fake_agent):
    agents = install_fake_agent()
    data = m340_snmp.pull_snmp(DEV_IP, community="secret", max_varbinds=500)

    assert agents[0].community == "secret"
    queried = [q[0] for q in agents[0].queries]
    # globalData (bit 2) and addressServer (bit 4) aren't advertised
    assert f"{TFE}.4" not in queried
    assert f"{TFE}.6" not in queried
    assert {f"{TFE}.{arc}" for arc in ["7", "2", "3", "5", "8", "9", "255"]} <= set(queried)
    assert set(data["tfe"]) == {
        "equipment_profile",
        "port502_messaging",
        "io_scanning",
        "web",
        "time_management",
        "email",
        "tfe_mib_version",
    }

    assert data["mibs_loaded"] == ["SNMPv2-MIB", "IF-MIB", "RFC1213-MIB", "TFPRIVATE-MIB"]
    assert "incomplete" not in data
    assert data["product"] == "modiconM340PLC"
    assert data["system"]["sysUpTime"] == 8640000
    assert data["system"]["sysObjectID"] == f"{TFE}.7.255.20"

    profile = data["tfe"]["equipment_profile"]
    assert profile["profileGlobalStatus"] == "ok"
    assert profile["profileIpConfigMode"] == "local"
    assert profile["profileMacAddress"] == "00:80:f4:01:02:03"
    assert profile["communication_services"]["email"] is True
    assert profile["communication_services"]["global_data"] is False
    assert profile["unknown"] == {f"{TFE}.7.200.1.0": 5}
    leds = profile["profileLedDisplayTable"]
    assert [(r["ledName"], r["ledState"]) for r in leds] == [
        ("RUN", "on"),
        ("ERR", "off"),
        ("ETH ACT", "blinking"),
    ]
    assert profile["profileTrapTable"][0]["_index"] == "192.0.2.50"

    io_scan = data["tfe"]["io_scanning"]
    assert io_scan["ioScanStatus"] == "operationnal"  # Schneider's spelling
    assert [r["_index"] for r in io_scan["ioScanDeviceTable"]] == ["192.0.2.21", "192.0.2.22"]
    assert io_scan["ioScanDeviceTable"][1]["ioScanDeviceHealth"] == "nok"

    conns = data["tfe"]["port502_messaging"]["port502ConnTable"]
    assert conns[0]["_index_parts"] == [512, "192.0.2.30", 49152, 0, 0]
    assert conns[0]["port502ConnType"] == "remote"

    assert data["tfe"]["email"]["emailTable"][0]["_index"] == "0"
    assert data["tfe"]["tfe_mib_version"]["tfeMibVersionNumber"] == "V01.04"

    assert [r["ifDescr"] for r in data["interfaces"]] == ["ETH1", "lo0"]
    assert [r["ipAdEntAddr"] for r in data["ip_addresses"]] == ["127.0.0.1", "192.0.2.10"]
    assert data["ip_addresses"][1]["ipAdEntIfIndex"] == 1
    assert data["ip_addresses"][1]["ipAdEntNetMask"] == "255.255.255.0"
    assert data["ip_addresses"][1]["_index_parts"] == ["192.0.2.10"]


def test_pull_snmp_standard_mibs_resolution(install_fake_agent):
    # RFC1213-MIB is only used for ipAddrTable, PySNMP's copy doesn't define the
    # system and interfaces groups (those are resolved using SNMPv2-MIB and IF-MIB)
    agents = install_fake_agent()
    m340_snmp.pull_snmp(DEV_IP)
    assert len(agents[0].all_output) == len(agents[0].queries)  # every query is kept
    values = [v for out in agents[0].all_output.values() for v in out]
    mib_by_object = {v["object_name"]: v["mib_name"] for v in values}
    assert mib_by_object["sysDescr"] == "SNMPv2-MIB"
    assert mib_by_object["ifType"] == "IF-MIB"
    assert mib_by_object["ipAdEntAddr"] == "RFC1213-MIB"


def test_pull_snmp_walks_all_groups_without_comm_services(install_fake_agent, m340_entries):
    agents = install_fake_agent(_without(m340_entries, f"{TFE}.7.3.0"))
    data = m340_snmp.pull_snmp(DEV_IP)
    queried = {q[0] for q in agents[0].queries}
    assert {f"{TFE}.4", f"{TFE}.6"} <= queried
    assert data["tfe"]["global_data"] == {"glbDataStatus": "operationnal"}
    assert "communication_services" not in data["tfe"]["equipment_profile"]


def test_pull_snmp_no_response_raises_commerror(install_fake_agent):
    agents = install_fake_agent(timeout_after=0)
    with pytest.raises(CommError):
        m340_snmp.pull_snmp(DEV_IP)
    assert len(agents[0].queries) == 1  # fail fast


def test_pull_snmp_mib_unavailable_raises(install_fake_agent, monkeypatch, tmp_path):
    monkeypatch.setattr(m340_snmp, "SCHNEIDER_MIBS_DIR", tmp_path)
    agents = install_fake_agent()
    with pytest.raises(m340_snmp.TfeMibUnavailableError):
        m340_snmp.pull_snmp(DEV_IP)
    assert agents[0].queries == []


def test_pull_snmp_partial_and_bounded(install_fake_agent):
    agents = install_fake_agent(timeout_after=20)
    data = m340_snmp.pull_snmp(DEV_IP)
    assert data["system"]["sysName"] == "M340-LAB-01"
    assert data["tfe"]["equipment_profile"]["profileProductName"] == "BMX P34 2020"
    assert agents[0].responses == 20

    # The agent stopped responding: the remaining subtrees aren't walked
    assert [q[0] for q in agents[0].queries] == [m340_snmp.SYSTEM_OID, f"{TFE}.7"]
    assert data["incomplete"]["timed_out_walking"] == "equipment_profile"
    skipped = data["incomplete"]["skipped"]
    assert skipped[0] == "port502_messaging"
    assert skipped[-2:] == ["interfaces", "ip_addresses"]
    assert "global_data" not in skipped  # not advertised by the agent
    assert data["interfaces"] == []
    assert list(data["tfe"]) == ["equipment_profile"]

    agents = install_fake_agent()
    m340_snmp.pull_snmp(DEV_IP, max_varbinds=2)
    assert agents[0].responses <= 2 * len(agents[0].queries)


def test_apply_to_dev(snmp_data):
    dev = DeviceData(ip=DEV_IP)
    m340_snmp.apply_to_dev(dev, snmp_data)

    assert dev.extra["snmp"] is snmp_data
    assert dev.uptime == timedelta(days=1)
    assert dev.name == "M340-LAB-01"
    assert dev.description.contact_info == "plc-admin@example.com"
    assert dev.geo.name == "Building 1, Rack 2"
    assert "BMX P34 2020" in dev.description.description

    assert len(dev.module) == 1
    mod = dev.module[0]
    assert mod.slot == "0"
    assert mod.description.product == "BMX P34 2020"
    assert mod.firmware.version == "V3.40"
    assert mod.mac == "00:80:F4:01:02:03"
    assert mod.ip == DEV_IP
    assert mod.status == "ok"
    assert [led["state"] for led in mod.extra["leds"]] == ["on", "off", "blinking"]

    # Loopback interface isn't stored
    assert len(dev.interface) == 1
    iface = dev.interface[0]
    assert iface.name == "ETH1"
    assert iface.id == "1"
    assert iface.type == "ethernet"
    assert iface.speed == 100
    assert iface.mtu == 1500
    assert iface.mac == "00:80:F4:01:02:03"
    assert iface.enabled is True
    assert iface.connected is True
    assert iface.uptime == timedelta(days=1) - timedelta(seconds=1)
    assert iface.ip == DEV_IP
    assert iface.subnet_mask == "255.255.255.0"
    assert iface.gateway == "192.0.2.1"

    services = {s.protocol: s for s in dev.service}
    assert set(services) == {"snmp", "modbus_tcp", "http", "ntp", "smtp"}  # no dhcp
    assert services["snmp"].status == "verified"
    assert services["snmp"].port == 161
    assert services["snmp"].transport == "udp"
    assert services["modbus_tcp"].port == 502
    assert services["modbus_tcp"].enabled is True
    assert services["modbus_tcp"].extra["port502SupportedProtocol"] == "modbusDirectAndUnite"
    assert "port502ConnTable" not in services["modbus_tcp"].extra
    assert services["http"].port == 80
    assert services["ntp"].role == "client"
    assert services["ntp"].transport == "udp"
    assert services["ntp"].port is None  # the device isn't listening, it's a client
    assert services["smtp"].role == "client"
    assert services["smtp"].extra["smtpSrvAddr"] == "192.0.2.25"
    assert len(iface.services) == 5

    peers = {"192.0.2.21", "192.0.2.22", "192.0.2.30", "192.0.2.31", "192.0.2.66"}
    peers |= {"192.0.2.50", "192.0.2.123", "192.0.2.25"}
    assert peers <= dev.related.ip
    assert "127.0.0.1" not in dev.related.ip
    assert "0.0.0.0" not in dev.related.ip
    assert "00:80:F4:01:02:03" in dev.related.mac
    assert {80, 161, 502} <= dev.related.ports


def test_apply_to_dev_disabled_services(install_fake_agent, m340_entries):
    entries = [list(e) for e in m340_entries]
    for entry in entries:
        if entry[0] in [f"{TFE}.2.1.0", f"{TFE}.8.1.1.0", f"{TFE}.9.1.1.1.2.0"]:
            entry[2] = 1  # idle
    entries.append([f"{TFE}.6.1.0", "Integer32", 1])
    install_fake_agent([e for e in entries if e[0] != f"{TFE}.7.3.0"])

    dev = DeviceData(ip=DEV_IP)
    m340_snmp.apply_to_dev(dev, m340_snmp.pull_snmp(DEV_IP))
    services = {s.protocol: s for s in dev.service}
    assert services["modbus_tcp"].enabled is False
    assert services["ntp"].enabled is False
    assert services["smtp"].enabled is False
    assert services["dhcp"].enabled is False
    assert services["dhcp"].role == "server"
    assert services["dhcp"].port == 67
    assert services["dhcp"].transport == "udp"
    assert services["http"].enabled is True


def test_apply_to_dev_merges_with_parsed_modules(snmp_data):
    dev = DeviceData(ip=DEV_IP, name="existing-name")
    dev.store("module", DeviceData(slot="0", type="CPU", serial_number="1234"), lookup="slot")
    dev.store("module", DeviceData(slot="1", type="Discrete I/O"), lookup="slot")
    m340_snmp.apply_to_dev(dev, snmp_data)

    assert dev.name == "existing-name"
    assert len(dev.module) == 2
    cpu = next(m for m in dev.module if m.slot == "0")
    assert cpu.type == "CPU"
    assert cpu.serial_number == "1234"
    assert cpu.description.product == "BMX P34 2020"


def test_apply_to_dev_tolerates_missing_and_bad_data():
    dev = DeviceData(ip=DEV_IP)
    m340_snmp.apply_to_dev(dev, {})
    assert [s.protocol for s in dev.service] == ["snmp"]
    assert dev.module == []
    assert dev.interface == []

    bad = {
        "port": 161,
        "system": {"sysUpTime": "garbage", "sysName": 5, "sysContact": None},
        "tfe": {
            "equipment_profile": {
                "profileSlot": 2,
                "profileMacAddress": "not-a-mac",
                "profileIpAddress": "999.1.1.1",
                "profileIpGateway": "0.0.0.0",
                "profileProductName": None,
            },
            "io_scanning": {"ioScanDeviceTable": [{"ioScanDeviceRemAddress": "0.0.0.0"}, {}]},
            "time_management": {"ntpSrvAddr": DEV_IP},
            "email": {"emailTable": [{"smtpSrvAddr": "<script>"}]},
        },
        "interfaces": [
            {"ifIndex": 1, "ifType": "ethernetCsmacd", "ifMtu": 0, "ifSpeed": -1},
            {"ifIndex": 2, "ifPhysAddress": "00:00:00:00:00:00", "ifLastChange": 10**9},
        ],
        "ip_addresses": [{"ipAdEntIfIndex": "x", "ipAdEntAddr": "bad"}],
    }
    dev = DeviceData(ip=DEV_IP)
    m340_snmp.apply_to_dev(dev, bad)
    assert dev.uptime is None
    assert dev.name == ""
    assert dev.module[0].slot == "2"
    assert dev.module[0].mac == ""
    assert dev.module[0].ip == ""
    assert len(dev.interface) == 2
    assert all(i.mtu is None and i.mac == "" and i.uptime is None for i in dev.interface)
    assert dev.related.ip == set()  # own IP, unspecified and invalid addresses aren't peers


def test_to_legacy_shape_and_fixed_values(snmp_data):
    module_info, system_info = m340_snmp.to_legacy(snmp_data)

    assert set(module_info) == {
        "slot",
        "model_name",
        "module_description",
        "module_status",
        "mac_address",
        "configured_ipv4_address",
        "configured_ipv4_netmask",
        "configured_ipv4_gateway",
        "ip_config_mode",
        "num_network_interfaces",
        "bandwidth_management",
        "communication_services",
        "port_502",
        "web_server",
        "smtp_server",
        "led_0",
        "led_1",
        "led_2",
    }
    assert module_info["slot"] == 0
    assert module_info["mac_address"] == "00:80:F4:01:02:03"
    assert module_info["module_status"] == "ok"
    assert module_info["communication_services"] == {
        "port_502_messaging": "supported",
        "io_scanning": "supported",
        "global_data": "unsupported",
        "web": "supported",
        "address_server": "unsupported",
        "time_management": "supported",
        "email": "supported",
    }
    assert module_info["port_502"]["service_status"] == "operational"
    assert module_info["port_502"]["port_security"] == "disabled"
    assert module_info["web_server"]["service_status"] == "operational"
    assert module_info["web_server"]["password_status"] == "enabled"
    assert module_info["smtp_server"]["service_status"] == "operational and running"
    assert module_info["smtp_server"]["link_service_status"] == "reachable"
    assert module_info["led_2"] == {
        "name": "ETH ACT",
        "description": "Ethernet activity",
        "state": 3,
    }
    assert system_info == {
        "full_model": "BMX P34 2020",
        "system_uptime": 8640000,  # sysUpTime, not ifTableLastChange
        "implementation_class": "B30",
        "firmware_version": "V3.40",
    }
    assert m340_snmp.to_legacy({}) == ({}, {})


@pytest.fixture
def no_ftp_or_modbus(monkeypatch):
    def _fail(*_args, **_kwargs):
        raise OSError("not available in tests")

    monkeypatch.setattr(m340_pull, "_get_ftp_metadata", _fail)
    monkeypatch.setattr(m340_pull, "_get_modbus_metadata", _fail)


def test_pull_network_config_snmp(install_fake_agent, no_ftp_or_modbus):  # noqa: ARG001
    agents = install_fake_agent()
    info = m340_pull.pull_network_config(
        DEV_IP, timeout=0.5, snmp_community="secret", snmp_port=1161, snmp_max_varbinds=100
    )
    assert agents[0].port == 1161
    assert agents[0].timeout == 0.5
    assert agents[0].community == "secret"
    assert info["snmp"]["product"] == "modiconM340PLC"
    assert info["module_0"]["model_name"] == "BMX P34 2020"
    assert info["firmware_version"] == "V3.40"
    assert info["system_uptime"] == 8640000


def test_pull_network_config_missing_slot(install_fake_agent, m340_entries, no_ftp_or_modbus):  # noqa: ARG001
    install_fake_agent(_without(m340_entries, f"{TFE}.7.10.0"))
    info = m340_pull.pull_network_config(DEV_IP)
    assert "slot" not in info["module_snmp"]
    assert info["module_snmp"]["model_name"] == "BMX P34 2020"


def test_pull_network_config_no_snmp_response(install_fake_agent, no_ftp_or_modbus):  # noqa: ARG001
    install_fake_agent(timeout_after=0)
    assert m340_pull.pull_network_config(DEV_IP) == {}


def test_pull_network_config_without_snmp(monkeypatch, no_ftp_or_modbus):  # noqa: ARG001
    def _fail(*_args, **_kwargs):
        raise AssertionError("SNMP must not be used")

    monkeypatch.setattr(m340_snmp, "pull_snmp", _fail)
    monkeypatch.setattr(m340_pull, "_get_snmp_metadata", _fail)
    assert m340_pull.pull_network_config(DEV_IP, methods=["ftp", "modbus_tcp"]) == {}
    assert m340_pull.pull_network_config(DEV_IP, methods=[]) == {}


def test_pull_network_config_methods(monkeypatch):
    used = []

    def _ftp(*_args, **_kwargs):
        used.append("ftp")
        return {"free_space_sd_card": 1024}

    def _modbus(*_args, **_kwargs):
        used.append("modbus_tcp")
        return {"memory_card_model": "BMXRMS008MP"}

    def _snmp(*_args, **_kwargs):
        raise AssertionError("SNMP must not be used")

    monkeypatch.setattr(m340_pull, "_get_ftp_metadata", _ftp)
    monkeypatch.setattr(m340_pull, "_get_modbus_metadata", _modbus)
    monkeypatch.setattr(m340_snmp, "pull_snmp", _snmp)
    monkeypatch.setattr(m340_pull, "_get_snmp_metadata", _snmp)

    # Services are used in a fixed order, unknown methods are ignored
    info = m340_pull.pull_network_config(DEV_IP, methods=["modbus_tcp", "bogus", "ftp"])
    assert used == ["ftp", "modbus_tcp"]
    assert info == {"free_space_sd_card": 1024, "memory_card_model": "BMXRMS008MP"}

    used.clear()
    assert m340_pull.pull_network_config(DEV_IP, methods=["modbus_tcp"]) == {
        "memory_card_model": "BMXRMS008MP"
    }
    assert used == ["modbus_tcp"]


def test_fallback_raw_oid_path(install_fake_agent, monkeypatch, tmp_path, no_ftp_or_modbus):  # noqa: ARG001
    # TFPRIVATE-MIB can't be loaded => raw OIDs, without the vendor MIB
    monkeypatch.setattr(m340_snmp, "SCHNEIDER_MIBS_DIR", tmp_path)
    install_fake_agent()
    agents = install_fake_agent(target=m340_pull)

    info = m340_pull.pull_network_config(DEV_IP, snmp_port=1161)
    assert agents[0].port == 1161
    assert "snmp" not in info

    mod = info["module_0"]
    assert mod["slot"] == 0
    assert mod["model_name"] == "BMX P34 2020"
    assert mod["mac_address"] == "00:80:F4:01:02:03"
    assert mod["module_status"] == "ok"
    assert mod["ip_config_mode"] == "local"
    assert mod["configured_ipv4_address"] == DEV_IP
    assert mod["num_network_interfaces"] == 2
    assert mod["communication_services"]["port_502_messaging"] == "supported"
    assert mod["communication_services"]["global_data"] == "unsupported"
    assert mod["communication_services"]["email"] == "supported"
    assert mod["port_502"]["service_status"] == "operational"
    assert mod["port_502"]["supported_protocol"] == "modbusDirectAndUnite"
    assert mod["web_server"]["service_status"] == "operational"
    assert mod["smtp_server"]["service_status"] == "operational and running"
    assert mod["smtp_server"]["link_service_status"] == "reachable"
    assert [mod[f"led_{i}"]["name"] for i in range(3)] == ["RUN", "ERR", "ETH ACT"]
    assert mod["led_2"]["state"] == 3
    assert "led_3" not in mod
    assert info["system_uptime"] == 8640000
    assert info["firmware_version"] == "V3.40"


def test_fallback_without_leds(install_fake_agent, m340_entries):
    agents = install_fake_agent(_without(m340_entries, f"{TFE}.7.9."), target=m340_pull)
    module_info, _ = m340_pull._get_snmp_metadata(DEV_IP)
    assert agents
    assert not any(k.startswith("led_") for k in module_info)


def test_verify_snmp_caches_community(monkeypatch):
    def _verify(self, *_args, **_kwargs):
        return self.community == "private"

    monkeypatch.setattr(m340.SNMP, "verify", _verify)
    dev = DeviceData(ip=DEV_IP)
    assert M340._verify_snmp(dev)
    assert dev._cache["snmp_community"] == "private"


def test_get_snmp_community_precedence():
    project = {
        "network_configurations": {
            "eth": {"ip_config": {"IPNetwork": DEV_IP}, "snmp_config": {"get": "from-project"}},
            "other": {"ip_config": {"IPNetwork": "192.0.2.99"}, "snmp_config": {"get": "nope"}},
        }
    }
    dev = DeviceData(ip=DEV_IP)
    assert M340._get_snmp_community(dev, {}) == "public"
    assert M340._get_snmp_community(dev, {"network_configurations": {"x": None}}) == "public"
    assert M340._get_snmp_community(dev, project) == "from-project"
    dev._cache["snmp_community"] = "verified"
    assert M340._get_snmp_community(dev, project) == "verified"


def test_pull_config_passes_options_and_applies(monkeypatch, snmp_data):
    calls = {}

    def _pull_network_config(**kwargs):
        calls.update(kwargs)
        return {"snmp": snmp_data}

    monkeypatch.setattr(m340.m340_parse, "parse_config_to_dict", lambda _blob: {})
    monkeypatch.setattr(m340_pull, "pull_network_config", _pull_network_config)

    dev = DeviceData(ip=DEV_IP)
    dev._runtime_options["snmp"] = {"port": 1161, "timeout": 2.5, "max_varbinds": 50}
    dev._runtime_options["m340"] = {"pull_methods": ["ftp", "modbus_tcp"]}
    dev._cache["snmp_community"] = "verified"

    M340._pull_config(dev, b"")
    assert calls["snmp_port"] == 1161
    assert calls["snmp_timeout"] == 2.5
    assert calls["methods"] == ["ftp", "modbus_tcp"]
    assert calls["snmp_max_varbinds"] == 50
    assert calls["snmp_community"] == "verified"
    assert dev.module[0].description.product == "BMX P34 2020"
    assert dev.extra["snmp"] is snmp_data


def test_pull_config_survives_apply_errors(monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("bug in the mapping")

    monkeypatch.setattr(m340.m340_parse, "parse_config_to_dict", lambda _blob: {})
    monkeypatch.setattr(m340_pull, "pull_network_config", lambda **_kw: {"snmp": {"port": 161}})
    monkeypatch.setattr(m340_snmp, "apply_to_dev", _boom)

    dev = DeviceData(ip=DEV_IP)
    assert M340._pull_config(dev, b"") == {"snmp": {"port": 161}}


def test_pull_snmp_timeout_during_system_and_last_walks(install_fake_agent):
    agents = install_fake_agent(timeout_after=2)
    data = m340_snmp.pull_snmp(DEV_IP)
    assert len(agents[0].queries) == 1
    assert len(data["system"]) == 2
    assert data["incomplete"]["timed_out_walking"] == "system"
    assert data["incomplete"]["skipped"][0] == "equipment_profile"

    agents = install_fake_agent()
    m340_snmp.pull_snmp(DEV_IP)
    total = agents[0].responses

    agents = install_fake_agent(timeout_after=total - 1)
    data = m340_snmp.pull_snmp(DEV_IP)
    assert data["incomplete"] == {"timed_out_walking": "ip_addresses", "skipped": []}
    assert [r["ipAdEntAddr"] for r in data["ip_addresses"]] == ["127.0.0.1", "192.0.2.10"]


@pytest.mark.usefixtures("no_ftp_or_modbus")
def test_pull_snmp_malformed_index_doesnt_abort(install_fake_agent, m340_entries):
    # IpAddress-indexed ioScanDeviceTable column with an excessive sub-identifier
    bad_oid = f"{TFE}.3.6.1.2.192.0.2.22.7"
    entries = [*m340_entries, [bad_oid, "Integer32", 2]]
    install_fake_agent(entries)
    data = m340_snmp.pull_snmp(DEV_IP)

    io_scan = data["tfe"]["io_scanning"]
    assert io_scan["unknown"] == {bad_oid: 2}
    assert [r["_index"] for r in io_scan["ioScanDeviceTable"]] == ["192.0.2.21", "192.0.2.22"]
    assert {"email", "tfe_mib_version"} <= set(data["tfe"])  # walked after io_scanning
    assert len(data["interfaces"]) == 2
    assert "incomplete" not in data

    info = m340_pull.pull_network_config(DEV_IP)
    assert info["snmp"]["tfe"]["io_scanning"]["unknown"] == {bad_oid: 2}
    assert info["module_0"]["model_name"] == "BMX P34 2020"


def test_pull_snmp_survives_pysnmp_errors(install_fake_agent):
    # PySNMP raises (e.g. a response it can't decode) part way through
    agents = install_fake_agent(raise_after=20)
    data = m340_snmp.pull_snmp(DEV_IP)
    assert data["system"]["sysName"] == "M340-LAB-01"
    assert data["tfe"]["equipment_profile"]["profileProductName"] == "BMX P34 2020"
    assert "incomplete" not in data  # not a timeout, so the other subtrees are tried
    assert len(agents[0].queries) > 2


@pytest.mark.usefixtures("no_ftp_or_modbus")
def test_pull_network_config_falls_back_on_unexpected_errors(install_fake_agent, monkeypatch):
    def _boom(*_args, **_kwargs):
        raise RuntimeError("bug in the TFE MIB code")

    monkeypatch.setattr(m340_snmp, "pull_snmp", _boom)
    agents = install_fake_agent(target=m340_pull)
    info = m340_pull.pull_network_config(DEV_IP)
    assert agents
    assert "snmp" not in info
    assert info["module_0"]["model_name"] == "BMX P34 2020"


def test_apply_to_dev_keeps_interfaces_sharing_mac_or_name():
    # e.g. a BMX NOC 0401 (4-port switch): one MAC and IP, four ifTable rows
    data = {
        "port": 161,
        "interfaces": [
            {
                "ifIndex": i,
                "ifDescr": "ETH",
                "ifType": "ethernetCsmacd",
                "ifPhysAddress": "00:80:f4:01:02:03",
                "ifOperStatus": "up" if i == 1 else "down",
            }
            for i in range(1, 5)
        ],
        "ip_addresses": [{"ipAdEntAddr": DEV_IP, "ipAdEntIfIndex": 1}],
    }
    dev = DeviceData(ip=DEV_IP)
    m340_snmp.apply_to_dev(dev, data)
    assert [(i.id, i.ip, i.connected) for i in dev.interface] == [
        ("1", DEV_IP, True),
        ("2", "", False),
        ("3", "", False),
        ("4", "", False),
    ]

    # Applying again (or the project file's interface, by IP) doesn't add interfaces
    m340_snmp.apply_to_dev(dev, data)
    dev.store("interface", Interface(ip=DEV_IP, type="ethernet"), lookup="ip")
    assert [i.id for i in dev.interface] == ["1", "2", "3", "4"]

    # Rows without an ifIndex or type are kept as separate interfaces
    dev = DeviceData(ip=DEV_IP)
    m340_snmp.apply_to_dev(dev, {"interfaces": [{"ifDescr": "ETH"}, {"ifDescr": "ETH"}]})
    assert len(dev.interface) == 2


@pytest.mark.parametrize("pull_methods", [["ftp", "modbus_tcp"], [], None])
def test_verify_snmp_disabled_by_pull_methods(monkeypatch, pull_methods):
    def _fail(*_args, **_kwargs):
        raise AssertionError("SNMP must not be used")

    monkeypatch.setattr(m340, "SNMP", _fail)
    dev = DeviceData(ip=DEV_IP)
    dev._runtime_options["m340"] = {"pull_methods": pull_methods}
    assert M340._verify_snmp(dev) is False


def test_pull_config_default_options(monkeypatch):
    calls = {}

    def _pull_network_config(**kwargs):
        calls.update(kwargs)
        return {}

    monkeypatch.setattr(m340.m340_parse, "parse_config_to_dict", lambda _blob: {})
    monkeypatch.setattr(m340_pull, "pull_network_config", _pull_network_config)

    dev = DeviceData(ip=DEV_IP)
    M340._pull_config(dev, b"")
    assert calls["methods"] == ["ftp", "snmp", "modbus_tcp"]
    assert calls["snmp_max_varbinds"] == m340_snmp.DEFAULT_MAX_VARBINDS
    assert M340.default_options["m340"]["pull_methods"] == list(m340_pull.NETWORK_PULL_METHODS)
    assert DeviceData().options["snmp"]["max_varbinds"] == m340_snmp.DEFAULT_MAX_VARBINDS


@pytest.mark.parametrize("pull_methods", [["snmp", "telnet"], [{"ftp": None}]])
def test_pull_invalid_pull_method(monkeypatch, pull_methods):
    def _fail(*_args, **_kwargs):
        raise AssertionError("must not contact the device")

    monkeypatch.setattr(M340, "pull_apx_file", _fail)
    dev = DeviceData(ip=DEV_IP)
    # [{"ftp": None}] is what YAML gives for a stray ":" ("- ftp:")
    dev._runtime_options["m340"] = {"pull_methods": pull_methods}
    assert M340._pull(dev) is False


def test_pull_without_snmp_sends_no_snmp(monkeypatch, tmp_path):
    # What "peat pull --skip-scan -d m340" does with "snmp" removed from pull_methods.
    # The SNMP code paths catch exceptions, so record the calls instead of raising.
    snmp_calls = []

    def _snmp(*args, **kwargs):
        snmp_calls.append((args, kwargs))
        raise CommError("SNMP must not be used")

    monkeypatch.setattr(m340, "SNMP", _snmp)
    monkeypatch.setattr(m340_pull, "SNMP", _snmp)
    monkeypatch.setattr(m340_snmp, "SNMP", _snmp)
    monkeypatch.setattr(m340_snmp, "pull_snmp", _snmp)
    monkeypatch.setattr(m340_pull, "_get_snmp_metadata", _snmp)
    monkeypatch.setattr(m340_pull, "_get_ftp_metadata", lambda *_a, **_kw: {"ftp": 1})
    monkeypatch.setattr(m340_pull, "_get_modbus_metadata", lambda *_a, **_kw: {"modbus": 2})
    monkeypatch.setattr(M340, "pull_apx_file", lambda _ip: b"")
    monkeypatch.setattr(M340, "_parse_blob", lambda **_kwargs: None)
    monkeypatch.setattr(m340.m340_parse, "parse_config_to_dict", lambda _blob: {})

    dev = DeviceData(ip=DEV_IP)
    dev._out_dir = tmp_path
    dev._runtime_options["m340"] = {"pull_methods": ["ftp", "modbus_tcp"]}
    dev._is_active = True
    dev._is_verified = True
    assert M340._pull(dev) is True
    assert dev.extra["ftp"] == 1
    assert dev.extra["modbus"] == 2
    assert not snmp_calls
