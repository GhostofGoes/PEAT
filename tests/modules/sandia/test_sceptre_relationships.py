"""
Relationships, tasks and canonical protocol names from SCEPTRE (bennu) field
device configs. Synthetic configs in the format of the bennu examples.
"""

from datetime import timedelta

import pytest

from peat import SCEPTRE, config, datastore
from peat.modules.sandia import sceptre_fcd

SERIAL_CLIENT = """<?xml version="1.0" encoding="utf-8"?>
<SCEPTRE>
    <field-device>
        <name>fep-2</name>
        <comms>
            <modbus-client>
                <modbus-connection>
                    <endpoint>/dev/ttyS1</endpoint>
                    <coil>
                        <address>0</address>
                        <tag>breaker-toggle</tag>
                    </coil>
                </modbus-connection>
            </modbus-client>
        </comms>
    </field-device>
</SCEPTRE>
"""

RTU = """<?xml version="1.0" encoding="utf-8"?>
<SCEPTRE>
    <field-device>
        <name>rtu-9</name>
        <cycle-time>500</cycle-time>
        <comms>
            <dnp3-server>
                <endpoint>tcp://192.0.2.9:20000</endpoint>
                <address>10</address>
                <binary-input>
                    <address>0</address>
                    <tag>brkr</tag>
                </binary-input>
            </dnp3-server>
            <iec60870-5-104-client>
                <iec60870-5-104-connection>
                    <endpoint>tcp://192.0.2.50:2404</endpoint>
                    <binary-input>
                        <address>100</address>
                        <tag>status</tag>
                    </binary-input>
                </iec60870-5-104-connection>
            </iec60870-5-104-client>
        </comms>
        <input>
            <endpoint>udp://192.0.2.9;239.0.0.1:40000</endpoint>
            <analog>
                <id>I0</id>
                <name>bus-1.voltage</name>
            </analog>
        </input>
        <output>
            <endpoint>tcp://192.0.2.2:5555</endpoint>
            <binary>
                <id>O0</id>
                <name>breaker.closed</name>
            </binary>
        </output>
    </field-device>
</SCEPTRE>
"""


@pytest.fixture(autouse=True)
def _isolated_datastore(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch.object(datastore, "objects", [])


def test_dnp3_client_relationship(datapath, assert_no_errors):
    dev = SCEPTRE.parse_config(datapath("bp/dnp3-client.xml"))

    assert dev.name == "fep-1"
    assert len(dev.relationships) == 1
    rel = dev.relationships[0]
    assert rel.type == "communicates_with"
    assert rel.protocol == "dnp3"
    assert rel.transport == "tcp"
    assert rel.direction == "egress"
    assert rel.evidence == {"config"}
    assert rel.local.role == "master"
    assert rel.local.protocol_address == "1"
    assert rel.remote.role == "outstation"
    assert rel.remote.ip == "127.0.0.1"
    assert rel.remote.port == 20000
    assert rel.remote.protocol_address == "10"
    assert rel.extra == {"scan_rate": 5}
    assert rel.id

    # The scan rate moved from the service to the relationship
    svc = dev.service[0]
    assert svc.protocol == "dnp3"
    assert "scan-rate" not in svc.extra

    # No cycle time in this config
    assert not dev.logic.tasks
    assert "cycle_time" not in dev.extra
    assert_no_errors()


def test_serial_client_relationship(assert_no_errors):
    dev = SCEPTRE.parse_config(SERIAL_CLIENT)

    assert len(dev.relationships) == 1
    rel = dev.relationships[0]
    assert rel.protocol == "modbus_rtu"
    assert rel.medium == "serial"
    assert rel.transport == ""
    assert rel.local.serial_port == "/dev/ttyS1"
    assert rel.local.role == "client"
    assert rel.remote.role == "server"
    assert rel.remote.ip == ""
    assert rel.direction == "egress"

    # Same protocol name as the device's own service
    assert dev.service[0].protocol == "modbus_rtu"
    assert_no_errors()


def test_rtu_relationships_and_cycle_time(assert_no_errors):
    dev = SCEPTRE.parse_config(RTU)

    # <cycle-time> (milliseconds) -> the main task of the device
    assert "cycle_time" not in dev.extra
    assert len(dev.logic.tasks) == 1
    task = dev.logic.tasks[0]
    assert task.name == "main"
    assert task.type == "cyclic"
    assert task.interval == timedelta(milliseconds=500)

    rels = {(r.type, r.extra.get("io", "")): r for r in dev.relationships}
    assert set(rels) == {
        ("communicates_with", ""),
        ("depends_on", "input"),
        ("depends_on", "output"),
    }

    iec104 = rels[("communicates_with", "")]
    assert iec104.protocol == "iec104"
    assert iec104.local.role == "controlling_station"
    assert iec104.remote.role == "controlled_station"
    assert iec104.remote.ip == "192.0.2.50"
    assert iec104.remote.port == 2404

    io_in = rels[("depends_on", "input")]
    assert io_in.remote.role == "io_provider"
    assert io_in.extra["multicast_ip"] == "239.0.0.1"
    assert io_in.local.ip == "192.0.2.9"
    assert io_in.remote.ip == ""
    assert io_in.remote.port == 40000
    assert io_in.transport == "udp"
    assert io_in.direction == "ingress"

    io_out = rels[("depends_on", "output")]
    assert io_out.remote.role == "io_provider"
    assert io_out.remote.ip == "192.0.2.2"
    assert io_out.remote.port == 5555
    assert io_out.transport == "tcp"
    assert io_out.direction == "egress"

    # DNP3 server: the canonical protocol name, no relationship (no peer configured)
    protocols = {s.protocol for s in dev.service}
    assert protocols == {"dnp3", "iec104"}
    assert {"192.0.2.50", "192.0.2.2"} <= dev.related.ip
    assert_no_errors()


@pytest.mark.parametrize(
    ("protocol", "endpoint", "expected"),
    [
        ("modbus", {"transport": "tcp", "ip": "192.0.2.1"}, "modbus_tcp"),
        ("modbus", {"ip": "192.0.2.1"}, "modbus_tcp"),
        ("modbus", {"serial_port": "/dev/ttyS0"}, "modbus_rtu"),
        ("modbus", {}, "modbus"),
        ("iec60870_5_104", {"transport": "tcp"}, "iec104"),
        ("dnp3", {"transport": "tcp"}, "dnp3"),
        ("bacnet", {"transport": "udp"}, "bacnet"),
        ("sunspec_tcp", {"transport": "tcp"}, "sunspec_tcp"),
    ],
)
def test_canonical_protocol(protocol, endpoint, expected):
    assert sceptre_fcd.canonical_protocol(protocol, endpoint) == expected


def test_io_provider_relationship():
    assert sceptre_fcd.io_provider_relationship("input", None) is None
    assert sceptre_fcd.io_provider_relationship("input", "/dev/ttyS0") is None

    rel = sceptre_fcd.io_provider_relationship("input", "udp://239.0.0.1:40000")
    assert rel.extra == {"io": "input", "multicast_ip": "239.0.0.1"}
    assert rel.remote.ip == ""
    assert rel.local.ip == ""
    assert rel.remote.address == "udp://239.0.0.1:40000"
