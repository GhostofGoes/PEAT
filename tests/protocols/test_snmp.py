import pytest
from pyasn1.type import univ
from pysnmp.proto import rfc1902, rfc1905

from peat import config
from peat.modules.schneider.m340.m340_snmp import SCHNEIDER_MIBS_DIR
from peat.protocols.snmp import (
    MAX_VALUE_LENGTH,
    SNMP,
    group_table_rows,
    normalize_iftype,
    value_to_python,
)

IF_TABLE_ENTRIES = [
    ("1.3.6.1.2.1.2.2.1.1.1", "Integer32", 1),
    ("1.3.6.1.2.1.2.2.1.1.2", "Integer32", 2),
    ("1.3.6.1.2.1.2.2.1.2.1", "OctetString", "ETH1"),
    ("1.3.6.1.2.1.2.2.1.2.2", "OctetString", "lo0"),
    ("1.3.6.1.2.1.2.2.1.3.1", "Integer32", 6),
    ("1.3.6.1.2.1.2.2.1.3.2", "Integer32", 24),
    ("1.3.6.1.2.1.2.2.1.6.1", "Hex", "0080f4010203"),
    ("1.3.6.1.2.1.2.2.1.6.2", "Hex", ""),
    ("1.3.6.1.2.1.2.2.1.7.1", "Integer32", 1),
    ("1.3.6.1.2.1.2.2.1.7.2", "Integer32", 2),
]

TFE = "1.3.6.1.4.1.3833.1"


def test_snmp_get_fails(mocker):
    mocker.patch.dict(config["CONFIG"], {"DEBUG": True})

    with pytest.raises(ValueError):
        SNMP(ip="127.0.0.1", snmp_version=20)

    with pytest.raises(ValueError):
        SNMP(ip="127.0.0.1").get(())

    assert not SNMP(ip="127.0.0.1", timeout=0.01).get("1.3.6.1.2.1.1.1.0")


def test_value_to_python_types():
    assert value_to_python(rfc1902.Integer32(-5)) == -5
    assert value_to_python(rfc1902.Counter32(7)) == 7
    assert value_to_python(rfc1902.Counter64(2**40)) == 2**40
    assert value_to_python(rfc1902.Gauge32(100)) == 100
    assert value_to_python(rfc1902.Unsigned32(3)) == 3
    assert value_to_python(rfc1902.TimeTicks(12345)) == 12345
    assert value_to_python(rfc1902.IpAddress("192.0.2.1")) == "192.0.2.1"
    assert value_to_python(rfc1902.ObjectName("1.3.6.1.4.1.3833")) == "1.3.6.1.4.1.3833"
    assert value_to_python(rfc1902.OctetString(b"BMX P34 2020\x00\x00")) == "BMX P34 2020"
    assert value_to_python(rfc1902.OctetString("café".encode())) == "café"
    assert value_to_python(rfc1902.OctetString(b"line1\r\nline2\t")) == "line1\r\nline2\t"
    assert value_to_python(rfc1902.OctetString(b"")) == ""
    # Non-printable or invalid UTF-8 => hex
    assert value_to_python(rfc1902.OctetString(hexValue="0080f4010203")) == "0080f4010203"
    assert value_to_python(rfc1902.OctetString(b"\xff\xfe")) == "fffe"
    assert value_to_python(rfc1902.OctetString(b"ab\x1bc")) == "61621b63"


def test_value_to_python_empty_values():
    for value in [
        None,
        univ.Null(""),
        rfc1905.noSuchObject,
        rfc1905.noSuchInstance,
        rfc1905.endOfMibView,
        rfc1902.Integer32(),  # schema object without a value
    ]:
        assert value_to_python(value) is None


def test_value_to_python_truncates_untrusted_strings():
    long_text = rfc1902.OctetString(b"a" * (MAX_VALUE_LENGTH + 10))
    assert len(value_to_python(long_text)) == MAX_VALUE_LENGTH
    long_binary = rfc1902.OctetString(b"\x01" * (MAX_VALUE_LENGTH * 5))
    assert len(value_to_python(long_binary)) == MAX_VALUE_LENGTH


def test_value_to_python_mib_types():
    snmp = SNMP(ip="192.0.2.10", mib_paths=[SCHNEIDER_MIBS_DIR])
    assert snmp.load_mibs("IF-MIB", "TFPRIVATE-MIB") == ["IF-MIB", "TFPRIVATE-MIB"]
    builder = snmp.engine.getMibBuilder()
    phys_address, display_string = builder.importSymbols(
        "SNMPv2-TC", "PhysAddress", "DisplayString"
    )
    (port502_status,) = builder.importSymbols("TFPRIVATE-MIB", "port502Status")
    (if_type,) = builder.importSymbols("IF-MIB", "ifType")

    assert value_to_python(phys_address(hexValue="0080f4010203")) == "00:80:f4:01:02:03"
    assert value_to_python(display_string(b"V3.40\x00")) == "V3.40"
    assert value_to_python(display_string("café".encode())) == "café"
    assert value_to_python(port502_status.getSyntax().clone(2)) == "operationnal"
    assert value_to_python(if_type.getSyntax().clone(6)) == "ethernetCsmacd"


def test_normalize_iftype():
    assert normalize_iftype(6) == "ethernet"
    assert normalize_iftype(24) == "loopback"
    assert normalize_iftype(999) == "999"
    assert normalize_iftype("ethernetCsmacd") == "ethernet"
    assert normalize_iftype("softwareLoopback") == "loopback"
    assert normalize_iftype("propVirtual") == "prop_virtual"
    assert normalize_iftype("") == ""


def test_group_table_rows():
    def col(table, name, index, value, parts):
        return {
            "node_type": "MibTableColumn",
            "table": table,
            "object_name": name,
            "index": index,
            "index_parts": parts,
            "value": value,
        }

    values = [
        {"node_type": "MibScalar", "table": "", "object_name": "ifNumber", "index": "0"},
        col("ifTable", "ifIndex", "2", 2, [2]),
        col("ifTable", "ifIndex", "1", 1, [1]),
        col("ifTable", "ifDescr", "2", "lo0", [2]),
        col("ifTable", "ifDescr", "1", "ETH1", [1]),
        col("connTable", "msgIn", "512.192.0.2.30", 5, [512, "192.0.2.30"]),
        col("", "orphan", "1", 1, [1]),  # no table name, ignored
    ]
    assert group_table_rows(values) == {
        "ifTable": [
            {"_index": "2", "_index_parts": [2], "ifIndex": 2, "ifDescr": "lo0"},
            {"_index": "1", "_index_parts": [1], "ifIndex": 1, "ifDescr": "ETH1"},
        ],
        "connTable": [
            {"_index": "512.192.0.2.30", "_index_parts": [512, "192.0.2.30"], "msgIn": 5}
        ],
    }
    assert group_table_rows([]) == {}


def test_load_mibs_reports_missing():
    snmp = SNMP(ip="192.0.2.10", mib_paths=[SCHNEIDER_MIBS_DIR])
    assert snmp.load_mibs("NOT-A-REAL-MIB", "SNMPv2-MIB", "TFPRIVATE-MIB") == [
        "SNMPv2-MIB",
        "TFPRIVATE-MIB",
    ]
    # Without the Schneider MIB directory, the vendor MIB isn't found
    assert SNMP(ip="192.0.2.10").load_mibs("TFPRIVATE-MIB") == []


def test_mib_sources_added_once(fake_snmp_cls):
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=IF_TABLE_ENTRIES)
    snmp.load_mibs("IF-MIB")
    snmp.get("1.3.6.1.2.1.2.2.1.2.1")
    # NOTE: PySNMP adds its MIB compiler's output directory once, on the first query
    num_sources = len(snmp.engine.getMibBuilder().getMibSources())
    snmp.get("1.3.6.1.2.1.2.2.1.2.1")
    snmp.walk("1.3.6.1.2.1.2.2")
    snmp.load_mibs("IF-MIB")
    assert len(snmp.engine.getMibBuilder().getMibSources()) == num_sources


def test_walk_resolves_types_and_tables(fake_snmp_cls):
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=IF_TABLE_ENTRIES)
    snmp.load_mibs("IF-MIB")

    values = snmp.walk("1.3.6.1.2.1.2.2")
    assert len(values) == len(IF_TABLE_ENTRIES)
    by_name = {(v["object_name"], v["index"]): v for v in values}

    if_type = by_name[("ifType", "1")]
    assert if_type["mib_name"] == "IF-MIB"
    assert if_type["node_type"] == "MibTableColumn"
    assert if_type["table"] == "ifTable"
    assert if_type["value"] == "ethernetCsmacd"
    assert if_type["value_encoded"] == 6
    assert if_type["value_string"] == "ethernet"  # legacy conversion
    assert if_type["index_parts"] == [1]
    assert by_name[("ifPhysAddress", "1")]["value"] == "00:80:f4:01:02:03"
    assert by_name[("ifAdminStatus", "2")]["value"] == "down"
    assert values in snmp.all_output.values()

    assert snmp.get_table("1.3.6.1.2.1.2.2") == [
        {
            "_index": "1",
            "_index_parts": [1],
            "ifIndex": 1,
            "ifDescr": "ETH1",
            "ifType": "ethernetCsmacd",
            "ifPhysAddress": "00:80:f4:01:02:03",
            "ifAdminStatus": "up",
        },
        {
            "_index": "2",
            "_index_parts": [2],
            "ifIndex": 2,
            "ifDescr": "lo0",
            "ifType": "softwareLoopback",
            "ifPhysAddress": "",
            "ifAdminStatus": "down",
        },
    ]


def test_get_index_pretty_ipaddress(fake_snmp_cls):
    entries = [
        (f"{TFE}.3.6.1.2.192.0.2.21", "Integer32", 2),
        # glbDataPubTable, index: glbDataPubGroupId (IpAddress) + glbDataPubNetId (string)
        (f"{TFE}.4.9.1.2.239.0.0.1.3.110.101.116", "Integer32", 7),
    ]
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=entries, mib_paths=[SCHNEIDER_MIBS_DIR])
    snmp.load_mibs("TFPRIVATE-MIB")

    io_scan = snmp.get(f"{TFE}.3.6.1.2.192.0.2.21")
    assert len(io_scan) == 1
    assert io_scan[0]["index"] == "192.0.2.21"
    assert io_scan[0]["index_parts"] == ["192.0.2.21"]
    assert io_scan[0]["table"] == "ioScanDeviceTable"
    assert io_scan[0]["value"] == "ok"

    glb_data = snmp.walk(f"{TFE}.4.9")
    assert glb_data[0]["object_name"] == "glbDataPubHostId"
    assert glb_data[0]["index_parts"] == ["239.0.0.1", "net"]
    assert glb_data[0]["value"] == 7


def test_get_includes_oid_valued_objects(fake_snmp_cls):
    snmp = fake_snmp_cls(
        ip="192.0.2.10",
        entries=[("1.3.6.1.2.1.1.2.0", "OID", f"{TFE}.7.255.20")],
        mib_paths=[SCHNEIDER_MIBS_DIR],
    )
    snmp.load_mibs("SNMPv2-MIB", "TFPRIVATE-MIB")

    result = snmp.get("1.3.6.1.2.1.1.2.0")
    assert len(result) == 1
    assert result[0]["object_name"] == "sysObjectID"
    assert result[0]["node_type"] == "MibScalar"
    assert result[0]["value"] == f"{TFE}.7.255.20"
    assert result[0]["value_encoded"] == f"{TFE}.7.255.20"
    assert "TFPRIVATE-MIB" in result[0]["value_string"]


def test_unresolved_and_out_of_range_values(fake_snmp_cls):
    entries = [
        ("1.3.6.1.4.1.99999.1.0", "Integer32", 3),  # no MIB for this enterprise
        (f"{TFE}.2.1.0", "Integer32", 7),  # port502Status, not in the enumeration
        # port502ConnTable, port502ConnLocalPort (512..3071) out of range in the index
        (f"{TFE}.2.8.1.5.80.192.0.2.30.49152.0.0", "Counter32", 1),
    ]
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=entries, mib_paths=[SCHNEIDER_MIBS_DIR])
    snmp.load_mibs("TFPRIVATE-MIB")

    unresolved = snmp.get("1.3.6.1.4.1.99999.1.0")[0]
    assert unresolved["value"] == 3
    assert unresolved["node_type"] != "MibScalar"
    assert unresolved["table"] == ""

    assert snmp.get(f"{TFE}.2.1.0")[0]["value"] == 7

    conn = snmp.walk(f"{TFE}.2.8")[0]
    assert conn["object_name"] == "port502ConnMsgIn"
    assert conn["index"] == "80.192.0.2.30.49152.0.0"
    assert conn["value"] == 1


def test_walk_drops_empty_values_and_v1_end_echo(fake_snmp_cls):
    entries = IF_TABLE_ENTRIES[:4]
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=entries, v1_end_echo=True)
    snmp.load_mibs("IF-MIB")
    values = snmp.walk("1.3.6.1.2.1.2.2")
    assert [v["oid"] for v in values] == [e[0] for e in entries]

    # noSuchObject, noSuchInstance, endOfMibView, etc. are dropped
    sys_descr = rfc1902.OctetString(b"x")
    var_name, _ = snmp._resolve_var_bind(rfc1902.ObjectName("1.3.6.1.2.1.1.1.0"), sys_descr, [])
    for empty in [univ.Null(""), rfc1905.noSuchObject, rfc1905.endOfMibView]:
        assert SNMP._var_bind_to_dict(var_name, empty) is None
    assert SNMP._var_bind_to_dict(var_name, sys_descr)["object_name"] == "sysDescr"


def test_walk_returns_partial_on_timeout(fake_snmp_cls):
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=IF_TABLE_ENTRIES, timeout_after=3)
    snmp.load_mibs("IF-MIB")
    partial = snmp.walk("1.3.6.1.2.1.2.2")
    assert len(partial) == 3
    assert partial in snmp.all_output.values()
    assert snmp.timed_out

    # get() keeps the existing behavior of returning nothing on errors
    assert snmp.get("1.3.6.1.2.1.2.2", single_query=False) == []
    assert snmp.get("1.3.6.1.2.1.2.2.1.1.1") == []
    assert snmp.walk("1.3.6.1.2.1.2.2") == []

    # The error is reset by the next query
    snmp.timeout_after = None
    assert len(snmp.walk("1.3.6.1.2.1.2.2")) == len(IF_TABLE_ENTRIES)
    assert snmp.last_error is None
    assert not snmp.timed_out


def test_malformed_index_kept_unresolved_and_walk_continues(fake_snmp_cls):
    # ioScanDeviceTable is indexed by an IpAddress (4 sub-identifiers)
    column = f"{TFE}.3.6.1.2"
    entries = [
        (f"{column}.192.0.2.21", "Integer32", 1),
        (f"{column}.192.0.2.22.7", "Integer32", 2),  # one sub-identifier too many
        (f"{column}.192.0.2.23", "Integer32", 2),
        (f"{TFE}.3.6.1.3.192.0.2.300", "Integer32", 1),  # not an IPv4 address
        (f"{TFE}.3.6.1.3.192.0.2.21", "Integer32", 1),
    ]
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=entries, mib_paths=[SCHNEIDER_MIBS_DIR])
    snmp.load_mibs("TFPRIVATE-MIB")

    values = snmp.walk(f"{TFE}.3.6")
    assert [v["oid"] for v in values] == [e[0] for e in sorted(entries)]
    assert snmp.last_error is None

    by_oid = {v["oid"]: v for v in values}
    for bad in [f"{column}.192.0.2.22.7", f"{TFE}.3.6.1.3.192.0.2.300"]:
        assert by_oid[bad]["object_name"] == ""
        assert by_oid[bad]["node_type"] == ""
        assert by_oid[bad]["pretty_name"] == bad
        assert by_oid[bad]["value"] in (1, 2)
    assert by_oid[f"{column}.192.0.2.23"]["object_name"] == "ioScanDeviceHealth"

    rows = group_table_rows(values)["ioScanDeviceTable"]
    assert [r["_index"] for r in rows] == ["192.0.2.21", "192.0.2.23"]


def test_walk_returns_partial_on_pysnmp_error(fake_snmp_cls):
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=IF_TABLE_ENTRIES, raise_after=2)
    snmp.load_mibs("IF-MIB")

    partial = snmp.walk("1.3.6.1.2.1.2.2")
    assert len(partial) == 2
    assert partial in snmp.all_output.values()
    assert snmp.last_error is not None
    assert not snmp.timed_out
    assert snmp.get("1.3.6.1.2.1.2.2", single_query=False) == []

    # The engine is still usable after the error
    snmp.raise_after = None
    assert len(snmp.walk("1.3.6.1.2.1.2.2")) == len(IF_TABLE_ENTRIES)


def test_get_single_query_missing_object(fake_snmp_cls):
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=IF_TABLE_ENTRIES)
    assert snmp.get("1.3.6.1.2.1.1.1.0") == []  # SNMPv1 noSuchName
    assert snmp.get("1.3.6.1.2.1.2.2.1.1.2")[0]["value"] == 2


def test_walk_max_varbinds(fake_snmp_cls):
    snmp = fake_snmp_cls(ip="192.0.2.10", entries=IF_TABLE_ENTRIES)
    assert len(snmp.walk("1.3.6.1.2.1.2.2", max_varbinds=4)) == 4
    assert snmp.responses == 4
    assert len(snmp.walk("1.3.6.1.2.1.2.2", max_varbinds=0)) == len(IF_TABLE_ENTRIES)
