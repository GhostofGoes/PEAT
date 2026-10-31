import pytest
from pydantic import ValidationError

from peat import ModuleProtocol, PeatError
from peat.module_protocol import (
    MODULE_OPERATIONS,
    PROTOCOL_OPERATIONS,
    ProtocolFilterTerm,
    normalize_protocol_name,
    parse_protocol_filter,
)


def _proto(**kwargs) -> ModuleProtocol:
    values = {"name": "ftp", "transport": "tcp", "ports": [21], "operations": ["pull"]}
    values.update(kwargs)
    return ModuleProtocol(**values)


def _term(value: str) -> ProtocolFilterTerm:
    terms = parse_protocol_filter(value)
    assert len(terms) == 1
    return terms[0]


def test_operation_constants():
    assert PROTOCOL_OPERATIONS == ("scan", "pull", "push")
    assert MODULE_OPERATIONS == ("scan", "pull", "push", "parse")


def test_module_protocol_normalization():
    proto = _proto(
        name="  Modbus_TCP ",
        ports=[503, 502, 502],
        operations=["push", "pull", "push", "scan"],
        options_key=" SSH ",
    )
    assert proto.name == "modbus_tcp"
    assert proto.ports == [502, 503]
    assert proto.operations == ["scan", "pull", "push"]
    assert proto.options_key == "ssh"
    assert proto.description == ""


def test_module_protocol_defaults():
    proto = ModuleProtocol(name="serial", transport="serial", operations=["pull"])
    assert proto.ports == []
    assert proto.options_key is None
    assert proto.configured_by == "serial"
    assert proto.transports == {"serial"}

    other = ModuleProtocol(name="raw_ethernet", transport="other", operations=["scan"])
    assert other.ports == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"transport": "tcp", "ports": []},
        {"transport": "udp", "ports": []},
        {"transport": "both", "ports": []},
        {"transport": "serial", "ports": [21]},
        {"transport": "sctp"},
        {"ports": [0]},
        {"ports": [70000]},
        {"ports": [-21]},
        {"operations": []},
        {"operations": ["parse"]},
        {"operations": ["scan", "delete"]},
        {"name": "ftp/21"},
        {"name": "ftp,ssh"},
        {"name": "1ftp"},
        {"name": ""},
        {"name": "f t p"},
        {"options_key": "bad key"},
        {"options_key": "-ssh"},
        {"unknown_field": True},
    ],
)
def test_module_protocol_validation_errors(kwargs):
    with pytest.raises(ValidationError):
        _proto(**kwargs)


def test_module_protocol_assignment_validated():
    proto = _proto(ports=[21])
    with pytest.raises(ValidationError):
        proto.ports = []
    with pytest.raises(ValidationError):
        proto.operations = []

    proto.ports = [990, 21, 990]
    assert proto.ports == [21, 990]
    proto.operations = ["push", "scan"]
    assert proto.operations == ["scan", "push"]


def test_module_protocol_properties():
    assert _proto().configured_by == "ftp"
    assert _proto(name="sftp", ports=[22], options_key="ssh").configured_by == "ssh"
    assert _proto(transport="both").transports == {"tcp", "udp"}
    assert _proto(transport="udp").transports == {"udp"}


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (None, []),
        ("", []),
        ("  ", []),
        ([], []),
        (",, ,", []),
        ("ftp", [ProtocolFilterTerm(raw="ftp", name="ftp")]),
        ("FTP", [ProtocolFilterTerm(raw="ftp", name="ftp")]),
        (" modbus_tcp ", [ProtocolFilterTerm(raw="modbus_tcp", name="modbus_tcp")]),
        ("servlink-tcp", [ProtocolFilterTerm(raw="servlink-tcp", name="servlink-tcp")]),
        (502, [ProtocolFilterTerm(raw="502", port_range=(502, 502))]),
        ("502", [ProtocolFilterTerm(raw="502", port_range=(502, 502))]),
        ("20-25", [ProtocolFilterTerm(raw="20-25", port_range=(20, 25))]),
        ("1-65535", [ProtocolFilterTerm(raw="1-65535", port_range=(1, 65535))]),
        (
            "161/UDP",
            [ProtocolFilterTerm(raw="161/udp", port_range=(161, 161), transport="udp")],
        ),
        (
            "20-21/tcp",
            [ProtocolFilterTerm(raw="20-21/tcp", port_range=(20, 21), transport="tcp")],
        ),
        (
            "ftp,telnet",
            [
                ProtocolFilterTerm(raw="ftp", name="ftp"),
                ProtocolFilterTerm(raw="telnet", name="telnet"),
            ],
        ),
        (
            ["ftp", 502, "ftp, 161/udp", "FTP"],
            [
                ProtocolFilterTerm(raw="ftp", name="ftp"),
                ProtocolFilterTerm(raw="502", port_range=(502, 502)),
                ProtocolFilterTerm(raw="161/udp", port_range=(161, 161), transport="udp"),
            ],
        ),
        (
            ("http https",),
            [
                ProtocolFilterTerm(raw="http", name="http"),
                ProtocolFilterTerm(raw="https", name="https"),
            ],
        ),
    ],
)
def test_parse_protocol_filter_valid(values, expected):
    assert parse_protocol_filter(values) == expected


@pytest.mark.parametrize(
    "value",
    [
        "ftp:21",
        "0",
        "70000",
        "65536",
        "123456",
        "25-20",
        "0-10",
        "21/sctp",
        "/tcp",
        "-5",
        "21-",
        "tcp/21",
        "_ftp",
        "ftp/tcp",
        "ftp;rm -rf",
        "21/tcp/udp",
        "*",
    ],
)
def test_parse_protocol_filter_invalid(value):
    with pytest.raises(PeatError):
        parse_protocol_filter(value)


def test_parse_protocol_filter_invalid_in_list():
    with pytest.raises(PeatError, match="ftp:21"):
        parse_protocol_filter(["ftp", "ftp:21"])


def test_matches_names():
    ftp = _proto()
    assert ftp.matches(_term("ftp"))
    assert not ftp.matches(_term("ftps"))
    assert not ftp.matches(_term("ft"))
    assert not ftp.matches(_term("http"))

    modbus = _proto(name="modbus_tcp", ports=[502])
    assert modbus.matches(_term("modbus"))
    assert modbus.matches(_term("modbus_tcp"))
    assert not modbus.matches(_term("modbusx"))
    assert not modbus.matches(_term("modbus_t"))
    assert not modbus.matches(_term("tcp"))

    # Match the options key
    sftp = _proto(name="sftp", ports=[22], options_key="ssh")
    assert sftp.matches(_term("ssh"))
    assert sftp.matches(_term("sftp"))
    umas = _proto(name="umas", ports=[502], options_key="modbus_tcp")
    assert umas.matches(_term("modbus"))

    # "serial" matches any serial protocol
    servlink = ModuleProtocol(name="servlink_serial", transport="serial", operations=["scan"])
    assert servlink.matches(_term("serial"))
    assert servlink.matches(_term("servlink"))
    assert not ftp.matches(_term("serial"))


def test_matches_ports():
    ftp = _proto()
    assert ftp.matches(_term("21"))
    assert ftp.matches(_term("20-25"))
    assert ftp.matches(_term("21-21"))
    assert ftp.matches(_term("21/tcp"))
    assert not ftp.matches(_term("21/udp"))
    assert not ftp.matches(_term("22"))
    assert not ftp.matches(_term("22-30"))

    servlink = _proto(name="servlink_tcp", ports=[666, 667])
    assert servlink.matches(_term("667"))
    assert servlink.matches(_term("660-666"))
    assert not servlink.matches(_term("668-700"))

    cip_udp = _proto(name="cip", transport="udp", ports=[44818])
    assert cip_udp.matches(_term("44818/udp"))
    assert not cip_udp.matches(_term("44818/tcp"))

    modbus_both = _proto(name="modbus_tcp", transport="both", ports=[502])
    assert modbus_both.matches(_term("502/tcp"))
    assert modbus_both.matches(_term("502/udp"))

    serial = ModuleProtocol(name="serial", transport="serial", operations=["scan"])
    assert not serial.matches(_term("1-65535"))


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ftp", "ftp"),
        ("modbus_tcp", "modbus_tcp"),
        ("servlink-serial", "servlink-serial"),
        ("  HTTPS ", "https"),
        ("opc.ua", "opc_ua"),
        ("Modbus/TCP", "modbus_tcp"),
        ("ethernet/ip", "ethernet_ip"),
        ("iec 60870-5-104", "iec_60870-5-104"),
        ("bacnet//ip..", "bacnet_ip"),
        ("_private", "private"),
        ("104", "proto_104"),
        ("<script>", "script"),
        ("ünïcode", "n_code"),
        ("", "unknown"),
        ("...", "unknown"),
    ],
)
def test_normalize_protocol_name(name, expected):
    result = normalize_protocol_name(name)
    assert result == expected
    # The result is always a valid protocol name
    ModuleProtocol(name=result, transport="other", operations=["scan"])
