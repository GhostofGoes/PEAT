"""
Tests for the capability metadata of device modules (operations, protocols,
ports, and supported models), including checks that the metadata of the modules
included with PEAT is complete and agrees with the documentation tables.
"""

import csv
import json
import re
from pathlib import Path

import pytest

from peat import (
    DeviceData,
    DeviceModule,
    IPMethod,
    ModuleProtocol,
    PeatError,
    SerialMethod,
    module_api,
)
from peat.data.default_options import DEFAULT_OPTIONS
from peat.file_signature import FileSignature
from peat.module_protocol import PROTOCOL_OPERATIONS

DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"

# Modules referenced in the documentation that aren't included in open-source PEAT
DOC_ONLY_MODULES = {"ION"}


def _identify(dev: DeviceData) -> bool:  # noqa: ARG001
    return False


def _ip_method(name: str, protocol: str, port: int, **kwargs) -> IPMethod:
    values = {
        "name": name,
        "description": name,
        "type": "unicast_ip",
        "identify_function": _identify,
        "reliability": 5,
        "protocol": protocol,
        "transport": "tcp",
        "default_port": port,
    }
    values.update(kwargs)
    return IPMethod(**values)


class ScanOnly(DeviceModule):
    """A module that can only identify devices."""

    ip_methods = [
        _ip_method("http one", "http", 80),
        _ip_method("http two", "http", 80),
        _ip_method("snmp", "snmp", 161, transport="udp"),
        _ip_method("snmp broadcast", "snmp", 161, transport="udp", type="broadcast_ip"),
    ]


class ParseOnly(DeviceModule):
    """A module that can only parse files.

    More details.
    """

    filename_patterns = ["*.parseme"]

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:  # noqa: ARG003
        return None


class ParseNoPatterns(DeviceModule):
    # No docstring, no filename patterns or signatures, so it can't parse
    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:  # noqa: ARG003
        return None


class ParseSignatures(ParseNoPatterns):
    """Parses files using signatures."""

    file_signatures = [FileSignature(default_filename="thing.bin", magic_number="00ff")]


class ParseDir(ParseNoPatterns):
    """Parses directories."""

    can_parse_dir = True


class PullNoScan(DeviceModule):
    """Implements _pull(), but has no way to identify devices."""

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:  # noqa: ARG003
        return True


class Full(DeviceModule):
    """A module that does everything."""

    device_type = "PLC"
    vendor_id = "ACME"
    vendor_name = "ACME, Inc."
    brand = "Roadrunner"
    model = "RR-1"
    supported_models = ["RR-1", "RR-2"]
    module_aliases = ["acme-full"]
    filename_patterns = ["*.acme"]
    ip_methods = [
        _ip_method("ftp login", "ftp", 21),
        _ip_method("cip list identity", "cip", 44818, transport="udp"),
    ]
    serial_methods = [
        SerialMethod(
            name="serial check",
            description="serial check",
            type="direct",
            identify_function=_identify,
            reliability=4,
        )
    ]
    protocols = [
        ModuleProtocol(
            name="ftp",
            transport="tcp",
            ports=[21],
            operations=["pull", "push"],
            description="Download and upload files",
        ),
        ModuleProtocol(
            name="cip",
            transport="tcp",
            ports=[44818],
            operations=["pull"],
            description="Explicit messaging",
        ),
        ModuleProtocol(
            name="sftp",
            transport="tcp",
            ports=[22, 2222],
            operations=["pull"],
            options_key="ssh",
            description="Download files via SFTP",
        ),
        ModuleProtocol(
            name="modbus_tcp",
            transport="both",
            ports=[502],
            operations=["push"],
        ),
    ]

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:  # noqa: ARG003
        return True

    @classmethod
    def _push(cls, dev, to_push, push_type) -> bool:  # noqa: ARG003
        return True

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:  # noqa: ARG003
        return None


class PullUndeclared(DeviceModule):
    """A module (e.g. a third-party module) that doesn't declare its protocols."""

    ip_methods = [
        _ip_method("telnet login", "telnet", 23),
        _ip_method("http page", "http", 8080),
    ]
    serial_methods = [
        SerialMethod(
            name="servlink",
            description="servlink",
            type="direct",
            identify_function=_identify,
            reliability=4,
            protocol="servlink_serial",
        )
    ]

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:  # noqa: ARG003
        return True


class PushDeclaredPullUndeclared(PullUndeclared):
    """Declares protocols for push, but not for pull."""

    protocols = [
        ModuleProtocol(name="ftp", transport="tcp", ports=[21], operations=["push"]),
    ]

    @classmethod
    def _push(cls, dev, to_push, push_type) -> bool:  # noqa: ARG003
        return True


SYNTHETIC_MODULES = [
    ScanOnly,
    ParseOnly,
    ParseNoPatterns,
    ParseSignatures,
    ParseDir,
    PullNoScan,
    Full,
    PullUndeclared,
    PushDeclaredPullUndeclared,
]


@pytest.mark.parametrize(
    ("mod", "expected"),
    [
        (ScanOnly, ["scan"]),
        (ParseOnly, ["parse"]),
        (ParseNoPatterns, []),
        (ParseSignatures, ["parse"]),
        (ParseDir, ["parse"]),
        (PullNoScan, []),
        (Full, ["scan", "pull", "push", "parse"]),
        (PullUndeclared, ["scan", "pull"]),
        (PushDeclaredPullUndeclared, ["scan", "pull", "push"]),
        (DeviceModule, []),
    ],
)
def test_get_operations(mod, expected):
    assert mod.get_operations() == expected
    for op in ("scan", "pull", "push", "parse"):
        assert mod.supports(op) is (op in expected)


def test_get_comm_types():
    assert ScanOnly.get_comm_types() == ["unicast_ip", "broadcast_ip"]
    assert Full.get_comm_types() == ["unicast_ip", "serial"]
    assert ParseOnly.get_comm_types() == []


def test_get_method_names():
    assert ScanOnly.get_method_names() == ["http one", "http two", "snmp", "snmp broadcast"]
    assert ScanOnly.get_method_names("unicast_ip") == ["http one", "http two", "snmp"]
    assert ScanOnly.get_method_names("broadcast_ip") == ["snmp broadcast"]
    assert ScanOnly.get_method_names("serial") == []
    assert Full.get_method_names() == ["ftp login", "cip list identity", "serial check"]
    assert Full.get_method_names("serial") == ["serial check"]
    assert ParseOnly.get_method_names() == []


def test_get_protocol_details_scan_only():
    details = ScanOnly.get_protocol_details()
    # Methods with the same protocol and transport are merged
    assert [(p.name, p.transport, p.ports, p.operations) for p in details] == [
        ("http", "tcp", [80], ["scan"]),
        ("snmp", "udp", [161], ["scan"]),
    ]
    assert ScanOnly.get_protocol_details("pull") == []
    assert ParseOnly.get_protocol_details() == []


def test_get_protocol_details_merged():
    details = {(p.name, p.transport): p for p in Full.get_protocol_details()}
    assert sorted(details) == [
        ("cip", "tcp"),
        ("cip", "udp"),
        ("ftp", "tcp"),
        ("modbus_tcp", "both"),
        ("serial", "serial"),
        ("sftp", "tcp"),
    ]
    # Scan (from ip_methods) and declared pull/push are merged into one entry
    assert details[("ftp", "tcp")].operations == ["scan", "pull", "push"]
    assert details[("ftp", "tcp")].description == "Download and upload files"
    # A different transport is a separate entry
    assert details[("cip", "udp")].operations == ["scan"]
    assert details[("cip", "tcp")].operations == ["pull"]
    assert details[("serial", "serial")].operations == ["scan"]
    assert details[("sftp", "tcp")].options_key == "ssh"

    # Sorted by name, then transport
    names = [(p.name, p.transport) for p in Full.get_protocol_details()]
    assert names == sorted(names)

    assert [p.name for p in Full.get_protocol_details("push")] == ["ftp", "modbus_tcp"]
    assert [(p.name, p.transport) for p in Full.get_protocol_details("scan")] == [
        ("cip", "udp"),
        ("ftp", "tcp"),
        ("serial", "serial"),
    ]


def test_get_protocol_details_inferred():
    # Pull isn't declared, so it's assumed to use the scan protocols
    details = PullUndeclared.get_protocol_details()
    assert [(p.name, p.operations) for p in details] == [
        ("http", ["scan", "pull"]),
        ("servlink_serial", ["scan", "pull"]),
        ("telnet", ["scan", "pull"]),
    ]
    assert PullUndeclared.get_protocols("pull") == ["http", "servlink_serial", "telnet"]
    assert PullUndeclared.get_protocols("push") == []

    # Push is declared, pull isn't
    assert PushDeclaredPullUndeclared.get_protocols("push") == ["ftp"]
    assert PushDeclaredPullUndeclared.get_protocols("pull") == [
        "http",
        "servlink_serial",
        "telnet",
    ]


def test_get_protocol_details_invalid_operation():
    with pytest.raises(ValueError, match="invalid operation"):
        Full.get_protocol_details("parse")
    with pytest.raises(ValueError, match="invalid operation"):
        Full.get_protocols("delete")


@pytest.mark.parametrize(
    ("mod", "operation", "comm_type", "expected"),
    [
        # Scans only use the methods for the comm type
        (ScanOnly, "scan", "unicast_ip", [("http", "tcp"), ("snmp", "udp")]),
        (ScanOnly, "scan", "broadcast_ip", [("snmp", "udp")]),
        (ScanOnly, "scan", "serial", []),
        (Full, "scan", "unicast_ip", [("cip", "udp"), ("ftp", "tcp")]),
        (Full, "scan", "broadcast_ip", []),
        (Full, "scan", "serial", [("serial", "serial")]),
        (Full, None, "serial", [("serial", "serial")]),
        # Pull and push use the serial or network protocols
        (Full, "pull", "unicast_ip", [("cip", "tcp"), ("ftp", "tcp"), ("sftp", "tcp")]),
        (Full, "pull", "broadcast_ip", [("cip", "tcp"), ("ftp", "tcp"), ("sftp", "tcp")]),
        (Full, "pull", "serial", []),
        (Full, "push", "unicast_ip", [("ftp", "tcp"), ("modbus_tcp", "both")]),
        # Inferred pull protocols include methods of other IP comm types
        (PullUndeclared, "pull", "unicast_ip", [("http", "tcp"), ("telnet", "tcp")]),
        (PullUndeclared, "pull", "broadcast_ip", [("http", "tcp"), ("telnet", "tcp")]),
        (PullUndeclared, "pull", "serial", [("servlink_serial", "serial")]),
        (PullUndeclared, "scan", "broadcast_ip", []),
    ],
)
def test_get_protocol_details_comm_type(mod, operation, comm_type, expected):
    details = mod.get_protocol_details(operation, comm_type)
    assert [(p.name, p.transport) for p in details] == expected
    assert mod.get_protocols(operation, comm_type) == sorted({name for name, _ in expected})


def test_get_protocol_details_comm_type_operations():
    # Operations of entries are limited to the ones used with the comm type
    details = {p.name: p for p in ScanOnly.get_protocol_details(comm_type="broadcast_ip")}
    assert list(details) == ["snmp"]
    details = {p.name: p for p in PullUndeclared.get_protocol_details(comm_type="broadcast_ip")}
    assert details["http"].operations == ["pull"]


def test_get_protocol_details_invalid_comm_type():
    with pytest.raises(ValueError, match="invalid comm_type"):
        Full.get_protocol_details(comm_type="carrier_pigeon")


class OddProtocolNames(DeviceModule):
    """A third-party module with protocol names that need to be normalized."""

    ip_methods = [
        _ip_method("opc", "opc.ua", 4840),
        _ip_method("modbus", "Modbus/TCP", 502),
        _ip_method("iec", "104", 2404),
        _ip_method("blank", "", 1234),
    ]
    serial_methods = [
        SerialMethod(
            name="serial",
            description="serial",
            type="direct",
            identify_function=_identify,
            reliability=4,
            protocol="iec 101",
        )
    ]

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:  # noqa: ARG003
        return True


def test_get_protocol_details_normalizes_method_names():
    assert OddProtocolNames.get_protocols() == [
        "iec_101",
        "modbus_tcp",
        "opc_ua",
        "proto_104",
        "unknown",
    ]
    assert OddProtocolNames.get_ports("pull") == [502, 1234, 2404, 4840]

    caps = OddProtocolNames.get_capabilities()
    json.dumps(caps)
    # The identify methods keep the names they were defined with
    assert [m["protocol"] for m in caps["identify_methods"]] == [
        "opc.ua",
        "modbus/tcp",
        "104",
        "",
        "iec 101",
    ]

    # Normalized names can be used in protocol filters
    for term in ("opc", "opc_ua", "modbus", "4840", "serial"):
        assert module_api.filter_by_protocols([OddProtocolNames], term, "scan") == [
            OddProtocolNames
        ], term


class DictProtocols(ScanOnly):
    """Declares protocols as dicts."""

    protocols = [{"name": "ftp", "transport": "tcp", "ports": [21], "operations": ["pull"]}]

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:  # noqa: ARG003
        return True


class InvalidProtocols(ScanOnly):
    """Declares an invalid protocol (no ports)."""

    protocols = [{"name": "ftp", "transport": "tcp", "operations": ["pull"]}]


class NotAProtocol(ScanOnly):
    """Declares something that isn't a protocol."""

    protocols = ["ftp"]


def test_declared_protocols_as_dicts():
    assert DictProtocols.get_protocols("pull") == ["ftp"]
    assert module_api.is_valid_module(DictProtocols)


@pytest.mark.parametrize("mod", [InvalidProtocols, NotAProtocol])
def test_invalid_declared_protocols(mod, caplog):
    with pytest.raises(PeatError, match=f"Invalid protocol in {mod.__name__}.protocols"):
        mod.get_protocol_details()
    # Modules with invalid protocols can't be imported
    assert not module_api.is_valid_module(mod)
    assert f"Module validation failed for '{mod.__name__}'" in caplog.text


def test_get_protocols():
    assert Full.get_protocols() == ["cip", "ftp", "modbus_tcp", "serial", "sftp"]
    assert Full.get_protocols("scan") == ["cip", "ftp", "serial"]
    assert Full.get_protocols("pull") == ["cip", "ftp", "sftp"]
    assert Full.get_protocols("push") == ["ftp", "modbus_tcp"]
    assert ParseOnly.get_protocols() == []


def test_get_ports():
    assert Full.get_ports() == [21, 22, 502, 2222, 44818]
    assert Full.get_ports("scan") == [21, 44818]
    assert Full.get_ports("push") == [21, 502]
    assert Full.get_ports(transport="udp") == [502, 44818]  # "both" counts as udp
    assert Full.get_ports("push", transport="udp") == [502]
    assert Full.get_ports("pull", transport="tcp") == [21, 22, 2222, 44818]
    assert ScanOnly.get_ports(transport="tcp") == [80]
    assert PullUndeclared.get_ports() == [23, 8080]
    assert ParseOnly.get_ports() == []


def test_class_attributes_not_mutated():
    before = [p.copy(deep=True) for p in Full.protocols]
    for _ in range(2):
        for proto in Full.get_protocol_details():
            if proto.transport != "serial":
                proto.ports = [*proto.ports, 9999]
            proto.operations = ["scan", "pull", "push"]
        Full.get_capabilities()
    assert Full.protocols == before
    assert PullUndeclared.protocols == []
    assert DeviceModule.protocols == []
    assert Full.get_ports() == [21, 22, 502, 2222, 44818]


def test_get_capabilities():
    caps = Full.get_capabilities()
    assert json.loads(json.dumps(caps)) == caps  # JSON-serializable

    assert caps["name"] == "Full"
    assert caps["description"] == "A module that does everything."
    assert caps["python_module"] == __name__
    assert caps["device_type"] == "PLC"
    assert caps["vendor_id"] == "ACME"
    assert caps["vendor_name"] == "ACME, Inc."
    assert caps["brand"] == "Roadrunner"
    assert caps["model"] == "RR-1"
    assert caps["supported_models"] == ["RR-1", "RR-2"]
    assert caps["module_aliases"] == ["acme-full"]
    assert caps["operations"] == ["scan", "pull", "push", "parse"]
    assert caps["comm_types"] == ["unicast_ip", "serial"]
    assert caps["ports"] == [21, 22, 502, 2222, 44818]
    assert caps["protocols"][0] == {
        "name": "cip",
        "transport": "tcp",
        "ports": [44818],
        "operations": ["pull"],
        "description": "Explicit messaging",
        "options_key": None,
    }
    assert caps["identify_methods"] == [
        {
            "name": "ftp login",
            "type": "unicast_ip",
            "protocol": "ftp",
            "transport": "tcp",
            "default_port": 21,
            "reliability": 5,
        },
        {
            "name": "cip list identity",
            "type": "unicast_ip",
            "protocol": "cip",
            "transport": "udp",
            "default_port": 44818,
            "reliability": 5,
        },
        {
            "name": "serial check",
            "type": "serial",
            "protocol": "serial",
            "transport": "serial",
            "default_port": None,
            "reliability": 4,
        },
    ]
    assert caps["parse"] == {
        "filename_patterns": ["*.acme"],
        "file_signatures": [],
        "can_parse_dir": False,
    }

    # Returned lists are copies
    caps["supported_models"].append("RR-3")
    assert Full.supported_models == ["RR-1", "RR-2"]


def test_get_capabilities_description():
    # First line of the module's own docstring
    assert ParseOnly.get_capabilities()["description"] == "A module that can only parse files."
    # No docstring: empty, instead of the DeviceModule docstring
    assert ParseNoPatterns.get_capabilities()["description"] == ""
    sig_caps = ParseSignatures.get_capabilities()
    assert sig_caps["parse"]["file_signatures"] == ["thing.bin"]
    assert ParseDir.get_capabilities()["parse"]["can_parse_dir"] is True


def test_serial_method_protocol_default():
    assert Full.serial_methods[0].protocol == "serial"
    assert PullUndeclared.serial_methods[0].protocol == "servlink_serial"


# --- Checks of the modules included with PEAT ---

BUILTIN_MODULES = module_api._sort(list(module_api._get_static_modules().values()))


@pytest.mark.parametrize("mod", BUILTIN_MODULES, ids=lambda m: m.__name__)
def test_builtin_modules_declare_protocols_for_implemented_ops(mod):
    declared = {op for proto in mod.protocols for op in proto.operations}
    for op in ("pull", "push"):
        if mod.supports(op):
            assert op in declared, (
                f"{mod.__name__} implements _{op}() but doesn't declare the protocols "
                f"it uses for {op} in '{mod.__name__}.protocols'"
            )
        else:
            assert op not in declared, f"{mod.__name__} declares {op} protocols, but can't {op}"
    assert isinstance(mod.protocols, list)
    assert all(isinstance(p, ModuleProtocol) for p in mod.protocols)
    assert mod.protocols is not DeviceModule.protocols or not mod.protocols


@pytest.mark.parametrize("mod", BUILTIN_MODULES, ids=lambda m: m.__name__)
def test_builtin_modules_metadata(mod):
    caps = mod.get_capabilities()
    assert json.loads(json.dumps(caps)) == caps
    assert caps["description"], f"{mod.__name__} has no docstring"
    assert caps["operations"], f"{mod.__name__} doesn't support any operations"
    assert isinstance(mod.supported_models, list)
    assert all(isinstance(m, str) and m for m in mod.supported_models)


@pytest.mark.parametrize("mod", BUILTIN_MODULES, ids=lambda m: m.__name__)
def test_declared_ports_match_default_options(mod):
    for proto in mod.protocols:
        if proto.transport not in ("tcp", "udp", "both"):
            continue
        key = proto.configured_by
        module_port = mod.default_options.get(key, {}).get("port")
        global_port = DEFAULT_OPTIONS.get(key, {}).get("port")
        default_port = module_port if module_port is not None else global_port
        if default_port is not None:
            assert default_port in proto.ports, (
                f"{mod.__name__}: default port for '{key}' is {default_port}, "
                f"but protocol '{proto.name}' declares ports {proto.ports}"
            )


@pytest.mark.parametrize("mod", BUILTIN_MODULES, ids=lambda m: m.__name__)
def test_protocols_are_option_keys(mod):
    for name in [m.protocol for m in mod.serial_methods] + [m.protocol for m in mod.ip_methods]:
        assert name in DEFAULT_OPTIONS, f"{mod.__name__}: unknown protocol options key '{name}'"
    for proto in mod.protocols:
        assert proto.configured_by in DEFAULT_OPTIONS, (
            f"{mod.__name__}: protocol '{proto.name}' isn't configured by a device "
            f"options key (set 'options_key')"
        )


def _norm_protocol(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _doc_modules(text: str) -> set[str]:
    return set(re.findall(r"~peat\.modules\.[\w.]+\.(\w+)`", text))


def _read_csv(name: str) -> list[dict[str, str]]:
    with (DOCS_DIR / name).open(encoding="utf-8", newline="") as fp:
        return list(csv.DictReader(fp, skipinitialspace=True))


def test_docs_tcp_ip_protocols_csv_in_sync():
    rows = _read_csv("tcp_ip_protocols_used_by_peat.csv")
    assert rows

    documented: dict[tuple[str, str], tuple[set[int], set[str]]] = {}
    for row in rows:
        proto = _norm_protocol(row["Protocol"])
        ports = {int(p) for p in re.findall(r"\d+", row["Port"])}
        transports = {t.strip().lower() for t in row["Transport protocol(s)"].split(",")}
        for name in _doc_modules(row["PEAT Module(s)"]):
            documented[(proto, name)] = (ports, transports)

            # Every module listed exists and uses the protocol
            if name in DOC_ONLY_MODULES:
                continue
            mod = module_api.get_module(name)
            assert mod is not None, f"'{name}' in the '{row['Protocol']}' row isn't a module"
            used = {_norm_protocol(p.name) for p in mod.get_protocol_details()}
            assert proto in used, f"{name} is listed for {row['Protocol']}, but doesn't use it"

    # Every network protocol of every module is listed, with its ports and transports
    for mod in BUILTIN_MODULES:
        for proto in mod.get_protocol_details():
            if proto.transport == "serial":
                continue
            key = (_norm_protocol(proto.name), mod.__name__)
            assert key in documented, (
                f"{mod.__name__} uses {proto.name}, but isn't listed for it in "
                f"docs/tcp_ip_protocols_used_by_peat.csv"
            )
            ports, transports = documented[key]
            assert set(proto.ports) <= ports, f"{mod.__name__} {proto.name}: ports {proto.ports}"
            assert proto.transports <= transports, (
                f"{mod.__name__} {proto.name}: transports {proto.transports}"
            )


def test_docs_supported_devices_csv_in_sync():
    rows = _read_csv("supported_devices.csv")
    assert rows
    documented: dict[str, set[str]] = {}

    for row in rows:
        names = _doc_modules(row["Notes"])
        assert names, f"No PEAT module referenced in the notes for '{row['Device']}'"

        claimed = set()
        for item in row["Supported Functions"].split(","):
            words = item.strip().lower().split()
            if words and words[0] in ("scan", "pull", "push", "parse"):
                claimed.add(words[0])

        for name in names - DOC_ONLY_MODULES:
            mod = module_api.get_module(name)
            assert mod is not None, f"'{name}' referenced for '{row['Device']}' isn't a module"
            unsupported = claimed - set(mod.get_operations())
            assert not unsupported, (
                f"supported_devices.csv claims '{row['Device']}' supports "
                f"{sorted(unsupported)}, but {name} doesn't"
            )
            documented.setdefault(name, set()).update(claimed)

    # Every module is documented, and the network operations it supports
    # (scan, pull, and push) are listed for at least one of its devices.
    # NOTE: parse isn't checked, since some modules parse only some files.
    for mod in BUILTIN_MODULES:
        assert mod.__name__ in documented, f"{mod.__name__} isn't in docs/supported_devices.csv"
        missing = (set(mod.get_operations()) & set(PROTOCOL_OPERATIONS)) - documented[mod.__name__]
        assert not missing, (
            f"docs/supported_devices.csv doesn't list {sorted(missing)} "
            f"for any of the devices of {mod.__name__}"
        )
