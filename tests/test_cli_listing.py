"""
Tests for the module listings of the command line interface
(``--list-modules``, ``--list-all``, ``--module-info``, etc.).
"""

import json
from pprint import pformat

import pytest

from peat import DeviceData, DeviceModule, IPMethod, cli_listing, config, module_api


@pytest.fixture
def list_args():
    def _list_args(func: str = "scan", **kwargs) -> dict:
        args = {
            "func": func,
            "device_types": None,
            "list_modules": None,
            "list_all": None,
            "list_aliases": None,
            "list_alias_mappings": None,
            "module_info": None,
        }
        args.update(kwargs)
        return args

    return _list_args


@pytest.fixture
def set_config(mocker):
    def _set_config(**values) -> None:
        mocker.patch.dict(config["CONFIG"], values)

    return _set_config


@pytest.fixture(autouse=True)
def _defaults(set_config, mocker):
    # Isolate from the user's environment (e.g. PEAT_PRINT_RESULTS)
    set_config(PRINT_RESULTS=False, NO_COLOR=False, PROTOCOL_FILTER=[])
    mocker.patch.dict(config["load_errors"], clear=True)
    # NOTE: other tests import built-in modules with import_module()
    mocker.patch.object(module_api, "runtime_imports", set())


def _table_modules(output: str) -> set[str]:
    """
    Names in the first column of the modules table.
    """
    names = set()
    for line in output.splitlines():
        if line.startswith("|"):
            names.add(line.strip("|").split("|")[0].strip())
    names.discard("Module")
    return names


def test_handle_list_args_no_list_args(list_args, capsys):
    assert cli_listing.handle_list_args(list_args()) is None
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("func", "included", "excluded"),
    [
        ("scan", {"ControlLogix", "M340", "SELRelay", "WDW2301E"}, {"L5X", "UEFI", "WindowsCE"}),
        ("pull", {"ControlLogix", "M340", "SELRelay"}, {"L5X", "UEFI"}),
        ("push", {"ControlLogix", "OpenPLCv4", "SELRelay"}, {"M340", "L5X", "Sage"}),
        ("parse", {"L5X", "SELRelay", "UEFI", "M340"}, {"ControlLogix", "GERTU", "Totus"}),
    ],
)
def test_list_modules_command_filtered(list_args, capsys, func, included, excluded):
    assert cli_listing.handle_list_args(list_args(func, list_modules=True)) == 0
    output = capsys.readouterr().out
    names = _table_modules(output)
    assert included <= names
    assert not excluded & names
    assert f"can be used with 'peat {func}'" in output
    assert f"peat {func} --module-info" in output


@pytest.mark.parametrize("func", ["pillage", "heat", "encrypt_config", None])
def test_list_modules_other_commands_list_all_modules(list_args, capsys, func):
    assert cli_listing.handle_list_args(list_args(func, list_modules=True)) == 0
    output = capsys.readouterr().out
    assert _table_modules(output) == set(module_api.names)
    assert "imported" in output


def test_list_modules_push_all(list_args, capsys):
    args = list_args("push", list_modules=True, device_types=["all"])
    assert cli_listing.handle_list_args(args) == 0
    assert _table_modules(capsys.readouterr().out) == {"ControlLogix", "OpenPLCv4", "SELRelay"}


def test_list_modules_table_columns(list_args, capsys):
    assert cli_listing.handle_list_args(list_args("scan", list_modules=True)) == 0
    output = capsys.readouterr().out
    header = next(line for line in output.splitlines() if "Module" in line)
    for col in ["Module", "Type", "Vendor", "Operations", "Protocols"]:
        assert col in header
    sel_line = next(line for line in output.splitlines() if "| SELRelay " in line)
    assert "scan, pull, push, parse" in sel_line
    assert "ftp" in sel_line
    assert "ymodem" in sel_line


def test_list_modules_device_types(list_args, capsys):
    args = list_args("pull", list_modules=True, device_types=["sel"])
    assert cli_listing.handle_list_args(args) == 0
    assert _table_modules(capsys.readouterr().out) == {"SEL3620", "SELRTAC", "SELRelay"}


def test_list_modules_unknown_device_type(list_args, capsys):
    args = list_args("scan", list_modules=True, device_types=["doesnotexist"])
    assert cli_listing.handle_list_args(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "doesnotexist" in captured.err


def test_list_modules_unsupported_operation(list_args, capsys):
    args = list_args("push", list_modules=True, device_types=["m340"])
    assert cli_listing.handle_list_args(args) == 1
    captured = capsys.readouterr()
    assert "None of the selected modules support 'push'" in captured.err
    assert "M340" in captured.err


def test_list_modules_json(list_args, capsys, set_config):
    set_config(PRINT_RESULTS=True)
    assert cli_listing.handle_list_args(list_args("scan", list_modules=True)) == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert [d["name"] for d in data] == sorted(d["name"] for d in data)
    for item in data:
        for key in [
            "name",
            "operations",
            "protocols",
            "ports",
            "supported_models",
            "identify_methods",
            "imported_at_runtime",
        ]:
            assert key in item
        assert "scan" in item["operations"]
    names = {d["name"] for d in data}
    assert "ControlLogix" in names
    assert "L5X" not in names


@pytest.mark.parametrize(
    ("func", "protocol_filter", "expected"),
    [
        ("scan", ["502"], {"M340"}),
        ("scan", ["modbus"], {"M340"}),
        ("scan", ["8443"], {"OpenPLCv4"}),
        ("push", ["ftp"], {"SELRelay"}),
        ("scan", ["serial"], {"Easygen3500XT", "SELRelay", "WDW2301E"}),
    ],
)
def test_list_modules_protocol_filter(
    list_args, capsys, set_config, func, protocol_filter, expected
):
    set_config(PROTOCOL_FILTER=protocol_filter)
    assert cli_listing.handle_list_args(list_args(func, list_modules=True)) == 0
    output = capsys.readouterr().out
    assert _table_modules(output) == expected
    assert f"protocol filter: {protocol_filter[0]}" in output


def test_list_modules_protocol_filter_operation_aware(list_args, capsys, set_config):
    set_config(PROTOCOL_FILTER=["ftp"])
    assert cli_listing.handle_list_args(list_args("scan", list_modules=True)) == 0
    scan_mods = _table_modules(capsys.readouterr().out)
    assert cli_listing.handle_list_args(list_args("pull", list_modules=True)) == 0
    pull_mods = _table_modules(capsys.readouterr().out)

    # SELRelay pulls with FTP, but doesn't use FTP to identify relays
    assert "SELRelay" not in scan_mods
    assert "SELRelay" in pull_mods
    assert scan_mods < pull_mods


def test_list_modules_protocol_filter_ignored_for_parse(list_args, capsys, set_config):
    set_config(PROTOCOL_FILTER=["502"])
    assert cli_listing.handle_list_args(list_args("parse", list_modules=True)) == 0
    output = capsys.readouterr().out
    assert "SELRelay" in _table_modules(output)
    assert "protocol filter" not in output


@pytest.mark.parametrize(
    ("protocol_filter", "message"),
    [
        (["nope"], "None of the selected modules use the protocol(s)"),
        (["ftp:21"], "Invalid protocol filter 'ftp:21'"),
        (["44818/tcp"], "Protocols used for 'scan'"),
    ],
)
def test_list_modules_protocol_filter_errors(
    list_args, capsys, set_config, protocol_filter, message
):
    set_config(PROTOCOL_FILTER=protocol_filter)
    assert cli_listing.handle_list_args(list_args("scan", list_modules=True)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("ERROR: ")
    assert message in captured.err


def test_list_modules_no_color(list_args, capsys, set_config, mocker):
    set_config(NO_COLOR=True)
    mocker.patch.object(cli_listing, "format_modules_table", return_value="\x1b[1mtable\x1b[0m")
    assert cli_listing.handle_list_args(list_args("scan", list_modules=True)) == 0
    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert output.startswith("table\n")


def test_list_all(list_args, capsys):
    assert cli_listing.handle_list_args(list_args("pull", list_all=True)) == 0
    output = capsys.readouterr().out
    assert "** Modules **" in output
    assert "** Aliases **" in output
    assert "** Alias Mappings **" in output
    assert "'clx'" in output
    modules_section = output.split("** Aliases **")[0]
    # --list-all includes all modules, regardless of the command
    assert _table_modules(modules_section) == set(module_api.names)
    assert pformat(module_api.alias_mappings, compact=True) in output


def test_list_all_json(list_args, capsys, set_config):
    set_config(PRINT_RESULTS=True)
    assert cli_listing.handle_list_args(list_args("scan", list_all=True)) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"modules", "aliases", "alias_mappings"}
    assert {m["name"] for m in data["modules"]} == set(module_api.names)
    assert "clx" in data["aliases"]
    assert data["alias_mappings"] == module_api.alias_mappings


def test_list_aliases_unchanged(list_args, capsys):
    assert cli_listing.handle_list_args(list_args("scan", list_aliases=True)) == 0
    assert capsys.readouterr().out == json.dumps(list(module_api.module_aliases.keys())) + "\n"

    assert cli_listing.handle_list_args(list_args("scan", list_alias_mappings=True)) == 0
    assert capsys.readouterr().out == json.dumps(module_api.alias_mappings) + "\n"


def test_module_info(list_args, capsys):
    assert cli_listing.handle_list_args(list_args("parse", module_info=["sel"])) == 0
    output = capsys.readouterr().out
    for name in ["SELRelay", "SELRTAC", "SEL3620"]:
        assert f"{name} (peat.modules.sel." in output
    assert "Supported models:" in output
    assert "351S" in output or "351s" in output
    assert "Identification methods (scan)" in output
    assert "Protocols" in output
    assert "ymodem" in output
    assert "options: serial" in output


def test_module_info_parse_only(list_args, capsys):
    assert cli_listing.handle_list_args(list_args("scan", module_info=["L5X"])) == 0
    output = capsys.readouterr().out
    assert "L5X (peat.modules." in output
    assert "Operations:" in output
    assert "parse" in output
    assert "None (the module doesn't communicate with devices)" in output
    assert "Identification methods" not in output


def test_module_info_deduplicates(list_args, capsys):
    args = list_args("scan", module_info=["selrelay", "SELRelay", "sel-351"])
    assert cli_listing.handle_list_args(args) == 0
    assert capsys.readouterr().out.count("SELRelay (peat.modules.sel.") == 1


def test_module_info_json(list_args, capsys, set_config):
    set_config(PRINT_RESULTS=True)
    assert cli_listing.handle_list_args(list_args("scan", module_info=["m340"])) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["name"] == "M340"
    protocols = {(p["name"], p["transport"]): p for p in data[0]["protocols"]}
    assert protocols[("umas", "tcp")]["options_key"] == "modbus_tcp"
    assert protocols[("umas", "tcp")]["operations"] == ["pull"]
    assert protocols[("modbus_tcp", "tcp")]["operations"] == ["scan", "pull"]


def test_module_info_unknown(list_args, capsys):
    args = list_args("scan", module_info=["selrelay", "doesnotexist"])
    assert cli_listing.handle_list_args(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "doesnotexist" in captured.err


def test_format_module_info_undeclared_note():
    from peat import DeviceModule, IPMethod

    class Undeclared(DeviceModule):
        """Module that pulls without declaring protocols."""

        @classmethod
        def _pull(cls, dev) -> bool:  # noqa: ARG003
            return True

    Undeclared.ip_methods = [
        IPMethod(
            name="Undeclared HTTP",
            description="test",
            type="unicast_ip",
            identify_function=lambda dev: False,  # noqa: ARG005
            reliability=5,
            protocol="http",
            transport="tcp",
            default_port=80,
        )
    ]

    output = cli_listing.format_module_info(Undeclared)
    assert "Module that pulls without declaring protocols." in output
    assert "doesn't declare the protocols it uses for pull" in output
    assert "for push" not in output


def test_command_modules_includes_runtime_imports(list_args, mocker):
    mocker.patch.object(module_api, "runtime_imports", {"l5x"})
    # L5X can't scan, so it's excluded from scan even if imported at runtime
    mods = cli_listing.command_modules(list_args("scan", device_types=["selrelay"]))
    assert [m.__name__ for m in mods] == ["SELRelay"]
    mods = cli_listing.command_modules(list_args("parse", device_types=["selrelay"]))
    assert [m.__name__ for m in mods] == ["L5X", "SELRelay"]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"host_list": ["192.0.2.1"]}, "unicast_ip"),
        ({"broadcast_list": ["192.0.2.255"]}, "broadcast_ip"),
        ({"port_list": ["/dev/ttyS0"]}, "serial"),
        ({"host_file": "hosts.json"}, None),
        ({}, None),
    ],
)
def test_args_comm_type(args, expected):
    assert cli_listing.args_comm_type(args) == expected


def test_list_modules_protocol_filter_comm_type(list_args, capsys, set_config):
    # No module uses SNMP broadcasts
    set_config(PROTOCOL_FILTER=["161/udp"])
    args = list_args("scan", list_modules=True, broadcast_list=["192.0.2.255"])
    assert cli_listing.handle_list_args(args) == 1
    assert "for 'scan' (broadcast_ip)" in capsys.readouterr().err
    args = list_args("scan", list_modules=True, host_list=["192.0.2.1"])
    assert cli_listing.handle_list_args(args) == 0
    assert "M340" in _table_modules(capsys.readouterr().out)

    set_config(PROTOCOL_FILTER=["cip"])
    args = list_args("scan", list_modules=True, broadcast_list=["192.0.2.255"])
    assert cli_listing.handle_list_args(args) == 0
    output = capsys.readouterr().out
    assert _table_modules(output) == {"ControlLogix"}
    assert "(protocol filter: cip, broadcast_ip)" in output

    # Serial pulls only consider serial protocols
    set_config(PROTOCOL_FILTER=["ftp"])
    args = list_args("pull", list_modules=True, port_list=["/dev/ttyS0"])
    assert cli_listing.handle_list_args(args) == 1


@pytest.mark.parametrize("func", ["scan", "pull", "push"])
def test_list_modules_protocol_filter_load_error(list_args, capsys, mocker, func):
    # A protocol filter that failed to load (e.g. a malformed environment
    # variable) is an error, instead of silently not filtering modules.
    mocker.patch.dict(config["load_errors"], {"PROTOCOL_FILTER": "bad value"})
    assert cli_listing.handle_list_args(list_args(func, list_modules=True)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Failed to load the protocol filter" in captured.err
    assert "bad value" in captured.err

    with pytest.raises(cli_listing.PeatError, match="Refusing to run"):
        cli_listing.get_protocol_filter()


def test_list_modules_protocol_filter_load_error_ignored(list_args, capsys, mocker):
    # The protocol filter isn't used by parse, so it doesn't matter if it failed to load
    mocker.patch.dict(config["load_errors"], {"PROTOCOL_FILTER": "bad value"})
    assert cli_listing.handle_list_args(list_args("parse", list_modules=True)) == 0
    assert cli_listing.handle_list_args(list_args("scan", list_all=True)) == 0
    capsys.readouterr()


def _identify(dev: DeviceData) -> bool:  # noqa: ARG001
    return False


class OddProto(DeviceModule):
    """Third-party module with protocol names that aren't valid ModuleProtocol names."""

    device_type = "PLC"
    vendor_id = "ACME"

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:  # noqa: ARG003
        return True


OddProto.ip_methods = [
    IPMethod(
        name=name,
        description=name,
        type="unicast_ip",
        identify_function=_identify,
        reliability=5,
        protocol=protocol,
        transport="tcp",
        default_port=port,
    )
    for name, protocol, port in [("opc", "opc.ua", 4840), ("bacnet", "BACnet/IP", 47808)]
]


@pytest.fixture
def odd_runtime_module(mocker):
    mocker.patch.dict(module_api.modules, {"oddproto": OddProto})
    mocker.patch.object(module_api, "runtime_imports", {"oddproto"})


@pytest.mark.usefixtures("odd_runtime_module")
def test_listings_with_odd_protocol_names(list_args, capsys, set_config):
    assert cli_listing.handle_list_args(list_args("scan", list_modules=True)) == 0
    output = capsys.readouterr().out
    assert "OddProto" in _table_modules(output)
    assert "bacnet_ip, opc_ua" in output

    assert cli_listing.handle_list_args(list_args("parse", list_all=True)) == 0
    assert "OddProto" in capsys.readouterr().out

    assert cli_listing.handle_list_args(list_args("scan", module_info=["OddProto"])) == 0
    assert "opc_ua" in capsys.readouterr().out

    set_config(PROTOCOL_FILTER=["opc"])
    assert cli_listing.handle_list_args(list_args("pull", list_modules=True)) == 0
    assert _table_modules(capsys.readouterr().out) == {"OddProto"}

    set_config(PROTOCOL_FILTER=[], PRINT_RESULTS=True)
    assert cli_listing.handle_list_args(list_args("scan", list_modules=True)) == 0
    caps = {c["name"]: c for c in json.loads(capsys.readouterr().out)}
    assert [p["name"] for p in caps["OddProto"]["protocols"]] == ["bacnet_ip", "opc_ua"]
