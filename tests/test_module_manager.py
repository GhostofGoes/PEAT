import shutil
from pathlib import Path

import pytest

from peat import (
    M340,
    SCEPTRE,
    SELRTAC,
    WDW2301E,
    ControlLogix,
    DeviceModule,
    MicroNet,
    ModuleProtocol,
    OpenPLCv4,
    PeatError,
    Sage,
    SELRelay,
    Siprotec,
    module_api,
)

module_compares = [
    ("ControlLogix", ControlLogix),
    ("controllogix", ControlLogix),
    ("M340", M340),
    ("MICRONET", MicroNet),
    ("selrelay", SELRelay),
    ("selrtac", SELRTAC),
    ("sceptre", SCEPTRE),
    ("sage", Sage),
    ("siprotec", Siprotec),
    ("WDW2301E", WDW2301E),
]


def test_names():
    assert all(isinstance(x, str) for x in module_api.names)
    assert "M340" in module_api.names


def test_classes():
    assert all(module_api.is_valid_module(x) for x in module_api.classes)
    assert M340 in module_api.classes


def test_filter_names():
    assert all(isinstance(x, str) for x in module_api.filter_names("vendor"))
    # NOTE: this test might fail if a module doesn't set a default for "device_type"
    assert len(module_api.filter_names("device_type")) == len(module_api.modules)
    assert "ControlLogix" in module_api.filter_names("ip_methods")
    assert not module_api.filter_names("WHATARETHESE")


def test_import_module():
    assert module_api.import_module([]) is False
    assert module_api.import_module(Path("404HEALERNOTFOUND")) is False
    assert module_api.import_module(["DROIDSTHATDONOTEXIST"]) is False


@pytest.mark.parametrize("cls", [x[1] for x in module_compares])
def test_import_module_parameterized(cls):
    assert module_api.import_module(cls)
    assert cls.__name__ in module_api.names


def test_import_module_path_invalid_modules(tmp_path):
    assert module_api.import_module_path(Path("404HEALERNOTFOUND")) is False
    empty_module_dir = tmp_path / "empty_module_dir"
    empty_module_dir.mkdir()
    assert module_api.import_module_path(empty_module_dir) is False
    empty_module_file = empty_module_dir / "somemodule.py"
    empty_module_file.write_text("#nothing here\n")
    assert module_api.import_module_path(empty_module_file) is False
    with pytest.raises(AttributeError):
        module_api.import_module_path(None)


def test_import_module_path_valid_module_file(mocker, tmp_path, example_module_file):
    # TODO: mock the import so we can test valid_module_dir
    #  (currently it will pass if this test passes)
    # Mock the imported modules so this test doesn't affect other module tests
    mocker.patch.object(module_api, "modules", {})
    mocker.patch.object(module_api, "module_aliases", {})
    mocker.patch.object(module_api, "runtime_imports", set())
    mocker.patch.object(module_api, "runtime_paths", set())
    mod_dir = tmp_path / "valid_module_file"
    mod_dir.mkdir()
    mod_path = mod_dir / "awesome_module.py"
    shutil.copyfile(example_module_file("awesome_module.py"), mod_path)
    assert module_api.import_module(mod_path) is True
    assert "awesometool" in module_api.runtime_imports
    assert mod_path in module_api.runtime_paths

    # List of modules (TODO: move this to separate test)
    assert module_api.import_module([mod_path]) is True


def test_import_module_path_valid_module_dir(mocker, tmp_path, example_module_file):
    # Mock the imported modules so this test doesn't affect other module tests
    mocker.patch.object(module_api, "modules", {})
    mocker.patch.object(module_api, "module_aliases", {})
    mocker.patch.object(module_api, "runtime_imports", set())
    mocker.patch.object(module_api, "runtime_paths", set())
    mod_dir = tmp_path / "valid_module_dir"
    mod_dir.mkdir()
    mod_path = mod_dir / "awesome_module.py"
    shutil.copyfile(example_module_file("awesome_module.py"), mod_path)
    assert module_api.import_module(mod_dir) is True


@pytest.mark.parametrize("cls", [x[1] for x in module_compares])
def test_import_module_cls(cls):
    assert module_api.import_module_cls(cls)
    assert cls.__name__ in module_api.names


def test_import_module_cls_special_cases():
    assert module_api.import_module_cls(M340)
    assert module_api.import_module_cls(SELRelay, False)
    assert module_api.import_module_cls(None) is False
    assert module_api.import_module_cls("") is False
    assert module_api.import_module_cls(DeviceModule) is False
    assert module_api.import_module_cls(M340()) is False
    assert module_api.import_module_cls("DROIDSTHATDONOTEXIST") is False


@pytest.mark.parametrize(("name", "cls"), module_compares)
def test_get_module(name, cls):
    assert module_api.get_module(name) is cls


def test_get_module_special_cases():
    assert module_api.get_module("allen-bradley") is None
    assert module_api.get_module("INVALIDMODULE") is None


@pytest.mark.parametrize(("name", "cls"), module_compares)
def test_get_modules(name, cls):
    assert module_api.get_modules(name) == [cls]


def test_get_modules_filter():
    assert ControlLogix in module_api.get_modules("ControlLogix", "ip_methods")
    assert ControlLogix not in module_api.get_modules("ControlLogix", "serial_methods")


def test_get_modules_special_cases():
    assert module_api.get_modules("allen-bradley") == [ControlLogix]
    assert module_api.get_modules("sandia") == [SCEPTRE]
    assert module_api.get_modules("INVALIDMODULE") == []


@pytest.mark.parametrize(("name", "cls"), module_compares)
def test_lookup_types(name, cls):
    assert module_api.lookup_types(name) == [cls]
    assert module_api.lookup_types([name]) == [cls]
    assert module_api.lookup_types([name], filter_attr="vendor_id") == [cls]


def test_lookup_names():
    assert module_api.lookup_names("controllogix") == ["ControlLogix"]
    assert module_api.lookup_names("ControlLogix") == ["ControlLogix"]
    assert module_api.lookup_names(["controllogix"]) == ["ControlLogix"]
    assert module_api.lookup_names(ControlLogix) == ["ControlLogix"]
    assert module_api.lookup_names([ControlLogix]) == ["ControlLogix"]
    assert module_api.lookup_names(["controllogix"], filter_attr="vendor_id") == ["ControlLogix"]
    assert module_api.lookup_names("all") == module_api.names


def test_process_types_special_cases():
    assert module_api.lookup_types() == module_api.classes
    assert module_api.get_modules("INVALIDMODULE") == []
    assert module_api.lookup_types("INVALIDMODULE") == []
    assert module_api.lookup_types(["allen-bradley", "clx", "controllogix"]) == [ControlLogix]
    assert module_api.lookup_types(M340) == [M340]  # Class
    assert module_api.lookup_types([M340]) == [M340]  # Class
    assert module_api.lookup_types(M340()) == [M340]  # Instance
    assert module_api.lookup_types([M340()]) == [M340]  # Instance
    assert SELRelay in module_api.lookup_types(
        filter_attr="filename_patterns", subclass_method="_parse"
    )
    ip_mods = module_api.lookup_types(filter_attr="ip_methods")
    assert ControlLogix in ip_mods
    assert WDW2301E not in ip_mods

    parse_mods = module_api.lookup_types(module_api.classes, subclass_method="_parse")

    file_mods = module_api.lookup_types(module_api.classes, "filename_patterns")
    assert set(file_mods) <= set(parse_mods)
    sig_mods = module_api.lookup_types(module_api.classes, "file_signatures")
    assert set(sig_mods) <= set(parse_mods)
    # NOTE: GERelay has _parse() implemented but not filename_patterns
    dir_mods = module_api.lookup_types(module_api.classes, "can_parse_dir")
    assert set(dir_mods) <= set(parse_mods)

    assert set(file_mods + sig_mods + dir_mods) == set(parse_mods)


def test_alias_to_names():
    assert module_api.alias_to_names("clx") == ["ControlLogix"]
    assert module_api.alias_to_names("all") == module_api.names
    assert module_api.alias_to_names("ALL") == module_api.names
    assert module_api.alias_to_names("INVALIDALIAS") == []


@pytest.mark.parametrize("cls", [x[1] for x in module_compares])
def test_is_valid_module(cls):
    assert module_api.is_valid_module(cls)


def test_is_valid_module_special_cases():
    assert module_api.is_valid_module(DeviceModule) is False
    assert module_api.is_valid_module(ControlLogix()) is False
    assert module_api.is_valid_module("INVALIDMODULE") is False
    assert module_api.is_valid_module(Path) is False
    assert module_api.is_valid_module(ModuleProtocol) is False


def test_extract_members():
    assert module_api._extract_members("invalid.path") == []


def _names(mods) -> list[str]:
    return [m.__name__ for m in mods]


def test_filter_by_protocols_operation_aware():
    mods = module_api.classes
    # SELRelay pulls and pushes via FTP, but doesn't use FTP to identify relays
    assert SELRelay not in module_api.filter_by_protocols(mods, "ftp", "scan")
    assert SELRelay in module_api.filter_by_protocols(mods, "ftp", "pull")
    assert module_api.filter_by_protocols(mods, "ftp", "push") == [SELRelay]
    assert M340 in module_api.filter_by_protocols(mods, "ftp", "scan")

    # Any protocol for parse or no operation
    assert SELRelay in module_api.filter_by_protocols(mods, "ftp", "parse")
    assert SELRelay in module_api.filter_by_protocols(mods, ["ftp"])


@pytest.mark.parametrize(
    ("protocols", "operation", "expected"),
    [
        ("502", "scan", [M340]),
        ("modbus", "scan", [M340]),
        ("umas", "scan", []),
        ("umas", "pull", [M340]),
        ("8443", "push", [OpenPLCv4]),
        ("44818/tcp", "scan", []),
        ("44818/tcp", "pull", [ControlLogix]),
        ("44818/udp", "scan", [ControlLogix]),
        (["161/udp", "5432"], "scan", [ControlLogix, M340, SELRTAC, Siprotec]),
        ("servlink", "pull", ["Easygen3500XT", "WDW2301E"]),
    ],
)
def test_filter_by_protocols(protocols, operation, expected):
    result = module_api.filter_by_protocols(module_api.classes, protocols, operation)
    if expected and isinstance(expected[0], str):
        assert _names(result) == expected
    else:
        assert result == expected


def test_filter_by_protocols_empty_and_invalid():
    mods = [SELRelay, M340]
    assert module_api.filter_by_protocols(mods, None) == [M340, SELRelay]
    assert module_api.filter_by_protocols(mods, []) == [M340, SELRelay]
    assert module_api.filter_by_protocols(mods, " , ") == [M340, SELRelay]
    with pytest.raises(PeatError, match="Invalid protocol filter"):
        module_api.filter_by_protocols(mods, "ftp:21")


def test_select_modules():
    assert module_api.select_modules("sel", operation="push") == [SELRelay]
    assert module_api.select_modules(["M340", "selrelay"], "scan") == [M340, SELRelay]
    assert module_api.select_modules(["M340", SELRelay], "push") == [SELRelay]
    assert module_api.select_modules(None) == module_api._sort(module_api.classes)
    assert module_api.select_modules([]) == []
    assert module_api.select_modules("doesnotexist", "scan") == []

    all_push = module_api.select_modules("all", operation="push")
    assert all_push == [ControlLogix, OpenPLCv4, SELRelay]

    parse_mods = module_api.select_modules("all", operation="parse")
    assert ControlLogix not in parse_mods
    assert SELRelay in parse_mods


def test_select_modules_errors():
    with pytest.raises(PeatError, match="None of the selected modules support 'push'"):
        module_api.select_modules(["M340"], operation="push")
    with pytest.raises(PeatError, match="Protocols used for 'scan' by the selected modules"):
        module_api.select_modules("all", operation="scan", protocols="nope")
    with pytest.raises(PeatError, match="ftp, modbus_tcp, snmp"):
        module_api.select_modules("m340", operation="scan", protocols="telnet")
    with pytest.raises(PeatError, match="Invalid protocol filter"):
        module_api.select_modules("all", operation="scan", protocols=["ftp:21"])
    with pytest.raises(ValueError, match="invalid operation"):
        module_api.select_modules("all", operation="pillage")


def test_select_modules_protocol_filter():
    assert module_api.select_modules("all", "pull", ["ftp", "502"]) == module_api._sort(
        module_api.filter_by_protocols(module_api.classes, ["ftp", "502"], "pull")
    )
    assert module_api.select_modules(["sel"], "pull", "ftp") == [SELRelay]
    # Protocol filters only consider the modules that support the operation
    assert module_api.select_modules("all", "push", "https") == [OpenPLCv4]


@pytest.mark.parametrize(
    ("operation", "comm_type", "protocols", "expected"),
    [
        # Broadcast scans only use broadcast identify methods
        ("scan", "unicast_ip", "161/udp", ["ControlLogix", "M340", "Siprotec"]),
        ("scan", "broadcast_ip", "161/udp", None),
        ("scan", "broadcast_ip", "cip", ["ControlLogix"]),
        ("scan", "broadcast_ip", "44818/udp", ["ControlLogix"]),
        # Serial scans and pulls only use serial protocols
        ("scan", "serial", "telnet", None),
        ("scan", "serial", "serial", ["Easygen3500XT", "SELRelay", "WDW2301E"]),
        ("pull", "serial", "ftp", None),
        ("pull", "serial", "ymodem", ["SELRelay"]),
        ("pull", "unicast_ip", "ymodem", None),
        # Pulls after a broadcast scan use network protocols
        ("pull", "broadcast_ip", "ftp", ["ControlLogix", "Easygen3500XT", "M340", "SELRelay"]),
    ],
)
def test_select_modules_comm_type(operation, comm_type, protocols, expected):
    dev_types = ["ControlLogix", "M340", "SELRelay", "Siprotec", "Easygen3500XT", "WDW2301E"]
    if expected is None:
        with pytest.raises(PeatError, match=f"for '{operation}' \\({comm_type}\\)"):
            module_api.select_modules(dev_types, operation, protocols, comm_type)
    else:
        result = module_api.select_modules(dev_types, operation, protocols, comm_type)
        assert _names(result) == expected


def test_select_modules_comm_type_error_lists_protocols():
    with pytest.raises(PeatError, match=r"by the selected modules: cip$"):
        module_api.select_modules("all", "scan", "161/udp", "broadcast_ip")
    assert module_api.all_protocols("scan", [M340], "serial") == []
    assert module_api.all_protocols("pull", [SELRelay], "serial") == ["serial", "ymodem"]


def test_all_protocols():
    protocols = module_api.all_protocols()
    for name in ["cip", "ftp", "umas", "servlink_serial", "ymodem"]:
        assert name in protocols
    assert protocols == sorted(set(protocols))
    assert "umas" not in module_api.all_protocols("scan")
    assert module_api.all_protocols("push", [SELRelay]) == ["ftp", "telnet"]


def test_get_capabilities(mocker, tmp_path, example_module_file):
    # NOTE: other tests import built-in modules with import_module()
    mocker.patch.object(module_api, "runtime_imports", set())
    caps = module_api.get_capabilities([SELRelay, M340])
    assert [c["name"] for c in caps] == ["M340", "SELRelay"]
    assert all(c["imported_at_runtime"] is False for c in caps)
    assert {c["name"] for c in module_api.get_capabilities()} == set(module_api.names)

    # Mock the imported modules so this test doesn't affect other module tests
    mocker.patch.object(module_api, "modules", {})
    mocker.patch.object(module_api, "module_aliases", {})
    mocker.patch.object(module_api, "runtime_imports", set())
    mocker.patch.object(module_api, "runtime_paths", set())
    mod_path = tmp_path / "awesome_module.py"
    shutil.copyfile(example_module_file("awesome_module.py"), mod_path)
    assert module_api.import_module(mod_path) is True

    caps = module_api.get_capabilities()
    assert [c["name"] for c in caps] == ["AwesomeTool"]
    assert caps[0]["imported_at_runtime"] is True
    assert caps[0]["operations"] == ["scan", "pull", "parse"]
