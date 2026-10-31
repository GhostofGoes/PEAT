import socket
import threading

import pytest

from peat import (
    M340,
    SEL3620,
    SELRTAC,
    ControlLogix,
    DeviceData,
    PeatError,
    SELRelay,
    module_api,
    module_selection,
)
from peat.module_selection import (
    ModuleExclusions,
    TargetMatcher,
    compile_targets,
    configured_device_types,
    describe_source,
    get_exclusions,
    select_modules,
    warn_requested_but_excluded,
    warn_unknown_device_types,
)

SEL_MODULES = [SEL3620, SELRTAC, SELRelay]


pytestmark = pytest.mark.usefixtures("isolated_config")


def test_no_exclusions_fast_path():
    excl = ModuleExclusions({})
    mods = module_api.lookup_types(["all"])
    assert bool(excl) is False
    assert excl.filter_global(mods) == mods
    assert excl.filter_for(mods, target="192.0.2.1") == (mods, [])
    assert not excl.fully_excluded(mods, target="192.0.2.1")
    assert not excl.is_excluded(SELRelay, target="192.0.2.1")


def test_no_exclusions_empty_modules():
    excl = ModuleExclusions({"all": True})
    assert not excl.fully_excluded([], target="192.0.2.1")


@pytest.mark.parametrize(
    ("rules", "excluded"),
    [
        ({"controllogix": True}, [ControlLogix]),
        ({"CLX": True}, [ControlLogix]),
        ({"sel": True}, SEL_MODULES),
        ({"sel": True, "SELRelay": False}, SEL_MODULES),
        ({"SELRelay": False}, []),
        ({"SELRelay": []}, []),
    ],
)
def test_global_exact_and_alias(rules, excluded):
    excl = ModuleExclusions(rules)
    assert excl.global_mods == set(excluded)
    remaining = select_modules(["sel", "clx"], exclusions=excl)
    assert set(remaining) == (set(SEL_MODULES) | {ControlLogix}) - set(excluded)


def test_global_all():
    excl = ModuleExclusions({"all": True})
    assert select_modules(["all"], exclusions=excl) == []
    assert excl.is_excluded(M340)


def test_select_modules_filter_attr():
    excl = ModuleExclusions({"SELRTAC": True})
    mods = select_modules(["sel"], filter_attr="ip_methods", exclusions=excl)
    assert SELRTAC not in mods
    assert all(m.ip_methods for m in mods)


def test_select_modules_uses_config(isolated_config):
    isolated_config.EXCLUDED_MODULES = {"SELRelay": True}
    assert SELRelay not in select_modules(["sel"])
    assert SELRTAC in select_modules(["sel"])


def test_select_modules_device_types_from_config(isolated_config, mocker):
    # API calls without device types use the device_types option, like the CLI
    assert select_modules(None) == module_api.lookup_types(["all"])

    mocker.patch.dict("os.environ", {"PEAT_DEVICE_TYPES": "sel,m340"})
    isolated_config.load_from_environment()
    assert select_modules(None) == sorted([*SEL_MODULES, M340], key=lambda m: m.__name__)

    # Explicit device types win
    assert select_modules(["m340"]) == [M340]


def test_scan_api_uses_configured_device_types(isolated_config, mocker):
    from peat.api import scan_api

    isolated_config.DEVICE_TYPES = ["controllogix"]
    isolated_config.ASSUME_ONLINE = True
    mocker.patch.object(scan_api.datastore, "objects", [])
    run_identify = mocker.patch.object(scan_api, "run_identify", return_value={})

    scan_api.unicast_ip_scan(["192.0.2.1"], None)
    assert run_identify.call_args.args[2] == [ControlLogix]


@pytest.mark.parametrize(
    ("target", "hit", "miss"),
    [
        ("192.0.2.5", "192.0.2.5", "192.0.2.6"),
        (" 192.0.2.5 ", "192.0.2.5", "192.0.2.6"),
        ("192.0.2.0/30", "192.0.2.3", "192.0.2.4"),
        ("192.0.2.5/24", "192.0.2.200", "192.0.3.1"),  # Non-strict network
        ("192.0.2.10-12", "192.0.2.11", "192.0.2.13"),
        ("/dev/ttyUSB0", "/dev/ttyUSB0", "/dev/ttyUSB1"),
        ("COM4", "com4", "COM5"),
    ],
)
def test_per_target_matching(target, hit, miss):
    excl = ModuleExclusions({"SELRelay": [target]})
    assert bool(excl)
    assert not excl.global_mods
    assert excl.is_excluded(SELRelay, target=hit)
    assert not excl.is_excluded(SELRelay, target=miss)
    assert not excl.is_excluded(SELRTAC, target=hit)
    # No target or device means only global exclusions apply
    assert not excl.is_excluded(SELRelay)


def test_per_target_matching_device_fields():
    excl = ModuleExclusions(
        {"SELRelay": ["00:30:a7:11:12:13", "192.0.2.5"], "M340": ["/dev/ttyS0"]}
    )

    assert excl.is_excluded(SELRelay, dev=DeviceData(mac="00-30-A7-11-12-13"))
    assert excl.is_excluded(SELRelay, dev=DeviceData(ip="192.0.2.5"))
    assert not excl.is_excluded(SELRelay, dev=DeviceData(ip="192.0.2.6"))
    assert not excl.is_excluded(SELRelay, dev=DeviceData(mac="00:30:a7:11:12:14"))
    assert excl.is_excluded(M340, dev=DeviceData(serial_port="/dev/ttyS0"))

    # Device and target are both checked
    assert excl.is_excluded(SELRelay, dev=DeviceData(ip="192.0.2.6"), target="192.0.2.5")


def test_per_target_host_file(tmp_path):
    txt = tmp_path / "hosts.txt"
    txt.write_text("192.0.2.1\n192.0.2.8/30  192.0.2.20-21\n", encoding="utf-8")
    jsn = tmp_path / "hosts.json"
    jsn.write_text('["192.0.2.30", null, ""]', encoding="utf-8")

    excl = ModuleExclusions({"SELRelay": [str(txt), str(jsn)]})
    for ip in ["192.0.2.1", "192.0.2.9", "192.0.2.21", "192.0.2.30"]:
        assert excl.is_excluded(SELRelay, target=ip), ip
    assert not excl.is_excluded(SELRelay, target="192.0.2.2")


@pytest.mark.parametrize(
    "content",
    ["", "{}", '["other.txt"]', "nested.json"],
)
def test_per_target_bad_host_file(tmp_path, content):
    suffix = ".json" if content.startswith(("{", "[")) else ".txt"
    path = tmp_path / f"hosts{suffix}"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PeatError, match="hosts"):
        ModuleExclusions({"SELRelay": [str(path)]})


def test_per_target_missing_host_file(tmp_path):
    with pytest.raises(PeatError, match="doesn't exist"):
        ModuleExclusions({"SELRelay": [str(tmp_path / "missing.txt")]})


def test_per_target_host_label():
    labels = {
        "line-3-plc": {"ip": "192.0.2.77", "mac": "00:30:a7:00:00:01"},
        "serial-relay": {"serial_port": "/dev/ttyS1", "hostname": "Relay-1"},
    }
    excl = ModuleExclusions({"all": ["LINE-3-PLC", "serial-relay"]}, labels)

    assert excl.is_excluded(M340, target="192.0.2.77")
    assert excl.is_excluded(SELRelay, dev=DeviceData(mac="00:30:A7:00:00:01"))
    assert excl.is_excluded(SELRelay, target="/dev/ttyS1")
    assert excl.is_excluded(SELRelay, dev=DeviceData(hostname="relay-1"))
    assert not excl.is_excluded(SELRelay, target="192.0.2.78")


def test_host_label_from_config(isolated_config):
    isolated_config.HOSTS = [
        {"label": "plc-1", "identifiers": {"ip": "192.0.2.50"}, "peat_module": "M340"},
        {"label": "no-ids"},
        "not-a-dict",
    ]
    isolated_config.EXCLUDED_MODULES = {"M340": ["plc-1"]}
    assert get_exclusions().is_excluded(M340, target="192.0.2.50")

    isolated_config.EXCLUDED_MODULES = {"M340": ["no-ids"]}
    with pytest.raises(PeatError, match="no identifiers"):
        get_exclusions()


def test_true_dominates_list_and_lists_union():
    excl = ModuleExclusions({"sel": ["192.0.2.1"], "SELRelay": ["192.0.2.2"], "SELRTAC": True})
    assert excl.global_mods == {SELRTAC}
    assert excl.is_excluded(SELRelay, target="192.0.2.1")
    assert excl.is_excluded(SELRelay, target="192.0.2.2")
    assert excl.is_excluded(SEL3620, target="192.0.2.1")
    assert not excl.is_excluded(SEL3620, target="192.0.2.2")
    assert excl.is_excluded(SELRTAC, target="192.0.2.99")


def test_false_never_removes(isolated_config):
    isolated_config["file_configs"]["EXCLUDED_MODULES"] = {"sel": True}
    isolated_config.EXCLUDED_MODULES = {"sel": False, "SELRelay": False}
    excl = get_exclusions()
    assert excl.global_mods == set(SEL_MODULES)


def test_filter_for_and_fully_excluded():
    excl = ModuleExclusions({"SELRelay": ["192.0.2.1"], "SELRTAC": ["192.0.2.1"]})
    kept, removed = excl.filter_for([SELRelay, SELRTAC, SEL3620], target="192.0.2.1")
    assert kept == [SEL3620]
    assert removed == [SELRelay, SELRTAC]
    assert excl.fully_excluded([SELRelay, SELRTAC], target="192.0.2.1")
    assert not excl.fully_excluded([SELRelay, SEL3620], target="192.0.2.1")
    assert not excl.fully_excluded([SELRelay, SELRTAC], target="192.0.2.2")


@pytest.mark.parametrize(
    ("rules", "expected"),
    [
        ({"ControlLgix": True}, "'ControlLgix' doesn't match any PEAT module or alias"),
        ({"NotAModule": ["192.0.2.5"]}, "'NotAModule' doesn't match any PEAT module"),
        # An env-style token passed to -x as a single value
        ({"ControlLogix SEL": ["192.0.2.5"]}, "one name or NAME=TARGETS per '-x'"),
        # Targets that ended up as module names
        ({"SEL": ["192.0.2.5"], "192.0.2.6": True}, "'192.0.2.6' isn't a PEAT module"),
        ({"192.0.2.0/24": True}, "it looks like a target"),
        ({"00:11:22:33:44:55": True}, "it looks like a target"),
        ({"COM3": True}, "it looks like a target"),
        ({"/dev/ttyS0": True}, "it looks like a target"),
        ({"hosts.txt": True}, "it looks like a target"),
    ],
)
def test_unknown_key_fails_closed(rules, expected):
    with pytest.raises(PeatError, match="PEAT won't run without the requested exclusions") as exc:
        ModuleExclusions(rules)
    assert expected in str(exc.value)


def test_unknown_keys_all_listed():
    with pytest.raises(PeatError) as exc:
        ModuleExclusions({"Typo1": True, "SEL3620": True, "Typo2": ["192.0.2.5"]})
    assert "'Typo1'" in str(exc.value)
    assert "'Typo2'" in str(exc.value)


def test_unknown_key_false_is_ignored():
    # A no-op rule (false) for an unknown name can't lose an exclusion
    assert not ModuleExclusions({"NotAModule": False})


def test_numeric_aliases_are_not_targets():
    # Some aliases look numeric (e.g. "1756", "3620"), they must still work
    excl = ModuleExclusions({"1756": True, "3620": ["192.0.2.5"]})
    assert ControlLogix in excl.global_mods
    assert excl.is_excluded(SEL3620, target="192.0.2.5")


def test_log_summary(caplog):
    excl = ModuleExclusions({"SEL3620": True, "SELRelay": ["192.0.2.5"]})

    excl.log_summary()
    assert "Excluded modules (all targets): SEL3620" in caplog.text
    assert "Excluded 'SELRelay' (SELRelay) for 1 target: 192.0.2.5" in caplog.text

    # Only logged once
    caplog.clear()
    excl.log_summary()
    assert caplog.text == ""


def test_log_summary_truncates_targets(caplog):
    targets = [f"192.0.2.{i}" for i in range(1, 31)]
    ModuleExclusions({"sel": targets}).log_summary()
    assert "(SEL3620, SELRTAC, SELRelay)" in caplog.text
    assert "30 targets" in caplog.text
    assert "192.0.2.20, ... (10 more)" in caplog.text
    assert "192.0.2.21" not in caplog.text


@pytest.mark.parametrize(
    "target",
    ["192.0.2.300", "192.0.2", "10.1", "192.0.2.0/33", "192.0.2.300-305", "all", "*"],
)
def test_bad_target_raises(target):
    with pytest.raises(PeatError, match="excluded_modules for 'SELRelay'") as exc:
        ModuleExclusions({"SELRelay": [target]})
    assert target in str(exc.value)


def test_unresolvable_hostname_raises(mocker):
    mocker.patch(
        "peat.protocols.addresses.socket.gethostbyname",
        side_effect=socket.gaierror("Name or service not known"),
    )
    with pytest.raises(PeatError, match="couldn't resolve the hostname") as exc:
        compile_targets("SELRelay", ["plc.example"])
    assert "plc.example" in str(exc.value)


def test_hostname_resolved(mocker):
    mock_dns = mocker.patch(
        "peat.protocols.addresses.socket.gethostbyname", return_value="192.0.2.9"
    )
    excl = ModuleExclusions({"SELRelay": ["plc.example"]})
    mock_dns.assert_called_once_with("plc.example")
    assert excl.is_excluded(SELRelay, target="192.0.2.9")
    assert excl.is_excluded(SELRelay, dev=DeviceData(hostname="PLC.example"))
    assert not excl.is_excluded(SELRelay, target="192.0.2.10")


def test_unknown_key_checked_before_resolving_targets(mocker):
    # Names are checked first, so no DNS lookups happen for a broken config
    mock_dns = mocker.patch("peat.protocols.addresses.socket.gethostbyname")
    with pytest.raises(PeatError, match="'NotAModule' doesn't match"):
        ModuleExclusions({"SELRelay": ["plc.example"], "NotAModule": ["192.0.2.5"]})
    mock_dns.assert_not_called()


def test_global_only_doesnt_resolve_targets(mocker):
    mock_dns = mocker.patch(
        "peat.protocols.addresses.socket.gethostbyname",
        side_effect=socket.gaierror("Name or service not known"),
    )
    excl = ModuleExclusions(
        {"SELRelay": ["plc.nonexistent.invalid", "192.0.2.300"], "M340": True},
        global_only=True,
    )
    mock_dns.assert_not_called()
    assert excl.global_mods == {M340}
    assert not excl.per_target
    assert excl.ignored_target_keys == ["SELRelay"]
    assert not excl.is_excluded(SELRelay, target="192.0.2.300")

    # Module names are still checked
    with pytest.raises(PeatError, match="'NotAModule' doesn't match"):
        ModuleExclusions({"NotAModule": ["plc.example"]}, global_only=True)


def test_get_exclusions_global_only(isolated_config, mocker):
    mock_dns = mocker.patch(
        "peat.protocols.addresses.socket.gethostbyname",
        side_effect=socket.gaierror("Name or service not known"),
    )
    isolated_config.EXCLUDED_MODULES = {"SELRelay": ["plc.nonexistent.invalid"], "M340": True}
    isolated_config.HOSTS = [{"label": "plc1", "identifiers": {"ip": "192.0.2.1"}}]

    excl = get_exclusions(global_only=True)
    assert excl.global_mods == {M340}
    assert get_exclusions(global_only=True) is excl  # Cached
    mock_dns.assert_not_called()

    # The full exclusions resolve the targets, and fail closed
    with pytest.raises(PeatError, match="couldn't resolve the hostname"):
        get_exclusions()


def test_warn_unenforced(caplog):
    excl = ModuleExclusions(
        {"all": ["192.0.2.200"], "SELRelay": ["192.0.2.5", "192.0.2.200"], "M340": True}
    )
    excl.warn_unenforced("sweep")
    assert "excluded_modules can't stop the sweep (--sweep)" in caplog.text
    assert "(sweeps don't use PEAT modules): 192.0.2.200, 192.0.2.5." in caplog.text

    # Nothing to warn about without exclusions for specific targets
    caplog.clear()
    ModuleExclusions({"M340": True}).warn_unenforced("broadcast")
    ModuleExclusions({"M340": True, "m340": ["192.0.2.5"]}).warn_unenforced("broadcast")
    assert caplog.text == ""


def test_target_matcher_merge():
    first = compile_targets("a", ["192.0.2.1", "COM1"])
    second = compile_targets("b", ["192.0.2.0/30", "COM1"])
    first.merge(second)
    assert first.entries == ["192.0.2.1", "COM1", "192.0.2.0/30"]
    assert first.matches(target="192.0.2.2")
    assert TargetMatcher().matches(target="192.0.2.2") is False


def test_cache_invalidation(isolated_config):
    isolated_config.EXCLUDED_MODULES = {"SELRelay": True}
    first = get_exclusions()
    assert get_exclusions() is first

    isolated_config.EXCLUDED_MODULES = {"M340": True}  # Union with the runtime value
    second = get_exclusions()
    assert second is not first
    assert second.global_mods == {M340}

    isolated_config["file_configs"]["EXCLUDED_MODULES"] = {"SELRTAC": True}
    third = get_exclusions()
    assert third is not second
    assert third.global_mods == {M340, SELRTAC}

    # Changes to the hosts in the config invalidate the cache (labels)
    isolated_config.EXCLUDED_MODULES = {"M340": ["plc"]}
    isolated_config.HOSTS = [{"label": "plc", "identifiers": {"ip": "192.0.2.1"}}]
    assert get_exclusions().is_excluded(M340, target="192.0.2.1")
    isolated_config.HOSTS = [{"label": "plc", "identifiers": {"ip": "192.0.2.2"}}]
    assert not get_exclusions().is_excluded(M340, target="192.0.2.1")
    assert get_exclusions().is_excluded(M340, target="192.0.2.2")


def test_configured_device_types(isolated_config):
    assert configured_device_types({}) == (None, "")
    assert configured_device_types(None) == (None, "")
    assert configured_device_types({"device_types": None}) == (None, "")

    isolated_config["file_configs"]["DEVICE_TYPES"] = ["SELRelay"]
    types, source = configured_device_types({"device_types": None})
    assert types == ["SELRelay"]
    assert "config file" in source

    isolated_config["section_configs"]["DEVICE_TYPES"] = ["M340"]
    isolated_config["section_command"] = "pull"
    assert configured_device_types({}) == (["M340"], "'pull' section of the config file")

    isolated_config["env_configs"]["DEVICE_TYPES"] = ["sel"]
    types, source = configured_device_types({})
    assert types == ["sel"]
    assert "PEAT_DEVICE_TYPES" in source

    # The command line argument wins
    assert configured_device_types({"device_types": ["clx"]}) == (
        ["clx"],
        "command line argument '-d'",
    )


def test_describe_source(isolated_config):
    assert describe_source("DEBUG") == "default ('debug')"
    isolated_config.DEBUG = 1
    assert describe_source("DEBUG") == "command line or runtime ('debug')"


def test_warn_unknown_device_types(caplog):
    warn_unknown_device_types(["sel", "sell", 5], "the test")
    assert "Unknown device type 'sell' from the test" in caplog.text
    assert "'sel'" not in caplog.text


def test_warn_requested_but_excluded(caplog):
    excl = ModuleExclusions({"SELRelay": True, "SELRTAC": True, "M340": ["192.0.2.1"]})
    warn_requested_but_excluded(["selrelay", "sel", "m340", "foo"], excl, "the test")
    assert "Device type 'selrelay' from the test only matches modules" in caplog.text
    assert "'sel'" not in caplog.text  # SEL3620 is still available
    assert "'m340'" not in caplog.text  # Only excluded for a target

    caplog.clear()
    warn_requested_but_excluded(["selrelay"], ModuleExclusions({}), "the test")
    assert caplog.text == ""


def test_skip_summary_thread_safe(caplog):
    excl = ModuleExclusions({"SELRelay": ["192.0.2.0/24"], "SEL3620": True})

    def worker(i: int) -> None:
        excl.filter_for([SELRelay, SELRTAC, SEL3620], target=f"192.0.2.{i}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 51)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(excl._skips["SELRelay"]) == 50
    assert "SEL3620" not in excl._skips  # Global exclusions aren't recorded

    excl.log_skip_summary()
    assert "Modules skipped due to per-target exclusions: SELRelay for 50 targets" in caplog.text
    assert not excl._skips

    caplog.clear()
    excl.log_skip_summary()
    assert caplog.text == ""


def test_imported_module_can_be_excluded(isolated_config, mocker):
    class ExcludeTestModule(SELRelay):
        pass

    mocker.patch.dict(module_api.modules, {"excludetestmodule": ExcludeTestModule})
    isolated_config.EXCLUDED_MODULES = {"excludetestmodule": True}
    assert get_exclusions().global_mods == {ExcludeTestModule}

    module_selection._CACHE.clear()


def test_runtime_value_not_normalized(isolated_config):
    # Values set at runtime aren't type casted, they're normalized when used
    isolated_config["runtime_configs"]["EXCLUDED_MODULES"] = ["SELRelay", "M340=192.0.2.1"]
    excl = get_exclusions()
    assert excl.global_mods == {SELRelay}
    assert excl.is_excluded(M340, target="192.0.2.1")

    isolated_config["runtime_configs"]["EXCLUDED_MODULES"] = 5
    with pytest.raises(PeatError, match="Invalid value for excluded_modules"):
        get_exclusions()
