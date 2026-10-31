import pytest

from peat import (
    ControlLogix,
    DeviceData,
    DeviceModule,
    IPMethod,
    MicroNet,
    config,
    datastore,
    module_api,
    state,
)
from peat.api import scan_api
from peat.module_selection import ModuleExclusions, compile_targets


def test_portscan(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
        },
    )
    mocker.patch.object(datastore, "objects")

    assert scan_api.portscan(DeviceData(), []) is None


def test_unicast_ip_scan(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
            "DEFAULT_TIMEOUT": 0.01,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    datastore.device_options["cip"]["timeout"] = 0.01

    assert scan_api.unicast_ip_scan([], []) is None
    assert scan_api.unicast_ip_scan([], [ControlLogix]) is None

    results = scan_api.unicast_ip_scan(["127.0.0.1", "127.0.0.0/24"], [ControlLogix])

    assert results
    assert isinstance(results, tuple)
    assert results[1] == [ControlLogix]
    assert len(results[2]) == 254
    assert results[0]
    assert isinstance(results[0], dict)
    assert "127.0.0.1" in results[0]


def test_check_host_unicast_ip(mocker):
    mocker.patch.dict(config["CONFIG"], {"VERBOSE": True, "DEBUG": 3})
    mocker.patch.object(datastore, "objects", [])

    datastore.device_options["cip"]["timeout"] = 0.01

    assert scan_api.check_host_unicast_ip("", []) is False
    assert scan_api.check_host_unicast_ip("127.0.0.1", []) is False
    assert scan_api.check_host_unicast_ip("127.0.0.1", None) is False
    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix]) is False


def test_check_host_unicast_ip_module_edge_case(mocker):
    """
    Test Edge case: PEAT module for a host is set in config file,
    but not in the list of modules that are available to scan.
    """
    mocker.patch.dict(config["CONFIG"], {"VERBOSE": True, "DEBUG": 3})
    mocker.patch.dict(
        state["CONFIG"],
        {
            "error": False,
        },
    )

    dev = DeviceData(ip="127.0.0.1")
    dev._module = ControlLogix
    mocker.patch.object(datastore, "objects", [dev])

    assert state.error is False

    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix]) is False
    assert state.error is False

    assert scan_api.check_host_unicast_ip("127.0.0.1", [MicroNet]) is False
    assert state.error is True


def test_check_host_unicast_ip_force_module(mocker, caplog):
    """
    test dev._module only uses methods for that module.
    """
    mocker.patch.dict(config["CONFIG"], {"VERBOSE": True, "DEBUG": 3})
    mocker.patch.dict(
        state["CONFIG"],
        {
            "error": False,
        },
    )

    dev = DeviceData(ip="127.0.0.1")
    dev._module = ControlLogix
    mocker.patch.object(datastore, "objects", [dev])

    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix, MicroNet]) is False
    assert state.error is False
    assert "Forcing usage of module 'ControlLogix'" in caplog.text


def test_broadcast_scan(mocker, examples_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    datastore.device_options["cip"]["timeout"] = 0.01

    assert not scan_api.broadcast_scan([], [])

    assert scan_api.broadcast_scan(["127.0.0.1"], [ControlLogix]) == (
        {"127.0.0.1": False},
        [ControlLogix],
        ["127.0.0.1"],
    )

    assert scan_api.broadcast_scan(["127.0.0.0/24"], [ControlLogix]) == (
        {"127.0.0.255": False},
        [ControlLogix],
        ["127.0.0.255"],
    )

    assert scan_api.broadcast_scan([examples_path("broadcast_targets.txt")], [ControlLogix]) == (
        {"127.0.0.255": False, "127.0.1.255": False, "127.0.3.255": False},
        [ControlLogix],
        ["127.0.0.255", "127.0.1.255", "127.0.3.255"],
    )


def test_serial_scan(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 2,
        },
    )
    mocker.patch.object(datastore, "objects", [])
    # On macOS, port numbers index the serial devices present on the system,
    # so provide one to make the result the same on every platform.
    mocker.patch(
        "peat.protocols.serial.macos_serial_ports", return_value=["/dev/cu.usbserial-0000"]
    )

    assert not scan_api.serial_scan([])
    assert not scan_api.serial_scan(["bogusportlist"])

    results = scan_api.serial_scan(["0"], [])

    assert results
    assert results[0]
    assert results[1] == []
    assert results[2]


def test_check_host_serial():
    assert scan_api.check_host_serial("0", []) is False


def test_run_identify():
    assert scan_api.run_identify(lambda x: x, [], []) == {}


def test_scan_static(mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "VERBOSE": True,
            "DEBUG": 3,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    assert scan_api.scan(None, "unicast_ip") is None
    assert scan_api.scan([], "unicast_ip") is None
    assert scan_api.scan([], "broadcast_ip") is None
    assert scan_api.scan(None, "broadcast_ip") is None
    assert scan_api.scan([], "serial") is None
    assert scan_api.scan(None, "broadcast_ip") is None
    assert scan_api.scan([], "some bogus scan type lol") is None


# ---------------------------------------------------------------------------
# Module exclusions (excluded_modules)
# ---------------------------------------------------------------------------


@pytest.fixture
def excl_config(isolated_config, mocker):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(state["CONFIG"], {"error": False})
    return isolated_config


@pytest.fixture
def no_network(mocker):
    """Fail the test if anything tries to contact a host."""
    return {
        name: mocker.patch.object(scan_api, name, side_effect=AssertionError(name))
        for name in ["check_host", "portscan", "check_tcp_port", "get_reachable_hosts"]
    }


@pytest.mark.usefixtures("no_network")
def test_check_host_unicast_ip_all_excluded(excl_config, caplog):
    excl_config.EXCLUDED_MODULES = {"ControlLogix": ["127.0.0.1"]}

    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix]) is False
    assert state.error is False
    assert "Every module is excluded for 127.0.0.1" in caplog.text


@pytest.mark.usefixtures("no_network")
def test_check_host_unicast_ip_peat_module_excluded(excl_config, caplog, mocker):
    dev = DeviceData(ip="127.0.0.1")
    dev._module = ControlLogix
    mocker.patch.object(datastore, "objects", [dev])
    excl_config.EXCLUDED_MODULES = {"clx": ["127.0.0.0/8"]}

    # Unlike a missing peat_module (see the edge case test above), this isn't an error
    assert scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix, MicroNet]) is False
    assert state.error is False
    assert "The PEAT module 'ControlLogix' configured for 127.0.0.1" in caplog.text


@pytest.mark.usefixtures("no_network")
def test_check_host_unicast_ip_exclusions_argument(excl_config):
    # Exclusions passed as an argument are used instead of the config
    excl_config.EXCLUDED_MODULES = {"MicroNet": True}
    exclusions = ModuleExclusions({"ControlLogix": ["127.0.0.1"]})
    assert (
        scan_api.check_host_unicast_ip("127.0.0.1", [ControlLogix], exclusions=exclusions) is False
    )


@pytest.mark.parametrize(
    ("learned", "rule_target"),
    [
        ({"mac": "00:11:22:33:44:55"}, "00-11-22-33-44-55"),
        ({"hostname": "plc1.example"}, "PLC1.example"),
    ],
)
def test_check_host_unicast_ip_rechecks_after_mac_and_hostname(
    excl_config, mocker, caplog, no_network, learned, rule_target
):
    # The MAC address and hostname are only known after populate_fields(), so the
    # exclusions are checked again before any ports are scanned
    excl_config.ASSUME_ONLINE = True
    mocker.patch("peat.protocols.addresses.socket.gethostbyname", return_value="198.51.100.1")
    exclusions = ModuleExclusions({"ControlLogix": [rule_target]})

    def fake_populate_fields(self, **_kwargs):
        for key, value in learned.items():
            setattr(self, key, value)

    mocker.patch.object(DeviceData, "populate_fields", fake_populate_fields)

    # Every module is excluded: no ports are scanned
    assert (
        scan_api.check_host_unicast_ip("192.0.2.9", [ControlLogix], exclusions=exclusions) is False
    )
    assert "Every module is excluded for 192.0.2.9 (matched by MAC address or hostname)" in (
        caplog.text
    )
    assert exclusions._skips == {"ControlLogix": {"192.0.2.9"}}
    for mock in no_network.values():
        mock.assert_not_called()

    # Only some of the modules are excluded: the others are still used
    no_network["portscan"].side_effect = None
    assert (
        scan_api.check_host_unicast_ip(
            "192.0.2.10", [ControlLogix, MicroNet], exclusions=exclusions
        )
        is False  # No services found by the (mocked) port scan
    )
    no_network["portscan"].assert_called_once()
    scanned_modules = {m[1] for m in no_network["portscan"].call_args.args[1]}
    assert scanned_modules == {MicroNet}


def _capture_run_identify(mocker) -> dict:
    captured = {}

    def fake_run_identify(func, addresses, modules):
        captured.update(func=func, addresses=list(addresses), modules=list(modules))
        return dict.fromkeys(addresses, False)

    mocker.patch.object(scan_api, "run_identify", side_effect=fake_run_identify)
    return captured


def test_unicast_ip_scan_prunes_fully_excluded(excl_config, mocker, caplog, no_network):
    excl_config.ASSUME_ONLINE = True
    excl_config.EXCLUDED_MODULES = {"all": ["192.0.2.1"], "MicroNet": ["192.0.2.2"]}
    captured = _capture_run_identify(mocker)

    results = scan_api.unicast_ip_scan(
        ["192.0.2.1", "192.0.2.2", "192.0.2.3"], [ControlLogix, MicroNet]
    )
    assert results is not None
    assert captured["addresses"] == ["192.0.2.2", "192.0.2.3"]
    assert captured["modules"] == [ControlLogix, MicroNet]
    assert captured["func"].keywords["exclusions"] is scan_api.get_exclusions()
    assert results[1] == [ControlLogix, MicroNet]
    assert results[2] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]  # All resolved targets
    assert "Skipping 1 target that have every module excluded" in caplog.text
    for mock in no_network.values():
        mock.assert_not_called()


def test_unicast_ip_scan_prunes_before_online_check(excl_config, mocker, no_network):
    excl_config.ASSUME_ONLINE = False
    excl_config.EXCLUDED_MODULES = {"ControlLogix": ["192.0.2.1"]}
    mocker.patch.dict(state["CONFIG"], {"raw_socket_capable": True})
    no_network["get_reachable_hosts"].side_effect = lambda addrs, **_: list(addrs)
    captured = _capture_run_identify(mocker)

    assert scan_api.unicast_ip_scan(["192.0.2.1", "192.0.2.2"], [ControlLogix])
    no_network["get_reachable_hosts"].assert_called_once_with(["192.0.2.2"])
    assert captured["addresses"] == ["192.0.2.2"]


@pytest.mark.usefixtures("no_network")
def test_unicast_ip_scan_peat_module_excluded(excl_config, mocker, caplog):
    excl_config.ASSUME_ONLINE = True
    excl_config.EXCLUDED_MODULES = {"ControlLogix": ["192.0.2.1"]}
    dev = DeviceData(ip="192.0.2.1")
    dev._module = ControlLogix
    mocker.patch.object(datastore, "objects", [dev])
    captured = _capture_run_identify(mocker)

    # MicroNet isn't excluded, but only the host's peat_module would be used
    assert scan_api.unicast_ip_scan(["192.0.2.1", "192.0.2.2"], [ControlLogix, MicroNet])
    assert captured["addresses"] == ["192.0.2.2"]
    assert "('peat_module' in the YAML config hosts) is excluded" in caplog.text


@pytest.mark.usefixtures("no_network")
def test_unicast_ip_scan_everything_pruned(excl_config, mocker, caplog):
    excl_config.ASSUME_ONLINE = True
    excl_config.EXCLUDED_MODULES = {"all": ["192.0.2.0/24"]}
    captured = _capture_run_identify(mocker)

    assert scan_api.unicast_ip_scan(["192.0.2.1", "192.0.2.2"], [ControlLogix]) is None
    assert not captured
    assert "nothing to scan" in caplog.text


@pytest.mark.usefixtures("no_network")
def test_unicast_ip_scan_global_exclusion(excl_config, mocker):
    excl_config.ASSUME_ONLINE = True
    excl_config.EXCLUDED_MODULES = {"MicroNet": True}
    captured = _capture_run_identify(mocker)

    results = scan_api.unicast_ip_scan(["192.0.2.1"], [ControlLogix, MicroNet])
    assert captured["modules"] == [ControlLogix]
    assert results[1] == [ControlLogix]


@pytest.mark.usefixtures("no_network")
def test_unicast_ip_scan_sweep_not_pruned(excl_config, mocker, caplog):
    excl_config.ASSUME_ONLINE = True
    excl_config.SCAN_SWEEP = True
    excl_config.EXCLUDED_MODULES = {"all": ["192.0.2.1"]}
    captured = _capture_run_identify(mocker)

    results = scan_api.unicast_ip_scan(["192.0.2.1", "192.0.2.2"], [ControlLogix])
    assert results == ({"192.0.2.1": True, "192.0.2.2": True}, [], [])
    assert not captured
    # The operator is warned that the sweep still reaches the excluded target
    assert (
        "excluded_modules can't stop the sweep (--sweep) from reaching targets that have "
        "modules excluded for them (sweeps don't use PEAT modules): 192.0.2.1."
    ) in caplog.text


@pytest.mark.usefixtures("no_network")
def test_unicast_ip_scan_sweep_no_warning_for_global_exclusions(excl_config, mocker, caplog):
    excl_config.ASSUME_ONLINE = True
    excl_config.SCAN_SWEEP = True
    excl_config.EXCLUDED_MODULES = {"MicroNet": True}
    _capture_run_identify(mocker)

    assert scan_api.unicast_ip_scan(["192.0.2.1"], [ControlLogix])
    assert "excluded_modules can't stop" not in caplog.text


def test_serial_sweep_warns_about_exclusions(excl_config, mocker, caplog):
    excl_config.SCAN_SWEEP = True
    excl_config.EXCLUDED_MODULES = {"all": ["/dev/ttyS0"]}
    mocker.patch.object(
        scan_api, "port_nums_to_addresses", return_value=["/dev/ttyS0", "/dev/ttyS1"]
    )
    mocker.patch.object(scan_api, "find_serial_ports", return_value=["/dev/ttyS1"])

    results = scan_api.serial_scan(["0-1"])
    assert results == ({"/dev/ttyS0": False, "/dev/ttyS1": True}, [], [])
    assert "excluded_modules can't stop the serial port sweep (--sweep)" in caplog.text


def test_serial_scan_exclusions(excl_config, mocker, caplog):
    mocker.patch.object(
        scan_api, "port_nums_to_addresses", return_value=["/dev/ttyS0", "/dev/ttyS1"]
    )
    captured = _capture_run_identify(mocker)
    excl_config.EXCLUDED_MODULES = {"all": ["/dev/ttyS0"]}

    results = scan_api.serial_scan(["0-1"])
    assert results is not None
    assert captured["addresses"] == ["/dev/ttyS1"]
    assert captured["func"].keywords["exclusions"] is scan_api.get_exclusions()
    assert results[2] == ["/dev/ttyS0", "/dev/ttyS1"]
    assert "Skipping serial port /dev/ttyS0" in caplog.text

    excl_config.EXCLUDED_MODULES = {"all": ["/dev/ttyS0", "/dev/ttyS1"]}
    assert scan_api.serial_scan(["0-1"]) is None


@pytest.mark.usefixtures("excl_config")
def test_check_host_serial_all_excluded(caplog):
    serial_mods = module_api.lookup_types(None, filter_attr="serial_methods")
    assert serial_mods
    exclusions = ModuleExclusions({"all": ["COM3"]})
    assert scan_api.check_host_serial("com3", serial_mods, exclusions=exclusions) is False
    assert "Every module is excluded for serial port com3" in caplog.text


class _BroadcastTestModule(DeviceModule):
    vendor_id = "Test"


_BroadcastTestModule.ip_methods = [
    IPMethod(
        name="test broadcast",
        description="test broadcast",
        type="broadcast_ip",
        identify_function=lambda _target: [
            {"ip": "192.0.2.5", "port": 44818},
            {"ip": "192.0.2.6", "port": 44818},
        ],
        reliability=5,
        protocol="cip",
        transport="udp",
        default_port=44818,
    )
]


@pytest.mark.usefixtures("excl_config")
def test_broadcast_scan_filters_responses(mocker, caplog):
    exclusions = ModuleExclusions({})
    exclusions.per_target[_BroadcastTestModule] = compile_targets("test", ["192.0.2.5"])
    mocker.patch.object(scan_api, "get_exclusions", return_value=exclusions)

    results = scan_api.broadcast_scan(["127.0.0.1"], [_BroadcastTestModule])
    assert results == ({"127.0.0.1": True}, [_BroadcastTestModule], ["127.0.0.1"])

    assert datastore.search("192.0.2.5", "ip") is None
    dev = datastore.search("192.0.2.6", "ip")
    assert dev is not None
    assert dev._is_verified
    assert dev._module is _BroadcastTestModule
    assert "Ignoring _BroadcastTestModule broadcast response from 192.0.2.5" in caplog.text
    assert exclusions._skips == {"_BroadcastTestModule": {"192.0.2.5"}}


@pytest.mark.usefixtures("excl_config")
def test_broadcast_scan_warns_about_exclusions(mocker, caplog):
    exclusions = ModuleExclusions({"all": ["192.0.2.200"]})
    mocker.patch.object(scan_api, "get_exclusions", return_value=exclusions)

    assert scan_api.broadcast_scan(["127.0.0.1"], [_BroadcastTestModule])
    assert (
        "excluded_modules can't stop broadcast probes (-b) from reaching targets that "
        "have modules excluded for them (broadcasts reach every device on the network, "
        "only the responses are ignored): 192.0.2.200."
    ) in caplog.text


@pytest.mark.usefixtures("excl_config")
def test_broadcast_scan_global_exclusion(mocker, caplog):
    exclusions = ModuleExclusions({})
    exclusions.global_mods.add(_BroadcastTestModule)
    mocker.patch.object(scan_api, "get_exclusions", return_value=exclusions)
    identify = mocker.spy(_BroadcastTestModule.ip_methods[0], "identify_function")

    # No modules remain, so nothing is sent
    assert scan_api.broadcast_scan(["127.0.0.1"], [_BroadcastTestModule]) is None
    identify.assert_not_called()
    assert not datastore.objects
    assert "No modules with broadcast methods" in caplog.text


def test_scan_logs_skip_summary(excl_config, mocker, caplog):
    excl_config.EXCLUDED_MODULES = {"ControlLogix": ["192.0.2.1"]}

    def fake_unicast_ip_scan(targets, _device_types):
        scan_api.get_exclusions().record_skip(ControlLogix, target=targets[0])
        return {}, [ControlLogix], targets

    mocker.patch.object(scan_api, "unicast_ip_scan", side_effect=fake_unicast_ip_scan)
    assert scan_api.scan(["192.0.2.1"], "unicast_ip", [ControlLogix]) is None
    assert "ControlLogix for 1 target" in caplog.text


def test_scan_bad_exclusions(excl_config, mocker, caplog):
    excl_config.EXCLUDED_MODULES = {"ControlLogix": ["192.0.2.300"]}
    mock_scan = mocker.patch.object(scan_api, "unicast_ip_scan")

    assert scan_api.scan(["192.0.2.1"], "unicast_ip", [ControlLogix]) is None
    assert state.error is True
    mock_scan.assert_not_called()
    assert "Invalid target '192.0.2.300'" in caplog.text
