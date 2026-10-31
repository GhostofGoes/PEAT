import socket

import pytest

from peat import M340, PeatError, SELRelay, cli_main, config


def test_cli_get_targets_labels(mocker, assert_no_errors, caplog):
    """
    test resolving labels from YAML config to host targets.
    This reads from config.HOSTS which is loaded from YAML config.
    """
    mocker.patch.dict(
        config["CONFIG"],
        {
            "DEBUG": 2,
            "HOSTS": [
                {
                    "label": "example-host",
                    "identifiers": {"ip": "192.0.2.10"},
                    "peat_module": "SELrtac",  # case-insensitive
                },
                {
                    "label": "Switch1-DATACENTER",
                    "identifiers": {"ip": "192.0.2.20"},
                    "peat_module": "SELRelay",
                },
                # Host with no label
                {
                    "identifiers": {"serial_port": "/dev/ttyS0"},
                    "peat_module": "SELRelay",
                },
                # Host with no identifiers
                {
                    "label": "host-no-identifiers",
                    "peat_module": "SELRelay",
                },
            ],
        },
    )

    # test labels, including case-insensitive match
    assert cli_main.get_targets(
        {
            "host_list": ["example-host", "switch1-DataCenter"],
            "device_types": ["SELRTAC", "SELRelay"],
        }
    ) == (
        ["192.0.2.10", "192.0.2.20"],
        "unicast_ip",
        ["SELRTAC", "SELRelay"],
    )

    # test "all" target
    assert cli_main.get_targets(
        {
            "host_list": ["all"],
            "device_types": ["SELRTAC", "SELRelay"],
        }
    ) == (
        ["192.0.2.10", "192.0.2.20"],
        "unicast_ip",
        ["SELRTAC", "SELRelay"],
    )

    # test "all" target with serial
    assert cli_main.get_targets(
        {
            "port_list": ["all"],
            "device_types": ["SELRelay"],
        }
    ) == (
        ["/dev/ttyS0"],
        "serial",
        ["SELRelay"],
    )

    assert_no_errors()
    assert "WARNING" in caplog.text


def test_cli_get_targets_comm_types(assert_no_warns):
    assert cli_main.get_targets(
        {"device_types": ["selrtac", "controllogix"], "host_list": ["192.168.0.20"]}
    ) == (
        ["192.168.0.20"],
        "unicast_ip",
        ["ControlLogix", "SELRTAC"],
    )

    assert cli_main.get_targets(
        {
            "device_types": ["selrelay", "controllogix"],
            "broadcast_list": ["192.168.0.0/24"],
        }
    ) == (
        ["192.168.0.0/24"],
        "broadcast_ip",
        ["ControlLogix", "SELRelay"],
    )

    assert cli_main.get_targets(
        {"device_types": ["selrtac", "selrelay"], "port_list": ["/dev/ttyS0"]}
    ) == (
        ["/dev/ttyS0"],
        "serial",
        ["SELRTAC", "SELRelay"],
    )
    assert_no_warns()


def test_cli_get_targets_errors(mocker):
    with pytest.raises(PeatError):
        cli_main.get_targets({"host_file": "/invalid_path"})

    with pytest.raises(PeatError):
        cli_main.get_targets({"device_types": ["selrtac", "ion"]})

    # test "all" target fails with no hosts
    with pytest.raises(PeatError):
        mocker.patch.dict(config["CONFIG"], {"DEBUG": 2, "HOSTS": []})
        cli_main.get_targets({"host_list": ["all"], "device_types": ["selrtac"]})

    # test "all" target fails no Unicast IP or Serial hosts
    with pytest.raises(PeatError):
        mocker.patch.dict(config["CONFIG"], {"DEBUG": 2, "HOSTS": [{"label": "dummy"}]})
        cli_main.get_targets({"broadcast_list": ["all"], "device_types": ["selrtac"]})


def test_cli_parse_scan_summary_errors():
    with pytest.raises(PeatError):
        cli_main.parse_scan_summary({})

    with pytest.raises(PeatError):
        cli_main.parse_scan_summary({"module_names": []})


def test_cli_read_host_file_bad_inputs():
    assert cli_main.read_host_file(None) is None  # type: ignore
    assert cli_main.read_host_file("") is None
    assert cli_main.read_host_file("./tmp/__peat_fake_file.txt") is None


def test_cli_write_readme(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"OUT_DIR": tmp_path})
    expected_path = tmp_path / "README.md"

    assert not expected_path.exists()

    assert cli_main.write_readme()

    assert expected_path.is_file()
    first_text = expected_path.read_text(encoding="utf-8")
    assert "(PEAT)" in first_text

    assert cli_main.write_readme()

    assert expected_path.is_file()
    assert first_text == expected_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# device_types, targets, and excluded_modules
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_config(isolated_config, mocker):
    mocker.patch.object(cli_main.module_api, "runtime_imports", set())
    return isolated_config


def test_get_targets_device_types_from_config(cli_config):
    cli_config["file_configs"]["DEVICE_TYPES"] = ["SELRelay"]
    args = {"func": "scan", "host_list": ["192.0.2.1"], "device_types": None}
    assert cli_main.get_targets(args) == (["192.0.2.1"], "unicast_ip", ["SELRelay"])

    # The command line argument wins
    args["device_types"] = ["m340"]
    assert cli_main.get_targets(args)[2] == ["M340"]


@pytest.mark.usefixtures("cli_config")
def test_get_targets_default_all():
    args = {"func": "pull", "host_list": ["192.0.2.1"], "device_types": None}
    assert cli_main.get_targets(args)[2] == cli_main.module_api.names


@pytest.mark.usefixtures("cli_config")
def test_get_targets_push_requires_device_types():
    # Regression test: this used to raise a TypeError
    args = {"func": "push", "host_list": ["192.0.2.1"], "device_types": None}
    with pytest.raises(PeatError, match="No device type specified for push"):
        cli_main.get_targets(args)


def test_get_targets_push_config_device_types_warns(cli_config, caplog):
    cli_config["env_configs"]["DEVICE_TYPES"] = ["selrelay"]
    args = {"func": "push", "host_list": ["192.0.2.1"], "device_types": None}
    assert cli_main.get_targets(args)[2] == ["SELRelay"]
    assert "from environment variable PEAT_DEVICE_TYPES for push" in caplog.text

    caplog.clear()
    args["device_types"] = ["all"]
    cli_main.get_targets(args)
    assert "for push" not in caplog.text
    assert "device type 'all'" in caplog.text


@pytest.mark.usefixtures("cli_config")
def test_get_targets_unknown_device_type_warns(caplog):
    args = {"func": "scan", "host_list": ["192.0.2.1"], "device_types": ["sel", "notamodule"]}
    assert set(cli_main.get_targets(args)[2]) == {"SEL3620", "SELRTAC", "SELRelay"}
    assert "Unknown device type 'notamodule'" in caplog.text


def test_get_targets_targets_key(cli_config, caplog):
    cli_config["section_configs"]["TARGETS"] = ["192.0.2.1", "example-host"]
    cli_config["section_command"] = "scan"
    cli_config.HOSTS = [{"label": "example-host", "identifiers": {"ip": "192.0.2.10"}}]
    args = {"func": "scan", "device_types": ["selrelay"]}

    targets, comm_type, modules = cli_main.get_targets(args)
    assert targets == ["192.0.2.1", "192.0.2.10"]
    assert comm_type == "unicast_ip"
    assert modules == ["SELRelay"]
    assert "Using 2 targets from 'scan' section of the config file" in caplog.text

    # Targets on the command line win
    args["host_list"] = ["192.0.2.99"]
    assert cli_main.get_targets(args)[0] == ["192.0.2.99"]

    # push doesn't use "targets"
    cli_config.HOSTS = []
    with pytest.raises(PeatError, match="No hosts specified"):
        cli_main.get_targets({"func": "push", "device_types": ["selrelay"]})


def test_get_targets_hosts_fallback_scan(cli_config):
    cli_config.HOSTS = [
        {"label": "a", "identifiers": {"ip": "192.0.2.10"}, "peat_module": "M340"},
        {"label": "b", "identifiers": {"serial_port": "/dev/ttyS0"}},
    ]
    targets, comm_type, modules = cli_main.get_targets({"func": "scan", "device_types": ["clx"]})
    assert targets == ["192.0.2.10"]
    assert comm_type == "unicast_ip"
    assert sorted(modules) == ["ControlLogix", "M340"]


@pytest.mark.usefixtures("cli_config")
def test_get_targets_no_targets():
    with pytest.raises(PeatError, match="targets"):
        cli_main.get_targets({"func": "scan", "device_types": None})


def _dry_run_args(**kwargs) -> dict:
    args = {"func": "scan", "host_list": ["192.0.2.1"], "device_types": ["sel"]}
    args.update(kwargs)
    return args


def test_oneshot_main_dry_run_logs_exclusions(cli_config, caplog):
    cli_config.DRY_RUN = True
    cli_config.EXCLUDED_MODULES = {"SELRTAC": True, "SELRelay": ["192.0.2.5"]}

    assert cli_main.oneshot_main(_dry_run_args()) is True
    assert "Excluded modules (all targets): SELRTAC" in caplog.text
    assert "Excluded 'SELRelay' (SELRelay) for 1 target: 192.0.2.5" in caplog.text
    assert "Running scan of 1 target using 2 modules" in caplog.text
    assert "Dry run enabled" in caplog.text


def test_oneshot_main_requested_but_excluded(cli_config, caplog):
    cli_config.DRY_RUN = True
    cli_config.EXCLUDED_MODULES = {"SELRelay": True}

    assert cli_main.oneshot_main(_dry_run_args(device_types=["selrelay", "m340"])) is True
    assert "Device type 'selrelay' from command line argument '-d' only matches" in caplog.text
    assert "using 1 module" in caplog.text


@pytest.mark.parametrize(
    ("func", "extra"),
    [
        ("scan", {}),
        ("pull", {}),
        ("push", {"device_types": ["selrelay"]}),
        ("parse", {"host_list": None}),
    ],
)
def test_oneshot_main_all_excluded_fails(cli_config, caplog, func, extra):
    cli_config.DRY_RUN = True
    cli_config.EXCLUDED_MODULES = {"all": True}

    assert cli_main.oneshot_main(_dry_run_args(func=func, **extra)) is False
    assert "No PEAT modules remain after applying excluded_modules" in caplog.text


def test_oneshot_main_no_matching_modules_fails(cli_config, caplog):
    cli_config.DRY_RUN = True
    assert cli_main.oneshot_main(_dry_run_args(device_types=["notamodule"])) is False
    assert "No PEAT modules match the device types" in caplog.text


def test_oneshot_main_sweep_without_modules(cli_config):
    cli_config.DRY_RUN = True
    cli_config.SCAN_SWEEP = True
    cli_config.EXCLUDED_MODULES = {"all": True}
    assert cli_main.oneshot_main(_dry_run_args()) is True


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"scan_sweep": True}, "excluded_modules can't stop the sweep (--sweep)"),
        (
            {"host_list": None, "broadcast_list": ["192.0.2.255"]},
            "excluded_modules can't stop broadcast probes (-b)",
        ),
    ],
)
def test_oneshot_main_dry_run_warns_unenforced(cli_config, caplog, mocker, args, expected):
    # The scan functions aren't called by a dry run, so the warning is logged here
    mocker.patch.dict(cli_main.state["runtime_configs"])
    cli_config.DRY_RUN = True
    cli_config.EXCLUDED_MODULES = {"all": ["192.0.2.200"]}
    if args.pop("scan_sweep", False):
        cli_config.SCAN_SWEEP = True

    assert cli_main.oneshot_main(_dry_run_args(**args)) is True
    assert expected in caplog.text
    assert "192.0.2.200" in caplog.text


def test_oneshot_main_bad_exclusion_target_fails(cli_config, caplog):
    cli_config.DRY_RUN = True
    cli_config.EXCLUDED_MODULES = {"SELRelay": ["192.0.2.300"]}
    assert cli_main.oneshot_main(_dry_run_args()) is False
    assert "Invalid target '192.0.2.300' in excluded_modules for 'SELRelay'" in caplog.text


@pytest.mark.parametrize(
    ("excluded", "expected"),
    [
        (["ControlLgix"], "'ControlLgix' doesn't match any PEAT module or alias"),
        (["ControlLogix SEL=192.0.2.5"], "one name or NAME=TARGETS per '-x'"),
        ("SEL=192.0.2.5 192.0.2.6", "'192.0.2.6' isn't a PEAT module or alias"),
    ],
)
def test_oneshot_main_unknown_excluded_module_fails(cli_config, caplog, excluded, expected):
    # A misspelled or malformed module name must not quietly turn into no exclusion
    cli_config.DRY_RUN = True
    cli_config.EXCLUDED_MODULES = excluded
    assert cli_main.oneshot_main(_dry_run_args(device_types=["all"])) is False
    assert expected in caplog.text
    assert "Running scan" not in caplog.text


def test_oneshot_main_parse_ignores_exclusion_targets(cli_config, mocker, caplog):
    # parse is passive: the targets of exclusions aren't resolved (no DNS lookups),
    # so a hostname that can't be resolved (e.g. offline) doesn't stop it
    mock_dns = mocker.patch(
        "peat.protocols.addresses.socket.gethostbyname",
        side_effect=socket.gaierror("Name or service not known"),
    )
    cli_config.DRY_RUN = True
    cli_config.EXCLUDED_MODULES = {"SELRelay": ["plc1.nonexistent-site.invalid"], "M340": True}
    mock_resolve = mocker.spy(cli_main, "_resolve_modules")

    assert cli_main.oneshot_main({"func": "parse", "device_types": None}) is True
    mock_dns.assert_not_called()
    assert M340 not in mock_resolve.spy_return
    assert SELRelay in mock_resolve.spy_return

    # scan resolves them, and fails closed
    assert cli_main.oneshot_main(_dry_run_args()) is False
    assert "couldn't resolve the hostname" in caplog.text


def test_oneshot_main_parse_device_types(cli_config, mocker):
    cli_config.DRY_RUN = True
    mock_resolve = mocker.spy(cli_main, "_resolve_modules")

    # Nothing configured: all modules
    assert cli_main.oneshot_main({"func": "parse", "device_types": None}) is True
    assert mock_resolve.call_args.args[1] == ["all"]

    # From the config
    cli_config["env_configs"]["DEVICE_TYPES"] = ["m340"]
    assert cli_main.oneshot_main({"func": "parse", "device_types": None}) is True
    assert mock_resolve.call_args.args[1] == ["m340"]

    # The command line argument wins
    assert cli_main.oneshot_main({"func": "parse", "device_types": ["sel"]}) is True
    assert mock_resolve.call_args.args[1] == ["sel"]


def test_oneshot_main_parse_runtime_imports_only(cli_config, mocker):
    # "peat parse -I mod.py" without device types only uses the imported modules
    cli_config.DRY_RUN = True
    mocker.patch.object(cli_main.module_api, "runtime_imports", {"SELRelay"})
    mock_resolve = mocker.spy(cli_main, "_resolve_modules")
    assert cli_main.oneshot_main({"func": "parse", "device_types": None}) is True
    assert mock_resolve.call_args.args[1] == ["SELRelay"]


def test_config_for_elastic():
    raw = {
        "DEBUG": 1,
        "DEVICE_OPTIONS": {"sel": {}},
        "HOSTS": [{}],
        "SCAN": {"sweep": True},
        "PULL": {},
        "PUSH": {},
        "PARSE": {},
        "DEVICE_TYPES": ["sel"],
        "EXCLUDED_MODULES": {"ControlLogix": True, "SEL": ["192.0.2.5"], "M340": False},
    }
    result = cli_main.config_for_elastic(raw)
    assert result == {
        "DEBUG": 1,
        "DEVICE_TYPES": ["sel"],
        "EXCLUDED_MODULES": ["ControlLogix", "SEL=192.0.2.5"],
    }
    assert "SCAN" in raw  # The input isn't modified

    assert cli_main.config_for_elastic({"EXCLUDED_MODULES": 5}) == {}
