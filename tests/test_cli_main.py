import pytest

from peat import PeatError, cli_main, config


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


@pytest.fixture
def no_protocol_filter(mocker):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": [], "DRY_RUN": False})
    mocker.patch.dict(config["load_errors"], clear=True)


@pytest.mark.usefixtures("no_protocol_filter")
def test_resolve_command_modules_operation(caplog):
    args = {"func": "push", "device_types": ["M340", "SELRelay"]}
    assert cli_main.resolve_command_modules(args, {"SELRelay", "M340"}) == ["SELRelay"]
    # Modules explicitly named with -d that won't be used are warned about
    assert "Not using module 'M340' for push: it doesn't support push" in caplog.text

    with pytest.raises(PeatError, match="support 'push'"):
        cli_main.resolve_command_modules({"func": "push", "device_types": None}, {"M340"})


@pytest.mark.usefixtures("no_protocol_filter")
def test_resolve_command_modules_all(caplog):
    args = {"func": "push", "device_types": None}
    assert cli_main.resolve_command_modules(args, {"all"}) == [
        "ControlLogix",
        "OpenPLCv4",
        "SELRelay",
    ]
    assert "Not using module" not in caplog.text

    args = {"func": "scan", "device_types": None}
    names = cli_main.resolve_command_modules(args, {"all"})
    assert "SELRelay" in names
    assert "L5X" not in names


@pytest.mark.usefixtures("no_protocol_filter")
def test_resolve_command_modules_protocol_filter(mocker, caplog):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["ftp"]})
    pull_names = cli_main.resolve_command_modules({"func": "pull"}, {"all"})
    scan_names = cli_main.resolve_command_modules({"func": "scan"}, {"all"})
    assert "SELRelay" in pull_names
    assert "SELRelay" not in scan_names
    assert "M340" in scan_names
    assert "Protocol filter" in caplog.text

    args = {"func": "scan", "device_types": ["M340", "SELRelay"]}
    assert cli_main.resolve_command_modules(args, {"M340", "SELRelay"}) == ["M340"]
    assert "Not using module 'SELRelay' for scan: it doesn't use any of the protocols" in (
        caplog.text
    )

    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["telnet"]})
    with pytest.raises(PeatError, match="None of the selected modules use"):
        cli_main.resolve_command_modules({"func": "pull"}, {"M340"})


@pytest.fixture
def oneshot_mocks(mocker):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": [], "DRY_RUN": False})
    mocker.patch.dict(config["load_errors"], clear=True)
    mocker.patch.object(
        cli_main,
        "get_targets",
        return_value=(["192.0.2.1"], "unicast_ip", ["M340", "SELRelay"]),
    )
    mocker.patch.object(cli_main.module_api, "runtime_imports", set())
    mocker.patch.object(cli_main, "export_device_data", return_value=True)
    return {
        "scan": mocker.patch.object(cli_main, "scan", return_value={"scan": True}),
        "pull": mocker.patch.object(cli_main, "pull", return_value={"pull": True}),
    }


def test_oneshot_main_protocol_filter(mocker, oneshot_mocks):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["ftp"]})
    args = {"func": "scan", "device_types": ["M340", "SELRelay"]}
    assert cli_main.oneshot_main(args) is True
    oneshot_mocks["scan"].assert_called_once_with(["192.0.2.1"], "unicast_ip", ["M340"])

    args = {"func": "pull", "device_types": ["M340", "SELRelay"]}
    assert cli_main.oneshot_main(args) is True
    assert oneshot_mocks["pull"].call_args.args[2] == ["M340", "SELRelay"]


def test_oneshot_main_protocol_filter_no_match(mocker, oneshot_mocks, caplog):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["cip"]})
    args = {"func": "scan", "device_types": ["M340", "SELRelay"]}
    assert cli_main.oneshot_main(args) is False
    oneshot_mocks["scan"].assert_not_called()
    assert any(
        r.levelname == "CRITICAL" and "None of the selected modules use" in r.getMessage()
        for r in caplog.records
    )


def test_oneshot_main_invalid_protocol_filter(mocker, oneshot_mocks, caplog):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["ftp:21"]})
    assert cli_main.oneshot_main({"func": "scan", "device_types": None}) is False
    oneshot_mocks["scan"].assert_not_called()
    assert "Invalid protocol filter 'ftp:21'" in caplog.text


def test_oneshot_main_dry_run_selects_modules(mocker, oneshot_mocks, caplog):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["502"], "DRY_RUN": True})
    assert cli_main.oneshot_main({"func": "scan", "device_types": None}) is True
    oneshot_mocks["scan"].assert_not_called()
    assert "Protocol filter ['502'] selected 1 module for scan: M340" in caplog.text


@pytest.mark.usefixtures("no_protocol_filter")
def test_resolve_command_modules_comm_type(mocker, caplog):
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["161/udp"]})
    args = {"func": "scan", "device_types": ["ControlLogix", "M340"]}
    mods = {"ControlLogix", "M340"}
    assert cli_main.resolve_command_modules(args, mods, "unicast_ip") == ["ControlLogix", "M340"]
    # No module uses SNMP broadcasts
    with pytest.raises(PeatError, match=r"for 'scan' \(broadcast_ip\)"):
        cli_main.resolve_command_modules(args, mods, "broadcast_ip")

    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["44818/udp"]})
    assert cli_main.resolve_command_modules(args, mods, "broadcast_ip") == ["ControlLogix"]
    assert "Not using module 'M340' for scan: it doesn't use any of the protocols" in caplog.text
    assert "protocol filter with broadcast_ip" in caplog.text


@pytest.mark.usefixtures("no_protocol_filter")
def test_resolve_command_modules_load_error(mocker):
    mocker.patch.dict(config["load_errors"], {"PROTOCOL_FILTER": "bad value"})
    with pytest.raises(PeatError, match="Failed to load the protocol filter"):
        cli_main.resolve_command_modules({"func": "scan"}, {"all"}, "unicast_ip")


def test_oneshot_main_protocol_filter_comm_type(mocker, oneshot_mocks):
    mocker.patch.object(
        cli_main,
        "get_targets",
        return_value=(["192.0.2.255"], "broadcast_ip", ["ControlLogix", "M340"]),
    )
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["cip"]})
    assert cli_main.oneshot_main({"func": "scan", "device_types": None}) is True
    oneshot_mocks["scan"].assert_called_once_with(
        ["192.0.2.255"], "broadcast_ip", ["ControlLogix"]
    )

    oneshot_mocks["scan"].reset_mock()
    mocker.patch.dict(config["CONFIG"], {"PROTOCOL_FILTER": ["161/udp"]})
    assert cli_main.oneshot_main({"func": "scan", "device_types": None}) is False
    oneshot_mocks["scan"].assert_not_called()


def test_oneshot_main_protocol_filter_load_error(mocker, oneshot_mocks, caplog):
    # A protocol filter that failed to load must not result in all modules being used
    mocker.patch.dict(config["load_errors"], {"PROTOCOL_FILTER": "bad value"})
    assert cli_main.oneshot_main({"func": "scan", "device_types": None}) is False
    oneshot_mocks["scan"].assert_not_called()
    assert any(
        r.levelname == "CRITICAL" and "Failed to load the protocol filter" in r.getMessage()
        for r in caplog.records
    )
