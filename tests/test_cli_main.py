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


def test_oneshot_main_dispatches_baseline_commands(mocker):
    run = mocker.patch.object(cli_main, "run_baseline", return_value=3)
    args = {"func": "baseline_compare"}
    assert cli_main.oneshot_main(args) is True
    assert args["_exit_code"] == 3
    run.assert_called_once_with(args)
    run.return_value = 1
    assert cli_main.oneshot_main(args) is False
    assert args["_exit_code"] == 1

    # An unexpected error fails the command like other commands (no traceback
    # out of oneshot_main, so the end-of-run handling of run_peat still runs)
    args["_exit_code"] = 0
    run.side_effect = OSError("disk full")
    assert cli_main.oneshot_main(args) is False
    assert args["_exit_code"] == 1
