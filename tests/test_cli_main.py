import pytest

from peat import PeatError, cli_main, config, state


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


SCAN_ARGS = {"func": "scan", "device_types": ["selrtac"], "host_list": ["192.0.2.1"]}


@pytest.fixture
def capture_mocks(mocker):
    from peat.protocols import pcap

    start = mocker.patch.object(pcap, "start_traffic_capture")
    stop = mocker.patch.object(pcap, "stop_traffic_capture")
    mocker.patch.object(cli_main.exit_handler, "run_and_unregister")
    mocker.patch.object(cli_main, "export_device_data", return_value=True)
    mocker.patch.dict(state["CONFIG"], {"comm_type": None})
    mocker.patch.dict(
        config["CONFIG"], {"CAPTURE_TRAFFIC": True, "DRY_RUN": False, "PRINT_RESULTS": False}
    )
    return start, stop


def test_oneshot_main_traffic_capture(mocker, capture_mocks):
    start, stop = capture_mocks
    scan = mocker.patch.object(cli_main, "scan", return_value={"hosts_verified": 1})

    assert cli_main.oneshot_main(dict(SCAN_ARGS))
    scan.assert_called_once()
    start.assert_called_once_with(["192.0.2.1"], "unicast_ip")
    stop.assert_called_once_with()

    # Capture is stopped even if the command fails
    scan.side_effect = PeatError("scan failed")
    assert not cli_main.oneshot_main(dict(SCAN_ARGS))
    assert stop.call_count == 2


def test_oneshot_main_closes_connections_before_stopping_capture(mocker, capture_mocks):
    """Connections are closed while capturing, so their teardowns are in the capture."""
    _, stop = capture_mocks
    order = []
    cli_main.exit_handler.run_and_unregister.side_effect = order.append
    stop.side_effect = lambda: order.append("stop")
    mocker.patch.object(cli_main, "scan", return_value={"hosts_verified": 1})

    assert cli_main.oneshot_main(dict(SCAN_ARGS))
    assert order == ["CONNECTION", "stop"]

    # Not changed if traffic isn't being captured
    order.clear()
    mocker.patch.dict(config["CONFIG"], {"CAPTURE_TRAFFIC": False})
    assert cli_main.oneshot_main(dict(SCAN_ARGS))
    assert order == []


def test_oneshot_main_traffic_capture_ctrl_c(mocker, capture_mocks):
    start, stop = capture_mocks
    mocker.patch.object(cli_main, "pull", side_effect=KeyboardInterrupt)
    mocker.patch.dict(config["CONFIG"], {"PULL_SKIP_SCAN": False})

    with pytest.raises(KeyboardInterrupt):
        cli_main.oneshot_main({**SCAN_ARGS, "func": "pull"})
    start.assert_called_once()
    stop.assert_called_once_with()


def test_oneshot_main_traffic_capture_disabled(mocker, capture_mocks, caplog):
    start, stop = capture_mocks
    mocker.patch.object(cli_main, "scan", return_value={"hosts_verified": 1})
    mocker.patch.dict(config["CONFIG"], {"CAPTURE_TRAFFIC": False})

    assert cli_main.oneshot_main(dict(SCAN_ARGS))
    assert "traffic capture is disabled" not in caplog.text
    assert cli_main.oneshot_main({**SCAN_ARGS, "capture_tool": "scapy"})
    assert "traffic capture is disabled" in caplog.text
    start.assert_not_called()
    stop.assert_not_called()


def test_oneshot_main_traffic_capture_skipped(mocker, capture_mocks):
    start, stop = capture_mocks

    # Dry runs don't capture
    mocker.patch.dict(config["CONFIG"], {"DRY_RUN": True})
    assert cli_main.oneshot_main(dict(SCAN_ARGS))

    # Commands that don't communicate with devices don't capture
    mocker.patch.dict(config["CONFIG"], {"DRY_RUN": False})
    mocker.patch.object(cli_main, "parse", return_value={"parse_results": 1})
    assert cli_main.oneshot_main({"func": "parse", "device_types": None, "input_source": ["x"]})

    start.assert_not_called()
    stop.assert_not_called()
