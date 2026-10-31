import argparse

import pytest

from peat import cli_args


def test_build_argument_parser():
    parser = cli_args.build_argument_parser(version="2019.01.01")
    assert isinstance(parser, argparse.ArgumentParser)
    assert parser.prog == "peat"
    assert "PEAT" in parser.description


def test_parse_peat_arguments(mocker):
    mocker.patch("sys.argv", ["peat"])
    with pytest.raises(SystemExit) as exit_result:
        cli_args.parse_peat_arguments()
    assert exit_result.type is SystemExit
    assert exit_result.value.code == 0

    mocker.patch("sys.argv", ["peat", "parse"])
    with pytest.raises(SystemExit) as exit_result:
        assert isinstance(cli_args.parse_peat_arguments(), argparse.Namespace)
    assert exit_result.type is SystemExit
    assert exit_result.value.code == 0

    mocker.patch("sys.argv", ["peat", "parse", "-vV"])
    result = cli_args.parse_peat_arguments()
    assert isinstance(result, argparse.Namespace)
    assert result.verbose is True
    assert result.debug == 1


def test_pull_skip_scan_arg(mocker):
    mocker.patch("sys.argv", ["peat", "pull", "--skip-scan"])
    result = cli_args.parse_peat_arguments()
    assert isinstance(result, argparse.Namespace)
    assert result.pull_skip_scan is True


def test_pull_skip_scan_default_none(mocker):
    mocker.patch("sys.argv", ["peat", "pull", "-i", "192.168.0.1"])
    result = cli_args.parse_peat_arguments()
    assert not result.pull_skip_scan


@pytest.mark.parametrize("command", ["scan", "pull", "push"])
@pytest.mark.parametrize("flag", ["--capture-traffic", "--pcap"])
def test_capture_traffic_args(mocker, command, flag):
    mocker.patch("sys.argv", ["peat", command, "-i", "192.0.2.1", flag])
    result = cli_args.parse_peat_arguments()
    assert result.capture_traffic is True
    assert result.capture_interfaces is None
    assert result.capture_filter is None
    assert result.capture_tool is None


def test_capture_traffic_default_none(mocker):
    mocker.patch("sys.argv", ["peat", "pull", "-i", "192.0.2.1"])
    result = cli_args.parse_peat_arguments()
    assert result.capture_traffic is None


def test_capture_options_args(mocker):
    mocker.patch(
        "sys.argv",
        [
            "peat",
            "scan",
            "-i",
            "192.0.2.0/24",
            "--capture-traffic",
            "--capture-interfaces",
            "eth0",
            "eth1",
            "--capture-filter",
            "tcp port 502",
            "--capture-tool",
            "scapy",
        ],
    )
    result = cli_args.parse_peat_arguments()
    assert result.capture_interfaces == ["eth0", "eth1"]
    assert result.capture_filter == "tcp port 502"
    assert result.capture_tool == "scapy"
    assert result.host_list == ["192.0.2.0/24"]


def test_capture_tool_invalid(mocker):
    mocker.patch("sys.argv", ["peat", "scan", "-i", "192.0.2.1", "--capture-tool", "wireshark"])
    with pytest.raises(SystemExit):
        cli_args.parse_peat_arguments()


@pytest.mark.parametrize("command", [["parse", "examples/"], ["pillage", "-P", "x"]])
def test_capture_traffic_not_on_other_commands(mocker, command):
    mocker.patch("sys.argv", ["peat", *command, "--capture-traffic"])
    with pytest.raises(SystemExit):
        cli_args.parse_peat_arguments()


def test_capture_traffic_examples():
    assert "--capture-traffic" in cli_args.ALL_EXAMPLES["scan"]
    assert "--capture-traffic" in cli_args.ALL_EXAMPLES["pull"]
