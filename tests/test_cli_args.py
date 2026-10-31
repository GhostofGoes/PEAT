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


@pytest.mark.parametrize("subcmd", ["scan", "pull", "push"])
def test_protocols_arg(mocker, subcmd):
    mocker.patch("sys.argv", ["peat", subcmd, "-p", "ftp", "502", "-i", "192.0.2.1"])
    result = cli_args.parse_peat_arguments()
    assert result.protocol_filter == ["ftp", "502"]

    # Long option, and unambiguous abbreviation of it
    for opt in ["--protocols", "--prot"]:
        mocker.patch("sys.argv", ["peat", subcmd, opt, "161/udp", "-i", "192.0.2.1"])
        assert cli_args.parse_peat_arguments().protocol_filter == ["161/udp"]

    mocker.patch("sys.argv", ["peat", subcmd, "-i", "192.0.2.1"])
    assert cli_args.parse_peat_arguments().protocol_filter is None


def test_protocols_arg_push_input_source(mocker):
    mocker.patch(
        "sys.argv",
        ["peat", "push", "-d", "selrelay", "-p", "ftp", "-i", "192.0.2.1", "--", "SET_1.TXT"],
    )
    result = cli_args.parse_peat_arguments()
    assert result.protocol_filter == ["ftp"]
    assert result.input_source == "SET_1.TXT"


def test_protocols_arg_list_modules_without_hosts(mocker):
    mocker.patch("sys.argv", ["peat", "scan", "-p", "ftp", "--list-modules"])
    result = cli_args.parse_peat_arguments()
    assert result.protocol_filter == ["ftp"]
    assert result.list_modules is True


def test_password_short_arg_unchanged(mocker):
    # "-p" is "--password" for the encryption commands, and "--protocols" for others
    mocker.patch("sys.argv", ["peat", "encrypt", "-f", "config.yaml", "-p", "secret"])
    result = vars(cli_args.parse_peat_arguments())
    assert result["user-password"] == "secret"
    assert "protocol_filter" not in result


@pytest.mark.parametrize("subcmd", ["parse", "pillage", "heat"])
def test_protocols_arg_not_on_other_commands(mocker, subcmd):
    mocker.patch("sys.argv", ["peat", subcmd, "-p", "ftp"])
    with pytest.raises(SystemExit) as exit_result:
        cli_args.parse_peat_arguments()
    assert exit_result.value.code == 2


@pytest.mark.parametrize("subcmd", ["scan", "pull", "push", "parse", "pillage", "heat"])
def test_module_info_arg(mocker, subcmd):
    mocker.patch("sys.argv", ["peat", subcmd, "--module-info", "sel", "m340"])
    result = cli_args.parse_peat_arguments()
    assert result.module_info == ["sel", "m340"]
