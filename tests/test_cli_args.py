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
def test_cache_args_default_none(mocker, command):
    argv = ["peat", command, "-i", "192.0.2.1"]
    if command == "push":
        argv.append("config.txt")
    mocker.patch("sys.argv", argv)
    result = cli_args.parse_peat_arguments()
    assert result.cache_enabled is None
    assert result.cache_ttl is None


@pytest.mark.parametrize("command", ["scan", "pull", "push"])
def test_cache_args(mocker, command):
    argv = ["peat", command, "-i", "192.0.2.1", "--no-cache", "--cache-ttl", "12.5"]
    if command == "push":
        argv.append("config.txt")
    mocker.patch("sys.argv", argv)
    result = cli_args.parse_peat_arguments()
    assert result.cache_enabled is False
    assert result.cache_ttl == 12.5


@pytest.mark.parametrize("value", ["0", "0.5", "86400"])
def test_cache_ttl_valid(mocker, value):
    mocker.patch("sys.argv", ["peat", "scan", "-i", "192.0.2.1", "--cache-ttl", value])
    assert cli_args.parse_peat_arguments().cache_ttl == float(value)


@pytest.mark.parametrize("value", ["inf", "-inf", "nan", "-5", "-0.1", "five", ""])
def test_cache_ttl_invalid(mocker, capsys, value):
    mocker.patch("sys.argv", ["peat", "scan", "-i", "192.0.2.1", "--cache-ttl", value])
    with pytest.raises(SystemExit) as exc_info:
        cli_args.parse_peat_arguments()
    assert exc_info.value.code == 2
    assert "--cache-ttl" in capsys.readouterr().err
