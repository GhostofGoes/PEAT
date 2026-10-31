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


def _parse(mocker, *argv: str) -> argparse.Namespace:
    mocker.patch("sys.argv", ["peat", *argv])
    return cli_args.parse_peat_arguments()


@pytest.mark.parametrize("subcmd", ["scan", "pull"])
def test_device_types_default_none(mocker, subcmd):
    # None means "not specified", so device_types from the config can be used
    assert _parse(mocker, subcmd, "-i", "192.0.2.1").device_types is None
    assert _parse(mocker, subcmd, "-d", "sel", "clx", "-i", "192.0.2.1").device_types == [
        "sel",
        "clx",
    ]


def test_device_types_default_none_push_parse(mocker):
    assert _parse(mocker, "push", "-i", "192.0.2.1", "--", "file.txt").device_types is None
    assert _parse(mocker, "parse", "file.txt").device_types is None


def test_sweep_default_none(mocker):
    # None means "not specified", so scan_sweep from the config can be used
    assert _parse(mocker, "scan", "-i", "192.0.2.1").scan_sweep is None
    assert _parse(mocker, "scan", "--sweep", "-i", "192.0.2.1").scan_sweep is True


@pytest.mark.parametrize("flag", ["-x", "--exclude-modules"])
def test_exclude_modules_arg(mocker, flag):
    result = _parse(mocker, "scan", flag, "clx", flag, "sel=192.0.2.5,192.0.2.6", "-i", "x")
    assert result.excluded_modules == ["clx", "sel=192.0.2.5,192.0.2.6"]
    assert result.host_list == ["x"]

    assert _parse(mocker, "scan", "-i", "x").excluded_modules is None


def test_exclude_modules_arg_doesnt_consume_positionals(mocker):
    result = _parse(mocker, "parse", "-x", "m340", "file.apx")
    assert result.excluded_modules == ["m340"]
    assert result.input_source == ["file.apx"]

    result = _parse(mocker, "push", "-d", "selrelay", "-x", "sel3620", "-i", "x", "--", "f.txt")
    assert result.excluded_modules == ["sel3620"]
    assert result.input_source == "f.txt"

    result = _parse(mocker, "pull", "-x", "selrtac,sel3620", "--skip-scan", "-i", "192.0.2.1")
    assert result.excluded_modules == ["selrtac,sel3620"]
    assert result.pull_skip_scan is True


@pytest.mark.parametrize("subcmd", ["heat", "pillage", "encrypt-config", "decrypt-config"])
def test_exclude_modules_arg_only_on_module_commands(mocker, subcmd):
    with pytest.raises(SystemExit):
        _parse(mocker, subcmd, "-x", "clx")


def test_scan_host_args_optional(mocker):
    # Targets can come from the config file ("targets" or "hosts")
    result = _parse(mocker, "scan", "-c", "cfg.yaml")
    assert result.host_list is None
    assert result.config_file == "cfg.yaml"

    # push always requires targets
    with pytest.raises(SystemExit):
        _parse(mocker, "push", "-d", "selrelay", "-c", "cfg.yaml", "--", "f.txt")
