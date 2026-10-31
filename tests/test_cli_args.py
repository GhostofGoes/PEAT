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


def test_pillage_backend_arg(mocker):
    mocker.patch("sys.argv", ["peat", "pillage", "-P", "disk.E01", "--pillage-backend", "library"])
    result = cli_args.parse_peat_arguments()
    assert result.pillage_backend == "library"
    assert result.pillage_source == "disk.E01"


def test_pillage_backend_default_none(mocker):
    # None, so the PILLAGE_BACKEND value from the config file or environment is used
    mocker.patch("sys.argv", ["peat", "pillage", "-P", "disk.img"])
    assert cli_args.parse_peat_arguments().pillage_backend is None


@pytest.mark.parametrize(
    "argv",
    [
        ["pillage", "--pillage-backend", "bogus"],
        ["scan", "-i", "192.0.2.1", "--pillage-backend", "library"],
        ["parse", "--pillage-backend", "auto"],
    ],
)
def test_pillage_backend_invalid(mocker, argv):
    mocker.patch("sys.argv", ["peat", *argv])
    with pytest.raises(SystemExit) as exit_result:
        cli_args.parse_peat_arguments()
    assert exit_result.value.code == 2
