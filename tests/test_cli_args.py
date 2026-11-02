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


def test_baseline_commands_args(mocker):
    mocker.patch(
        "sys.argv",
        ["peat", "baseline-compare", "dir1/", "dir2/", "-b", "b.json", "--fail-on", "high"],
    )
    result = cli_args.parse_peat_arguments()
    assert result.func == "baseline_compare"
    assert result.input_source == ["dir1/", "dir2/"]
    assert result.baseline_files == ["b.json"]
    assert result.fail_on == "high"
    assert not result.known_defaults

    mocker.patch("sys.argv", ["peat", "baseline-create", "--kind", "approved", "x.json"])
    result = cli_args.parse_peat_arguments()
    assert result.func == "baseline_create"
    assert (result.baseline_kind, result.baseline_scope) == ("approved", "device")

    mocker.patch("sys.argv", ["peat", "baseline-show", "--known-defaults"])
    result = cli_args.parse_peat_arguments()
    assert result.func == "baseline_show"
    assert result.known_defaults is True

    for func in ("baseline_create", "baseline_compare", "baseline_show"):
        assert "peat baseline-" in cli_args.ALL_EXAMPLES[func]
