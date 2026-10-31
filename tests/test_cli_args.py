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


def test_import_args(mocker):
    mocker.patch(
        "sys.argv",
        [
            "peat",
            "import",
            "./run1",
            "./peat_results/",
            "--thorium-url",
            "https://thorium.example.com",
            "--thorium-groups",
            "ot,lab",
            "--thorium-groups",
            "ics",
            "--no-thorium-verify-tls",
        ],
    )
    result = cli_args.parse_peat_arguments()
    assert result.func == "import"
    assert result.import_paths == ["./run1", "./peat_results/"]
    assert result.thorium_url == "https://thorium.example.com"
    assert result.thorium_groups == ["ot,lab", "ics"]
    assert result.thorium_verify_tls is False
    assert result.elastic_server is None


def test_import_args_thorium_groups_before_paths(mocker):
    # --thorium-groups doesn't consume the paths after it
    mocker.patch(
        "sys.argv",
        ["peat", "import", "--thorium-groups", "ot", "./run1", "./peat_results/"],
    )
    result = cli_args.parse_peat_arguments()
    assert result.import_paths == ["./run1", "./peat_results/"]
    assert result.thorium_groups == ["ot"]


def test_import_args_elastic_after_paths(mocker):
    mocker.patch("sys.argv", ["peat", "import", "./peat_results/", "-e"])
    result = cli_args.parse_peat_arguments()
    assert result.import_paths == ["./peat_results/"]
    assert result.elastic_server == "http://localhost:9200/"
    assert result.thorium_url is None
    assert result.thorium_verify_tls is None


def test_import_args_no_path(mocker):
    mocker.patch("sys.argv", ["peat", "import", "--examples"])
    result = cli_args.parse_peat_arguments()
    assert result.import_paths == []
    assert result.examples is True


def test_import_examples():
    assert "peat import" in cli_args.ALL_EXAMPLES["import"]
