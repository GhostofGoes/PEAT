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


@pytest.mark.parametrize("subcmd", ["scan", "pull", "push", "parse", "pillage", "heat"])
def test_html_report_args(subcmd):
    parser = cli_args.build_argument_parser()
    required = {"scan": ["-i", "192.0.2.1"], "push": ["-i", "192.0.2.1", "file"]}
    base = [subcmd, *required.get(subcmd, [])]
    assert parser.parse_args(base).html_report is None  # use the configured value
    assert parser.parse_args([*base, "--html-report"]).html_report is True
    assert parser.parse_args([*base, "--no-html-report"]).html_report is False


def test_html_report_arg_not_on_other_commands():
    parser = cli_args.build_argument_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["encrypt-results", "--no-html-report"])
    with pytest.raises(SystemExit):
        parser.parse_args(["report", "--no-html-report"])


def test_report_args():
    parser = cli_args.build_argument_parser()
    result = parser.parse_args(["report", "a", "b", "-w", "out.html"])
    assert result.func == "report"
    assert result.run_dirs == ["a", "b"]
    assert result.report_file == "out.html"

    result = parser.parse_args(["report", "--examples"])
    assert result.run_dirs == []
    assert result.examples is True
    assert result.report_file is None

    assert "report" in cli_args.ALL_EXAMPLES
