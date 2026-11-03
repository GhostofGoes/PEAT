"""
Tests of "peat baseline-create", "peat baseline-compare" and "peat baseline-show".

The argument parsing tests run the documented examples through the real parser:
a positional before a nargs="*" positional, or an option that swallows the inputs,
breaks on some Python versions (3.11/3.12) when options precede the inputs.
"""

import contextlib
import io
import json
import shlex
from pathlib import Path

import pytest

from peat import cli_args, config, module_api, state
from peat.api import baseline_api
from peat.api.baseline_api import run_baseline
from peat.data.models import Service
from tests.api.test_baseline_api import _acme_device, _AcmePLC, write_pull
from tests.data.example_devices import sel_relay

BASELINE_COMMANDS = {
    "baseline_create": "baseline-create",
    "baseline_compare": "baseline-compare",
    "baseline_show": "baseline-show",
}


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def _example_lines(func: str) -> list[str]:
    return [
        line.strip()
        for line in cli_args.ALL_EXAMPLES[func].strip().splitlines()
        if line.strip().startswith("peat baseline-")
    ]


@pytest.mark.parametrize("func", list(BASELINE_COMMANDS))
def test_baseline_examples_parse(func):
    parser = cli_args.build_argument_parser("0.0.0")
    lines = _example_lines(func)
    assert lines
    for line in lines:
        argv = shlex.split(line.replace("<run>", "run1"))[1:]
        args, rest = parser.parse_known_args(argv)
        assert not rest, line
        assert args.func == func, line
        if func != "baseline_show":  # every path (and nothing else) is an input
            paths = [a for a in argv if "/" in a and not a.startswith("http")]
            assert args.input_source == paths, line


@pytest.mark.parametrize("command", list(BASELINE_COMMANDS.values()))
@pytest.mark.parametrize("extra", [["--examples"], ["--list-modules"], ["-v", "--examples"]])
def test_baseline_commands_without_inputs(command, extra):
    parser = cli_args.build_argument_parser("0.0.0")
    with contextlib.redirect_stderr(io.StringIO()):
        args = parser.parse_args([command, *extra])
    assert args.examples or args.list_modules
    if command != "baseline-show":
        assert args.input_source == []


def test_baseline_option_values_never_swallow_inputs():
    parser = cli_args.build_argument_parser("0.0.0")
    args = parser.parse_args(
        ["baseline-compare", "-b", "a.json", "-b", "b.json", "dir1/", "dir2/"]
    )
    assert args.baseline_files == ["a.json", "b.json"]
    assert args.input_source == ["dir1/", "dir2/"]

    args = parser.parse_args(["baseline-compare", "-d", "selrelay", "--known-defaults", "dir/"])
    assert args.device_types == ["selrelay"]
    assert args.known_defaults is True
    assert args.input_source == ["dir/"]

    args = parser.parse_args(
        ["baseline-create", "--scope", "device_type", "-w", "x.json", "a/", "b/"]
    )
    assert args.baseline_scope == "device_type"
    assert args.baseline_output == "x.json"
    assert args.baseline_kind == "first_observed"
    assert args.input_source == ["a/", "b/"]

    args = parser.parse_args(["baseline-compare", "-v", "-e", "http://localhost:9200", "dir/"])
    assert args.input_source == ["dir/"]
    assert args.verbose is True
    assert args.elastic_server == "http://localhost:9200"

    args = parser.parse_args(["baseline-compare", "dir/", "--fail-on", "high", "--no-passed"])
    assert (args.fail_on, args.no_passed, args.input_source) == ("high", True, ["dir/"])

    args = parser.parse_args(["baseline-show", "--known-defaults", "-d", "sel", "-d", "sage"])
    assert args.device_types == ["sel", "sage"]

    with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
        parser.parse_args(["baseline-compare", "--fail-on", "severe", "dir/"])
    with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
        parser.parse_args(["baseline-create", "--kind", "golden", "dir/"])


# --------------------------------------------------------------------------- #
# run_baseline() (in-process)
# --------------------------------------------------------------------------- #
@pytest.fixture
def run_dir(tmp_path, mocker) -> Path:
    run = tmp_path / "run"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": run,
            "DEVICE_DIR": run / "devices",
            "SUMMARIES_DIR": run / "summaries",
            "TEMP_DIR": run / "temp",
            "PRINT_RESULTS": False,
            "DRY_RUN": False,
        },
    )
    mocker.patch.dict(state["CONFIG"], {"elastic": None})
    return run


def _args(func: str, **kwargs) -> dict:
    parser = cli_args.build_argument_parser("0.0.0")
    args = vars(parser.parse_args([BASELINE_COMMANDS[func]]))
    args.update(kwargs)
    return args


def _pulls(tmp_path: Path) -> tuple[Path, Path]:
    first = write_pull(tmp_path, sel_relay(), name="pull1")
    changed = sel_relay()
    changed.firmware.version = "R517"
    changed.store("service", Service(protocol="http", port=80))
    second = write_pull(tmp_path, changed, name="pull2")
    return first, second


def test_run_baseline_create_and_compare(tmp_path, run_dir, capsys):
    first, second = _pulls(tmp_path)
    baseline_file = tmp_path / "relay-1.json"

    rc = run_baseline(
        _args("baseline_create", input_source=[str(first)], baseline_output=str(baseline_file))
    )
    assert rc == 0
    baseline = json.loads(baseline_file.read_text())
    assert baseline["kind"] == "first_observed"
    assert baseline["selector"] == {"device_id": "192.0.2.10"}

    # default output location: <run dir>/baselines/baseline-<device id>.json
    rc = run_baseline(
        _args(
            "baseline_create",
            input_source=[str(tmp_path / "pull1")],
            baseline_kind="engineer_provided",
            baseline_id="relay-1-golden",
        )
    )
    assert rc == 0
    golden = json.loads((run_dir / "baselines" / "baseline-192.0.2.10.json").read_text())
    assert (golden["id"], golden["kind"]) == ("relay-1-golden", "engineer_provided")

    capsys.readouterr()
    rc = run_baseline(
        _args("baseline_compare", input_source=[str(second)], baseline_files=[str(baseline_file)])
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "SEVERITY  RESULT   DIFFERENCE  PATH" in out
    assert "firmware.version" in out
    assert "service[protocol=http,port=80]" in out
    assert "192.0.2.10: 2 findings, 2 failed, 0 passed (max severity: high)" in out

    findings = json.loads(
        (run_dir / "devices" / "192.0.2.10" / "baseline-findings.json").read_text()
    )
    assert {f["path"] for f in findings} == {"firmware.version", "service[protocol=http,port=80]"}
    summary = json.loads((run_dir / "summaries" / "baseline-summary.json").read_text())
    assert summary["devices"][0]["summary"]["max_severity"] == "high"
    assert summary["devices"][0]["source"] == second.resolve().as_posix()
    assert summary["threshold_reached"] is False

    # --fail-on: exit code 3 when the threshold is reached
    args = _args(
        "baseline_compare", input_source=[str(second)], baseline_files=[str(baseline_file)]
    )
    assert run_baseline(args | {"fail_on": "high"}) == 3
    assert run_baseline(args | {"fail_on": "critical"}) == 0
    # the unchanged device has no findings
    args["input_source"] = [str(first)]
    assert run_baseline(args | {"fail_on": "info"}) == 0


@pytest.mark.usefixtures("run_dir")
def test_run_baseline_compare_json_output(tmp_path, mocker, capsys):
    first, _ = _pulls(tmp_path)
    baseline_file = tmp_path / "b.json"
    run_baseline(
        _args("baseline_create", input_source=[str(first)], baseline_output=str(baseline_file))
    )
    mocker.patch.dict(config["CONFIG"], {"PRINT_RESULTS": True})
    capsys.readouterr()
    rc = run_baseline(
        _args(
            "baseline_compare",
            input_source=[str(tmp_path / "pull2")],
            baseline_files=[str(baseline_file)],
        )
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    (device,) = data["devices"]
    assert device["device_id"] == "192.0.2.10"
    assert device["summary"]["total"] == 2
    assert {f["difference"] for f in device["findings"]} == {"change", "unexpected"}


def test_run_baseline_known_defaults(tmp_path, run_dir, mocker, capsys):
    mocker.patch.dict(module_api.modules, {"_acmeplc": _AcmePLC})
    plc = write_pull(tmp_path, _acme_device(), name="plc")

    capsys.readouterr()
    args = _args("baseline_compare", input_source=[str(plc)], known_defaults=True)
    assert run_baseline(args) == 0
    out = capsys.readouterr().out
    assert "medium    fail     mismatch    service[protocol=telnet]" in out
    assert "Telnet is exposed" in out
    assert "3 findings, 1 failed, 2 passed (max severity: medium)" in out
    assert run_baseline(args | {"fail_on": "medium"}) == 3

    # --no-passed and -d
    assert run_baseline(args | {"no_passed": True, "device_types": ["_AcmePLC"]}) == 0
    findings = json.loads(
        (run_dir / "devices" / "192.0.2.30" / "baseline-findings.json").read_text()
    )
    assert [f["rule_id"] for f in findings] == ["acme.telnet.absent"]

    # no baseline applies to the device
    assert run_baseline(args | {"device_types": ["SELRelay"]}) == 1

    # baseline-show
    capsys.readouterr()
    show = _args("baseline_show", known_defaults=True, device_types=["_AcmePLC"])
    assert run_baseline(show) == 0
    shown = json.loads(capsys.readouterr().out)
    assert [b["id"] for b in shown] == [
        "acme-plc-vendor-recommended",
        "acme-plc-factory-defaults",
    ]
    assert shown[0]["selector"] == {"vendor_id": "ACME", "device_type": "PLC"}


@pytest.mark.usefixtures("run_dir")
def test_run_baseline_device_type(tmp_path, capsys):
    inputs = []
    for n in range(3):
        dev = sel_relay()
        dev.ip = f"192.0.2.{20 + n}"
        dev.name = f"BAY {n}"
        for iface in dev.interface:
            if iface.ip:
                iface.ip = dev.ip
        inputs.append(str(write_pull(tmp_path, dev, name=f"unit{n}").parent.parent.parent))
    profile = tmp_path / "typical.json"
    args = _args(
        "baseline_create",
        input_source=inputs,
        baseline_scope="device_type",
        baseline_name="Typical SEL-351S",
        baseline_output=str(profile),
    )
    assert run_baseline(args) == 0
    data = json.loads(profile.read_text())
    assert (data["id"], data["name"]) == ("SEL-351S-typical", "Typical SEL-351S")

    capsys.readouterr()
    compare = _args("baseline_compare", input_source=inputs, baseline_files=[str(profile)])
    assert run_baseline(compare | {"fail_on": "info"}) == 0
    out = capsys.readouterr().out
    for n in range(3):
        assert f"192.0.2.{20 + n}: 0 findings" in out

    # one baseline per device (scope "device") -> a list with -w
    several = tmp_path / "several.json"
    assert (
        run_baseline(_args("baseline_create", input_source=inputs, baseline_output=str(several)))
        == 0
    )
    assert len(json.loads(several.read_text())) == 3
    # --baseline-id needs one device
    args = _args("baseline_create", input_source=inputs, baseline_id="x")
    assert run_baseline(args) == 1


def test_run_baseline_errors(tmp_path, run_dir, mocker, caplog):
    first, _ = _pulls(tmp_path)
    assert run_baseline(_args("baseline_create")) == 1
    assert "No input given" in caplog.text
    assert run_baseline(_args("baseline_create", input_source=[str(tmp_path / "nope")])) == 1
    assert run_baseline(_args("baseline_compare", input_source=[str(first)])) == 1
    assert "-b/--baseline" in caplog.text
    assert run_baseline(_args("baseline_compare", baseline_files=["x.json"])) == 1
    args = _args(
        "baseline_compare", input_source=[str(first)], baseline_files=[str(tmp_path / "no.json")]
    )
    assert run_baseline(args) == 1
    assert "Failed to read baseline file" in caplog.text
    assert run_baseline(_args("baseline_show")) == 1
    assert run_baseline({"func": "baseline_nope"}) == 1
    # scope device_type with devices of different types
    plc = write_pull(tmp_path, _acme_device(), name="plc")
    args = _args(
        "baseline_create", input_source=[str(first), str(plc)], baseline_scope="device_type"
    )
    assert run_baseline(args) == 1
    assert "ONE vendor and model" in caplog.text

    mocker.patch.dict(config["CONFIG"], {"DRY_RUN": True})
    assert run_baseline(_args("baseline_create", input_source=[str(first)])) == 0
    assert not (run_dir / "baselines").exists()


def test_run_baseline_create_unwritable_output(tmp_path, run_dir, caplog):
    # A baseline file that can't be written is an error (exit code 1), not a traceback
    first, _ = _pulls(tmp_path)
    out_dir = tmp_path / "out-dir"
    out_dir.mkdir()
    args = _args("baseline_create", input_source=[str(first)], baseline_output=str(out_dir))
    assert run_baseline(args) == 1
    assert "Failed to write baseline file" in caplog.text

    caplog.clear()
    not_a_dir = tmp_path / "not-a-dir.txt"
    not_a_dir.write_text("x", encoding="utf-8")
    args["baseline_output"] = str(not_a_dir / "baseline.json")
    assert run_baseline(args) == 1
    assert "Failed to write baseline file" in caplog.text

    # the default output directory "<run dir>/baselines" is a file
    caplog.clear()
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "baselines").write_text("x", encoding="utf-8")
    assert run_baseline(_args("baseline_create", input_source=[str(first)])) == 1
    assert "Failed to write baseline file" in caplog.text


def test_run_baseline_duplicate_inputs(tmp_path, run_dir, caplog):
    # The same device in two inputs: baseline-create creates one baseline from each
    # (its files are not overwritten), baseline-compare overwrites its results
    dev = sel_relay()
    first = write_pull(tmp_path, dev, name="copy1")
    copy = tmp_path / "copy2" / "devices" / dev.ip / "device-data-full.json"
    copy.parent.mkdir(parents=True)
    copy.write_bytes(first.read_bytes())
    inputs = [str(first.parent.parent.parent), str(copy.parent.parent.parent)]

    assert run_baseline(_args("baseline_create", input_source=inputs)) == 0
    assert "is in 2 inputs: one baseline is created from each" in caplog.text
    assert "the last one wins" not in caplog.text
    saved = sorted(p.name for p in (run_dir / "baselines").iterdir())
    assert saved == [f"baseline-{dev.ip}-2.json", f"baseline-{dev.ip}.json"]
    # same device and observation time -> same default ID
    assert "2 baselines have the ID" in caplog.text

    caplog.clear()
    profile = tmp_path / "profile.json"
    args = _args(
        "baseline_create",
        input_source=inputs,
        baseline_scope="device_type",
        baseline_output=str(profile),
    )
    assert run_baseline(args) == 0
    assert "is in 2 inputs: each one is part of the profile" in caplog.text
    assert "the last one wins" not in caplog.text

    caplog.clear()
    args = _args("baseline_compare", input_source=inputs, baseline_files=[str(profile)])
    assert run_baseline(args) == 0
    assert "is in 2 inputs: its results are written to the same files" in caplog.text


@pytest.mark.usefixtures("run_dir")
def test_export_findings_is_used(tmp_path, mocker):
    first, second = _pulls(tmp_path)
    baseline_file = tmp_path / "b.json"
    run_baseline(
        _args("baseline_create", input_source=[str(first)], baseline_output=str(baseline_file))
    )
    export = mocker.patch.object(baseline_api, "export_findings", return_value=False)
    args = _args(
        "baseline_compare", input_source=[str(second)], baseline_files=[str(baseline_file)]
    )
    assert run_baseline(args) == 1  # Elasticsearch export failed
    assert export.call_count == 1


# --------------------------------------------------------------------------- #
# End-to-end (real command line, exit codes)
# --------------------------------------------------------------------------- #
def test_baseline_cli_exit_codes(tmp_path, exec_peat):
    first, second = _pulls(tmp_path)
    baseline_file = tmp_path / "relay-1.json"
    common = ["--no-logo", "--no-color", "-q", "-o", str(tmp_path / "peat_results")]

    result = exec_peat(
        ["baseline-create", *common, "-w", str(baseline_file), str(tmp_path / "pull1")]
    )
    assert result.returncode == 0, result.stderr
    assert baseline_file.is_file()

    compare = ["baseline-compare", *common, "-b", str(baseline_file)]
    result = exec_peat([*compare, "--fail-on", "medium", str(second)])
    assert result.returncode == 3, result.stderr
    assert b"firmware.version" in result.stdout

    result = exec_peat([*compare, "--fail-on", "medium", str(first)])
    assert result.returncode == 0, result.stderr

    result = exec_peat([*compare, str(tmp_path / "does-not-exist")])
    assert result.returncode == 1

    # an unreadable device file inside a directory input is an error, even if
    # other devices were loaded
    bad = tmp_path / "pull1" / "devices" / "192.0.2.99" / "device-data-full.json"
    bad.parent.mkdir(parents=True)
    bad.write_text('{"ip": "192.0.2.99", "name": ')
    result = exec_peat([*compare, "--fail-on", "info", str(tmp_path / "pull1")])
    assert result.returncode == 1, result.stderr
