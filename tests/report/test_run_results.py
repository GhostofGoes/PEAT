import json
from pathlib import Path

import pytest

from peat import PeatError, config, state
from peat.run_results import (
    MAX_DATA_DEPTH,
    DeviceResults,
    RunResults,
    find_run_dirs,
    is_run_dir,
    load_json_file,
    load_yaml_file,
)

from .conftest import PULLED_IP, RUN_NAME


def test_is_run_dir(make_run_dir, tmp_path):
    run_dir = make_run_dir()
    assert is_run_dir(run_dir)
    assert not is_run_dir(tmp_path)  # OUT_DIR, contains run dirs
    assert not is_run_dir(run_dir / "devices" / PULLED_IP)
    assert not is_run_dir(run_dir / "logs" / "peat.log")  # a file
    assert not is_run_dir(tmp_path / "missing")

    logs_only = tmp_path / "logs-only"
    (logs_only / "logs").mkdir(parents=True)
    assert not is_run_dir(logs_only)
    (logs_only / "logs" / "json-log.jsonl").write_text("{}\n")
    assert is_run_dir(logs_only)


def test_find_run_dirs(make_run_dir, tmp_path, caplog):
    out_dir = tmp_path / "peat_results"
    run_b = make_run_dir(name="scan_b", parent=out_dir)
    run_a = make_run_dir(name="pull_a", parent=out_dir)
    (out_dir / "README.md").write_text("readme")
    (out_dir / "not-a-run").mkdir()

    # Run dir and OUT_DIR expansion (sorted), de-duplicated
    assert find_run_dirs([run_b]) == [run_b.resolve()]
    assert find_run_dirs([out_dir]) == [run_a.resolve(), run_b.resolve()]
    assert find_run_dirs([run_b, out_dir, str(run_a)]) == [run_b.resolve(), run_a.resolve()]

    # Exclusions (None is ignored)
    assert find_run_dirs([out_dir], exclude=[run_a, None]) == [run_b.resolve()]

    # Bad paths are skipped and logged
    assert find_run_dirs([tmp_path / "missing", out_dir / "README.md"]) == []
    assert "Not a directory" in caplog.text
    assert find_run_dirs([out_dir / "not-a-run"]) == []
    assert "contains no run directories" in caplog.text


def test_open_errors(tmp_path):
    with pytest.raises(PeatError):
        RunResults.open(tmp_path / "missing")
    (tmp_path / "file").write_text("x")
    with pytest.raises(PeatError):
        RunResults.open(tmp_path / "file")


def test_open_empty_dir(tmp_path):
    results = RunResults.open(tmp_path)
    assert results.config_data is None
    assert results.state_data is None
    assert results.load_errors
    assert results.devices() == []
    assert results.summary_files() == {}
    assert results.load_summary("scan-summary") is None
    assert results.json_log_file() is None
    assert list(results.iter_json_logs()) == []
    assert results.elastic_doc_files() == {}
    assert results.run_id is None


def test_open_run_dir(make_run_dir):
    run_dir = make_run_dir()
    results = RunResults.open(run_dir)

    assert results.path == run_dir.resolve()
    assert results.name == RUN_NAME
    assert results.run_id == "179343190989"
    assert results.dirs["devices"] == run_dir.resolve() / "devices"
    assert results.dirs["elastic"] is None
    assert not results.load_errors

    # Keys are upper-case, like config.export()
    assert results.config_data["DEFAULT_TIMEOUT"] == 9.0
    assert results.config_data["METADATA"]["name"] == "site-a"
    assert results.state_data["ERROR"] is False

    assert results.load_summary("pull-summary")["num_pull_results"] == 1
    assert results.load_summary("pull-summary", index=5) is None
    assert results.json_log_file().name == "json-log.jsonl"

    # The truncated log line is skipped
    records = list(results.iter_json_logs())
    assert len(records) == 5
    assert records[-1]["message"] == "Finished run"

    files = {f.relative_to(results.path).as_posix() for f in results.iter_files()}
    assert "logs/peat.log" in files
    assert f"devices/{PULLED_IP}/ftp/config.txt" in files


def test_open_explicit_overrides(make_run_dir, tmp_path):
    run_dir = make_run_dir()
    results = RunResults.open(
        run_dir,
        dirs={"devices": None, "logs": tmp_path / "elsewhere"},
        config_data={"debug": 2},
        state_data={"error": True},
    )
    assert results.devices() == []
    assert results.json_log_file() is None
    assert results.config_data == {"DEBUG": 2}
    assert results.state_data == {"ERROR": True}


def _set_config(run_path: Path, **values: str) -> None:
    conf = run_path / "peat_metadata" / "peat_configuration.yaml"
    lines = [
        line
        for line in conf.read_text(encoding="utf-8").splitlines()
        if line.split(":", 1)[0] not in values
    ]
    lines.extend(f"{key}: {json.dumps(value)}" for key, value in values.items())
    conf.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_open_config_dir_fallback(make_run_dir):
    """Non-default directory locations inside the run directory are found."""
    run_dir = make_run_dir()
    custom = run_dir / "custom-devices"
    (run_dir / "devices").rename(custom)
    _set_config(run_dir, device_dir=custom.as_posix())
    results = RunResults.open(run_dir)
    assert results.dirs["devices"] == custom
    assert [d.dir_name for d in results.devices()] == [PULLED_IP]


@pytest.mark.parametrize(
    ("saved_run_dir", "saved_device_dir"),
    [
        ("/old/peat_results/run", "/old/peat_results/run/custom-devices"),
        ("C:\\peat_results\\run", "C:\\peat_results\\run\\custom-devices"),
    ],
)
def test_open_config_dir_moved_run_dir(make_run_dir, saved_run_dir, saved_device_dir):
    """Configured directories under the saved RUN_DIR are mapped into a moved run dir."""
    run_dir = make_run_dir()
    (run_dir / "devices").rename(run_dir / "custom-devices")
    _set_config(run_dir, run_dir=saved_run_dir, device_dir=saved_device_dir)
    results = RunResults.open(run_dir)
    assert results.dirs["devices"] == run_dir / "custom-devices"
    assert [d.dir_name for d in results.devices()] == [PULLED_IP]


@pytest.mark.parametrize(
    "target",
    [
        "outside",
        "/",
        "/outside",
        # Not absolute on Windows, but outside the run directory:
        # relative to the current drive, or to the current directory of drive C:
        "\\",
        "\\outside",
        "C:outside",
        "C:\\Users",
        # Under the run directory on POSIX, but on Windows, joining the
        # relative part to the run directory replaces the run directory
        "{run_dir}/\\outside",
        "{run_dir}/C:outside",
        "../outside",
    ],
)
def test_open_config_dir_outside_ignored(make_run_dir, tmp_path, target):
    """Directories outside the run directory from the (untrusted) configuration aren't used."""
    run_dir = make_run_dir()
    outside = tmp_path / "outside"
    (run_dir / "devices").rename(outside)
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    target = target.format(run_dir=run_dir.as_posix())
    if target == "outside":
        target = outside.as_posix()
    _set_config(run_dir, run_dir=run_dir.as_posix(), device_dir=target)
    results = RunResults.open(run_dir)
    assert results.dirs["devices"] is None
    assert results.devices() == []
    assert "secret.txt" not in {f.name for f in results.iter_files()}
    if target != "../outside":  # Relative paths are only mapped from the saved RUN_DIR
        assert any("outside the run directory" in e for e in results.load_errors)


@pytest.mark.parametrize(
    ("saved_run_dir", "value", "expected"),
    [
        ("/old/run", "/old/run/devices/x", ("devices", "x")),
        ("C:\\old\\run", "C:\\old\\run\\devices\\x", ("devices", "x")),
        ("C:\\old\\run", "C:/old/run/devices/x", ("devices", "x")),  # as_posix() on Windows
        ("C:\\old\\run", "c:\\OLD\\run\\devices", ("devices",)),  # Windows ignores case
        ("/old/run", "/old/other/x", None),
        ("/old/run", "/old/runx/x", None),
        ("/old/run", "devices/x", None),  # Relative paths aren't mapped
        ("/old/run", "/old/run/\\x", None),  # Joined on Windows: the root of the drive
        ("/old/run", "/old/run/C:x", None),  # Joined on Windows: on drive C:
        ("/old/run", "/old/run/devices/C:\\x", None),
        ("", "/old/run/devices", None),
    ],
)
def test_map_saved_path(make_run_dir, saved_run_dir, value, expected):
    run_dir = make_run_dir()
    results = RunResults.open(run_dir, config_data={"run_dir": saved_run_dir, "debug": 1})
    assert results.map_saved_path(value) == (run_dir.joinpath(*expected) if expected else None)
    # Paths under the current location of the run directory
    assert results.map_saved_path((run_dir / "logs" / "peat.log").as_posix()) == (
        run_dir / "logs" / "peat.log"
    )
    assert results.map_saved_path(str(run_dir / "logs")) == run_dir / "logs"
    assert results.map_saved_path(run_dir.parent.as_posix()) is None


def test_summary_duplicates(make_run_dir):
    run_dir = make_run_dir()
    summaries = run_dir / "summaries"
    (summaries / "scan-summary.json.2").write_text(json.dumps({"n": 2}))
    (summaries / "scan-summary.json.1").write_text(json.dumps({"n": 1}))
    (summaries / "notes.txt").write_text("ignored")
    (summaries / "bad-summary.json").write_text("{not json")

    results = RunResults.open(run_dir)
    files = results.summary_files()
    assert [f.name for f in files["scan-summary"]] == [
        "scan-summary.json",
        "scan-summary.json.1",
        "scan-summary.json.2",
    ]
    assert "notes" not in files
    assert results.load_summary("scan-summary", 2) == {"n": 2}
    assert results.load_summary("bad-summary") is None


def test_yaml_env_tags_not_expanded(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("PEAT_TEST_REPORT_SECRET", "env-secret-value")
    f = tmp_path / "peat_configuration.yaml"
    f.write_text("debug: !ENV PEAT_TEST_REPORT_SECRET\n")
    assert load_yaml_file(f) is None
    assert "env-secret-value" not in caplog.text

    # PEAT's own loader still supports the tag (it's not modified)
    import yaml

    assert yaml.safe_load(f.read_text()) == {"debug": "env-secret-value"}

    # Non-dict YAML results in a load error, not an exception
    meta = tmp_path / "run" / "peat_metadata"
    meta.mkdir(parents=True)
    (meta / "peat_configuration.yaml").write_text("debug: !ENV PEAT_TEST_REPORT_SECRET\n")
    (meta / "peat_state.yaml").write_text("- just\n- a list\n")
    results = RunResults.open(tmp_path / "run")
    assert results.config_data is None
    assert results.state_data is None
    assert any("peat_configuration.yaml" in e for e in results.load_errors)


def test_device_results(make_run_dir):
    run_dir = make_run_dir()
    dev = DeviceResults(path=run_dir / "devices" / PULLED_IP)
    (dev.path / "device-data-users.jsonl").write_text('\n{"name": "a"}\n[1]\nnot json\n\n')

    assert dev.dir_name == PULLED_IP
    assert dev.summary_file.name == "device-data-summary.json"
    assert dev.full_file.name == "device-data-full.json"
    assert sorted(dev.jsonl_files()) == ["event", "files", "users"]
    assert [f.relative_to(dev.path).as_posix() for f in dev.artifact_files()] == [
        "ftp/config.txt",
        "ftp/set_all.txt",
    ]
    assert dev.load_summary()["ip"] == PULLED_IP
    assert dev.load_full()["ip"] == PULLED_IP

    assert dev.count_jsonl("event") == 3
    assert dev.count_jsonl("users") == 3  # non-empty lines, not decoded
    assert dev.count_jsonl("missing") == 0
    assert list(dev.iter_jsonl("users")) == [{"name": "a"}]  # malformed lines skipped
    assert list(dev.iter_jsonl("missing")) == []

    # "original" (raw file contents) is dropped by default
    files = list(dev.iter_jsonl("files"))
    assert "original" not in files[0]
    assert files[0]["hash"]["sha256"]
    assert "original" in next(iter(dev.iter_jsonl("files", drop_keys=())))


def test_device_results_missing_files(tmp_path):
    dev = DeviceResults(path=tmp_path)
    assert dev.summary_file is None
    assert dev.full_file is None
    assert dev.load_summary() is None
    assert dev.load_full() is None
    assert dev.jsonl_files() == {}
    assert dev.artifact_files() == []


def test_symlinks_not_followed(make_run_dir, tmp_path):
    run_dir = make_run_dir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    try:
        (run_dir / "devices" / PULLED_IP / "link-dir").symlink_to(
            outside, target_is_directory=True
        )
        (run_dir / "devices" / PULLED_IP / "link-file").symlink_to(outside / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    results = RunResults.open(run_dir)
    names = {f.name for f in results.iter_files()}
    assert "secret.txt" not in names
    assert "link-file" not in names
    dev = results.devices()[0]
    rel = [f.relative_to(dev.path).as_posix() for f in dev.artifact_files()]
    assert rel == ["ftp/config.txt", "ftp/set_all.txt"]


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")


@pytest.mark.parametrize("subdir", ["devices", "summaries", "logs", "peat_metadata"])
def test_symlinked_subdir_outside_ignored(make_run_dir, tmp_path, subdir):
    """Top-level sub-directories that are symlinks to outside the run dir are ignored."""
    run_dir = make_run_dir()
    outside = tmp_path / "outside"
    (run_dir / subdir).rename(outside)
    _symlink(run_dir / subdir, outside)
    results = RunResults.open(run_dir)
    key = {"peat_metadata": "meta"}.get(subdir, subdir)
    assert results.dirs[key] is None
    assert any(f"Ignored '{subdir}'" in e for e in results.load_errors)
    assert results.devices() == [] if subdir == "devices" else results.devices()
    assert results.summary_files() == {} if subdir == "summaries" else results.summary_files()
    if subdir == "logs":
        assert results.json_log_file() is None
    if subdir == "peat_metadata":
        assert results.config_data is None


def test_symlinked_subdir_inside_allowed(make_run_dir):
    run_dir = make_run_dir()
    (run_dir / "devices").rename(run_dir / "real-devices")
    _symlink(run_dir / "devices", run_dir / "real-devices")
    results = RunResults.open(run_dir)
    assert results.dirs["devices"] == run_dir / "real-devices"
    assert [d.dir_name for d in results.devices()] == [PULLED_IP]


def test_symlinked_data_files_skipped(make_run_dir, tmp_path):
    """Known data files that are symlinks are never read."""
    run_dir = make_run_dir()
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"secret": "outside"}), encoding="utf-8")
    dev_dir = run_dir / "devices" / PULLED_IP
    for f in [
        dev_dir / "device-data-summary.json",
        dev_dir / "device-data-full.json",
        dev_dir / "device-data-event.jsonl",
        run_dir / "logs" / "json-log.jsonl",
        run_dir / "peat_metadata" / "peat_configuration.yaml",
        run_dir / "summaries" / "scan-summary.json",
    ]:
        f.unlink()
        _symlink(f, outside)
    results = RunResults.open(run_dir)
    dev = results.devices()[0]
    assert dev.summary_file is None
    assert dev.full_file is None
    assert dev.load_summary() is None
    assert "event" not in dev.jsonl_files()
    assert results.json_log_file() is None
    assert results.config_data is None
    assert "scan-summary" not in results.summary_files()


def test_find_run_dirs_skips_symlinked_children(make_run_dir, tmp_path):
    results_dir = tmp_path / "peat_results"
    results_dir.mkdir()
    real = make_run_dir(parent=results_dir)
    elsewhere = make_run_dir(name="elsewhere", parent=tmp_path / "other")
    _symlink(results_dir / "linked_run", elsewhere)
    assert find_run_dirs([results_dir]) == [real]
    # An explicit path is the user's choice, so it's followed
    assert find_run_dirs([results_dir / "linked_run"]) == [elsewhere.resolve()]


def test_deeply_nested_data_rejected(tmp_path):
    deep_json = tmp_path / "deep.json"
    deep_json.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    assert load_json_file(deep_json) is None

    nested = tmp_path / "nested.json"  # Decodes, but deeper than the limit
    depth = MAX_DATA_DEPTH + 1
    nested.write_text("[" * depth + "]" * depth, encoding="utf-8")
    assert load_json_file(nested) is None
    ok = tmp_path / "ok.json"
    ok.write_text("[" * MAX_DATA_DEPTH + "]" * MAX_DATA_DEPTH, encoding="utf-8")
    assert load_json_file(ok) is not None

    deep_yaml = tmp_path / "deep.yaml"
    deep_yaml.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    assert load_yaml_file(deep_yaml) is None

    jsonl = tmp_path / "data.jsonl"
    jsonl.write_text(
        "\n".join(
            [
                json.dumps({"ok": 1}),
                '{"a": ' + "[" * 200_000 + "]" * 200_000 + "}",
                '{"a": ' + "[" * depth + "]" * depth + "}",
                json.dumps({"ok": 2}),
            ]
        ),
        encoding="utf-8",
    )
    dev = DeviceResults(path=tmp_path)
    jsonl.rename(tmp_path / "device-data-event.jsonl")
    assert list(dev.iter_jsonl("event")) == [{"ok": 1}, {"ok": 2}]


def test_yaml_alias_bomb_rejected(tmp_path):
    levels = ["a: &a [x, x, x, x, x, x, x, x, x, x]"]
    for prev, cur in zip("abcdefgh", "bcdefghi", strict=True):
        levels.append(f"{cur}: &{cur} [{', '.join(f'*{prev}' for _ in range(10))}]")
    bomb = tmp_path / "bomb.yaml"
    bomb.write_text("\n".join(levels) + "\n", encoding="utf-8")
    assert load_yaml_file(bomb) is None

    recursive = tmp_path / "recursive.yaml"
    recursive.write_text("a: &a [*a]\n", encoding="utf-8")
    assert load_yaml_file(recursive) is None

    # A few aliases (e.g. from yaml.dump() of shared objects) are fine
    shared = tmp_path / "shared.yaml"
    shared.write_text("a: &id001 [1, 2]\nb: *id001\n", encoding="utf-8")
    assert load_yaml_file(shared) == {"a": [1, 2], "b": [1, 2]}


def test_open_bad_config_doesnt_raise(make_run_dir):
    run_dir = make_run_dir()
    conf = run_dir / "peat_metadata" / "peat_configuration.yaml"
    conf.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    results = RunResults.open(run_dir)
    assert results.config_data is None
    assert "Failed to load peat_configuration.yaml" in results.load_errors


def test_elastic_doc_files(make_run_dir):
    run_dir = make_run_dir()
    docs = run_dir / "elastic_data" / "179343190989"
    docs.mkdir(parents=True)
    (docs / "ot-device-hosts.jsonl").write_text('{"a": 1}\n{"a": 2}\n')
    (docs / "mappings.json").write_text("{}")
    results = RunResults.open(run_dir)
    assert list(results.elastic_doc_files()) == ["ot-device-hosts"]


def test_example_results_dir(examples_dir):
    """An existing run directory with an older, different summary schema."""
    path = examples_dir / "encryption" / "example_peat_results"
    run_dirs = find_run_dirs([path])
    assert run_dirs
    for run_dir in run_dirs:
        results = RunResults.open(run_dir)
        results.summary_files()
        results.devices()
        list(results.iter_json_logs())


def test_from_config(mocker, tmp_path):
    run_dir = tmp_path / "run"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": run_dir,
            "DEVICE_DIR": None,
            "SUMMARIES_DIR": run_dir / "summaries",
            "LOG_DIR": run_dir / "logs",
            "META_DIR": run_dir / "peat_metadata",
            "ELASTIC_DIR": "",
            "HEAT_ARTIFACTS_DIR": run_dir / "heat_artifacts",
            "TEMP_DIR": run_dir / "temp",
            "DEBUG": 3,
        },
    )
    results = RunResults.from_config()
    assert results.path == run_dir.resolve()
    assert results.dirs["devices"] is None
    assert results.dirs["elastic"] is None
    assert results.dirs["summaries"] == run_dir / "summaries"
    assert results.config_data["DEBUG"] == 3
    assert "ERROR" in results.state_data
    assert results.state_data["ERROR"] == state.error

    # Explicit config/state objects
    results = RunResults.from_config(config, state)
    assert results.config_data["DEBUG"] == 3


def test_find_run_dirs_relative(make_run_dir, monkeypatch, tmp_path):
    run_dir = make_run_dir()
    monkeypatch.chdir(tmp_path)
    assert find_run_dirs([Path(RUN_NAME)]) == [run_dir.resolve()]
