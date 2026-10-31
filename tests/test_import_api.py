"""
Tests for "peat import" (peat.api.import_api), using synthetic run directories
and an Elastic instance with a mocked client (no server is needed).
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from peat import Elastic, config, state
from peat.api import import_api
from peat.api.import_api import (
    RunImportResult,
    build_device,
    gen_doc_id,
    import_results,
    import_run_to_elastic,
    load_device,
    run_start_time,
)
from peat.data.models import DeviceData, Event, Register
from peat.run_results import RunResults

RUN_ID = "179343190989"  # 1793431909 => 2026-10-31T07:31:49Z
RUN_START = datetime.fromtimestamp(1793431909, UTC)
RUN_NAME = f"pull_default-config_2026-10-31_05-11-49_{RUN_ID}"
DEV_IP = "192.0.2.10"


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")


def make_device() -> DeviceData:
    dev = DeviceData(
        ip=DEV_IP,
        name="relay1",
        type="Relay",
        description={"vendor": {"id": "SEL", "name": "Schweitzer"}, "model": "351"},
    )
    dev.event.append(Event(message="Login", action="login", sequence=1))
    dev.event.append(Event(message="Logout", action="logout", sequence=2))
    dev.registers.append(Register(protocol="modbus_tcp", address="40001", name="breaker"))
    return dev


@pytest.fixture
def isolated(mocker, tmp_path):
    """Isolate the global configuration and state, and disable file output."""
    mocker.patch.dict(
        config["runtime_configs"],
        {
            "ELASTIC_DIR": None,
            "LOG_DIR": None,
            "DEVICE_DIR": None,
            "SUMMARIES_DIR": tmp_path / "import-run" / "summaries",
            "RUN_DIR": tmp_path / "import-run",
            "ELASTIC_SERVER": None,
            "THORIUM_URL": None,
            "DRY_RUN": False,
        },
    )
    mocker.patch.dict(state["runtime_configs"], {"error": False, "elastic": None})


@pytest.fixture
def make_run(tmp_path) -> Callable[..., Path]:
    """Create a synthetic run directory, like the ones PEAT writes."""

    def _make(
        name: str = RUN_NAME,
        parent: Path | None = None,
        full: bool = True,
        logs: int = 3,
    ) -> Path:
        run_dir = (parent or tmp_path / "peat_results") / name
        dev_dir = run_dir / "devices" / DEV_IP
        dev = make_device()
        exported = dev.export(include_original=True)
        if full:
            _write_json(dev_dir / "device-data-full.json", {"created": "x"} | exported)
        _write_json(dev_dir / "device-data-summary.json", dev.export_summary())
        for attr in ["event", "registers"]:
            lines = [json.dumps(r | {"device_id": DEV_IP}) for r in exported[attr]]
            (dev_dir / f"device-data-{attr}.jsonl").write_text("\n".join(lines))
        (dev_dir / "SET_1.TXT").write_text("config")

        _write_json(
            run_dir / "summaries" / "pull-summary.json",
            {"peat_run_id": RUN_ID, "pull_targets": [DEV_IP], "num_pull_results": 1},
        )
        _write_json(run_dir / "summaries" / "other-summary.json", {"something": 1})

        meta = run_dir / "peat_metadata"
        meta.mkdir(parents=True)
        (meta / "peat_configuration.yaml").write_text(
            "debug: 1\nhosts: []\ndevice_options:\n  sel:\n    pass: secret\n"
        )
        (meta / "peat_state.yaml").write_text("error: false\n")

        if logs:
            records = [
                json.dumps({"@timestamp": "2026-10-31T12:11:50.000Z", "message": f"msg {i}"})
                for i in range(logs)
            ]
            records.append('{"truncated": ')  # Crash mid-write
            (run_dir / "logs").mkdir(parents=True)
            (run_dir / "logs" / "json-log.jsonl").write_text("\n".join(records))
        return run_dir

    return _make


class FakeElastic(Elastic):
    """Elastic with a mocked client that records the documents pushed."""

    def __init__(self) -> None:
        super().__init__("http://localhost:9200/")
        self._es = MagicMock()
        self.docs: list[dict] = []  # {"_index", "_id", "_source"}
        self.fail_index: str | None = None

        def _bulk(client, actions):  # noqa: ARG001
            for action in actions:
                ok = not (self.fail_index and action["_index"].startswith(self.fail_index))
                if ok:
                    self.docs.append(action)
                yield ok, {}

        def _index(index, body, id):  # noqa: A002
            self.docs.append({"_index": index, "_id": id, "_source": body})

        self.parallel_bulk = _bulk
        self._es.index.side_effect = _index

    def create_index(self, index: str, fields_limit: int = 20000) -> bool:  # noqa: ARG002
        return True

    def by_index(self, prefix: str) -> list[dict]:
        return [d for d in self.docs if d["_index"].startswith(prefix)]


def test_run_start_time(mocker):
    assert run_start_time(RUN_ID) == RUN_START
    assert run_start_time(int(RUN_ID)) == RUN_START
    for bad in [None, "", "abc", "12345", "1793431909890", "014200000000"]:
        assert run_start_time(bad) is None
    # In the future
    mocker.patch("peat.utils.utc_now", return_value=datetime(2020, 1, 1, tzinfo=UTC))
    assert run_start_time(RUN_ID) is None


def test_gen_doc_id(make_run, tmp_path):
    results = RunResults.open(make_run())
    doc_id = gen_doc_id(results, RUN_ID, "device", DEV_IP)
    assert doc_id.startswith(f"peat~{RUN_ID}~import~")
    assert doc_id == gen_doc_id(results, RUN_ID, "device", DEV_IP)
    assert doc_id != gen_doc_id(results, RUN_ID, "device", "192.0.2.11")

    # Same run in a renamed directory: same IDs
    renamed = RunResults.open(make_run(name="renamed", parent=tmp_path / "other"))
    assert gen_doc_id(renamed, RUN_ID, "device", DEV_IP) == doc_id
    # Unknown run ID: the directory name is used instead
    assert gen_doc_id(renamed, None, "x").startswith("peat~unknown~import~")
    assert gen_doc_id(renamed, None, "x") != gen_doc_id(results, None, "x")


def test_build_device_roundtrip():
    exported = make_device().export(include_original=True)
    dev = build_device({"created": "2026-10-31T00:00:00"} | json.loads(json.dumps(exported)), "x")
    assert dev is not None
    assert dev.export(include_original=True) == exported


def test_build_device_removes_invalid_fields(caplog):
    data = make_device().export(include_original=True)
    data["field_from_the_future"] = {"a": 1}
    data["event"][1]["unknown"] = "x"
    data["description"]["vendor"]["bogus"] = 1
    data["ip"] = "not-an-ip"

    dev = build_device(data, "test-device")
    assert dev is not None
    assert dev.name == "relay1"
    assert not dev.ip
    assert len(dev.event) == 2
    assert dev.description.vendor.id == "SEL"
    assert "field_from_the_future" in caplog.text
    assert "event.1.unknown" in caplog.text


def test_build_device_gives_up(mocker, caplog):
    mocker.patch.object(import_api, "MAX_VALIDATION_ATTEMPTS", 1)
    data = make_device().export()
    data["bogus"] = 1
    assert build_device(data, "test-device") is None
    assert "too many invalid fields" in caplog.text

    mocker.patch.object(import_api, "DeviceData", side_effect=RuntimeError("boom"))
    assert build_device({}, "test-device") is None
    assert "boom" in caplog.text


def _dev_results(run_dir: Path):
    return RunResults.open(run_dir).devices()[0]


def test_load_device_full(make_run):
    res = RunImportResult(run_name="r", run_path="r")
    dev = load_device(_dev_results(make_run()), res)
    assert dev.ip == DEV_IP
    assert len(dev.event) == 2
    assert dev.registers[0].name == "breaker"
    assert not res.errors


def test_load_device_from_summary_and_jsonl(make_run):
    res = RunImportResult(run_name="r", run_path="r")
    dev = load_device(_dev_results(make_run(full=False)), res)
    assert dev.ip == DEV_IP
    assert [e.message for e in dev.event] == ["Login", "Logout"]
    assert dev.registers[0].address == "40001"
    assert not res.errors


def test_load_device_too_large(make_run, mocker, caplog):
    run_dir = make_run()
    dev_dir = run_dir / "devices" / DEV_IP
    full_size = (dev_dir / "device-data-full.json").stat().st_size
    summary_size = (dev_dir / "device-data-summary.json").stat().st_size
    assert full_size > summary_size

    # Full file is too large: falls back to the summary (only a warning)
    mocker.patch.object(import_api, "MAX_JSON_FILE_SIZE", full_size - 1)
    res = RunImportResult(run_name="r", run_path="r")
    dev = load_device(_dev_results(run_dir), res)
    assert dev is not None
    assert len(dev.event) == 2
    assert not res.errors
    assert "too large" in caplog.text

    # Everything is too large
    mocker.patch.object(import_api, "MAX_JSON_FILE_SIZE", 10)
    res = RunImportResult(run_name="r", run_path="r")
    assert load_device(_dev_results(run_dir), res) is None
    assert any("too large" in e for e in res.errors)


def test_load_device_corrupt_full_file(make_run):
    run_dir = make_run()
    (run_dir / "devices" / DEV_IP / "device-data-full.json").write_text("{not json")
    res = RunImportResult(run_name="r", run_path="r")
    dev = load_device(_dev_results(run_dir), res)
    assert dev is not None  # Fell back to the summary
    assert len(dev.event) == 2


def test_load_device_invalid_full_file(make_run, mocker):
    # device-data-full.json that can't be loaded as a device falls back to the summary
    real_build = import_api.build_device

    def _build(data, source):
        return None if "device-data-full.json" in source else real_build(data, source)

    mocker.patch.object(import_api, "build_device", side_effect=_build)
    res = RunImportResult(run_name="r", run_path="r")
    dev = load_device(_dev_results(make_run()), res)
    assert dev is not None
    assert len(dev.event) == 2


def test_import_run_to_elastic(make_run, isolated):  # noqa: ARG001
    es = FakeElastic()
    results = RunResults.open(make_run())
    res = import_run_to_elastic(es, results)

    assert not res.errors, res.errors
    assert res.run_id == RUN_ID
    assert (res.devices_found, res.devices_imported, res.devices_failed) == (1, 1, 0)
    assert res.summaries_imported == 1  # "other-summary" has no index
    assert res.metadata_imported == 2
    assert res.log_records == 3  # The truncated line is skipped

    # Attributed to the original run, and indices dated with the run's date
    for doc in es.docs:
        assert doc["_index"].endswith("-2026.10.31"), doc["_index"]
        assert doc["_source"]["agent"]["id"] == RUN_ID
        assert doc["_id"].startswith(f"peat~{RUN_ID}~import~")

    hosts = es.by_index(config.ELASTIC_HOSTS_INDEX)
    assert len(hosts) == 1
    assert hosts[0]["_source"]["@timestamp"] == "2026-10-31T07:31:49.000Z"
    assert hosts[0]["_source"]["host"]["ip"] == DEV_IP
    assert len(es.by_index(config.ELASTIC_EVENTS_INDEX)) == 2
    assert len(es.by_index(config.ELASTIC_REGISTERS_INDEX)) == 1
    assert len(es.by_index(config.ELASTIC_PULL_INDEX)) == 1
    assert len(es.by_index(config.ELASTIC_LOG_INDEX)) == 3

    # event.ingested is the actual time of the import, @timestamp is the run's time
    ingested = {d["_source"].get("event", {}).get("ingested") for d in es.docs}
    assert "2026-10-31T07:31:49.000Z" not in ingested

    conf_doc = es.by_index(config.ELASTIC_CONFIG_INDEX)[0]["_source"]
    assert conf_doc["DEBUG"] == 1
    assert "DEVICE_OPTIONS" not in conf_doc
    assert "HOSTS" not in conf_doc
    assert len(es.by_index(config.ELASTIC_STATE_INDEX)) == 1

    # Unique IDs, and the attribution is undone afterwards
    assert len({d["_id"] for d in es.docs}) == len(es.docs)
    assert es.base_info["agent"]["id"] != RUN_ID
    assert es.index_date is None
    assert Elastic._time_override is None


def test_import_run_to_elastic_redacts_credentials(make_run, isolated):  # noqa: ARG001
    # Credentials for the original run's servers aren't copied to the import target
    run_dir = make_run()
    meta = run_dir / "peat_metadata"
    (meta / "peat_configuration.yaml").write_text(
        "elastic_server: https://elastic:FieldSecret@field-es:9200/\n"
        "heat_elastic_server: http://heat:HeatPass@heat:9200/\n"
        "thorium_url: https://u:ThorPass@thorium/\n"
    )
    (meta / "peat_state.yaml").write_text(
        'elastic: Elastic("https://elastic:FieldSecret@field-es:9200/")\n'
    )
    es = FakeElastic()
    res = import_run_to_elastic(es, RunResults.open(run_dir))
    assert res.metadata_imported == 2
    conf_doc = es.by_index(config.ELASTIC_CONFIG_INDEX)[0]["_source"]
    state_doc = es.by_index(config.ELASTIC_STATE_INDEX)[0]["_source"]
    pushed = json.dumps([conf_doc, state_doc])
    for secret in ["FieldSecret", "HeatPass", "ThorPass"]:
        assert secret not in pushed
    assert conf_doc["ELASTIC_SERVER"] == "https://REDACTED@field-es:9200/"


def test_import_run_to_elastic_yaml_alias_bomb(make_run, isolated):  # noqa: ARG001
    # A crafted configuration that expands exponentially isn't pushed
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 9):
        refs = ", ".join([f"*a{i - 1}"] * 10)
        lines.append(f"a{i}: &a{i} [{refs}]")
    run_dir = make_run()
    (run_dir / "peat_metadata" / "peat_configuration.yaml").write_text("\n".join(lines))
    es = FakeElastic()
    res = import_run_to_elastic(es, RunResults.open(run_dir))
    assert not es.by_index(config.ELASTIC_CONFIG_INDEX)
    assert len(es.by_index(config.ELASTIC_STATE_INDEX)) == 1
    assert res.devices_imported == 1


def test_import_run_to_elastic_idempotent(make_run, isolated):  # noqa: ARG001
    run_dir = make_run()
    es1, es2 = FakeElastic(), FakeElastic()
    import_run_to_elastic(es1, RunResults.open(run_dir))
    import_run_to_elastic(es2, RunResults.open(run_dir))
    assert sorted(d["_id"] for d in es1.docs) == sorted(d["_id"] for d in es2.docs)


def test_import_run_to_elastic_respects_save_options(make_run, isolated, mocker):  # noqa: ARG001
    mocker.patch.dict(
        config["runtime_configs"],
        {"ELASTIC_SAVE_LOGS": False, "ELASTIC_SAVE_CONFIG": False, "ELASTIC_SAVE_STATE": False},
    )
    es = FakeElastic()
    res = import_run_to_elastic(es, RunResults.open(make_run()))
    assert res.log_records == 0
    assert res.metadata_imported == 0
    assert not es.by_index(config.ELASTIC_LOG_INDEX)
    assert not es.by_index(config.ELASTIC_CONFIG_INDEX)
    assert res.devices_imported == 1


def test_import_run_to_elastic_failures(make_run, isolated):  # noqa: ARG001
    run_dir = make_run()
    (run_dir / "summaries" / "pull-summary.json").write_text("[1, 2]")
    es = FakeElastic()
    es.fail_index = config.ELASTIC_EVENTS_INDEX
    res = import_run_to_elastic(es, RunResults.open(run_dir))
    assert res.devices_failed == 1
    assert res.summaries_imported == 0
    assert len(res.errors) == 2
    assert res.failed


def test_import_results(make_run, isolated, tmp_path):  # noqa: ARG001
    out_dir = tmp_path / "peat_results"
    make_run()
    make_run(name=f"scan_default-config_2026-10-31_05-20-00_{RUN_ID[:-1]}8")
    # Previous imports are detected by their import summary, not their name
    prev = make_run(name="nightly-import")
    _write_json(prev / "summaries" / "import-summary.json", {"num_runs": 1})
    make_run(name="import_line3")  # A run named with --run-name
    (out_dir / "README.md").write_text("readme")

    es = FakeElastic()
    summary = import_results([out_dir], elastic=es)
    assert summary is not None
    assert summary["num_runs"] == 3
    assert "nightly-import" not in {r["run_name"] for r in summary["runs"]}
    assert summary["num_runs_failed"] == 0
    assert [r["devices_imported"] for r in summary["runs"]] == [1, 1, 1]
    assert not state.error

    saved = json.loads((tmp_path / "import-run" / "summaries" / "import-summary.json").read_text())
    assert saved["num_runs"] == 3
    assert saved["import_targets"] == ["Elasticsearch (http://localhost:9200/)"]

    # Network lookups are disabled for imported devices
    assert config.RESOLVE_IP is False


def test_import_results_failures(make_run, isolated):  # noqa: ARG001
    es = FakeElastic()
    es.fail_index = config.ELASTIC_HOSTS_INDEX
    summary = import_results([make_run()], elastic=es)
    assert summary["num_runs_failed"] == 1
    assert summary["runs"][0]["errors"]
    assert state.error


def test_import_results_dry_run(make_run, isolated):  # noqa: ARG001
    es = FakeElastic()
    summary = import_results([make_run()], elastic=es, dry_run=True)
    assert summary["import_dry_run"] is True
    run = summary["runs"][0]
    assert run["devices_found"] == 1
    assert run["summaries_imported"] == 1
    assert run["metadata_imported"] == 2
    assert run["log_records"] == 4  # Counted, not parsed
    assert run["files_found"] == 1
    assert not es.docs


def test_import_results_dry_run_without_targets(make_run, isolated):  # noqa: ARG001
    assert import_results([make_run()], dry_run=True)["num_runs"] == 1


def test_import_results_errors(make_run, isolated, tmp_path, mocker, caplog):  # noqa: ARG001
    run_dir = make_run()

    # No targets configured
    assert import_results([run_dir]) is None
    assert "No import targets configured" in caplog.text

    # No run directories
    assert import_results([tmp_path / "missing"], elastic=FakeElastic()) is None
    empty = tmp_path / "empty"
    empty.mkdir()
    assert import_results([empty], elastic=FakeElastic()) is None

    # The current run directory is never imported
    mocker.patch.dict(config["runtime_configs"], {"RUN_DIR": run_dir})
    assert import_results([run_dir], elastic=FakeElastic()) is None

    # A server is configured, but connecting to it failed
    caplog.clear()
    mocker.patch.dict(config["runtime_configs"], {"ELASTIC_SERVER": str(tmp_path)})
    assert import_results([tmp_path / "peat_results"]) is None
    assert "failed to connect" in caplog.text
    assert 'Put "-e" after the paths' in caplog.text


def test_import_results_invalid_thorium_url(make_run, isolated, mocker):  # noqa: ARG001
    mocker.patch.dict(config["runtime_configs"], {"THORIUM_URL": "ftp://thorium"})
    assert import_results([make_run()], elastic=FakeElastic()) is None


def test_import_results_uses_global_elastic(make_run, isolated, mocker):  # noqa: ARG001
    es = FakeElastic()
    mocker.patch.dict(state["runtime_configs"], {"elastic": es})
    summary = import_results([make_run()])
    assert summary["runs"][0]["devices_imported"] == 1
    assert es.docs


def test_import_results_unknown_run_id(make_run, isolated, caplog):  # noqa: ARG001
    run_dir = make_run(name="my-run")
    (run_dir / "summaries" / "pull-summary.json").write_text("{}")
    es = FakeElastic()
    summary = import_results([run_dir], elastic=es)
    assert summary["runs"][0]["run_id"] is None
    assert "Couldn't determine when run 'my-run' happened" in caplog.text
    assert all(d["_id"].startswith("peat~unknown~import~") for d in es.docs)
