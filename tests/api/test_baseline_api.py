import io
import json
from datetime import UTC
from pathlib import Path

import pytest

from peat import (
    DeviceData,
    DeviceModule,
    PeatError,
    SELRelay,
    config,
    consts,
    module_api,
    state,
)
from peat.api import baseline_api as api
from peat.data.baseline import device_to_doc
from peat.data.models import (
    Baseline,
    BaselineFinding,
    BaselineRule,
    BaselineSelector,
    Service,
)
from tests.data.example_devices import sel_relay


class _AcmePLC(DeviceModule):
    """Dummy module with known defaults (no module declares them in core PEAT yet)."""

    vendor_id = "ACME"
    vendor_name = "ACME Corp"
    device_type = "PLC"
    known_defaults = [
        Baseline(
            id="acme-plc-vendor-recommended",
            name="ACME PLC hardening",
            kind="vendor_recommended",
            rules=[
                BaselineRule(
                    id="acme.telnet.absent",
                    path="service[protocol=telnet]",
                    operator="absent",
                    severity="medium",
                    reason="Telnet is exposed",
                ),
                BaselineRule(
                    id="acme.firmware.supported",
                    path="firmware.version",
                    operator="regex",
                    value=r"^2\.",
                    severity="high",
                ),
            ],
        ),
        Baseline(
            id="acme-plc-factory-defaults",
            kind="factory_default",
            rules=[
                BaselineRule(
                    id="acme.default.name",
                    path="name",
                    operator="equals",
                    value="PLC-1",
                    severity="info",
                )
            ],
        ),
    ]


def _acme_device(**kwargs) -> DeviceData:
    dev = DeviceData(ip="192.0.2.30", name="PLC-1", type="PLC", **kwargs)
    dev.description.vendor.id = "ACME"
    dev.firmware.version = "2.1"
    dev.store("service", Service(protocol="telnet", port=23, status="open"))
    return dev


@pytest.fixture
def acme_module(mocker):
    mocker.patch.dict(module_api.modules, {"_acmeplc": _AcmePLC})
    return _AcmePLC


@pytest.fixture
def run_dirs(tmp_path, mocker) -> Path:
    run_dir = tmp_path / "run"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": run_dir,
            "DEVICE_DIR": run_dir / "devices",
            "SUMMARIES_DIR": run_dir / "summaries",
            "TEMP_DIR": run_dir / "temp",
        },
    )
    mocker.patch.dict(state["CONFIG"], {"elastic": None})
    return run_dir


def write_pull(base: Path, dev: DeviceData, name: str = "pull") -> Path:
    """Write device-data-full.json like a PEAT pull and return its path."""
    dev._out_dir = base / name / "devices" / dev.ip
    assert dev.export_to_files(overwrite_existing=True)
    return dev._out_dir / "device-data-full.json"


# --------------------------------------------------------------------------- #
# Loading device data
# --------------------------------------------------------------------------- #
def test_load_device_data_from_files(tmp_path):
    full = write_pull(tmp_path, sel_relay())

    (dev,) = api.load_device_data(full)
    assert dev.ip == "192.0.2.10"
    assert dev.firmware.version == "R516"
    assert dev._cache["observed"].tzinfo is UTC
    assert dev._cache["source_file"] == full.resolve().as_posix()

    (summary,) = api.load_device_data(full.with_name("device-data-summary.json"))
    assert summary.ip == "192.0.2.10"
    assert not summary.files  # not in the summary

    # directories: device-data-full.json files only (not the summaries as well)
    write_pull(tmp_path, sel_relay(), name="pull2")
    devices = api.load_device_data(tmp_path)
    assert len(devices) == 2
    assert {d._cache["source_file"].split("/")[-4] for d in devices} == {"pull", "pull2"}
    assert api.load_device_data(str(tmp_path / "pull")) != []


def test_load_device_data_formats(mocker):
    exported = sel_relay().export()
    host_doc = consts.convert(sel_relay().elastic())
    host_doc["tags"] = ["protection"]
    host_doc["indicator_states"] = {"ENABLED": "on"}
    parse_summary = {
        "peat_version": "0.0.0",
        "parse_results": [{"name": "SET_ALL.TXT", "module": "SELRelay", "results": host_doc}],
    }
    (dev,) = api.load_device_data(parse_summary)
    assert dev.ip == "192.0.2.10"
    assert dev._module is SELRelay
    assert "observed" not in dev._cache

    devices = api.load_device_data([exported, exported])
    assert [d.ip for d in devices] == ["192.0.2.10", "192.0.2.10"]
    assert api.load_device_data(parse_summary["parse_results"])[0]._module is SELRelay

    mocker.patch(
        "sys.stdin", io.StringIO(json.dumps({"created": "2026-10-30T12:00:00"} | exported))
    )
    (dev,) = api.load_device_data("-")
    assert dev._cache["observed"].tzinfo is UTC
    assert dev._cache["source_file"] == "stdin"


def test_load_device_data_errors(tmp_path, caplog):
    assert api.load_device_data(tmp_path / "nope.json") == []
    assert "does not exist" in caplog.text

    assert api.load_device_data(tmp_path) == []  # empty directory
    assert "No device data" in caplog.text

    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert api.load_device_data(bad) == []

    assert api.load_device_data({"not_a_field": 1}) == []
    assert "Invalid device data" in caplog.text
    assert api.load_device_data([1, 2]) == []
    assert api.load_device_data({"parse_results": []}) == []


def test_load_device_data_reports_partial_failures(tmp_path):
    write_pull(tmp_path, sel_relay(), name="a")
    bad = tmp_path / "b" / "devices" / "192.0.2.11" / "device-data-full.json"
    bad.parent.mkdir(parents=True)
    bad.write_text('{"ip": "192.0.2.11", "name": ')  # truncated
    errors = []
    devices = api.load_device_data(tmp_path, errors)
    assert [d.ip for d in devices] == ["192.0.2.10"]
    assert errors == [bad.as_posix()]

    errors = []
    devices = api.load_device_data([sel_relay().export(), {"ip": "not an ip"}], errors)
    assert len(devices) == 1
    assert errors == ["input: [1]"]

    errors = []
    parse_summary = {
        "parse_results": [
            {"module": "SELRelay", "results": consts.convert(sel_relay().elastic())},
            {"module": "SELRelay", "results": {"ip": "not an ip"}},
        ]
    }
    assert len(api.load_device_data(parse_summary, errors)) == 1
    assert errors == ["input: parse_results[1]"]

    # without the errors argument, the loaded devices are still returned
    assert len(api.load_device_data(tmp_path)) == 1


def test_lossy_inputs_are_not_compared_as_complete(tmp_path, caplog):
    full = write_pull(tmp_path, sel_relay())
    (full_dev,) = api.load_device_data(full)
    assert "omitted_keys" not in full_dev._cache
    assert full_dev.files
    assert full_dev.relationships
    baseline = api.create_baseline(full_dev, "previous_observed")

    (summary,) = api.load_device_data(full.with_name("device-data-summary.json"))
    assert {"files", "relationships"} <= set(summary._cache["omitted_keys"])
    assert api.compare_to_baseline(summary, baseline, store=False) == []

    parse_summary = {
        "parse_results": [{"module": "SELRelay", "results": consts.convert(sel_relay().elastic())}]
    }
    (parsed,) = api.load_device_data(parse_summary)
    assert parsed._cache["omitted_keys"] == ("relationships", "baseline_findings")
    assert api.compare_to_baseline(parsed, baseline, store=False) == []

    # a baseline created from a summary ignores what the summary does not have
    from_summary = api.create_baseline(summary, "previous_observed")
    assert {"files", "relationships"} <= set(from_summary.ignore)
    assert "summary without" in caplog.text
    assert api.compare_to_baseline(full_dev, from_summary, store=False) == []


# --------------------------------------------------------------------------- #
# Creating, saving and loading baselines
# --------------------------------------------------------------------------- #
def test_create_save_load_compare(tmp_path):
    dev = sel_relay()
    dev.files[0].original = b"raw settings"
    full = write_pull(tmp_path, dev)
    (loaded,) = api.load_device_data(full)

    baseline = api.create_baseline(loaded, author="J. Engineer", description="first pull")
    observed = loaded._cache["observed"]
    assert baseline.id == f"192.0.2.10@{observed:%Y%m%dT%H%M%SZ}"
    assert baseline.name == "192.0.2.10 first_observed"
    assert (baseline.kind, baseline.scope, baseline.version) == ("first_observed", "device", "1")
    assert baseline.selector == BaselineSelector(device_id="192.0.2.10")
    prov = baseline.provenance
    assert prov.author == "J. Engineer"
    assert prov.observed == observed
    assert prov.created.tzinfo is not None
    assert prov.device_id == "192.0.2.10"
    assert prov.source_file == full.resolve().as_posix()
    assert len(prov.source_hash) == 64
    assert prov.run_id == str(consts.RUN_ID)
    assert prov.peat_version
    # NOTE: never call populate_fields() (e.g. export()) on a snapshot, it would change it
    expected = device_to_doc(baseline.expected)
    assert expected["firmware"]["version"] == "R516"
    for key in ("event", "memory", "baseline_findings"):
        assert key not in expected
    assert "original" not in baseline.json(exclude_defaults=True)

    # save + load (exclude defaults)
    path = api.save_baselines(baseline, tmp_path / "out" / "baseline.json")
    assert path.is_file()
    assert isinstance(json.loads(path.read_text()), dict)
    (reloaded,) = api.load_baselines(path)
    assert reloaded == baseline

    # the source device matches its own baseline exactly
    assert api.compare_to_baseline(loaded, reloaded) == []
    assert api.compare_to_baseline(api.load_device_data(full)[0], reloaded) == []

    # a changed device
    cur = sel_relay()
    cur.firmware.version = "R517"
    cur.store("service", Service(protocol="http", port=80))
    (current,) = api.load_device_data(write_pull(tmp_path, cur, name="pull2"))
    findings = api.compare_to_baseline(current, [reloaded])
    assert {(f.difference, f.path) for f in findings} == {
        ("change", "firmware.version"),
        ("unexpected", "service[protocol=http,port=80]"),
    }
    assert current.baseline_findings == findings
    assert all(f.baseline_id == baseline.id for f in findings)

    # several baselines -> a JSON list
    path = api.save_baselines([baseline, reloaded], tmp_path / "two.json")
    assert len(json.loads(path.read_text())) == 2
    assert len(api.load_baselines(path)) == 2


def test_create_baseline_errors():
    dev = sel_relay()
    with pytest.raises(PeatError, match="exactly one device"):
        api.create_baseline([dev, sel_relay()])
    with pytest.raises(PeatError, match="No device data"):
        api.create_baseline([])
    other = _acme_device()
    with pytest.raises(PeatError, match="ONE vendor and model"):
        api.create_baseline([dev, other], scope="device_type")
    with pytest.raises(PeatError, match="no vendor ID or model"):
        api.create_baseline(DeviceData(ip="192.0.2.1"), scope="device_type")
    with pytest.raises(PeatError, match="Invalid baseline values"):
        api.create_baseline(dev, kind="best_guess")
    with pytest.raises(PeatError, match="Invalid baseline scope"):
        api.create_baseline(dev, scope="site")


def test_create_baseline_without_id(caplog):
    dev = DeviceData(serial_number="12345")
    baseline = api.create_baseline(dev, baseline_id="b")
    assert baseline.selector == BaselineSelector(serial_number="12345")
    baseline = api.create_baseline(DeviceData(type="PLC"), baseline_id="c")
    assert baseline.selector.is_default_selector()
    assert "applies to ALL devices" in caplog.text


def _unit(n: int, firmware: str = "R516") -> DeviceData:
    dev = sel_relay()
    dev.ip = f"192.0.2.{20 + n}"
    dev.name = f"BAY {n}"
    dev.serial_number = f"SN{n}"
    for iface in dev.interface:
        if iface.ip:
            iface.ip = dev.ip
    dev.firmware.version = firmware
    dev.export()
    return dev


def test_create_device_type_baseline():
    units = [_unit(0), _unit(1), _unit(2, firmware="R517")]
    baseline = api.create_baseline(
        units, scope="device_type", kind="engineer_provided", ignore=["indicators"]
    )
    assert baseline.id == "SEL-351S-typical"
    assert baseline.name == "Typical SEL 351S"
    assert baseline.scope == "device_type"
    assert baseline.selector == BaselineSelector(vendor_id="SEL", model="351S")
    assert baseline.ignore == ["indicators", "firmware.version"]
    assert baseline.provenance.extra["device_ids"] == ["192.0.2.20", "192.0.2.21", "192.0.2.22"]
    doc = device_to_doc(baseline.expected)
    assert "ip" not in doc
    assert "firmware" not in doc  # the firmware versions differ

    # every unit (and a new unit of the type) matches the profile
    for unit in [*units, _unit(7, firmware="R518")]:
        assert api.compare_to_baseline(unit, baseline, store=False) == []
    # a different device type is not compared
    assert api.compare_to_baseline(_acme_device(), baseline) == []
    # a deviating unit
    odd = _unit(8)
    odd.store("service", Service(protocol="http", port=80))
    findings = api.compare_to_baseline(odd, baseline)
    assert [(f.difference, f.path) for f in findings] == [
        ("unexpected", "service[protocol=http,port=80]")
    ]

    single = api.create_baseline(units[0], scope="device_type", baseline_id="one")
    assert single.provenance.device_id == "192.0.2.20"
    assert single.ignore == []


def test_load_baselines_errors(tmp_path, caplog):
    with pytest.raises(PeatError, match="Failed to read"):
        api.load_baselines(tmp_path / "nope.json")
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([{"kind": "nope"}]))
    with pytest.raises(PeatError, match="Invalid baseline #1"):
        api.load_baselines(path)
    path.write_text(json.dumps({"rules": [{"path": "service[protocol=ftp"}]}))
    with pytest.raises(PeatError, match="Invalid path"):
        api.load_baselines(path)
    path.write_text(json.dumps([1]))
    with pytest.raises(PeatError, match="expected JSON object"):
        api.load_baselines(path)

    path = tmp_path / "golden.json"
    path.write_text(json.dumps({"rules": [{"path": "name", "operator": "present"}]}))
    (baseline,) = api.load_baselines(path)
    assert baseline.id == "golden"
    assert "has no 'id'" in caplog.text


# --------------------------------------------------------------------------- #
# Known defaults and comparisons
# --------------------------------------------------------------------------- #
def test_get_known_defaults(acme_module):
    dev = _acme_device()
    expected_ids = ["acme-plc-vendor-recommended", "acme-plc-factory-defaults"]
    # by vendor ID (device loaded from a file: module unknown)
    assert [b.id for b in api.get_known_defaults(dev)] == expected_ids
    # by module
    dev._module = acme_module
    assert [b.id for b in api.get_known_defaults(dev)] == expected_ids
    # explicit modules, by name or class
    assert [b.id for b in api.get_known_defaults(modules=["_AcmePLC"])] == expected_ids
    assert [b.id for b in api.get_known_defaults(modules=[acme_module])] == expected_ids
    assert api.get_known_defaults(modules=["nope-not-a-module"]) == []
    # all modules, selectors filter
    assert "acme-plc-vendor-recommended" in [b.id for b in api.get_known_defaults()]
    other = sel_relay()
    assert "acme-plc-vendor-recommended" not in [b.id for b in api.get_known_defaults(other)]
    # module defaults: selector and author
    (baseline, _) = api.get_known_defaults(dev)
    assert baseline.selector == BaselineSelector(vendor_id="ACME", device_type="PLC")
    assert baseline.provenance.author == "_AcmePLC"


@pytest.mark.usefixtures("acme_module")
def test_compare_to_known_defaults():
    dev = _acme_device()
    findings = api.compare_to_known_defaults(dev)
    results = {f.rule_id: f.result for f in findings}
    assert results == {
        "acme.telnet.absent": "fail",
        "acme.firmware.supported": "pass",
        "acme.default.name": "pass",
    }
    assert dev.baseline_findings == findings
    # an SEL relay only gets the SEL known defaults, never the ACME rules
    sel_findings = api.compare_to_known_defaults(sel_relay())
    assert not any(f.rule_id.startswith("acme.") for f in sel_findings)

    # re-compare: findings of the same baselines are replaced, never duplicated
    dev.service = []
    dev.firmware.version = "3.0"
    again = api.compare_to_known_defaults(dev, include_passed=False)
    assert {f.rule_id: f.result for f in again} == {"acme.firmware.supported": "fail"}
    assert dev.baseline_findings == again

    # a baseline without findings this time still replaces its old findings
    dev.firmware.version = "2.2"
    assert api.compare_to_known_defaults(dev, include_passed=False) == []
    assert dev.baseline_findings == []

    # store=False
    dev.name = "PLC-7"
    assert api.compare_to_known_defaults(dev, store=False)
    assert dev.baseline_findings == []


def test_summarize_findings():
    findings = [
        BaselineFinding(baseline_id="a", result="fail", severity="low", category="identity"),
        BaselineFinding(baseline_id="a", result="fail", severity="high", category="accounts"),
        BaselineFinding(baseline_id="b", result="fail", severity="high", category="accounts"),
        BaselineFinding(baseline_id="b", result="pass", category="accounts"),
        BaselineFinding(baseline_id="b", result="unknown"),
    ]
    assert api.summarize_findings(findings) == {
        "total": 5,
        "by_result": {"fail": 3, "pass": 1, "unknown": 1},
        "by_severity": {"high": 2, "low": 1},
        "by_category": {"accounts": 2, "identity": 1},
        "baselines": ["a", "b"],
        "max_severity": "high",
    }
    assert api.summarize_findings([])["max_severity"] == ""


@pytest.mark.usefixtures("acme_module")
def test_export_findings(run_dirs, mocker):
    dev = _acme_device()
    findings = api.compare_to_known_defaults(dev)
    assert api.export_findings(dev, findings)
    path = run_dirs / "devices" / "192.0.2.30" / "baseline-findings.json"
    data = json.loads(path.read_text())
    assert len(data) == len(findings)
    assert data[0]["baseline_id"] == findings[0].baseline_id

    # Elasticsearch export
    export = mocker.patch.object(api, "export_models_to_elastic", return_value=True)
    mocker.patch.dict(state["CONFIG"], {"elastic": mocker.MagicMock()})
    assert api.export_findings(dev, findings)
    assert export.call_args.args[0] == findings
    assert export.call_args.args[1] is dev
    export.return_value = False
    assert not api.export_findings(dev, findings)


@pytest.mark.usefixtures("acme_module", "run_dirs")
def test_export_findings_to_elastic_index(mocker):
    """Findings go through export_models_to_elastic() to the baseline findings index."""
    elastic = mocker.MagicMock()
    elastic.type = "Elasticsearch"
    elastic.gen_id.side_effect = [f"doc{i}" for i in range(10)]
    elastic.bulk_push.return_value = True
    mocker.patch.dict(state["CONFIG"], {"elastic": elastic})
    mocker.patch.dict(config["CONFIG"], {"ELASTIC_BASELINE_FINDINGS_INDEX": "findings-test"})

    dev = _acme_device()
    findings = api.compare_to_known_defaults(dev)
    assert api.export_findings(dev, findings)

    push = elastic.bulk_push.call_args.kwargs
    assert push["index"] == "findings-test"
    docs = [content for _, content in push["contents"]]
    assert len(docs) == len(findings) == 3
    for doc in docs:
        assert doc["event"]["dataset"] == "peat.baseline"
        assert doc["host"]["ip"] == "192.0.2.30"
        assert doc["baseline"]["id"].startswith("acme-plc-")
    failed = [d for d in docs if d["baseline"]["finding"]["result"] == "fail"]
    assert {d["rule"]["id"] for d in failed} == {"acme.telnet.absent"}
    assert failed[0]["event"]["severity"] == 3  # medium
    assert failed[0]["event"]["action"] == "baseline-deviation"

    # Host documents are not pushed again
    assert elastic.push.call_count == 0
    elastic.bulk_push.return_value = False
    assert not api.export_findings(dev, findings)
