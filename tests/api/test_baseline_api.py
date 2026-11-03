import io
import json
from datetime import UTC
from pathlib import Path, PurePosixPath, PureWindowsPath

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
    User,
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


def test_load_parse_summary_uses_the_last_entry_of_each_device():
    """
    A parse summary has an entry per parsed file of a device, with its state after
    that file: the last entry of each device is loaded (R6-5).
    """

    def entry(ip: str, protocols: list[str]) -> dict:
        doc = {"ip": ip, "service": [{"protocol": p, "port": 1} for p in protocols]}
        return {"name": f"{ip}-{len(protocols)}.xml", "module": "SCEPTRE", "results": doc}

    parse_summary = {
        "parse_results": [
            entry("192.0.2.10", ["dnp3"]),
            entry("192.0.2.11", ["ftp"]),
            entry("192.0.2.10", ["dnp3", "modbus_tcp"]),
        ]
    }
    devices = api.load_device_data(parse_summary)
    assert [(d.get_id(), sorted(s.protocol for s in d.service)) for d in devices] == [
        ("192.0.2.10", ["dnp3", "modbus_tcp"]),
        ("192.0.2.11", ["ftp"]),
    ]


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


def test_lossy_inputs_of_unknown_format(tmp_path, mocker):
    full = write_pull(tmp_path, sel_relay())
    baseline = api.create_baseline(api.load_device_data(full)[0], "previous_observed")
    assert not baseline.ignore
    summary_text = full.with_name("device-data-summary.json").read_text()

    # a device summary from standard input, or in a file with another name
    mocker.patch("sys.stdin", io.StringIO(summary_text))
    (stdin_summary,) = api.load_device_data("-")
    renamed = tmp_path / "relay-1.json"
    renamed.write_text(summary_text)
    (file_summary,) = api.load_device_data(renamed)
    for summary in (stdin_summary, file_summary):
        assert api.compare_to_baseline(summary, baseline, store=False) == []
        assert {"files", "relationships", "event"} <= set(summary._cache["omitted_keys"])

    # host documents (DeviceData.elastic(), e.g. printed by 'peat pull -P') have no
    # relationships; the lists they have are still compared
    (host,) = api.load_device_data([consts.convert(sel_relay().elastic())])
    assert api.compare_to_baseline(host, baseline, store=False) == []
    assert host._cache["omitted_keys"] == ("relationships",)
    changed = sel_relay()
    changed.files = changed.files[:1]
    (host,) = api.load_device_data([consts.convert(changed.elastic())])
    assert {(f.difference, f.path) for f in api.compare_to_baseline(host, baseline)} == {
        ("missing", "files[path=/SETTINGS/SET_61850.CID]")
    }

    # a complete export with all these lists has no omitted keys, whatever its source
    (exported,) = api.load_device_data(sel_relay().export())
    assert "omitted_keys" not in exported._cache


@pytest.mark.usefixtures("run_dirs")
def test_parse_input_files_compare_equal(tmp_path, mocker):
    """The same SCD file parsed from another folder and name has no findings."""
    from peat import IEC61850SCL, datastore

    scd = Path(__file__).parents[1] / "parsing" / "data_files" / "scl" / "synthetic_substation.scd"
    mocker.patch.object(datastore, "objects", [])
    first = tmp_path / "v1" / "substation.scd"
    first.parent.mkdir()
    first.write_bytes(scd.read_bytes())
    (dev,) = api.load_device_data(IEC61850SCL.parse(first).export())
    for kind in ("first_observed", "engineer_provided"):
        baseline = api.create_baseline(dev, kind)
        datastore.objects.clear()
        second = tmp_path / "v2" / "substation_v2.scd"
        second.parent.mkdir(exist_ok=True)
        second.write_bytes(scd.read_bytes())
        (cur,) = api.load_device_data(IEC61850SCL.parse(second).export())
        assert cur.iec61850.scl_file != dev.iec61850.scl_file
        assert api.compare_to_baseline(cur, baseline, store=False) == [], kind


@pytest.mark.usefixtures("run_dirs")
def test_parse_input_sel_cid_compare_equal(tmp_path, mocker):
    """The same zlib SEL CID parsed from another folder and name has no findings (R3-0)."""
    import zlib

    from peat import datastore

    scd = Path(__file__).parents[1] / "parsing" / "data_files" / "scl" / "synthetic_substation.scd"
    data = zlib.compress(scd.read_bytes())
    mocker.patch.object(datastore, "objects", [])
    first = tmp_path / "cid_v1" / "SET_61850.CID"
    first.parent.mkdir()
    first.write_bytes(data)
    (dev,) = api.load_device_data(SELRelay.parse(first).export())
    (cid,) = dev.files
    assert cid.path is not None
    assert cid.local_path is not None
    assert cid.path.as_posix() == cid.local_path.as_posix()  # a "peat parse" input file
    for kind in ("first_observed", "engineer_provided"):
        baseline = api.create_baseline(dev, kind)
        for name in ("SET_61850.CID", "relay2_61850.cid"):
            datastore.objects.clear()
            second = tmp_path / f"cid_v2_{kind}" / name
            second.parent.mkdir(exist_ok=True)
            second.write_bytes(data)
            (cur,) = api.load_device_data(SELRelay.parse(second).export())
            assert cur.files[0].path != dev.files[0].path
            assert api.compare_to_baseline(cur, baseline, store=False) == [], (kind, name)


@pytest.mark.usefixtures("run_dirs")
def test_peat_written_logic_and_firmware_files_compare_equal(tmp_path, mocker):
    """
    The logic and firmware files PEAT writes to the device directory of a run have
    a location on the PEAT host, which is not compared (R3-11).
    """
    from peat import ControlLogix, datastore

    mocker.patch.object(datastore, "objects", [])

    def pull(run: str, ip: str = "192.0.2.20", logic: str = "XIC(Start)OTE(Motor);") -> DeviceData:
        datastore.objects.clear()
        dev = DeviceData(ip=ip, type="PLC")
        dev.description.vendor.id = "Schneider"
        dev.description.model = "M340"
        dev.logic.original = logic  # written to logic.txt
        dev.firmware.original = b"project archive"
        dev.firmware.file.extension = "apx"  # written to firmware.apx
        (loaded,) = api.load_device_data(write_pull(tmp_path, dev, run))
        return loaded

    first = pull("pull_2026-10-30_120000")
    assert first.logic.file.path == first.logic.file.local_path
    second = pull("pull_2026-11-02_093000")
    assert second.firmware.file.path != first.firmware.file.path
    baseline = api.create_baseline(first)
    assert api.compare_to_baseline(second, baseline, store=False) == []
    # a profile of one unit, compared with another unit of the same run
    profile = api.create_baseline(first, scope="device_type")
    other = pull("pull_2026-10-30_120000", ip="192.0.2.21")
    assert api.compare_to_baseline(other, profile, store=False) == []
    # the content is still compared
    changed = pull("pull_2026-11-03_080000", logic="XIC(Stop)OTE(Motor);")
    diffs = {(f.difference, f.path) for f in api.compare_to_baseline(changed, baseline)}
    assert ("change", "logic.hash.sha256") in diffs
    assert ("change", "logic.file.hash.sha256") in diffs
    assert all(
        p.startswith(("logic.hash.", "logic.file.hash.", "logic.file.size")) for _, p in diffs
    )

    def clx_pull(run: str) -> DeviceData:
        """ControlLogix pull: the logic file is PEAT's parsed-logic.json."""
        datastore.objects.clear()
        dev = DeviceData(ip="192.0.2.30", type="PLC")
        dev._out_dir = tmp_path / run / "devices" / dev.ip
        logic = {"0": {}}
        dev.logic.original = json.dumps(logic)
        ControlLogix.parse_logic(dev, logic)
        (loaded,) = api.load_device_data(write_pull(tmp_path, dev, run))
        return loaded

    clx = [clx_pull("clx_1"), clx_pull("clx_2")]
    assert clx[0].logic.file.path != clx[1].logic.file.path
    assert api.compare_to_baseline(clx[1], api.create_baseline(clx[0]), store=False) == []


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
        ("unexpected", "service[protocol=http,port=80,transport=tcp]"),
    }
    assert current.baseline_findings == findings
    assert all(f.baseline_id == baseline.id for f in findings)

    # several baselines -> a JSON list
    path = api.save_baselines([baseline, reloaded], tmp_path / "two.json")
    assert len(json.loads(path.read_text())) == 2
    assert len(api.load_baselines(path)) == 2


@pytest.mark.parametrize(
    ("created_with", "compared_with"),
    [(PureWindowsPath, PurePosixPath), (PurePosixPath, PureWindowsPath)],
)
def test_baseline_file_compares_across_operating_systems(tmp_path, created_with, compared_with):
    """A baseline file made on Windows compares cleanly on Linux, and vice versa."""

    def relay(path_cls: type) -> DeviceData:
        dev = sel_relay()
        for f in dev.files:  # PurePath("/SETTINGS/SET_1.TXT") is a PureWindowsPath on Windows
            if f.path is not None:
                f.path = path_cls(f.path.as_posix())
        dev.export()
        return dev

    baseline = api.create_baseline(relay(created_with))
    path = api.save_baselines(baseline, tmp_path / "baseline.json")
    saved = json.loads(path.read_text(encoding="utf-8"))["expected"]["files"]
    assert saved
    assert all(f["path"].startswith("/") for f in saved if "path" in f)
    (loaded,) = api.load_baselines(path)
    assert api.compare_to_baseline(relay(compared_with), loaded, store=False) == []


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


def test_create_baseline_selector_matches_only_the_device():
    """Glob characters in default selector values match only themselves (R3-17)."""
    for dev_id in ("TEMPLATE@bay[1]", "TEMPLATE@[x]", "relay*", "relay?"):
        baseline = api.create_baseline(DeviceData(id=dev_id, name="A"), baseline_id="b")
        renamed = DeviceData(id=dev_id, name="B")
        assert baseline.selector.matches(renamed), dev_id
        findings = api.compare_to_baseline(renamed, baseline, store=False)
        assert [(f.difference, f.path) for f in findings] == [("change", "name")], dev_id
    star = api.create_baseline(DeviceData(id="relay*"), baseline_id="b")
    assert not star.selector.matches(DeviceData(id="relay-2"))
    serial = api.create_baseline(DeviceData(serial_number="SN[1]"), baseline_id="b")
    assert serial.selector.matches(DeviceData(serial_number="sn[1]"))  # case-insensitive
    assert not serial.selector.matches(DeviceData(serial_number="SN1"))

    def rtac(model: str) -> DeviceData:
        dev = DeviceData(ip="192.0.2.40")
        dev.description.vendor.id = "SEL"
        dev.description.model = model
        return dev

    profile = api.create_baseline(rtac("RTAC [3530]"), scope="device_type")
    assert profile.selector.matches(rtac("rtac [3530]"))
    assert not profile.selector.matches(rtac("RTAC 3"))


def test_complete_baselines_report_new_values(tmp_path):
    """
    Baselines created from an observed state, including approved copies of them,
    report values and list items the device did not have (R3-14, R3-24).
    """
    dev = DeviceData(ip="192.0.2.20", id="192.0.2.20")
    dev.firmware.version = "1.0"
    cur = DeviceData(ip="192.0.2.20", id="192.0.2.20")
    cur.firmware.version = "1.0"
    cur.os.name = "VxWorks"
    cur.store("users", User(name="backdoor"))
    cur.store("service", Service(protocol="telnet", port=23, transport="tcp"))
    new = {
        ("unexpected", "os"),
        ("unexpected", "users[name=backdoor]"),
        ("unexpected", "service[protocol=telnet,port=23,transport=tcp]"),
    }

    def diffs(baseline: Baseline) -> set:
        return {
            (f.difference, f.path) for f in api.compare_to_baseline(cur, baseline, store=False)
        }

    for kind in ("first_observed", "previous_observed", "approved"):
        baseline = api.create_baseline(dev, kind)
        assert baseline.complete, kind
        assert diffs(baseline) == new, kind
    for kind in ("engineer_provided", "vendor_recommended", "factory_default"):
        baseline = api.create_baseline(dev, kind)
        assert not baseline.complete, kind
        assert diffs(baseline) == set(), kind

    # NERC CIP-010 workflow: the reviewed first_observed baseline is saved as approved
    path = api.save_baselines(api.create_baseline(dev), tmp_path / "relay-1.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["complete"] is True
    data.update(kind="approved", id="relay-1-approved", version="2")
    path.write_text(json.dumps(data), encoding="utf-8")
    (approved,) = api.load_baselines(path)
    assert (approved.kind, approved.complete) == ("approved", True)
    assert diffs(approved) == new
    # a hand-written approved baseline only checks what it specifies
    del data["complete"]
    path.write_text(json.dumps(data), encoding="utf-8")
    (written,) = api.load_baselines(path)
    assert diffs(written) == set()

    # complete device type profiles report a service that moves from the address
    # of the unit itself to all addresses (R3-1)
    def unit(n: int, listen: str = "") -> DeviceData:
        ip = f"192.0.2.{n}"
        unit_dev = DeviceData(ip=ip, id=ip)
        unit_dev.description.vendor.id = "X"
        unit_dev.description.model = "Y"
        unit_dev.store("service", Service(protocol="ssh", port=22, listen_address=listen or ip))
        return unit_dev

    profile = api.create_baseline([unit(1), unit(2)], "approved", scope="device_type")
    assert profile.complete
    assert api.compare_to_baseline(unit(3), profile, store=False) == []
    findings = api.compare_to_baseline(unit(3, "0.0.0.0"), profile, store=False)
    assert [(f.difference, f.path) for f in findings] == [
        ("unexpected", "service[protocol=ssh,port=22].listen_address")
    ]


def test_cip010_review_ignores_values_instead_of_deleting_them(tmp_path):
    """
    The complete approved copy reports values deleted from its snapshot as
    unexpected: values that should not be enforced are ignored instead (R4-18).
    """
    reviewed = DeviceData(ip="192.0.2.20", id="192.0.2.20")
    reviewed.description.vendor.id = "SEL"
    reviewed.description.model = "351S"
    reviewed.store("service", Service(protocol="goose", enabled=True))
    reviewed.store("service", Service(protocol="telnet", port=23, transport="tcp", enabled=True))

    def approved_copy(**changes) -> Baseline:
        path = api.save_baselines(api.create_baseline(reviewed), tmp_path / "review.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        data.update(kind="approved", **changes)  # "complete" stays true
        path.write_text(json.dumps(data), encoding="utf-8")
        (approved,) = api.load_baselines(path)
        assert approved.complete
        return approved

    def diffs(dev: DeviceData, baseline: Baseline) -> set:
        return {
            (f.difference, f.path) for f in api.compare_to_baseline(dev, baseline, store=False)
        }

    deleted = approved_copy()
    deleted.expected.description.model = ""
    deleted.expected.service = [s for s in deleted.expected.service if s.protocol != "goose"]
    assert diffs(reviewed, deleted) == {
        ("unexpected", "description.model"),
        ("unexpected", "service[protocol=goose]"),
    }

    changed = reviewed.copy(deep=True)
    changed.description.model = "351"
    for svc in changed.service:
        svc.enabled = False
    assert diffs(changed, approved_copy()) == {
        ("change", "description.model"),
        ("change", "service[protocol=goose].enabled"),
        ("change", "service[protocol=telnet,port=23,transport=tcp].enabled"),
    }
    # ignore patterns have no selectors: they exempt a field of all items of a list
    ignored = approved_copy(ignore=["description.model", "service.enabled"])
    assert diffs(changed, ignored) == set()


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
        ("unexpected", "service[protocol=http,port=80,transport=tcp]")
    ]

    single = api.create_baseline(units[0], scope="device_type", baseline_id="one")
    assert single.provenance.device_id == "192.0.2.20"
    assert single.ignore == []


def test_device_type_baseline_of_devices_without_vendor_id():
    """Devices without a vendor ID (SCL IEDs) are of one type by vendor name (R4-20)."""

    def ied(n: int, manufacturer: str) -> DeviceData:
        dev = DeviceData(ip=f"192.0.2.{30 + n}", id=f"192.0.2.{30 + n}", name=f"PROT{n}")
        dev.description.vendor.name = manufacturer
        dev.description.model = "PR-100"
        return dev

    with pytest.raises(PeatError, match="got: acme pr-100, other corp pr-100"):
        api.create_baseline([ied(1, "ACME"), ied(2, "OTHER Corp")], scope="device_type")

    profile = api.create_baseline([ied(1, "ACME"), ied(2, "ACME")], scope="device_type")
    assert (profile.id, profile.name) == ("ACME-PR-100-typical", "Typical ACME PR-100")
    assert profile.selector == BaselineSelector(model="PR-100")
    assert "description.vendor.name" not in profile.ignore
    assert api.compare_to_baseline(ied(3, "ACME"), profile, store=False) == []
    findings = api.compare_to_baseline(ied(4, "THIRD Inc"), profile, store=False)
    assert [(f.difference, f.path) for f in findings] == [("change", "description.vendor.name")]

    # the selector matches the vendor ID only if every device has one
    with_id = ied(5, "ACME")
    with_id.description.vendor.id = "ACME"
    assert api.create_baseline([with_id, ied(6, "ACME")], scope="device_type").selector == (
        BaselineSelector(model="PR-100")
    )
    assert api.create_baseline(with_id, scope="device_type").selector == (
        BaselineSelector(vendor_id="ACME", model="PR-100")
    )
    # a vendor name alone does not select devices
    nameless = ied(7, "ACME")
    nameless.description.model = ""
    with pytest.raises(PeatError, match="no vendor ID or model"):
        api.create_baseline(nameless, scope="device_type")


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
