import json
import shutil

import pytest

from peat import DeviceData, __version__, config, datastore, state
from peat.api.parse_api import parse


def test_parse_api_parse_bad_args(top_datapath, tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])

    assert parse(top_datapath("test_load_from_file.json"), ["nopeinvaliddev"]) is None
    assert parse(top_datapath("test_load_from_file.json"), []) is None
    assert parse([top_datapath("test_load_from_file.json")], ["nopeinvaliddev"]) is None
    assert parse([top_datapath("test_load_from_file.json")], []) is None


def test_parse_api_parse_failures(top_datapath, tmp_path, mocker, assert_glob_path):
    parse_path = tmp_path / "summaries"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": parse_path,
            "TEMP_DIR": tmp_path / "temp",
            "DEBUG": 1,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    summary = parse([top_datapath("test_load_from_file.json")], ["SCEPTRE"])  # type: dict

    assert summary
    assert summary["peat_version"] == __version__
    assert summary["peat_run_id"]
    assert summary["parse_duration"]
    assert summary["parse_modules"] == ["SCEPTRE"]
    assert summary["input_paths"] == [top_datapath("test_load_from_file.json")]
    assert len(summary["files_parsed"]) == 1
    assert summary["num_files_parsed"] == 1
    assert summary["num_parse_successes"] == 0
    assert summary["num_parse_failures"] == 1
    assert len(summary["parse_failures"]) == 1
    assert not summary["parse_results"]

    assert_glob_path(parse_path, "parse-summary.json")


# Data from: https://github.com/sandialabs/sceptre-bennu/tree/main/data/configs
def test_parse_api_multiple_files(test_dir, tmp_path, mocker, assert_glob_path, assert_no_errors):
    parse_path = tmp_path / "summaries"
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": parse_path,
            "TEMP_DIR": tmp_path / "temp",
            "DEBUG": 1,
        },
    )
    mocker.patch.object(datastore, "objects", [])

    datafiles_path = test_dir / "modules" / "sandia" / "data_files"
    paths = [
        datafiles_path / "bp" / "dnp3-client.xml",
        datafiles_path / "ep" / "bacnet-client.xml",
        datafiles_path / "ep" / "sunspec-server.xml",
    ]
    modules = ["SCEPTRE", "SELRelay"]

    summary = parse(paths, modules)  # type: dict

    assert summary
    assert summary["peat_version"] == __version__
    assert summary["peat_run_id"]
    assert summary["parse_duration"]
    assert summary["parse_modules"] == modules
    assert "input_path" not in summary  # ensure old variable name isn't present
    assert summary["input_paths"] == paths
    assert len(summary["files_parsed"]) == 3
    assert summary["num_files_parsed"] == 3
    assert summary["num_parse_successes"] == 3
    assert summary["num_parse_failures"] == 0
    assert not summary["parse_failures"]
    assert len(summary["parse_results"]) == 3

    assert_glob_path(parse_path, "parse-summary.json")
    assert_no_errors()


def test_parse_api_pushes_devices_created_during_parse(test_dir, tmp_path, mocker):
    """Devices created during a parse (e.g. one per IED of an SCD file) are pushed."""
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    elastic = mocker.MagicMock()
    mocker.patch.dict(state["CONFIG"], {"elastic": elastic})

    old_dev = datastore.get("192.0.2.1")  # existed before the parse: not pushed

    def fake_parse_data(source, dev_cls):  # noqa: ARG001
        parsed = datastore.get("192.0.2.10")
        parsed.name = "PROT1"
        extra = datastore.get("192.0.2.11")  # created as a side effect of the parse
        extra.name = "MU1"
        return parsed

    mocker.patch("peat.api.parse_api.parse_data", side_effect=fake_parse_data)
    pushed = []
    mocker.patch.object(
        DeviceData,
        "export_to_elastic",
        autospec=True,
        side_effect=lambda dev, *args, **kwargs: pushed.append(dev.ip) or True,  # noqa: ARG005
    )

    path = test_dir / "modules" / "sandia" / "data_files" / "bp" / "dnp3-client.xml"
    summary = parse([path], ["SCEPTRE"])

    assert summary
    assert summary["num_parse_successes"] == 1
    assert sorted(pushed) == ["192.0.2.10", "192.0.2.11"]
    assert old_dev.ip not in pushed
    # each device is in the parse results, with the file it was parsed from (R4-19)
    assert [(r["name"], r["results"]["ip"]) for r in summary["parse_results"]] == [
        ("dnp3-client.xml", "192.0.2.10"),
        ("dnp3-client.xml", "192.0.2.11"),
    ]
    assert summary["files_parsed"] == [path.as_posix()]
    assert summary["num_files_parsed"] == 1


def test_parse_summary_has_every_ied_of_an_scd_file(test_dir, tmp_path, mocker):
    """
    The parse summary (a baseline input) has a result per IED of an SCD file, not
    only the IED the parse returned (R4-19).
    """
    from peat.api.baseline_api import load_device_data

    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    scd = test_dir / "parsing" / "data_files" / "scl" / "synthetic_substation.scd"

    summary = parse([scd], ["IEC61850SCL"])
    ieds = {d.get_id() for d in datastore.objects}
    assert len(ieds) > 1
    assert summary["files_parsed"] == [scd.as_posix()]
    assert summary["num_files_parsed"] == 1
    assert (summary["num_parse_successes"], summary["num_parse_failures"]) == (1, 0)
    results = summary["parse_results"]
    assert {(r["name"], r["path"], r["module"]) for r in results} == {
        (scd.name, scd.as_posix(), "IEC61850SCL")
    }
    assert sorted(r["results"]["id"] for r in results) == sorted(ieds)
    assert sorted(d.get_id() for d in load_device_data(summary)) == sorted(ieds)


def _push_config(tmp_path, mocker) -> list[str]:
    """Output to tmp_path, an empty datastore, and a fake Elasticsearch push."""
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(state["CONFIG"], {"elastic": mocker.MagicMock(), "error": False})
    pushed = []
    mocker.patch.object(
        DeviceData,
        "export_to_elastic",
        autospec=True,
        side_effect=lambda dev, *args, **kwargs: pushed.append(dev.get_id()) or True,  # noqa: ARG005
    )
    return pushed


def test_parse_api_does_not_push_devices_of_failed_parses(test_dir, tmp_path, mocker):
    """Devices left behind by a failed parse are not pushed (their files aren't written)."""
    pushed = _push_config(tmp_path, mocker)

    def fake_parse_data(source, dev_cls):  # noqa: ARG001
        if source.name == "dnp3-client.xml":
            datastore.get("failed_1", "id")  # created, then the parse fails
            return None
        datastore.get("192.0.2.11")  # created as a side effect of a successful parse
        return datastore.get("192.0.2.10")

    mocker.patch("peat.api.parse_api.parse_data", side_effect=fake_parse_data)
    data = test_dir / "modules" / "sandia" / "data_files"
    summary = parse(
        [data / "bp" / "dnp3-client.xml", data / "ep" / "bacnet-client.xml"], ["SCEPTRE"]
    )
    assert summary["num_parse_successes"] == 1
    assert summary["num_parse_failures"] == 1
    assert "failed_1" in [d.get_id() for d in datastore.objects]
    assert sorted(pushed) == ["192.0.2.10", "192.0.2.11"]


def test_parse_api_does_not_push_device_of_failed_sel_cid_parse(tmp_path, mocker):
    """SELRelay creates the device of a CID file before it fails to parse the file."""
    pushed = _push_config(tmp_path, mocker)
    cid = tmp_path / "in" / "SET_61850.CID"
    cid.parent.mkdir()
    cid.write_bytes(b"")

    summary = parse([cid], ["SELRelay"])
    assert summary["num_parse_failures"] == 1
    assert [d.get_id() for d in datastore.objects] == ["selrelay_set_61850"]
    assert pushed == []


@pytest.mark.parametrize("placeholder", ["name", "ip"])
def test_parse_api_pushes_ied_that_reused_a_config_placeholder(
    placeholder, test_dir, tmp_path, mocker
):
    """
    An IED of an SCD file (not the first one) that reuses the placeholder device of
    a "hosts" entry of the PEAT config file (by IED name or IP address) is pushed
    and in the parse results, like the IEDs the parse created (R6-4).
    """
    pushed = _push_config(tmp_path, mocker)
    scd = test_dir / "parsing" / "data_files" / "scl" / "synthetic_substation.scd"
    if placeholder == "name":
        identifiers = {"name": "MU1"}
        mu1_id = "MU1"
    else:  # MU1 with an IP address of its own
        data = scd.read_bytes().replace(
            b'<ConnectedAP iedName="MU1" apName="P1">',
            b'<ConnectedAP iedName="MU1" apName="P1">'
            b'<Address><P type="IP">192.0.2.11</P></Address>',
        )
        assert b"192.0.2.11" in data
        scd = tmp_path / "in" / "r6_4_placeholder_ip.scd"
        scd.parent.mkdir()
        scd.write_bytes(data)
        identifiers = {"ip": "192.0.2.11"}
        mu1_id = "192.0.2.11"
    # added before the parse, like peat.init does for each "hosts" entry
    placeholder_dev = DeviceData(**identifiers)
    datastore.objects.append(placeholder_dev)

    summary = parse([scd], ["IEC61850SCL"])

    assert summary["num_parse_successes"] == 1
    mu1 = next(d for d in datastore.objects if d.iec61850.ied_name == "MU1")
    assert mu1 is placeholder_dev  # the IED reused the placeholder
    assert sorted(d.get_id() for d in datastore.objects) == sorted(["192.0.2.10", mu1_id])
    assert sorted(pushed) == sorted(["192.0.2.10", mu1_id])
    results = summary["parse_results"]
    assert sorted(r["results"]["id"] for r in results) == sorted(["192.0.2.10", mu1_id])
    assert {r["name"] for r in results} == {scd.name}
    assert not any("parse_devices" in d._cache for d in datastore.objects)


def test_parse_api_exports_final_state_of_device_parsed_from_several_files(
    examples_dir, tmp_path, mocker
):
    """
    A device parsed from several files (SCEPTRE fep-1: dnp3-client.xml, then
    modbus-client.xml) has its final merged state in device-data-full.json, and
    the run directory and the parse summary give the baseline commands that
    state (R6-5).
    """
    from peat.api import baseline_api

    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    src = tmp_path / "in"
    src.mkdir()
    for name in ("dnp3-client.xml", "modbus-client.xml"):
        shutil.copyfile(examples_dir / "devices" / "sceptre" / "bp" / name, src / name)

    summary = parse([src], ["SCEPTRE"])
    assert summary["num_parse_successes"] == 2
    assert [d.get_id() for d in datastore.objects] == ["fep-1"]

    def protocols(dev_data: dict | DeviceData) -> set[str]:
        if isinstance(dev_data, DeviceData):
            return {s.protocol for s in dev_data.service}
        return {s["protocol"] for s in dev_data.get("service", [])}

    both = {"dnp3", "modbus_tcp"}
    full = tmp_path / "devices" / "fep-1" / "device-data-full.json"
    assert protocols(json.loads(full.read_text(encoding="utf-8"))) == both
    summary_file = tmp_path / "summaries" / "parse-summary.json"
    # the parse summary keeps an entry per file: the state after that file
    assert [protocols(r["results"]) for r in summary["parse_results"]] == [{"dnp3"}, both]

    from_run = baseline_api.load_device_data(tmp_path)
    from_summary = baseline_api.load_device_data(summary_file)
    assert [(d.get_id(), protocols(d)) for d in from_run] == [("fep-1", both)]
    assert [(d.get_id(), protocols(d)) for d in from_summary] == [("fep-1", both)]

    # the unchanged run compared to a baseline of its final state: no findings
    baseline = baseline_api.create_baseline(from_run[0])
    for dev in from_run + from_summary:
        findings = baseline_api.compare_to_baseline(dev, baseline, include_passed=False)
        assert findings == []


def test_parse_api_exports_and_pushes_config_host_a_parsed_device_was_merged_into(
    tmp_path, mocker
):
    """
    A parsed device (a FortiGate configuration) that de-duplication merges into the
    placeholder of a "hosts" entry of the PEAT config file (same IP) is exported and
    pushed as that device, with the label and asset context of the entry, to the
    output directory of the parsed device (R7-1).
    """
    from tests.modules.fortinet.test_fortigate_conf import SYNTHETIC_CONF

    pushed = _push_config(tmp_path, mocker)
    host = {
        "label": "fw1",
        "identifiers": {"ip": "192.0.2.1"},
        "asset": {"criticality": "high_impact"},
    }
    mocker.patch.dict(config["CONFIG"], {"HOSTS": [host]})
    placeholder = DeviceData(**host["identifiers"])  # like peat.init for each "hosts" entry
    assert placeholder.label == "fw1"
    datastore.objects.append(placeholder)
    conf = tmp_path / "in" / "r7_1_fortigate.conf"
    conf.parent.mkdir()
    conf.write_text(SYNTHETIC_CONF, encoding="utf-8")

    summary = parse([conf], ["Fortigate"])

    assert summary["num_parse_successes"] == 1
    assert len(datastore.objects) == 1
    assert datastore.objects[0] is placeholder  # the parsed device was merged into it
    assert placeholder.hostname == "fg-sub1"
    assert pushed == ["fw1"]
    out_dir = tmp_path / "devices" / "192.0.2.1"
    assert [p.name for p in (tmp_path / "devices").iterdir()] == [out_dir.name]
    assert [p.name for p in out_dir.glob("device-data-full.json*")] == ["device-data-full.json"]
    full = json.loads((out_dir / "device-data-full.json").read_text(encoding="utf-8"))
    assert (full["label"], full["hostname"]) == ("fw1", "fg-sub1")
    assert full["asset"]["criticality"] == "high_impact"
    # the parse result of the returned device stays its state after the file
    assert [r["results"]["id"] for r in summary["parse_results"]] == ["192.0.2.1"]


def test_parse_api_pushes_config_host_a_created_device_was_merged_into(test_dir, tmp_path, mocker):
    """
    A device that a parse created and that de-duplication merges into the placeholder
    of a "hosts" entry of the PEAT config file is replaced by the placeholder in the
    pushed devices and the parse results (R7-1).
    """
    pushed = _push_config(tmp_path, mocker)
    host = {"label": "mu1", "identifiers": {"ip": "192.0.2.11"}}
    mocker.patch.dict(config["CONFIG"], {"HOSTS": [host]})
    placeholder = DeviceData(**host["identifiers"])
    datastore.objects.append(placeholder)

    def fake_parse_data(source, dev_cls):  # noqa: ARG001
        extra = DeviceData()  # created without the datastore lookup that finds mu1
        extra.ip = "192.0.2.11"
        extra.name = "MU1"
        datastore.objects.append(extra)
        return datastore.get("192.0.2.10")

    mocker.patch("peat.api.parse_api.parse_data", side_effect=fake_parse_data)
    path = test_dir / "modules" / "sandia" / "data_files" / "bp" / "dnp3-client.xml"
    summary = parse([path], ["SCEPTRE"])

    assert [d.get_id() for d in datastore.objects] == ["mu1", "192.0.2.10"]
    assert placeholder.name == "MU1"
    assert sorted(pushed) == ["192.0.2.10", "mu1"]
    assert [(r["results"]["ip"], r["results"].get("label")) for r in summary["parse_results"]] == [
        ("192.0.2.10", None),
        ("192.0.2.11", "mu1"),
    ]
    full = tmp_path / "devices" / "mu1" / "device-data-full.json"
    assert json.loads(full.read_text(encoding="utf-8"))["name"] == "MU1"


def _full_files(device_dir) -> dict[str, dict]:
    """device-data-full.json* files of a device directory, by file name."""
    return {
        p.name: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(device_dir.glob("device-data-full.json*"))
    }


def test_parse_api_keeps_files_of_devices_with_the_same_output_directory(
    examples_dir, tmp_path, mocker
):
    """
    Different devices whose IDs give the same output directory (SCEPTRE "fep-1" and
    "FEP-1") do not overwrite each other's final state: the first device's is in
    device-data-full.json, the second's in a numbered file (R7-2).
    """
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    src = tmp_path / "in"
    src.mkdir()
    sceptre = examples_dir / "devices" / "sceptre" / "bp"
    shutil.copyfile(sceptre / "dnp3-client.xml", src / "r7_2_a_dnp3.xml")  # fep-1
    modbus = (sceptre / "modbus-client.xml").read_text(encoding="utf-8")
    assert "<name>fep-1</name>" in modbus
    (src / "r7_2_b_modbus.xml").write_text(
        modbus.replace("<name>fep-1</name>", "<name>FEP-1</name>"), encoding="utf-8"
    )

    summary = parse([src], ["SCEPTRE"])

    assert summary["num_parse_successes"] == 2
    assert [d.get_id() for d in datastore.objects] == ["fep-1", "FEP-1"]
    assert [p.name for p in (tmp_path / "devices").iterdir()] == ["fep-1"]
    files = _full_files(tmp_path / "devices" / "fep-1")
    states = {
        (name, data["name"], tuple(sorted(s["protocol"] for s in data["service"])))
        for name, data in files.items()
    }
    assert ("device-data-full.json", "fep-1", ("dnp3",)) in states
    assert {(dev_name, protocols) for _, dev_name, protocols in states} == {
        ("fep-1", ("dnp3",)),
        ("FEP-1", ("modbus_tcp",)),
    }
    summary_file = tmp_path / "devices" / "fep-1" / "device-data-summary.json"
    assert json.loads(summary_file.read_text(encoding="utf-8"))["name"] == "fep-1"


def test_parse_api_keeps_devices_with_the_same_device_id_apart(tmp_path, mocker):
    """
    The HISTORY.TXT and SER.TXT event files of one SEL relay are parsed as two devices
    (ids selrelay_history and selrelay_ser) with the same device ID (the relay name):
    the run directory and the parse summary have both devices (R7-4).
    """
    from peat.api.baseline_api import load_device_data
    from tests.modules.sel.test_relay_parse import HISTORY, SER

    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "SUMMARIES_DIR": tmp_path / "summaries",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    src = tmp_path / "in"
    src.mkdir()
    paths = [src / "HISTORY.TXT", src / "SER.TXT"]
    for path, text in zip(paths, [HISTORY, SER], strict=True):
        path.write_bytes(text.encode())  # the same line endings on every OS

    summary = parse(paths, ["SELRelay"])

    assert summary["num_parse_successes"] == 2
    devices = [(d.get_id(), d.id) for d in datastore.objects]
    assert len(devices) == 2
    assert devices[0][0] == devices[1][0]  # the same device ID
    assert [dev_id for _, dev_id in devices] == ["selrelay_history", "selrelay_ser"]
    device_dirs = list((tmp_path / "devices").iterdir())
    assert len(device_dirs) == 1  # the directory of the relay name
    files = _full_files(device_dirs[0])
    assert {data["id"] for data in files.values()} == {"selrelay_history", "selrelay_ser"}
    assert files["device-data-full.json"]["id"] == "selrelay_history"

    from_summary = load_device_data(tmp_path / "summaries" / "parse-summary.json")
    assert sorted(d.id for d in from_summary) == ["selrelay_history", "selrelay_ser"]
