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
