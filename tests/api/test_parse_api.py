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
