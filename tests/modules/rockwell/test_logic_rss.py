import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from peat import RSLogix500, SELRelay, config, datastore, module_api
from peat.api.parse_api import parse
from peat.modules.rockwell import logic_rss
from peat.modules.rockwell.logic_rss import _stream_filename
from peat.modules.rockwell.rss_parse import read_rss

from .rss_fixtures import (
    MOV,
    build_cfb,
    default_program_files,
    default_summary,
    default_tree,
    ins,
    ladder_payload,
    make_rss,
    object_data,
    processor_payload,
    summary_info_stream,
)


def read_payload(source, storage: str) -> bytes:
    return read_rss(source).payload(storage)


FEED = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<rss version="2.0"><channel><title>News</title></channel></rss>\n'
)


@pytest.fixture
def peat_dirs(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path / "run",
            "DEVICE_DIR": tmp_path / "run" / "devices",
            "SUMMARIES_DIR": tmp_path / "run" / "summaries",
            "TEMP_DIR": tmp_path / "run" / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    return inputs


def _out_dir(dev, source) -> Path:
    """Directory with the output files of a project file."""
    sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    return dev.get_out_dir() / "rss" / f"{source.stem}_{sha256[:8]}"


def _untitled_tree() -> dict:
    tree = default_tree()
    tree["PROCESSOR"]["ObjectData"] = object_data(processor_payload(name="UNTITLED"), 0)
    tree["\x05SummaryInformation"] = summary_info_stream({1: 1252, 20: "UNTITLED", 25: 4})
    return tree


def test_parse_project(peat_dirs):
    source = make_rss(peat_dirs, "PUMP_PROJECT.RSS")
    dev = RSLogix500.parse(source)

    assert dev is not None
    assert dev.name == "PUMP_CTL"
    assert dev.type == "PLC"
    assert dev.description.vendor.id == "Rockwell"
    assert dev._module is RSLogix500

    # Logic
    assert dev.logic.name == "PUMP_CTL"
    assert dev.logic.author == "jdoe"
    assert dev.logic.created.year == 2011
    assert dev.logic.last_updated.year == 2012
    assert dev.logic.file.local_path == source.resolve()
    assert dev.logic.file.mime_type == "application/x-ole-storage"
    assert "0002 SOR BST XIC I:1/0 XIO B3:2/4 NXB XIO I:1/0 XIC B3:2/4 BND" in dev.logic.parsed
    programs = dev.logic.formats["program_files"]
    assert list(programs) == ["2:MAIN", "3:SUB_A"]
    assert programs["3:SUB_A"].splitlines()[1] == "SOR MOV N7:2 F8:1 EOR"
    original = json.loads(dev.logic.original)
    assert [p["number"] for p in original] == [0, 1, 2, 3]
    assert original[2]["rungs"][0][1] == [0x2F, 1, ["B3:0/2"], "2f010203"]
    assert dev.logic.hash.sha256

    # Tags: the S2 status and empty entries are skipped
    tags = {tag.address: tag for tag in dev.tag}
    assert sorted(tags) == ["B3:0/2", "I:0/0", "N7:2", "O:0/2"]
    assert tags["N7:2"].name == "SPEED"
    assert tags["N7:2"].description == "Speed setpoint"
    assert tags["N7:2"].type == "integer"
    assert tags["I:0/0"].type == "input"

    extra = dev.extra["rslogix500"]
    assert extra["file_format_version"] == "0x80"
    assert extra["rslogix_version"] == "9.99.00.01"
    assert extra["processor_type_code"] == 0x2B
    assert extra["processor_type_code_hex"] == "0x002b"
    assert extra["engineering_workstation"] == "ENGWS01"
    assert extra["last_comms_path"] == "ENGWS01!AB_ETH-1\\192.0.2.10"
    assert extra["num_program_files"] == 4
    assert extra["num_data_files"] == 9
    assert extra["program_files"][2] == {"number": 2, "name": "MAIN", "type": "ladder", "rungs": 6}
    assert extra["rung_comment_count"] == 3
    assert extra["num_documented_addresses"] == 7
    assert extra["online_image_differs"] == {"PROCESSOR": False, "PROGRAM FILES": True}
    assert extra["vba"] == {"present": True, "modules": []}
    assert extra["summary_info"]["revision_number"] == "7"
    assert extra["warnings"] == []
    assert extra["errors"] == []
    sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    assert extra["project_files"] == [
        {
            "name": "PUMP_PROJECT.RSS",
            "path": str(source.resolve()),
            "sha256": sha256,
            "processor_name": "PUMP_CTL",
            "last_saved_time": "2012-08-09T10:11:12+00:00",
            "output_directory": f"rss/PUMP_PROJECT_{sha256[:8]}",
            "used_for_device": True,
        }
    ]

    # Output files
    dev_dir = dev.get_out_dir()
    assert (dev_dir / "PUMP_PROJECT.RSS").is_file()
    assert (dev_dir / "device-data-summary.json").is_file()
    out_dir = _out_dir(dev, source)
    assert (out_dir / "ladder.txt").read_text(encoding="utf-8").strip() == dev.logic.parsed
    online = (out_dir / "ladder-onlineimage.txt").read_text(encoding="utf-8")
    assert '"MAIN" (ladder, 7 rungs)' in online
    assert "comment:" not in online  # Comments are keyed to the offline rungs
    parsed = json.loads((out_dir / "parsed.json").read_text(encoding="utf-8"))
    assert parsed["program_files"][2]["rungs"][2]["tokens"][1]["mnemonic"] == "BST"
    inventory = json.loads((out_dir / "stream-inventory.json").read_text(encoding="utf-8"))
    by_path = {item["path"]: item for item in inventory}
    assert len(by_path) == len(list((out_dir / "streams").iterdir()))
    for item in inventory:
        assert (dev_dir / item["output_file"]).is_file(), item
    assert by_path["PROGRAM FILES/ObjectData"]["output_file"].endswith(
        "_PROGRAM FILES__ObjectData.bin"
    )
    assert by_path["Contents"]["output_file"].endswith("_Contents.raw")
    assert by_path["\x05SummaryInformation"]["output_file"].endswith("_SummaryInformation.raw")
    decoded = (dev_dir / by_path["PROGRAM FILES/ObjectData"]["output_file"]).read_bytes()
    assert decoded.startswith(b"\xff\xff\x80\x00\x0b\x00CProgHolder")


def test_parse_untitled_project(peat_dirs):
    source = peat_dirs / "Line_3.RSS"
    source.write_bytes(build_cfb(_untitled_tree()))
    dev = RSLogix500.parse(source)
    assert dev is not None
    assert dev.id == "rss_line_3"
    assert dev.name == ""
    assert dev.logic.name == "Line_3"


def test_parse_raw_bytes(peat_dirs):
    data = make_rss(peat_dirs).read_bytes()
    dev = RSLogix500.parse(data)
    assert dev is not None
    assert dev.name == "PUMP_CTL"
    assert (dev.get_out_dir() / "rslogix500_project.rss").is_file()


@pytest.mark.parametrize(
    "content",
    [
        FEED.encode(),
        b"",
        build_cfb({"Workbook": b"\x00" * 600, "SummaryInformation": b"\x00" * 10}),
    ],
)
def test_parse_not_a_project(peat_dirs, content, caplog):
    source = peat_dirs / "not_a_project.rss"
    source.write_bytes(content)
    assert RSLogix500.parse(source) is None
    assert "RSLogix 500" in caplog.text


def test_parse_decoders_fail(peat_dirs, mocker):
    """Extraction still works if every section decoder fails."""
    for name in (
        "parse_processor",
        "parse_version",
        "parse_program_files",
        "parse_mem_database",
        "parse_vba_project",
        "compare_online_image",
        "find_referenced_data_files",
        "_first_u16_of_class",
    ):
        mocker.patch(f"peat.modules.rockwell.rss_parse.{name}", side_effect=ValueError("boom"))

    source = make_rss(peat_dirs, "broken.RSS")
    dev = RSLogix500.parse(source)

    assert dev is not None
    assert dev.name == "PUMP_CTL"  # From the SummaryInformation
    errors = dev.extra["rslogix500"]["errors"]
    assert "failed to parse PROGRAM FILES: boom" in errors
    assert "failed to parse MEM DATABASE: boom" in errors
    assert len(errors) == 10
    out_dir = _out_dir(dev, source)
    assert list((out_dir / "streams").glob("*_PROGRAM FILES__ObjectData.bin"))
    assert (out_dir / "stream-inventory.json").is_file()
    assert (out_dir / "parsed.json").is_file()


def test_parse_summary_info_wrong_types(peat_dirs):
    """Regression: properties with unexpected types used to crash the parse."""
    tree = default_tree()
    summary = default_summary()
    summary[20] = 12345
    summary[12] = "yesterday"
    summary[4] = 7
    tree["\x05SummaryInformation"] = summary_info_stream(summary)
    source = make_rss(peat_dirs, "types.RSS", tree=tree)
    dev = RSLogix500.parse(source)
    assert dev is not None
    assert dev.name == "PUMP_CTL"  # From the PROCESSOR storage
    assert dev.logic.created is None
    assert dev.logic.author == "operator2"
    assert dev.extra["rslogix500"]["errors"] == []
    assert (_out_dir(dev, source) / "parsed.json").is_file()


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("PROGRAM FILES/ObjectData", "007_PROGRAM FILES__ObjectData.bin"),
        ("\x05SummaryInformation", "007_SummaryInformation.bin"),
        ("../../etc/passwd", "007_______etc__passwd.bin"),
        ("..\\..\\x:y*z?/CON", "007__.._x_y_z___CON.bin"),
        ("", "007__.bin"),
        # Long names are shortened in the middle
        (
            "apc/The VBA Project/Host Project Item Names/RSLogix_500_Project/"
            "ReqControl List Data/ReqControl List Data",
            "007_apc__The VBA Pro~List Data__ReqControl List Data.bin",
        ),
        ("a" * 15 + ". " + "b" * 40, "007_" + "a" * 15 + "~" + "b" * 31 + ".bin"),
    ],
)
def test_stream_filename(path, expected):
    name = _stream_filename(7, path, ".bin")
    assert name == expected
    assert "/" not in name
    assert "\\" not in name


def test_stream_filename_collisions(peat_dirs):
    tree = default_tree()
    tree["A:B"] = {"ObjectData": b"\x00" * 20}
    tree["A?B"] = {"ObjectData": b"\x01" * 20}
    source = make_rss(peat_dirs, tree=tree)
    dev = RSLogix500.parse(source)
    files = sorted((_out_dir(dev, source) / "streams").glob("*_A_B__ObjectData.raw"))
    assert len(files) == 2
    assert {f.read_bytes() for f in files} == {b"\x00" * 20, b"\x01" * 20}


def test_output_paths_are_short(peat_dirs):
    """Output paths stay well below the Windows path limit (260 characters)."""
    tree = default_tree()
    long_name = "ReqControl List Data"
    tree["apc"]["The VBA Project"]["Host Project Item Names"] = {
        "RSLogix_500_Project": {long_name: {long_name: b"\x00" * 10}}
    }
    source = make_rss(peat_dirs, "A" * 80 + ".RSS", tree=tree)
    dev = RSLogix500.parse(source)
    paths = [p.relative_to(dev.get_out_dir()) for p in dev.get_out_dir().rglob("*")]
    assert any(str(p).endswith(f"~List Data__{long_name}.raw") for p in paths), paths
    # "rss/<32>_<8>/streams/<3>_<48>.<3>" is 110 characters
    assert max(len(p.as_posix()) for p in paths if p.parts[0] == "rss") <= 110


def _project(directory, name: str, saved: datetime, rung: list) -> Path:
    """A project named PUMP_CTL, with an extra rung in MAIN."""
    tree = default_tree()
    summary = default_summary()
    summary[13] = saved
    tree["\x05SummaryInformation"] = summary_info_stream(summary)
    files = default_program_files()
    files[2]["rungs"].insert(0, rung)
    tree["PROGRAM FILES"]["ObjectData"] = object_data(ladder_payload(files))
    return make_rss(directory, name, tree=tree)


@pytest.mark.parametrize("backup_first", [True, False])
def test_parse_project_and_backup(peat_dirs, backup_first):
    """
    Regression: a project and its backup are the same device. The device's
    logic must come from the newest file, with a matching hash and file
    information, and each file's output files must be kept.
    """
    project = _project(
        peat_dirs, "PUMP.RSS", datetime(2020, 1, 2, tzinfo=UTC), [ins(MOV, "1", "1", "N7:0", "0")]
    )
    backup = _project(
        peat_dirs,
        "PUMP_BAK000.RSS",
        datetime(2019, 5, 6, tzinfo=UTC),
        [ins(MOV, "2", "2", "N7:0", "0")],
    )
    order = [backup, project] if backup_first else [project, backup]
    for source in order:
        dev = RSLogix500.parse(source)

    assert len([d for d in datastore.objects if d.name == "PUMP_CTL"]) == 1
    assert dev.logic.file.local_path == project.resolve()
    assert dev.logic.file.name == "PUMP.RSS"
    assert dev.logic.last_updated.year == 2020
    assert "0000 SOR MOV 1 N7:0 EOR" in dev.logic.parsed
    assert (
        dev.logic.hash.sha256.upper()
        == hashlib.sha256(dev.logic.original.encode()).hexdigest().upper()
    )

    project_files = dev.extra["rslogix500"]["project_files"]
    assert len(project_files) == 2
    used = {p["name"]: p["used_for_device"] for p in project_files}
    assert used == {"PUMP.RSS": True, "PUMP_BAK000.RSS": False}

    for source, text in ((project, "SOR MOV 1 N7:0 EOR"), (backup, "SOR MOV 2 N7:0 EOR")):
        out_dir = _out_dir(dev, source)
        assert text in (out_dir / "ladder.txt").read_text(encoding="utf-8")
        inventory = json.loads((out_dir / "stream-inventory.json").read_text(encoding="utf-8"))
        programs = next(i for i in inventory if i["path"] == "PROGRAM FILES/ObjectData")
        decoded = (dev.get_out_dir() / programs["output_file"]).read_bytes()
        assert (
            hashlib.sha256(decoded).hexdigest()
            == hashlib.sha256(read_payload(source, "PROGRAM FILES")).hexdigest()
        )
    # Nothing was written with a duplicate (".1") suffix
    assert not list((dev.get_out_dir() / "rss").rglob("*.1"))


def test_file_signatures(tmp_path):
    rss = make_rss(tmp_path)
    renamed = tmp_path / "renamed.dat"
    shutil.copy(rss, renamed)
    sel_like = tmp_path / "relay.rdb"
    sel_like.write_bytes(build_cfb({"Relays": {"SET_ALL.TXT": b"[INFO]\r\nFID=SEL-351\r\n" * 50}}))
    feed = tmp_path / "news.rss"
    feed.write_text(FEED)
    empty = tmp_path / "empty.rss"
    empty.write_bytes(b"")

    signature = RSLogix500.file_signatures[0]
    assert signature.matches(rss)
    assert signature.matches(renamed)
    assert signature.matches(rss.read_bytes())
    assert not signature.matches(sel_like)
    assert not signature.matches(feed)
    assert not signature.matches(empty)

    # Regression: SEL relay OLE signature claimed every OLE file, including RSS projects
    sel_signature = SELRelay.file_signatures[0]
    assert not sel_signature.matches(rss)
    assert not sel_signature.matches(renamed)
    assert sel_signature.matches(sel_like)


def test_module_lookup():
    assert module_api.get_modules("RSLogix500") == [RSLogix500]
    for alias in ("rss", "rslogix500", "RSLogix_500", "logic_rss", "rockwell_rss"):
        assert module_api.get_modules(alias) == [RSLogix500], alias
    assert RSLogix500 in module_api.get_modules("rockwell")
    assert module_api.get_modules("allen-bradley") != [RSLogix500]
    assert RSLogix500.filename_patterns == []


def test_parse_directory(peat_dirs):
    rss = make_rss(peat_dirs, "proj.RSS")
    shutil.copy(rss, peat_dirs / "renamed_project.dat")
    (peat_dirs / "news.rss").write_text(FEED)

    summary = parse([peat_dirs])

    assert summary is not None
    rss_results = [r for r in summary["parse_results"] if r["module"] == "RSLogix500"]
    assert sorted(r["name"] for r in rss_results) == ["proj.RSS", "renamed_project.dat"]
    assert summary["num_parse_failures"] == 0
    assert not any(r["module"] == "SELRelay" for r in summary["parse_results"])
    assert summary["num_files_parsed"] == 2


def test_dev_argument_is_used(peat_dirs):
    existing = datastore.get("192.0.2.50")
    dev = RSLogix500.parse(make_rss(peat_dirs), dev=existing)
    assert dev is existing
    assert dev.name == "PUMP_CTL"


def test_logic_from_another_source_is_replaced(peat_dirs):
    # The save times are only compared with logic from other project files
    existing = datastore.get("192.0.2.51")
    other = peat_dirs / "pulled_logic.txt"
    other.write_text("logic pulled from the device")
    existing.logic.file.local_path = other
    existing.logic.last_updated = datetime(2030, 1, 1, tzinfo=UTC)
    source = make_rss(peat_dirs)
    dev = RSLogix500.parse(source, dev=existing)
    assert dev.logic.file.local_path == source.resolve()
    assert dev.logic.last_updated.year == 2012


def test_module_docstring_mentions_usage():
    assert "peat parse -d RSLogix500" in logic_rss.__doc__
