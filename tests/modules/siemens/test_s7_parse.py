import shutil
import zipfile
from datetime import UTC, datetime

import pytest

from peat import ParseError
from peat.modules.siemens import s7_parse
from peat.modules.siemens.dbf import read_dbf


def test_convert_s7_timestamp():
    # 59993541 ms after midnight, 11919 days after 1984-01-01
    assert s7_parse.convert_s7_timestamp(bytes.fromhex("03936dc52e8f")) == datetime(
        2016, 8, 19, 16, 39, 53, 541000, tzinfo=UTC
    )
    assert s7_parse.convert_s7_timestamp(b"\x00" * 6) is None
    assert s7_parse.convert_s7_timestamp(b"\xff" * 6) is None
    assert s7_parse.convert_s7_timestamp(b"\x00") is None


def test_convert_ole_date():
    assert s7_parse.convert_ole_date("42601,5") == datetime(2016, 8, 19, 12, tzinfo=UTC)
    assert s7_parse.convert_ole_date("42601.5") == datetime(2016, 8, 19, 12, tzinfo=UTC)
    assert s7_parse.convert_ole_date("") is None


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("dotnetsiemensplctoolboxlibrary/UnitTest_Simatic_Project.zip", "step7_project"),
        ("dotnetsiemensplctoolboxlibrary/TestProjekt.zap19", "tia_project"),
        ("codegeneratoropenness/GraphJump.xml", "simaticml"),
        ("tia-portal-openness-mcp/MCP_E2E_Tags.xml", "simaticml"),
        ("step7-classic-algorithms/TON_D_ms.awl", "source"),
        ("s7-plc-snippets/GET_OUC.scl", "source"),
        ("awlsim/trafficlights_2.asc", "symbol_table"),
        ("README.md", ""),
    ],
)
def test_detect_file_type(datapath, filename, expected):
    assert s7_parse.detect_file_type(datapath(filename)) == expected


def test_read_dbf_with_memo(datapath, tmp_path):
    with zipfile.ZipFile(
        datapath("dotnetsiemensplctoolboxlibrary/UnitTest_Simatic_Project.zip")
    ) as zf:
        zf.extractall(tmp_path)
    folder = tmp_path / "UnitTest Simatic Project/UnitTest/ombstx/offline/00000001"

    table = read_dbf(folder / "SUBBLK.DBF", raw_fields={"TIMESTAMP1"})
    assert table.version == 0x8B  # dBASE IV with memo
    assert [f.name for f in table.fields][:4] == ["OBJECTID", "BLKLANG", "SUBBLKTYP", "BLKNUMBER"]
    db121 = next(
        r for r in table.records if r["BLKNUMBER"] == "00121" and r["SUBBLKTYP"] == "00010"
    )
    assert len(db121["MC5CODE"]) == db121["MC5LEN"] == 20824
    assert isinstance(db121["TIMESTAMP1"], bytes)

    with pytest.raises(ParseError):
        read_dbf(b"not a dbf")


@pytest.fixture(scope="module")
def step7_project(datapath):
    return s7_parse.parse_step7_project(
        datapath("dotnetsiemensplctoolboxlibrary/UnitTest_Simatic_Project.zip")
    )


def test_parse_step7_project(step7_project):
    assert step7_project["name"] == "UnitTest"
    assert step7_project["s7p_file"] == "UnitTest.s7p"
    assert step7_project["guid"] == "{7AC4BFF9-85CA-482A-88C9-72AC3631E1BE}"
    assert step7_project["has_hardware_config"] is False

    programs = {p["name"]: p for p in step7_project["programs"]}
    assert set(programs) == {"TestMC7Converter", "TestParameter"}
    assert programs["TestMC7Converter"]["type"] == "S7 CPU"
    assert programs["TestMC7Converter"]["block_folder_id"] == 1
    assert programs["TestParameter"]["block_folder_id"] == 2
    assert programs["TestMC7Converter"]["created"] == datetime(
        2016, 8, 19, 16, 39, 53, 743000, tzinfo=UTC
    )


def test_parse_step7_project_blocks(step7_project):
    folders = {f["id"]: f for f in step7_project["block_folders"]}
    assert set(folders) == {1, 2}
    assert folders[1]["total_size"] == 99044

    blocks = {b["name"]: b for b in folders[1]["blocks"]}
    assert sorted(blocks) == [
        "DB121",
        "DB13",
        "DB4",
        "FB1001",
        "FB101",
        "FB751",
        "FC1",
        "FC100",
        "FC21",
        "OB1",
    ]
    assert blocks["FC1"] == {
        **blocks["FC1"],
        "type": "FC",
        "number": 1,
        "symbolic_name": "SysBegin",
        "family": "BatchXpe",
        "author": "MLogics",
        "version": "1.0",
        "language": "STL",
        "know_how_protected": False,
    }
    assert blocks["DB4"]["language"] == "DB"
    assert blocks["DB4"]["version"] == "1.1"
    assert blocks["OB1"]["code_sha256"]


def test_parse_step7_project_symbols(step7_project):
    tables = {t["program_id"]: t for t in step7_project["symbol_tables"]}
    assert set(tables) == {1, 2}
    symbols = {s["name"]: s for s in tables[2]["symbols"]}
    assert symbols["GET"] == {
        "name": "GET",
        "address": "SFB 14",
        "address_iec": "SFB 14",
        "data_type": "SFB 14",
        "comment": "Read Data From a Remote CPU",
    }


def test_parse_step7_project_change_log(step7_project):
    log = step7_project["change_log"]
    assert len(log) == 3
    assert log[0]["computer"] == "WIN-O530NBMG6RG"
    assert log[0]["user"] == "Win2"
    assert log[0]["object_path"] == "Net"
    assert log[0]["timestamp"].date() == datetime(2016, 8, 19).date()
    assert "UnitTest.s7p" in log[2]["cause"]


def test_parse_step7_project_directory(datapath, tmp_path, step7_project):
    with zipfile.ZipFile(
        datapath("dotnetsiemensplctoolboxlibrary/UnitTest_Simatic_Project.zip")
    ) as zf:
        zf.extractall(tmp_path)
    project_dir = tmp_path / "UnitTest Simatic Project" / "UnitTest"

    # Same results from the directory, the .s7p file, and the archive
    assert s7_parse.parse_step7_project(project_dir) == step7_project
    assert s7_parse.parse_step7_project(project_dir / "UnitTest.s7p") == step7_project


def test_parse_step7_project_invalid(tmp_path):
    with pytest.raises(ParseError):
        s7_parse.parse_step7_project(tmp_path)


def test_parse_tia_archive(datapath, tmp_path):
    source = datapath("dotnetsiemensplctoolboxlibrary/TestProjekt.zap19")
    project = s7_parse.parse_tia_archive(source)

    assert project["name"] == "TestProjekt"
    assert project["version"] == "19.0.0.0"
    assert project["tia_portal_version"] == "V19"
    assert project["project_file"] == "TestProjekt.ap19"
    assert project["cpu_names"] == ["CPU 1515-2 PN"]
    assert "6ES7 515-2AN03-0AB0" in project["order_numbers"]
    assert project["ipv4_addresses"] == ["192.168.0.1", "192.168.1.1"]
    assert {"name": "System/PEData.plf", "size": 861957} in project["contents"]

    # The same project, extracted to a directory
    shutil.unpack_archive(source, tmp_path, format="zip")
    from_dir = s7_parse.parse_tia_archive(tmp_path)
    assert from_dir["name"] == "TestProjekt"
    assert from_dir["cpu_names"] == project["cpu_names"]
    assert s7_parse.parse_tia_archive(tmp_path / "TestProjekt.ap19")["version"] == "19.0.0.0"


def test_parse_simaticml_lad_fb(datapath):
    export = s7_parse.parse_simaticml(
        datapath("codegeneratoropenness/plcBlock_LAD_Block_Logic.xml").read_bytes()
    )
    assert export["engineering_version"] == "V16"
    assert {"name": "STEP 7 Professional", "version": "V16 Update 1", "type": "Product"} in export[
        "installed_products"
    ]
    block = export["blocks"][0]
    assert block["type"] == "FB"
    assert block["name"] == "Block_Logic"
    assert block["number"] == 1
    assert block["language"] == "LAD"
    assert block["interface"] == {
        "Input": [{"name": "A1", "data_type": "Bool"}],
        "Output": [{"name": "Out1", "data_type": "Bool"}],
        "Temp": [{"name": "MyValue", "data_type": "Bool"}],
    }
    assert len(block["networks"]) == 3
    assert all(n["language"] == "LAD" for n in block["networks"])


def test_parse_simaticml_graph_fb(datapath):
    block = s7_parse.parse_simaticml(datapath("codegeneratoropenness/GraphJump.xml").read_bytes())[
        "blocks"
    ][0]
    assert block["name"] == "FB_SEQ_One"
    assert block["number"] == 1234
    assert block["language"] == "GRAPH"
    assert block["interface"]["Input"][0] == {
        "name": "OFF_SQ",
        "data_type": "Bool",
        "start_value": "false",
        "comment": "Kette ausschalten",
    }


def test_parse_simaticml_scl_fc(datapath):
    block = s7_parse.parse_simaticml(
        datapath("tia-portal-openness-mcp/MCPVerify_FC_SCL_E2E.xml").read_bytes()
    )["blocks"][0]
    assert block["type"] == "FC"
    assert block["number"] == 903
    assert block["language"] == "SCL"
    assert block["interface"]["Return"] == [{"name": "Ret_Val", "data_type": "Void"}]
    source = block["networks"][0]["source"]
    assert source.startswith("#OutBool := #Enable AND (#InInt >= 0) OR (#Mode = 2);")
    assert "END_IF;" in source


def test_parse_simaticml_db_and_tags(datapath):
    db = s7_parse.parse_simaticml(
        datapath("tia-portal-openness-mcp/DB_HMI_Interface.xml").read_bytes()
    )
    block = db["blocks"][0]
    assert (block["type"], block["name"], block["number"]) == ("GlobalDB", "DB_HMI_Interface", 200)
    assert {"name": "OutputMax", "data_type": "Real", "start_value": "100.0"} in block[
        "interface"
    ]["Static"]

    tags = s7_parse.parse_simaticml(
        datapath("tia-portal-openness-mcp/MCP_E2E_Tags.xml").read_bytes()
    )
    assert tags["tag_tables"][0]["name"] == "MCP_E2E"
    assert tags["tag_tables"][0]["tags"][0] == {
        "name": "StartPB",
        "data_type": "Bool",
        "address": "%I0.0",
    }


def test_parse_simaticml_invalid():
    with pytest.raises(ParseError):
        s7_parse.parse_simaticml(b"<Project/>")
    with pytest.raises(ParseError):
        s7_parse.parse_simaticml(b"<Document><Engineering version='V17'/></Document>")
    with pytest.raises(ParseError):
        s7_parse.parse_simaticml(b"not xml")


def test_parse_stl_source(datapath):
    text = datapath("step7-classic-algorithms/TON_D_ms.awl").read_text()
    result = s7_parse.parse_s7_source(text, "TON_D_ms.awl")
    assert result["format"] == "STL source"
    block = result["blocks"][0]
    assert block["type"] == "FC"
    assert block["name"] == "TON_D_ms"
    assert block["return_type"] == "VOID"
    assert block["title"] == "ON-DELAY_TIMER_MSEC"
    assert (block["author"], block["family"], block["header_name"], block["version"]) == (
        "LEONARDO",
        "TIMING",
        "SD_T_MS",
        "1.0",
    )
    assert block["interface"]["Input"][1] == {
        "name": "PRESET",
        "data_type": "DINT",
        "comment": "Timer Preset Value (milliseconds)",
    }
    assert block["interface"]["InOut"] == [
        {"name": "ACCUM", "data_type": "DINT", "comment": "Time Accumulator (milliseconds)"}
    ]
    assert block["language"] == "STL"


def test_parse_stl_source_multiple_blocks(datapath):
    text = datapath("awlsim/trafficlights_2.awl").read_text(encoding="latin-1")
    blocks = s7_parse.parse_s7_source(text, "trafficlights_2.awl")["blocks"]
    assert [(b["type"], b["name"]) for b in blocks] == [
        ("FC", "Ampelsteuerung"),
        ("OB", "OB 1"),
        ("OB", "OB 100"),
    ]
    assert "title" not in blocks[0]  # empty "TITLE ="
    assert blocks[0]["network_count"] == 6
    assert blocks[1]["number"] == 1
    assert blocks[1]["title"] == "Main Program Sweep (Cycle)"
    assert len(blocks[1]["interface"]["Temp"]) == 10


def test_parse_scl_source(datapath):
    text = datapath("s7-plc-snippets/GET_OUC.scl").read_text(encoding="utf-8-sig")
    block = s7_parse.parse_s7_source(text, "GET_OUC.scl")["blocks"][0]
    assert (block["type"], block["name"], block["language"]) == ("FB", "GET_OUC", "SCL")
    assert block["author"] == "ThomasWiens"
    assert block["attributes"] == {"S7_Optimized_Access": "FALSE"}
    # Struct members are not included as top-level interface members
    names = [m["name"] for m in block["interface"]["Input"]]
    assert "REQ" in names
    assert "syntaxid" not in names


def test_parse_scl_source_db_and_udt(datapath):
    text = datapath("s7-plc-snippets/Globaldaten.scl").read_text(encoding="utf-8-sig")
    db, udt = s7_parse.parse_s7_source(text, "Globaldaten.scl")["blocks"]
    assert (db["type"], db["name"]) == ("DB", "global")
    assert [m["name"] for m in db["interface"]["Static"]] == [
        "sym", "symval", "input", "input_pos", "code_cnt", "code_entry",
    ]  # fmt: skip
    assert (udt["type"], udt["name"]) == ("UDT", "stack_t")
    assert udt["interface"]["Static"][1] == {
        "name": "size_act",
        "data_type": "INT",
        "start_value": "0",
        "comment": "aktuelle Größe",
    }


def test_parse_s7_source_invalid():
    with pytest.raises(ParseError):
        s7_parse.parse_s7_source("just some text", "notes.txt")


def test_parse_symbol_table_asc(datapath):
    text = datapath("awlsim/trafficlights_2.asc").read_text(encoding="latin-1")
    symbols = s7_parse.parse_symbol_table(text, "trafficlights_2.asc")
    assert len(symbols) == 9
    assert symbols[2] == {
        "name": "H3",
        "address": "A 0.2",
        "data_type": "BOOL",
        "comment": "Autoampel Grün",
    }
    assert symbols[-1] == {
        "name": "Ampelsteuerung",
        "address": "FC 1",
        "data_type": "FC 1",
        "comment": "",
    }


def test_parse_symbol_table_sdf():
    text = '"Motor_On","Q      4.0","BOOL","Motor contactor"\r\n"Level","IW   256","INT",""\r\n'
    assert s7_parse.parse_symbol_table(text, "symbols.sdf") == [
        {
            "name": "Motor_On",
            "address": "Q 4.0",
            "data_type": "BOOL",
            "comment": "Motor contactor",
        },
        {"name": "Level", "address": "IW 256", "data_type": "INT", "comment": ""},
    ]
    with pytest.raises(ParseError):
        s7_parse.parse_symbol_table("", "empty.sdf")
