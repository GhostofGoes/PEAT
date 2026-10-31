import io
import re
import struct
import zlib
from datetime import UTC, datetime

import pytest

from peat import ParseError
from peat.modules.rockwell import rss_parse
from peat.modules.rockwell.rss_parse import (
    decode_object_data,
    find_referenced_data_files,
    is_rslogix500_project,
    normalize_address,
    parse_mem_database,
    parse_processor,
    parse_program_files,
    parse_rss,
    parse_vba_project,
    parse_version,
    read_rss,
    render_ladder_text,
    render_rung,
)
from peat.parsing.mfc_archive import MAX_CSTRING_LENGTH, MfcFormatError

from .rss_fixtures import (
    COP,
    EQU,
    OTE,
    XIC,
    XIO,
    build_cfb,
    default_comments,
    default_entries,
    default_program_files,
    default_summary,
    default_tree,
    first_u16_payload,
    ins,
    ladder_payload,
    make_rss,
    memdb_payload,
    object_data,
    processor_payload,
    summary_info_stream,
    vba_project_text,
    version_payload,
)


def _rungs(result: dict, number: int) -> list[str]:
    pfile = next(p for p in result["program_files"] if p["number"] == number)
    return [rung["text"] for rung in pfile["rungs"]]


# ----------------------------------------------------------------------------
# ObjectData header and compression
# ----------------------------------------------------------------------------


@pytest.mark.parametrize(("mode", "name"), [(0, "stored"), (1, "pkware-dcl"), (2, "zlib")])
def test_decode_object_data_modes(mode, name):
    payload = b"\xff\xff\x80\x00\x05\x00CProc" + bytes(range(200))
    decoded, info = decode_object_data(object_data(payload, mode))
    assert decoded == payload
    assert info["status"] == "ok"
    assert info["compression"] == name
    assert info["mode"] == mode
    assert info["decoded_size"] == len(payload)


def test_decode_object_data_unknown_mode():
    decoded, info = decode_object_data(object_data(b"abc", 0, header_mode=7))
    assert decoded is None
    assert info["status"] == "unknown_mode"
    assert info["compression"] == "unknown"


@pytest.mark.parametrize(
    "raw",
    [b"", b"\x00" * 15, struct.pack("<4I", 0, 0, 0, 0) + b"abc", struct.pack("<4I", 2, 20, 3, 3)],
)
def test_decode_object_data_bad_header(raw):
    decoded, info = decode_object_data(raw)
    assert decoded is None
    assert info["status"] == "bad_header"


def test_decode_object_data_size_mismatch():
    decoded, info = decode_object_data(object_data(b"abcdef", 2, decoded_size=99))
    assert decoded == b"abcdef"
    assert info["status"] == "size_mismatch"
    assert "header says 99" in info["error"]


def test_decode_object_data_stored_size_mismatch():
    raw = object_data(b"abcdef", 0) + b"extra"
    decoded, info = decode_object_data(raw)
    assert decoded == b"abcdef"
    assert info["status"] == "size_mismatch"


def test_decode_object_data_corrupt():
    raw = struct.pack("<4I", 2, 16, 6, 10) + b"\x78\x9cbad!"
    decoded, info = decode_object_data(raw)
    assert decoded is None
    assert info["status"] == "decode_error"

    raw = struct.pack("<4I", 1, 16, 2, 10) + b"\x05\x06"
    decoded, info = decode_object_data(raw)
    assert decoded is None
    assert info["status"] == "decode_error"


def test_decode_object_data_too_large():
    payload = b"\x00" * 5000
    for mode in (0, 1, 2):
        decoded, info = decode_object_data(object_data(payload, mode), max_size=4096)
        assert decoded is None, mode
        assert info["status"] == "too_large", mode

    # Header lies about the decoded size: the zlib output limit still applies
    raw = object_data(payload, 2, decoded_size=100)
    decoded, info = decode_object_data(raw, max_size=4096)
    assert decoded is None
    assert info["status"] == "too_large"

    # DCL output is limited to the declared size plus some slack
    raw = object_data(b"\x00" * 100_000, 1, decoded_size=10)
    decoded, info = decode_object_data(raw)
    assert decoded is None
    assert info["status"] == "decode_error"


# ----------------------------------------------------------------------------
# Ladder logic
# ----------------------------------------------------------------------------


def test_parse_program_files():
    result = parse_program_files(ladder_payload(default_program_files()))
    assert result["declared_count"] == 4
    assert result["warnings"] == []
    assert result["cins_tag"] == "0b80"
    files = result["program_files"]
    assert [(p["number"], p["name"], p["type_name"]) for p in files] == [
        (0, "", "system"),
        (1, "", "system"),
        (2, "MAIN", "ladder"),
        (3, "SUB_A", "ladder"),
    ]
    assert all(not p["warnings"] for p in files)

    main = [rung["text"] for rung in files[2]["rungs"]]
    assert main == [
        "SOR OTE B3:0/2 EOR",
        "SOR MVM N7:2 00FFh N7:3 EOR",
        "SOR BST XIC I:1/0 XIO B3:2/4 NXB XIO I:1/0 XIC B3:2/4 BND OTE O:0/2 EOR",
        "SOR OP_7E ALPHA BETA EOR",
        "SOR EQU N7:2 3 JSR U:3 EOR",
        "SOR END EOR",
    ]
    sub = [rung["text"] for rung in files[3]["rungs"]]
    assert sub == [
        "SOR XIC S:1/13 BST XIC B3:1/0 BST XIO T4:1/DN NXB XIC C5:2/DN BND NXB "
        "OTL B3:1/1 BND COP #N10:4 #O:2.0 4 EOR",
        "SOR MOV N7:2 F8:1 EOR",
    ]

    # Token details
    tokens = files[2]["rungs"][1]["tokens"]
    assert tokens[0]["flag"] == 1
    mvm = tokens[1]
    assert mvm["mnemonic"] == "MVM"
    assert mvm["opcode_hex"] == "26"
    assert mvm["confidence"] == "high"
    assert mvm["operands"] == ["N7:2", "0", "00FFh", "255", "N7:3", "0"]
    assert mvm["compiled_hex"] == "26010203"
    unknown = files[2]["rungs"][3]["tokens"][1]
    assert unknown["mnemonic"] == "OP_7E"
    assert unknown["confidence"] == "unknown"
    # First rung's SOR has no compiled blob (flag 0)
    first = files[2]["rungs"][0]["tokens"][0]
    assert (first["mnemonic"], first["flag"], first["compiled_hex"]) == ("SOR", 0, "")


def test_parse_program_files_old_schema():
    result = parse_program_files(ladder_payload(default_program_files(), schema=0x71))
    assert len(result["program_files"][2]["rungs"]) == 6
    assert result["warnings"] == []


def test_parse_program_files_learns_cins_tag():
    # An extra program file before the first rung changes the CIns class index
    files = default_program_files()
    files.insert(2, {"number": 2, "name": "EMPTY", "type": 1})
    for number, pfile in enumerate(files):
        pfile["number"] = number
    result = parse_program_files(ladder_payload(files))
    assert result["cins_tag"] == "0c80"
    assert result["warnings"] == []
    assert len(result["program_files"][3]["rungs"]) == 6


def test_parse_program_files_cins_tag_differs_from_numbering():
    result = parse_program_files(ladder_payload(default_program_files(), index_gaps={"CIns": 5}))
    assert result["cins_tag"] == "1080"
    assert any("differs from the expected tag" in w for w in result["warnings"])
    assert len(result["program_files"][2]["rungs"]) == 6


def test_parse_program_files_big_cins_tag():
    payload = ladder_payload(default_program_files(), index_gaps={"CIns": 0x8000})
    result = parse_program_files(payload)
    assert result["cins_tag"].startswith("ff7f")
    assert len(result["program_files"][2]["rungs"]) == 6
    assert len(result["program_files"][3]["rungs"]) == 2


def test_parse_program_files_fake_tag_in_blob():
    # A compiled blob that contains the CIns tag and a valid looking instruction
    fake = b"\x0b\x80\x01\x00\x04FAKE\x00\x00\x2f\x00\x00\x00\x00\x00"
    files = [
        {"number": 0, "name": "", "type": 0},
        {"number": 1, "name": "", "type": 2},
        {
            "number": 2,
            "name": "",
            "type": 1,
            "rungs": [
                [ins(XIC, "B3:0/0"), ins(OTE, "O:0/0")],
                [ins(XIC, "B3:0/1", blob=b"\x39" + fake), ins(OTE, "O:0/1")],
                [ins(XIO, "B3:0/1"), ins(OTE, "O:0/2")],
            ],
        },
    ]
    result = parse_program_files(ladder_payload(files))
    assert _rungs(result, 2) == [
        "SOR XIC B3:0/0 OTE O:0/0 EOR",
        "SOR XIC B3:0/1 OTE O:0/1 EOR",
        "SOR XIO B3:0/1 OTE O:0/2 EOR",
    ]
    assert result["program_files"][2]["warnings"] == []


def test_parse_program_files_declared_rungs_too_high():
    files = default_program_files()
    files[2]["declared_rungs"] = 9
    result = parse_program_files(ladder_payload(files))
    main = result["program_files"][2]
    assert len(main["rungs"]) == 6
    assert "declared 9 rungs, decoded 6" in main["warnings"]
    # The next file's rungs aren't consumed
    assert len(result["program_files"][3]["rungs"]) == 2


def test_parse_program_files_missing_files():
    result = parse_program_files(ladder_payload(default_program_files(), declared_count=6))
    assert len(result["program_files"]) == 4
    assert "found 4 of 6 program files" in result["warnings"]


def test_parse_program_files_truncated():
    payload = ladder_payload(default_program_files())
    result = parse_program_files(payload[: len(payload) - 60])
    sub = result["program_files"][3]
    assert len(sub["rungs"]) < 2 or "last rung is incomplete" in sub["warnings"]
    assert any("decoded" in w or "incomplete" in w for w in sub["warnings"])


def test_parse_program_files_not_a_program():
    with pytest.raises(MfcFormatError):
        parse_program_files(b"\xff\xff\x80\x00\x05\x00CProc\x00\x00")
    with pytest.raises(MfcFormatError):
        parse_program_files(b"")


def test_parse_program_files_too_many_files():
    with pytest.raises(MfcFormatError, match="too large"):
        parse_program_files(b"\xff\xff\x80\x00\x0b\x00CProgHolder\xff\xff")


@pytest.mark.parametrize(
    ("opcodes", "problem"),
    [
        ([0, 2, 4, 5, 1], "not closed"),
        ([0, 3, 1], "branch end without a branch start"),
        ([0, 4, 1], "branch leg outside of a branch"),
        ([0, 2, 4, 3, 1], "branch ended while a leg was open"),
        ([0, 2, 5, 3, 1], "leg end without a leg start"),
        ([0, 2, 4, 4, 5, 3, 1], "started before the previous leg ended"),
        ([2, 3, 1], "doesn't start with SOR"),
        ([0, 0x39], "doesn't end with EOR"),
    ],
)
def test_render_rung_problems(opcodes, problem):
    tokens = [{"opcode": op, "operands": []} for op in opcodes]
    _, problems = render_rung(tokens)
    assert any(problem in p for p in problems), problems


@pytest.mark.parametrize(
    ("opcodes", "expected"),
    [
        # Empty (shorted) first leg: regression, the NXB used to be dropped
        ([0, 2, 4, 5, 4, XIC, 5, 3, OTE, 1], "SOR BST NXB XIC BND OTE EOR"),
        # Empty middle and last legs
        ([0, 2, 4, XIC, 5, 4, 5, 4, XIO, 5, 3, 1], "SOR BST XIC NXB NXB XIO BND EOR"),
        ([0, 2, 4, XIC, 5, 4, 5, 3, 1], "SOR BST XIC NXB BND EOR"),
        # First leg without a leg start
        ([0, 2, XIC, 4, XIO, 5, 3, 1], "SOR BST XIC NXB XIO BND EOR"),
        # Nested branch with an empty first leg, in the second leg of a branch
        (
            [0, 2, 4, XIC, 5, 4, 2, 4, 5, 4, XIO, 5, 3, 5, 3, 1],
            "SOR BST XIC NXB BST NXB XIO BND BND EOR",
        ),
    ],
)
def test_render_rung_legs(opcodes, expected):
    tokens = [{"opcode": op, "operands": []} for op in opcodes]
    assert render_rung(tokens) == (expected, [])


def test_render_rung_paired_odd_operands():
    # Paired opcodes with an odd number of strings show all of them
    tokens = [
        {"opcode": 0, "operands": []},
        {"opcode": EQU, "operands": ["N7:0", "1", "2"]},
        {"opcode": 1, "operands": []},
    ]
    assert render_rung(tokens) == ("SOR EQU N7:0 1 2 EOR", [])


def _break_eor(payload: bytes, rung: int) -> bytes:
    """Change the opcode of the EOR at the end of a rung of file 2 into XIO."""
    # No operands, flag 0 or 1, opcode EOR, reserved
    eor = re.compile(rb"\x00\x00[\x00\x01]\x00\x01\x00\x00\x00\x00\x00")
    at = payload.index(b"MAIN")
    for _ in range(rung + 1):
        at = eor.search(payload, at + 1).start()
    return payload[: at + 4] + b"\x3a\x00" + payload[at + 6 :]


def test_parse_program_files_missing_eor():
    payload = _break_eor(ladder_payload(default_program_files()), 0)
    result = parse_program_files(payload)
    main = result["program_files"][2]
    assert main["rungs"][0]["text"] == "SOR OTE B3:0/2 XIO"
    assert main["rungs"][1]["text"] == "SOR MVM N7:2 00FFh N7:3 EOR"
    assert "rung 0: rung doesn't end with EOR" in main["warnings"]
    assert len(main["rungs"]) == 6
    assert len(result["program_files"][3]["rungs"]) == 2


@pytest.mark.parametrize("rung", [1, 3, 4])
def test_parse_program_files_missing_eor_keeps_later_files(rung):
    # Regression: the recovery used to overwrite the program file number with
    # the rung number, so the next file (number 3) was rejected if rung >= 3
    payload = _break_eor(ladder_payload(default_program_files()), rung)
    result = parse_program_files(payload)
    assert [p["number"] for p in result["program_files"]] == [0, 1, 2, 3]
    main = result["program_files"][2]
    assert f"rung {rung}: rung doesn't end with EOR" in main["warnings"]
    assert len(main["rungs"]) == 6
    assert _rungs(result, 3) == [
        "SOR XIC S:1/13 BST XIC B3:1/0 BST XIO T4:1/DN NXB XIC C5:2/DN BND "
        "NXB OTL B3:1/1 BND COP #N10:4 #O:2.0 4 EOR",
        "SOR MOV N7:2 F8:1 EOR",
    ]
    assert not any("invalid program file header" in w for w in result["warnings"])


def test_parse_program_files_unbalanced_rung_warning():
    files = [
        {"number": 0, "name": "", "type": 0},
        {"number": 1, "name": "", "type": 2},
        {"number": 2, "name": "", "type": 1, "rungs": [[ins(2), ins(COP, "#N7:0", "#N7:1", "1")]]},
    ]
    result = parse_program_files(ladder_payload(files))
    assert any("not closed" in w for w in result["program_files"][2]["warnings"])


# ----------------------------------------------------------------------------
# MEM DATABASE
# ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("N0007:003/05", "N7:3/5"),
        ("N0010:120", "N10:120"),
        ("T0004:002", "T4:2"),
        ("B0003:000/00", "B3:0/0"),
        ("I0001:002.000/03", "I:2.0/3"),
        ("O0000:004.001", "O:4.1"),
        ("S0002:001/13", "S:1/13"),
        ("ST0012:001", "ST12:1"),
        ("PFILE:00003", "PFILE:00003"),
        ("M00000:008.000", "M0:8.0"),
        ("M10000:008.001/15", "M1:8.1/15"),
        ("MG0009:000", "MG9:0"),
        ("garbage", "garbage"),
    ],
)
def test_normalize_address(raw, expected):
    assert normalize_address(raw) == expected


def test_parse_mem_database():
    result = parse_mem_database(memdb_payload(default_entries(), default_comments()))
    assert result["warnings"] == []
    assert result["declared_entry_count"] == 7
    assert result["status_text"] == "Synthetic DB"
    assert result["schema"] == 0x80
    entries = result["entries"]
    assert [(e["address"], e["kind"]) for e in entries] == [
        ("S:1/13", "data"),
        ("B3:0/2", "data"),
        ("N7:2", "data"),
        ("I:0/0", "data"),
        ("O:0/2", "data"),
        ("PFILE:00003", "program_file"),
        ("N7:3", "data"),
    ]
    assert entries[2]["symbol"] == "SPEED"
    assert entries[2]["description_lines"] == ["Speed", "setpoint", "", "", ""]
    assert entries[2]["address_raw"] == "N0007:002"

    comments = {(c["file"], c["rung"]): c["text"] for c in result["rung_comments"]}
    assert comments == {
        (3, 0): "Latch the alarm when\r\nthe first pass bit is set.",
        (2, 2): "Exclusive OR of the start button and B3:2/4",
        (2, 0): "Always energize the pump enable bit",
    }


def test_parse_mem_database_module_files():
    entries = [("M10000:008.000", "", ["Module input"]), ("M00000:002.001/03", "", ["Out"])]
    result = parse_mem_database(memdb_payload(entries, []))
    assert [(e["address"], e["kind"]) for e in result["entries"]] == [
        ("M1:8.0", "data"),
        ("M0:2.1/3", "data"),
    ]
    assert rss_parse.address_type_name("M10000:008.000") == "module_input"
    assert rss_parse.address_type_name("M00000:002.001/03") == "module_output"


def test_parse_mem_database_long_comment():
    comments = [(2, 0, "x" * 600)]
    result = parse_mem_database(memdb_payload(default_entries(), comments))
    assert result["rung_comments"][0]["text"] == "x" * 600


def test_parse_mem_database_comment_count_mismatch():
    payload = memdb_payload(default_entries(), default_comments(), declared_comments=5)
    result = parse_mem_database(payload)
    assert sorted((c["file"], c["rung"]) for c in result["rung_comments"]) == [
        (2, 0),
        (2, 2),
        (3, 0),
    ]
    assert all(c["text"] == "" for c in result["rung_comments"])
    assert any("couldn't decode the rung comments" in w for w in result["warnings"])


def test_parse_mem_database_entry_count_mismatch():
    payload = memdb_payload(default_entries(), [], declared_entries=9)
    result = parse_mem_database(payload)
    assert len(result["entries"]) == 7
    assert "database header declares 9 entries, decoded 7" in result["warnings"]
    assert result["rung_comments"] == []


def test_parse_mem_database_bad_header():
    # Entries are still found if the header can't be parsed
    payload = memdb_payload(default_entries(), default_comments())
    result = parse_mem_database(b"\xff\xff\x80\x00\x05\x00Other" + payload[15:])
    assert len(result["entries"]) == 7
    assert any("database header" in w for w in result["warnings"])


# ----------------------------------------------------------------------------
# Other sections
# ----------------------------------------------------------------------------


def test_parse_processor():
    result = parse_processor(processor_payload())
    assert result["processor_type_code"] == 0x2B
    assert result["processor_name"] == "PUMP_CTL"
    assert result["comms_driver"] == "AB_DF1-1"
    assert result["comms_driver_settings"] == "AB_DF1-1%SYNTHETIC%D"
    assert result["last_comms_path"] == "ENGWS01!AB_ETH-1\\192.0.2.10"
    assert result["engineering_workstation"] == "ENGWS01"
    assert result["last_comms_driver"] == "AB_ETH-1"
    assert result["warnings"] == []


def test_parse_processor_no_comms_path():
    result = parse_processor(processor_payload(comms_path=None, name="UNTITLED", schema=0x71))
    assert result["schema"] == 0x71
    assert result["processor_name"] == "UNTITLED"
    assert result["last_comms_path"] == ""
    assert result["engineering_workstation"] == ""


def test_parse_processor_truncated_name():
    payload = processor_payload()
    cut = payload.index(b"PUMP_CTL") + 2
    result = parse_processor(payload[:cut])
    assert result["processor_type_code"] == 0x2B
    assert result["processor_name"] == ""
    assert result["warnings"]


def test_parse_version():
    assert parse_version(version_payload("8.30.00.12")) == {
        "rslogix_version": "8.30.00.12",
        "rslogix_version_short": "8.30.00",
        "rslogix_build": "12",
    }


def test_parse_vba_project():
    result = parse_vba_project(vba_project_text())
    assert result == {"present": True, "project_name": "VBASynthetic", "modules": []}

    result = parse_vba_project(vba_project_text(["Module1", "Helpers"]))
    assert [m["name"] for m in result["modules"]] == ["Module1", "Helpers"]

    text = b"Document=Sheet9/&H00000000\r\nClass=Thing\r\nBaseClass=Form1\r\n"
    result = parse_vba_project(text)
    assert [(m["type"], m["name"]) for m in result["modules"]] == [
        ("Document", "Sheet9"),
        ("Class", "Thing"),
        ("BaseClass", "Form1"),
    ]


def test_find_referenced_data_files():
    programs = parse_program_files(ladder_payload(default_program_files()))["program_files"]
    entries = parse_mem_database(memdb_payload(default_entries(), []))["entries"]
    assert find_referenced_data_files(programs, entries) == [
        "B3",
        "C5",
        "F8",
        "I1",
        "N7",
        "N10",
        "O0",
        "S2",
        "T4",
    ]
    assert find_referenced_data_files([], []) == []


def test_find_referenced_data_files_module_files():
    files = [
        {"number": 0, "name": "", "type": 0},
        {"number": 1, "name": "", "type": 2},
        {
            "number": 2,
            "name": "",
            "type": 1,
            "rungs": [[ins(COP, "#M1:8.0", "#N7:10", "16")], [ins(OTE, "M0:3.1/2")]],
        },
    ]
    programs = parse_program_files(ladder_payload(files))["program_files"]
    entries = [{"address_raw": "M10000:008.000"}, {"address_raw": "M00000:008.000"}]
    assert find_referenced_data_files(programs, []) == ["M0", "M1", "N7"]
    assert find_referenced_data_files([], entries) == ["M0", "M1"]


# ----------------------------------------------------------------------------
# Container and the whole project
# ----------------------------------------------------------------------------


def test_is_rslogix500_project(tmp_path):
    with make_rss(tmp_path).open("rb") as fp:
        assert is_rslogix500_project(fp)
        assert fp.tell() == 0
        assert not fp.closed

    other_ole = build_cfb({"Workbook": b"\x00" * 100, "PROCESSOR": {"Other": b"x"}})
    assert not is_rslogix500_project(io.BytesIO(other_ole))
    assert not is_rslogix500_project(io.BytesIO(b""))
    assert not is_rslogix500_project(io.BytesIO(b'<?xml version="1.0"?><rss></rss>'))
    # OLE magic, but not a valid OLE file
    assert not is_rslogix500_project(io.BytesIO(bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 10))


def test_read_rss_errors(tmp_path):
    feed = tmp_path / "news.rss"
    feed.write_text('<?xml version="1.0"?><rss version="2.0"></rss>')
    with pytest.raises(ParseError, match="not an OLE compound file"):
        read_rss(feed)

    other = tmp_path / "other.RSS"
    other.write_bytes(build_cfb({"Workbook": b"\x00" * 100}))
    with pytest.raises(ParseError, match="missing the RSLogix 500 storage"):
        read_rss(other)

    broken = tmp_path / "broken.RSS"
    broken.write_bytes(bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 600)
    with pytest.raises(ParseError, match="failed to read"):
        read_rss(broken)


@pytest.mark.parametrize("mode", [0, 1, 2])
def test_parse_rss(tmp_path, mode):
    path = tmp_path / "project.RSS"
    path.write_bytes(build_cfb(default_tree(mode)))
    container = read_rss(path)
    result = parse_rss(container)

    assert result["errors"] == []
    assert result["warnings"] == []
    assert result["file_format_version"] == 0x80
    assert result["processor"]["processor_name"] == "PUMP_CTL"
    assert result["version"]["rslogix_version"] == "9.99.00.01"
    assert result["io_type_code"] == 0x2B
    assert result["num_data_files"] == 9
    assert result["program_files_declared"] == 4
    assert len(_rungs(result, 2)) == 6
    assert len(result["online_image_program_files"][2]["rungs"]) == 7
    assert result["online_image_differs"] == {"PROCESSOR": False, "PROGRAM FILES": True}
    assert len(result["documentation"]) == 7
    assert len(result["rung_comments"]) == 3
    assert result["vba"]["present"] is True
    assert result["vba"]["modules"] == []
    assert "N7" in result["referenced_data_files"]

    summary = result["summary_info"]
    assert summary["author"] == "jdoe"
    assert summary["last_saved_by"] == "operator2"
    assert summary["create_time"] == datetime(2011, 3, 4, 5, 6, 7, tzinfo=UTC)
    assert summary["last_saved_time"] == datetime(2012, 8, 9, 10, 11, 12, tzinfo=UTC)
    assert summary["processor_name"] == "PUMP_CTL"
    assert summary["num_program_files"] == 4
    assert summary["num_data_files"] == 9
    assert summary["other_properties"] == {"21": 0}

    inventory = {item["path"]: item for item in container.inventory}
    item = inventory["PROGRAM FILES/ObjectData"]
    assert item["status"] == "ok"
    assert item["mode"] == mode
    assert item["mfc_classes"][:3] == ["CProgHolder", "CLadFile", "CRung"]
    assert len(item["sha256"]) == 64
    assert "size" in inventory["Contents"]
    assert [i["path"] for i in container.inventory] == sorted(inventory)


def test_parse_rss_cross_checks(tmp_path):
    tree = default_tree()
    tree["IO CONFIGURATION"]["ObjectData"] = object_data(first_u16_payload("CIOInfo", 0x11), 0)
    tree["DATA FILES"]["ObjectData"] = object_data(first_u16_payload("CDataHolder", 3))
    comments = [*default_comments(), (9, 0, "Comment for a missing file")]
    tree["MEM DATABASE"]["ObjectData"] = object_data(memdb_payload(default_entries(), comments))
    tree["PROCESSOR"]["ObjectData"] = object_data(processor_payload(name="OTHER"), 0)
    result = parse_rss(read_rss(make_rss(tmp_path, tree=tree)))
    warnings = "\n".join(result["warnings"])
    assert "processor type code 0x2b != I/O configuration type code 0x11" in warnings
    assert "SummaryInformation has 9 data files, CDataHolder has 3" in warnings
    assert "processor name 'OTHER' != SummaryInformation processor name" in warnings
    assert "rung comment for file 9 rung 0" in warnings
    assert result["errors"] == []


def test_parse_rss_section_failures(tmp_path):
    """A broken section is recorded and the other sections are still decoded."""
    tree = default_tree()
    tree["MEM DATABASE"]["ObjectData"] = struct.pack("<4I", 2, 16, 6, 10) + b"\x78\x9cbad!"
    tree["Version"]["ObjectData"] = object_data(b"\xff\xff\x80\x00\x05\x00Wrong")
    tree["PROGRAM FILES"]["ObjectData"] = object_data(zlib.compress(b"x"), 0, header_mode=9)
    container = read_rss(make_rss(tmp_path, tree=tree))
    result = parse_rss(container)

    inventory = {item["path"]: item for item in container.inventory}
    assert inventory["MEM DATABASE/ObjectData"]["status"] == "decode_error"
    assert inventory["PROGRAM FILES/ObjectData"]["status"] == "unknown_mode"
    assert container.streams["MEM DATABASE/ObjectData"].payload is None
    assert container.streams["MEM DATABASE/ObjectData"].raw  # Raw bytes are kept
    assert "PROGRAM FILES stream couldn't be decoded" in result["errors"]
    assert any(e.startswith("failed to parse Version") for e in result["errors"])
    assert result["processor"]["processor_name"] == "PUMP_CTL"
    assert result["documentation"] == []
    assert result["program_files"] == []


def test_parse_rss_legacy_database(tmp_path):
    tree = default_tree()
    del tree["MEM DATABASE"]
    tree["DATABASE"] = {"ObjectData": b"\x87\x79\x00\x80" + b"\x00" * 60}
    container = read_rss(make_rss(tmp_path, tree=tree))
    assert container.streams["DATABASE/ObjectData"].info["status"] == "not_decoded"
    assert parse_rss(container)["warnings"] == []


def test_read_rss_stream_limits(tmp_path, monkeypatch):
    path = make_rss(tmp_path)
    monkeypatch.setattr(rss_parse, "MAX_STREAM_COUNT", 3)
    container = read_rss(path, max_size=200)
    assert len(container.streams) == 3
    assert any("only reading the first 3" in w for w in container.warnings)


def test_read_rss_too_large_stream(tmp_path):
    container = read_rss(make_rss(tmp_path), max_size=250)
    info = container.streams["PROGRAM FILES/ObjectData"].info
    assert info["status"] == "too_large"
    result = parse_rss(container)
    assert "PROGRAM FILES stream couldn't be decoded" in result["errors"]


def test_parse_rss_vba_modules(tmp_path):
    tree = default_tree()
    tree["apc"]["The VBA Project"]["_VBA_Project"]["PROJECT"] = vba_project_text(["Macro1"])
    result = parse_rss(read_rss(make_rss(tmp_path, tree=tree)))
    assert result["vba"]["modules"] == [{"type": "Module", "name": "Macro1"}]


def test_parse_rss_minimal(tmp_path):
    tree = {
        "PROCESSOR": {"ObjectData": object_data(processor_payload(name="UNTITLED"), 0)},
        "PROGRAM FILES": {"ObjectData": object_data(ladder_payload(default_program_files()))},
    }
    result = parse_rss(read_rss(make_rss(tmp_path, tree=tree)))
    assert result["errors"] == []
    assert result["summary_info"] == {}
    assert result["file_format_version"] is None
    assert result["vba"]["present"] is False
    assert result["online_image_differs"] == {}
    assert len(_rungs(result, 3)) == 2


def test_render_ladder_text(tmp_path):
    result = parse_rss(read_rss(make_rss(tmp_path)))
    text = render_ladder_text(result)
    lines = text.splitlines()
    assert lines[0] == (
        "; RSLogix 500 project PUMP_CTL | format 0x80 | saved by RSLogix 500 9.99.00.01"
    )
    assert '; Program file 2 "MAIN" (ladder, 6 rungs)' in lines
    assert "; Rung 2:0 comment: Always energize the pump enable bit" in lines
    # Multi-line comments are collapsed to one line
    assert "; Rung 3:0 comment: Latch the alarm when the first pass bit is set." in lines
    assert "0002 SOR BST XIC I:1/0 XIO B3:2/4 NXB XIO I:1/0 XIC B3:2/4 BND OTE O:0/2 EOR" in lines
    assert text.endswith("\n")

    online = render_ladder_text(result, result["online_image_program_files"])
    assert '; Program file 2 "MAIN" (ladder, 7 rungs)' in online


def test_render_ladder_text_without_comments(tmp_path):
    result = parse_rss(read_rss(make_rss(tmp_path)))
    online = render_ladder_text(result, result["online_image_program_files"])
    assert "comment:" not in online
    assert "comment:" in render_ladder_text(result, result["online_image_program_files"], True)
    assert "; Rung comments aren't shown, they belong to the offline program" in online
    assert "0005 SOR XIC B3:0/2 OTE O:0/5 EOR" in online


# ----------------------------------------------------------------------------
# Untrusted input: types, limits and work budgets
# ----------------------------------------------------------------------------


def test_parse_rss_summary_info_wrong_types(tmp_path):
    """Named properties with an unexpected type don't break the parse."""
    tree = default_tree()
    summary = default_summary()
    summary[20] = 12345  # Processor name as an integer
    summary[12] = "not a time"
    summary[25] = "4"
    tree["\x05SummaryInformation"] = summary_info_stream(summary)
    tree["PROCESSOR"]["ObjectData"] = object_data(processor_payload(name=""), 0)
    container = read_rss(make_rss(tmp_path, tree=tree))
    info = container.summary_info
    assert "processor_name" not in info
    assert "create_time" not in info
    assert "num_program_files" not in info
    assert info["other_properties"]["20"] == 12345
    assert info["other_properties"]["12"] == "not a time"
    assert info["last_saved_time"] == datetime(2012, 8, 9, 10, 11, 12, tzinfo=UTC)
    assert any("property 20 (processor_name)" in w for w in container.warnings)

    result = parse_rss(container)
    assert result["errors"] == []
    assert render_ladder_text(result).startswith("; RSLogix 500 project (unnamed)")


def test_parse_rss_cross_check_failure_is_isolated(tmp_path, monkeypatch):
    def _broken(_result):
        raise TypeError("broken")

    monkeypatch.setattr(rss_parse, "_cross_check", _broken)
    result = parse_rss(read_rss(make_rss(tmp_path)))
    assert "failed to parse cross-checks: broken" in result["errors"]
    assert len(result["program_files"]) == 4


def test_read_rss_total_size_limit(tmp_path):
    path = make_rss(tmp_path)
    container = read_rss(path)
    total = sum(len(s.raw) + len(s.payload or b"") for s in container.streams.values())
    limited = read_rss(path, max_total_size=total // 2)
    statuses = [s.info.get("status") for s in limited.streams.values()]
    assert "too_large" in statuses
    assert len(limited.streams) == len(container.streams)  # All are in the inventory
    kept = sum(len(s.raw) + len(s.payload or b"") for s in limited.streams.values())
    assert kept <= total // 2
    assert any("total size limit" in w for w in limited.warnings)

    assert all(s.info.get("status") != "too_large" for s in container.streams.values())


def test_read_cins_fails_fast():
    # The second operand isn't printable: the rest isn't read
    data = b"\x20\x00" + b"\x01A" + b"\x02\x00\x01" + b"\x05hello" * 30
    budget = rss_parse._ScanBudget(10)
    with pytest.raises(MfcFormatError, match="printable"):
        rss_parse._read_cins(data, 0, budget=budget)
    assert budget.attempts == 9
    assert budget.scan_bytes == rss_parse._MAX_SCAN_BYTES - 7


def _junk_ladder(junk: bytes) -> bytes:
    """A program file followed by data with many candidate instruction tags."""
    files = [
        {"number": 0, "name": "", "type": 0},
        {"number": 1, "name": "", "type": 2},
        {"number": 2, "name": "MAIN", "type": 1, "rungs": [[ins(XIC, "I:1/0")]] * 3},
    ]
    payload = ladder_payload(files)
    # Insert the junk before the last rung, and claim there are more rungs
    at = payload.rindex(b"\x05I:1/0") - 4
    payload = bytearray(payload[:at] + junk + payload[at:])
    hdr = payload.index(b"MAIN") - 4
    struct.pack_into("<H", payload, hdr, 50)
    struct.pack_into("<H", payload, hdr + 17, 50)
    return bytes(payload)


def test_parse_program_files_vote_budget(monkeypatch):
    monkeypatch.setattr(rss_parse, "_MAX_VOTE_ATTEMPTS", 5)
    result = parse_program_files(_junk_ladder(b"\x00\x80\x20\x00" * 50))
    assert "stopped learning the CIns tag after 5 attempts" in result["warnings"]


def test_parse_program_files_resync_budget(monkeypatch):
    payload = _junk_ladder(b"\x0b\x80\x20\x00" * 50)
    unlimited = parse_program_files(payload)
    assert not any("stopped decoding" in w for w in unlimited["warnings"])

    monkeypatch.setattr(rss_parse, "_MAX_RESYNC_ATTEMPTS", 10)
    result = parse_program_files(payload)
    assert any(
        "stopped decoding in program file 2: too many invalid instruction records" in w
        for w in result["warnings"]
    )
    assert len(result["program_files"]) == 3


def test_parse_program_files_instruction_limit(monkeypatch):
    monkeypatch.setattr(rss_parse, "_MAX_INSTRUCTIONS", 5)
    result = parse_program_files(ladder_payload(default_program_files()))
    tokens = [t for f in result["program_files"] for r in f["rungs"] for t in r["tokens"]]
    assert len(tokens) == 5
    assert any("more than 5 instructions" in w for w in result["warnings"])
    assert [p["number"] for p in result["program_files"]] == [0, 1, 2]


def test_parse_mem_database_entry_limits(monkeypatch):
    payload = memdb_payload(default_entries(), default_comments())
    monkeypatch.setattr(rss_parse, "_MAX_DB_ENTRIES", 2)
    result = parse_mem_database(payload)
    assert len(result["entries"]) == 2
    assert "stopped looking for database entries after 2 entries" in result["warnings"]

    monkeypatch.setattr(rss_parse, "_MAX_DB_ENTRIES", 1000)
    monkeypatch.setattr(rss_parse, "_MAX_DB_ENTRY_FAILURES", 2)
    # Offsets that look like an entry, but aren't
    junk = b"\x08N7:000AB" * 4
    at = payload.index(b"\x0cS0002:001/13")
    result = parse_mem_database(payload[:at] + junk + payload[at:])
    assert result["entries"] == []
    assert any("too many invalid entries" in w for w in result["warnings"])


def test_parse_mem_database_comment_search_is_bounded(monkeypatch):
    """
    Regression: the search for the rung comment count used to decode the
    comment text at every possible offset, which took hours on crafted data.
    """
    calls = []

    class CountingReader(rss_parse.MfcReader):
        def cstring(self, max_length=MAX_CSTRING_LENGTH):
            calls.append(max_length)
            return super().cstring(max_length)

    monkeypatch.setattr(rss_parse, "MfcReader", CountingReader)
    # Many copies of the comment count (255), each followed by a huge length
    unit = bytes([0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0xFF, 0xFF])
    keys = b"".join(b"\x11" + f"RUNG{2:06d}-{k:06d}".encode() for k in range(255))
    payload = memdb_payload([], []) + unit * 20_000 + keys
    result = parse_mem_database(payload)
    assert len(result["rung_comments"]) == 255
    assert any("couldn't decode the rung comments" in w for w in result["warnings"])
    assert len(calls) < 50


def test_parse_mem_database_longest_comment():
    text = "y" * rss_parse._MAX_RUNG_COMMENT_LENGTH
    result = parse_mem_database(memdb_payload(default_entries(), [(2, 0, text), (2, 1, "z")]))
    assert [c["text"] for c in result["rung_comments"]] == [text, "z"]

    # Too long to be a real comment: only the keys are reported
    result = parse_mem_database(memdb_payload(default_entries(), [(2, 0, text + "y")]))
    assert result["rung_comments"][0]["text"] == ""
    assert any("couldn't decode the rung comments" in w for w in result["warnings"])
