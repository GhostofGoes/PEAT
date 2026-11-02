"""
Tests for the SEL Compressed ASCII parser (``peat/modules/sel/sel_cascii.py``)
and the ``ID`` command output parsing that uses it.

Unless noted, the data is synthetic, modeled on the Compressed ASCII format
described in public SEL instruction manuals (SEL-421 Instruction Manual
20130627, Reference Manual section 5 "SEL Compressed ASCII Commands";
SEL-351S Instruction Manual 20171023, Appendix K; SEL-551 Instruction Manual
20151105, Appendix E). The checksums of the synthetic lines were calculated
with the algorithm from those manuals. A few single lines are quoted from
the manuals as test vectors, with the source next to them.
"""

import pytest

from peat import config, datastore
from peat.modules.sel import sel_cascii
from peat.modules.sel.sel_cascii import (
    Field,
    checksum,
    extract_messages,
    format_record,
    is_compressed_ascii,
    is_no_data,
    parse_cas,
    parse_id_output,
    parse_number,
    parse_records,
    parse_report,
    split_records,
    tokenize,
)
from peat.modules.sel.sel_telnet import SELTelnet


@pytest.fixture(autouse=True)
def _env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])


# Output of the "id" command captured by PEAT from a SEL-700G (docs/sel.rst)
ID_700G = [
    "id",
    "\x02",
    '"FID=SEL-700G-R200-V0-Z006003-D20180629","08F0"',
    '"BFID=BOOTLDR-R501-V0-Z000000-D20140224","0947"',
    '"CID=59A0","025C"',
    '"DEVID=SEL-700G","0408"',
    '"DEVCODE=74","0312"',
    '"PARTNO=0700G12B1B1B7281A230","06C2"',
    '"CONFIG=112222010","041E"',
    '"SEL DISPLAY PACKAGE=1.0.50700.2000","087C"',
    '"CUSTOMER DISPLAY PACKAGE=1.574871567","09A2"',
    '"iedName=","0360"',
    '"type=","026F"',
    '"configVersion=","0609"',
    '"LIB61850ID=5C9A14CB","04F1"',
    "\x03\x02",
    "=>>\x03",
]


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        # Response when there's no data, e.g. SEL-351S IM Appendix K
        '"No Data Available","0668"',
        # SEL-551 IM Appendix E, CAS response (first line)
        '"CAS",5,"01A8"',
        # SEL-421 IM A.3.36 Figure 3.19 (lowercase hex)
        '"RID","SID","FID","03e2"',
        # SEL-751A IM Figure 3.5, a space before "=" on 700-series relays
        '"iedName =TEMPLATE","05DC"',
        # Header of the 700-series CSER layout PEAT has seen on relays
        '"REC_NUM","DATE","TIME","ELEMENT","STATE","0A31"',
        # SEL-421 IM, CST response: empty fields
        '"Ok","Ok","Ok","Ok","Ok","Ok","Ok","Ok","Ok","Ok","Ok","Ok",,,"Ok","Ok","Ok","Ok","12F8"',
        # SEL-421 IM, CST response: an unquoted float with strings
        '"Ok","Ok","Ok","Ok","Ok","Ok","Ok","Ok",24.8,"Ok","Ok","0C9C"',
        # Synthetic
        '1,"01/15/2021","17:09:45.504","Relay Powered Up","0BE4"',
        '"#","MONTH","DAY","YEAR","HOUR","MIN","SEC","MSEC","ELEMENT","STATE","0FC8"',
        '6,3,15,2001,00,00,00,004,"Power-up","Group 1","0B03"',
    ],
)
def test_checksum_vectors(line):
    records = split_records(line)

    assert len(records) == 1
    assert records[0].status == "valid"
    assert records[0].valid
    assert records[0].calculated == records[0].checksum


def test_checksum_algorithm():
    assert checksum('"No Data Available",') == 0x0668
    assert checksum(b'"CAS",5,') == 0x01A8
    # Latin-1, so a byte is one character (e.g. a degree sign)
    assert checksum("\xb0,") == 0xB0 + ord(",")
    assert checksum(b"") == 0


def test_checksum_16_bit_wrap():
    labels = [f"LABEL_{i:04d}" for i in range(600)]
    line = format_record(labels)
    body = line.rpartition(',"')[0] + ","

    assert sum(body.encode()) > 0xFFFF  # The sum wraps around
    record = split_records(line)[0]
    assert record.valid
    assert record.checksum == sum(body.encode()) & 0xFFFF
    assert record.labels == labels


def test_corrupted_record_is_invalid(caplog):
    good = '2,"12/09/2020","18:08:43.048","SALARM","Deasserted","0C46"'
    assert split_records(good)[0].valid

    corrupted = good.replace("SALARM", "SALARN")
    record = split_records(corrupted)[0]

    assert record.status == "invalid"
    assert not record.valid
    assert record.checksum == 0x0C46
    assert record.calculated == 0x0C46 + 1
    assert record.values == [2, "12/09/2020", "18:08:43.048", "SALARN", "Deasserted"]
    assert "Invalid Compressed ASCII checksum" in caplog.text


def test_format_record():
    assert format_record(["CAS", 5]) == '"CAS",5,"01A8"'
    assert format_record(["Ok", None, 24.8]) == '"Ok",,24.8,"{:04X}"'.format(
        checksum('"Ok",,24.8,')
    )
    assert split_records(format_record([1, "A", None, -2.5]))[0].values == [1, "A", None, -2.5]


# ---------------------------------------------------------------------------
# Fields
# ---------------------------------------------------------------------------


def test_tokenize_values():
    assert [f.value for f in tokenize('"Ok",,,"Ok",24.8')] == ["Ok", None, None, "Ok", 24.8]
    assert [f.value for f in tokenize("1,00,004,-8,+5,1.5E3")] == [1, 0, 4, -8, 5, 1500.0]
    # Placeholders for unknown values are kept as text
    assert [f.value for f in tokenize('$$$$.$$,$$$$$$$,"$$$$"')] == ["$$$$.$$", "$$$$$$$", "$$$$"]
    # Spaces in strings are kept
    assert tokenize('" ....","GROUND O/C 1 LINE 1"') == [
        Field(" ....", quoted=True),
        Field("GROUND O/C 1 LINE 1", quoted=True),
    ]
    # Trailing empty field
    assert [f.value for f in tokenize("1,2,")] == [1, 2, None]
    assert tokenize("") == []


def test_tokenize_unescaped_quotes():
    # Quotes inside strings aren't escaped. A quote that isn't
    # followed by a comma or the end of the line is part of the string.
    fields = tokenize('"SID : "Station A" here","next"')
    assert [f.text for f in fields] == ['SID : "Station A" here', "next"]


def test_parse_number():
    assert parse_number("") is None
    assert parse_number("  ") is None
    assert parse_number("60.00") == 60.0
    assert parse_number("0012") == 12
    assert parse_number("$$$$$$$") == "$$$$$$$"
    assert parse_number("nan") == "nan"  # Not a SEL number


# ---------------------------------------------------------------------------
# Framing and records
# ---------------------------------------------------------------------------


def test_extract_messages_wire_framing():
    # Command echo, STX, CR-only line endings (older relays), ETX, then the
    # prompt. XON/XOFF and a binary Fast Meter frame are mixed in. The frame
    # has ETX and STX bytes in it, and its last byte is the checksum
    # (the sum of the other bytes).
    fast_frame = b"\xa5\xc1\x07\x00\x03\x02\x72"
    raw = (
        b"CAS\r\n\x02"
        + format_record(["CAS", 1]).encode()
        + b"\r\x11"
        + format_record(["CST", 1]).encode()
        + b"\r\x13"
        + fast_frame
        + format_record(["1H", "FID"]).encode()
        + b"\r\x03=>"
    )

    messages = extract_messages(raw)
    assert len(messages) == 1
    assert "CAS\r\n" not in messages[0]  # echo is removed
    assert "=>" not in messages[0]  # prompt is removed

    records = parse_records(raw)
    assert [r.values for r in records] == [["CAS", 1], ["CST", 1], ["1H", "FID"]]
    assert all(r.valid for r in records)


def test_extract_messages_keeps_0xa5_text():
    # 0xA5 is the second byte of a UTF-8 "a with a ring" (C3 A5), and
    # a Latin-1 yen sign. It's only a Fast frame if the frame is valid.
    fid = format_record(["FID=SEL-751"])
    raw = b"Station \xc3\x85lesund \xc3\xa5 test \xa5\xc1\x20\r\n" + fid.encode() + b"\r\n"

    messages = extract_messages(raw)
    assert messages[0].startswith("Station \xc3\x85lesund \xc3\xa5 test \xa5\xc1 \r\n")
    assert [r.values for r in parse_records(raw)][-1] == ["FID=SEL-751"]

    # A Fast frame with a wrong checksum, or one that's cut off, isn't removed
    # (NUL characters are removed, and the ETX ends the message)
    assert extract_messages(b"A\xa5\xc1\x07\x00\x03\x01\x72B") == ["A\xa5\xc1\x07"]
    assert extract_messages(b"A\xa5\xc1\x40\x00") == ["A\xa5\xc1\x40"]

    # Fast Message (A546) frames end with a CRC, and the routing address is zero
    fast_message = b"\xa5\x46\x0e" + b"\x00" * 5 + b"\x00\x82\x00\x00\x12\x34"
    assert extract_messages(b"A" + fast_message + b"B") == ["AB"]


def test_extract_messages_back_to_back():
    raw = "\x02" + format_record(["A"]) + "\r\n\x03\x02" + format_record(["B"]) + "\r\n\x03"
    assert [r.values for r in parse_records(raw)] == [["A"], ["B"]]


def test_extract_messages_without_framing():
    # A file downloaded via FTP may not have STX/ETX
    data = format_record(["FID"]) + "\r\n" + format_record(["FID=SEL-751"]) + "\r\n"
    assert len(extract_messages(data)) == 1
    assert [r.values for r in parse_records(data)] == [["FID"], ["FID=SEL-751"]]
    assert extract_messages("") == []
    assert extract_messages("\x02  \r\n\x03") == []


def test_split_records_missing_checksum():
    records = split_records('id\r\n\r\n   \r\n"FID=SEL-351S","095B"\r\n=>')
    assert [r.status for r in records] == ["missing", "invalid", "missing"]
    assert records[0].values == ["id"]


def test_split_records_leading_whitespace():
    record = split_records('   "No Data Available","0668"   ')[0]
    assert record.valid
    assert record.text == '"No Data Available","0668"'


def test_multi_line_settings_record():
    # A quoted string that spans lines, like the SETTINGS block in CEV output
    # (SEL-351S IM K.5). How the relay calculates its checksum isn't publicly
    # documented, this assumes the CR LF line endings are included.
    data = '"SETTINGS","02E1"\r\n"Group 1\r\n\r\nCTR      : 400\r\n","05AA"\r\n"FID","0143"\r\n'
    records = split_records(data)

    assert [r.status for r in records] == ["valid", "valid", "valid"]
    assert records[1].lines == 4
    assert records[1].values == ["Group 1\r\n\r\nCTR      : 400\r\n"]
    assert records[2].values == ["FID"]


def test_multi_line_record_unverified():
    # Quotes inside the settings, and a checksum that doesn't match
    # any of the line ending variations
    data = '"Group 1\r\nSID : "Station A"\r\n1: EN,"REL_EN"\r\n","FFFF"\r\n"FID","0143"'
    records = split_records(data)

    assert records[0].status == "unverified"
    assert records[0].lines == 4
    assert records[0].values == ['Group 1\r\nSID : "Station A"\r\n1: EN,"REL_EN"\r\n']
    assert records[1].valid


def test_truncated_line_does_not_swallow_records(caplog):
    # A line that's cut off in a quoted string (e.g. by noise on a serial port)
    # is a record by itself if the next line is a record with a correct checksum
    data = '"FID=SEL\r\n' + format_record(["a"]) + "\r\n" + format_record(["b"])
    records = split_records(data)

    assert [(r.status, r.values) for r in records] == [
        ("missing", ["FID=SEL"]),
        ("valid", ["a"]),
        ("valid", ["b"]),
    ]
    assert "unterminated string" in caplog.text

    # Two truncated lines in a row
    records = split_records('"x\r\n"y\r\n' + format_record(["a"]))
    assert [r.status for r in records] == ["missing", "missing", "valid"]


def test_multi_line_record_limit(caplog):
    data = '"unterminated\r\n' + "line\r\n" * 10 + format_record(["after"])
    records = split_records(data, max_join=5)

    assert records[0].lines == 5
    assert records[0].status == "missing"
    assert "longer than 5 lines" in caplog.text
    assert records[-1].values == ["after"]


def test_is_compressed_ascii_and_no_data():
    assert is_compressed_ascii('\x02"No Data Available","0668"\r\n\x03')
    assert is_no_data('\x02"No Data Available","0668"\r\n\x03')
    assert is_no_data(split_records('"no data available","0668"'))
    assert not is_compressed_ascii("1   01/15/2021  17:09:45.504  Relay Powered Up")
    assert not is_no_data(format_record(["FID"]))


# ---------------------------------------------------------------------------
# CAS (CASCII)
# ---------------------------------------------------------------------------


def _cas_output() -> str:
    """CAS output with the layout of the SEL-551 example (SEL-551 IM Appendix E)."""
    time_labels = ["MONTH", "DAY", "YEAR", "HOUR", "MIN", "SEC", "MSEC"]
    rows = [
        ["CAS", 4],
        ["CHI", 1],
        ["12H", "REC_NUM", *time_labels, "EVENT", "SHOT", "CURR", "TARGETS"],
        ["20D", "I", "I", "I", "I", "I", "I", "I", "I", "6S", "I", "I", "22S"],
        ["CEV", 1],
        ["7H", *time_labels],
        ["1D", "I", "I", "I", "I", "I", "I", "I"],
        ["7H", "IA", "IB", "IC", "IN", "IG", "TRIG", "RLY_BITS"],
        ["60D", "F", "F", "F", "F", "F", "1S", "45S"],
        ["CEV R", 1],
        ["15H", "REF_NUM", "FREQ"],
        # The "D" is missing in an example in the SEL-351S manual
        ["1952", "F", "F"],
        ["CST", 1],
        ["2h", "A", "B"],
    ]
    # Lowercase checksum hex is accepted
    lines = [format_record(row) for row in rows]
    lines[1] = lines[1][:-5] + lines[1][-5:].lower()
    return "CAS\r\n\x02" + "\r\n".join(lines) + "\r\n\x03=>"


def test_parse_cas():
    commands = parse_cas(_cas_output())

    assert list(commands) == ["CHI", "CEV", "CEV R", "CST"]
    assert commands["CHI"]["access_level"] == 1
    assert commands["CHI"]["blocks"] == [
        {
            "labels": [
                "REC_NUM",
                "MONTH",
                "DAY",
                "YEAR",
                "HOUR",
                "MIN",
                "SEC",
                "MSEC",
                "EVENT",
                "SHOT",
                "CURR",
                "TARGETS",
            ],
            "types": ["I", "I", "I", "I", "I", "I", "I", "I", "6S", "I", "I", "22S"],
            "max_rows": 20,
        }
    ]
    assert [b["max_rows"] for b in commands["CEV"]["blocks"]] == [1, 60]
    assert commands["CEV"]["blocks"][1]["types"][-1] == "45S"
    assert commands["CEV R"]["blocks"][0]["max_rows"] == 1952
    assert commands["CST"]["blocks"][0]["format_fields"] is True


def test_parse_cas_data_line_without_header():
    records = parse_records(
        "\r\n".join(
            [format_record(["CAS", 1]), format_record(["X", 0]), format_record(["5D", "I"])]
        )
    )
    assert parse_cas(records)["X"] == {
        "access_level": 0,
        "blocks": [{"labels": [], "types": ["I"], "max_rows": 5}],
    }


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


# CSER layout seen by PEAT on 700-series relays, with a short row
CSER_700 = "\r\n".join(
    [
        '"FID","SERIAL NO","CID","0570"',
        '"FID=SEL-751-R400-V0-Z008004-D20200101","1234567890","ABCD","0C95"',
        '"REC_NUM","DATE","TIME","ELEMENT","STATE","0A31"',
        '1,"01/15/2021","17:09:45.504","Relay Powered Up","0BE4"',
        '2,"12/09/2020","18:08:43.048","SALARM","Deasserted","0C46"',
    ]
)


def test_parse_report_heuristic():
    blocks = parse_report(CSER_700)

    assert [b["labels"] for b in blocks] == [
        ["FID", "SERIAL NO", "CID"],
        ["REC_NUM", "DATE", "TIME", "ELEMENT", "STATE"],
    ]
    # The all-string line after a label line is data
    assert blocks[0]["rows"] == [
        {"FID": "FID=SEL-751-R400-V0-Z008004-D20200101", "SERIAL NO": "1234567890", "CID": "ABCD"}
    ]
    # A short row doesn't have the missing labels
    assert blocks[1]["rows"][0] == {
        "REC_NUM": 1,
        "DATE": "01/15/2021",
        "TIME": "17:09:45.504",
        "ELEMENT": "Relay Powered Up",
    }
    assert blocks[1]["rows"][1]["STATE"] == "Deasserted"
    assert all(r.valid for r in blocks[1]["records"])
    assert blocks[1]["label_record"].valid


def test_parse_report_extra_values_and_known_labels():
    data = "\r\n".join(
        [
            format_record(["MONTH", "DAY"]),
            format_record(["FID"]),  # Known label, even right after a label line
            format_record(["FID=SEL-351S"]),
            format_record(["A", "B"]),
            format_record([1, 2, 3, 4]),
        ]
    )
    blocks = parse_report(data)

    assert [b["labels"] for b in blocks] == [["MONTH", "DAY"], ["FID"], ["A", "B"]]
    assert blocks[0]["rows"] == []
    assert blocks[2]["rows"] == [{"A": 1, "B": 2, "_extra": [3, 4]}]


def test_parse_report_data_before_labels():
    blocks = parse_report(format_record([1, 2]))

    assert len(blocks) == 1
    assert blocks[0]["labels"] == []
    assert blocks[0]["label_record"] is None
    assert blocks[0]["rows"] == [{"_extra": [1, 2]}]


def test_parse_report_with_cas_layout():
    # Like CST: label lines each followed by one line of strings ("Ok").
    # Without a layout, the third line would be a label line.
    layout = [
        {"labels": ["CPU", "RAM"], "types": ["2S", "2S"], "max_rows": 2},
        {"labels": ["TEMP"], "types": ["F"], "max_rows": 1},
    ]
    data = "\r\n".join(
        [
            format_record(["CPU", "RAM"]),
            format_record(["Ok", "Ok"]),
            format_record(["Ok", "Warn"]),
            format_record(["TEMP"]),
            format_record([24.8]),
            format_record(["Extra"]),
            format_record(["Not in layout"]),
        ]
    )

    blocks = parse_report(data, layout=layout)
    assert [b["labels"] for b in blocks] == [["CPU", "RAM"], ["TEMP"], ["Extra"]]
    assert blocks[0]["rows"] == [{"CPU": "Ok", "RAM": "Ok"}, {"CPU": "Ok", "RAM": "Warn"}]
    assert blocks[1]["rows"] == [{"TEMP": 24.8}]
    assert blocks[2]["rows"] == [{"Extra": "Not in layout"}]

    # Without the layout, the second "Ok" line is a label line
    assert [b["labels"] for b in parse_report(data)][:2] == [["CPU", "RAM"], ["Ok", "Warn"]]


def test_parse_report_cas_layout_from_parse_cas():
    layout = parse_cas(_cas_output())["CHI"]["blocks"]
    data = "\r\n".join(
        [
            format_record(["FID"]),
            format_record(["FID=SEL-551-R101-V0-D20000101"]),
            format_record(layout[0]["labels"]),
            format_record([1, 2, 29, 2000, 16, 16, 8, 837, "TRIP", 0, 2279, "INST A N"]),
        ]
    )
    blocks = parse_report(data, layout=layout)

    assert blocks[-1]["labels"] == layout[0]["labels"]
    assert blocks[-1]["rows"][0]["TARGETS"] == "INST A N"
    assert blocks[-1]["rows"][0]["CURR"] == 2279


# ---------------------------------------------------------------------------
# ID command output
# ---------------------------------------------------------------------------


def test_parse_id_output_docs_sample():
    info = parse_id_output("\r\n".join(ID_700G))

    assert info == {
        "FID": "SEL-700G-R200-V0-Z006003-D20180629",
        "BFID": "BOOTLDR-R501-V0-Z000000-D20140224",
        "CID": "59A0",
        "DEVID": "SEL-700G",
        "DEVCODE": "74",
        "PARTNO": "0700G12B1B1B7281A230",
        "CONFIG": "112222010",
        "SEL DISPLAY PACKAGE": "1.0.50700.2000",
        "CUSTOMER DISPLAY PACKAGE": "1.574871567",
        # These were dropped by the old parser (lines[:-2])
        "LIB61850ID": "5C9A14CB",
    }


def test_parse_id_output_values():
    raw = "\r\n".join(
        [
            "ID",
            "\x02",
            # 700-series relays print a space before "=" (SEL-751A IM Figure 3.5)
            '"iedName =TEMPLATE","05DC"',
            format_record(["type =SEL_751A"]),
            # Values can contain "="
            format_record(["SPECIAL=A=B"]),
            # Duplicate key, the first value is used
            format_record(["SPECIAL=C"]),
            format_record(["no equals sign"]),
            "\x03",
            "=>",
        ]
    )

    assert parse_id_output(raw) == {"iedName": "TEMPLATE", "type": "SEL_751A", "SPECIAL": "A=B"}


def test_parse_id_output_parse_failure(caplog):
    raw = "\r\n".join(
        [
            # SEL-351S IM 20171023, ID message (invalid CID file)
            '"iedName=PARSE FAILURE","0703"',
            '"type=PARSE FAILURE","0612"',
            format_record(["FID=SEL-351S-5-R512-V0-Z104104-D20120830"]),
        ]
    )
    info = parse_id_output(raw)

    assert info == {
        "FID": "SEL-351S-5-R512-V0-Z104104-D20120830",
        "iec61850_parse_failure": ["iedName", "type"],
    }
    assert "PARSE FAILURE" in caplog.text


def test_parse_id_output_invalid_checksum(caplog):
    info = parse_id_output('"DEVID=STATION B","049C"\r\n')

    assert info == {"DEVID": "STATION B"}
    assert "invalid checksum" in caplog.text


def test_parse_id_output_unquoted_and_empty():
    assert parse_id_output("") == {}
    assert parse_id_output("=>") == {}
    # Lines without quotes or checksums are accepted
    assert parse_id_output("FID=SEL-2032-R115\r\n") == {"FID": "SEL-2032-R115"}


def test_get_id_uses_parser(mocker):
    tn = SELTelnet("192.0.2.30")
    exec_read = mocker.patch.object(tn, "exec_read", return_value="\r\n".join(ID_700G))

    info = tn.get_id()

    exec_read.assert_called_once_with("id", return_lines=False, added_delay=5.0)
    assert info["FID"] == "SEL-700G-R200-V0-Z006003-D20180629"
    assert info["LIB61850ID"] == "5C9A14CB"
    assert "iedName" not in info  # Empty value


def test_get_id_no_output(mocker):
    tn = SELTelnet("192.0.2.31")
    mocker.patch.object(tn, "exec_read", return_value="")
    assert tn.get_id() == {}


def test_module_exports():
    for name in sel_cascii.__all__:
        assert hasattr(sel_cascii, name)
