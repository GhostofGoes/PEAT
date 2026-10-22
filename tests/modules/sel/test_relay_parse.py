from pathlib import Path

import pytest

from peat import DeviceData, datastore
from peat.modules.sel import relay_parse
from peat.modules.sel.relay_parse import (
    clean_settings_text,
    combine_settings_files,
    create_dev_from_configs,
    extract_sections,
    is_event_filename,
    looks_like_show_output,
    parse_and_process_dnp3,
    parse_and_process_modbus,
    parse_config_data,
    parse_fid,
    parse_ids,
    parse_rdb,
    parse_rdb_relays,
    parse_set_all,
    parse_show_output,
    process_info_into_dev,
    read_rdb_streams,
    split_raw_sections,
)

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"


@pytest.fixture(autouse=True)
def _empty_datastore(mocker):
    mocker.patch.object(datastore, "objects", [])


def test_clean_settings_text():
    assert clean_settings_text(b'\xef\xbb\xbfRID,"A"\x1c\r\n\x1a') == 'RID,"A"\r\n'
    assert clean_settings_text(b'TID,\x00"B"') == 'TID,"B"'
    # Windows-1252 isn't valid UTF-8
    assert clean_settings_text(b'TID,"\xb5"') == 'TID,"\xb5"'


def test_split_raw_sections_skips_leading_lines():
    text = 'garbage before\r\n[INFO]\r\nFID=X\r\n\r\n[1]\r\nRID,"A"\r\n'
    assert split_raw_sections(text) == [("INFO", ["FID=X"]), ("1", ['RID,"A"'])]
    # This used to raise a KeyError
    assert extract_sections(text) == {"INFO": ["FID=X"], "1": ['RID,"A"']}


def test_combine_settings_files():
    cfg = '[INFO]\r\nRELAYTYPE=0351\r\nFID=CFG\r\n[CLASSES]\r\n1,"Group 1"\r\n'
    set_1 = '[INFO]\r\nRELAYTYPE=0351\r\nFID=SET1\r\n[1]\r\nRID,"A"\x1c\r\n'
    set_10 = '[INFO]\r\nFID=SET10\r\n[10]\r\nRID,"B"\r\n'
    set_2 = '[INFO]\r\nFID=SET2\r\n[2]\r\nRID,"C"\r\n'

    combined = combine_settings_files(
        {
            "set_10.txt": set_10,
            "SET_2.TXT": set_2,
            "SET_1.TXT": set_1.encode(),
            "cfg.txt": cfg,
            "SET_ALL.TXT": "[INFO]\r\nFID=IGNORED\r\n",
            "SER.TXT": "ignored",
        },
        save_info=['Saved on 2/16/2023 at 10:14:22 PM "x"'],
    )

    assert combined == (
        "[INFO]\r\nRELAYTYPE=0351\r\nFID=CFG\r\n"
        '[CLASSES]\r\n1,"Group 1"\r\n"Saved on 2/16/2023 at 10:14:22 PM ""x"""\r\n'
        '[1]\r\nRID,"A"\r\n'
        '[2]\r\nRID,"C"\r\n'
        '[10]\r\nRID,"B"\r\n'
    )

    configs = parse_config_data(combined)
    assert configs["INFO"]["FID"] == "CFG"
    assert configs["CLASSES"]["SAVE_INFO"] == ['Saved on 2/16/2023 at 10:14:22 PM "x"']
    assert configs["10"]["RID"]["value"] == "B"


def test_combine_settings_files_no_settings():
    assert combine_settings_files({}) == ""
    assert combine_settings_files({"SER.TXT": "x"}) == ""


def test_combine_settings_files_dnpb():
    combined = combine_settings_files(
        {"SET_DNPB.TXT": '[INFO]\r\nFID=X\r\n[DNPB]\r\nDNPB,"52A IN101 IN102"\r\n'}
    )
    assert '[DNPB]\r\nBI_1,"52A"\r\nBI_2,"IN101"\r\nBI_3,"IN102"\r\n' in combined


def test_read_rdb_streams():
    relays = read_rdb_streams((RELAY_DIR / "sel-710_Relay710.rdb").read_bytes())

    assert list(relays) == ["New Settings 2"]
    streams = relays["New Settings 2"]
    assert "Misc/Cfg.txt" in streams
    assert "set_P1.txt" in streams
    assert streams["Misc/Device.txt"] == b"New Settings 2"


def test_parse_rdb_matches_set_all():
    rdb_data = (RELAY_DIR / "sel-710_Relay710.rdb").read_bytes()
    set_all = (RELAY_DIR / "sel-710_SET_ALL.TXT").read_text(encoding="utf-8")

    from_rdb = parse_config_data(parse_rdb(rdb_data))
    from_set_all = parse_config_data(set_all)

    # The RDB also has the "Saved on" info, otherwise they're identical
    save_info = from_rdb["CLASSES"].pop("SAVE_INFO")
    assert save_info[-1] == "Saved on 30/08/2025 at 3:33:00 PM"
    assert from_rdb == from_set_all
    assert "\x1c" not in str(from_rdb)


def test_parse_rdb_relays_multiple(mocker):
    cfg = b"[INFO]\r\nRELAYTYPE=SEL-751\r\n"
    mocker.patch.object(
        relay_parse,
        "read_rdb_streams",
        return_value={
            "": {"Root Entry Stuff": b"junk"},
            "Feeder 1": {"Misc/Cfg.txt": cfg, "set_1.txt": b'[1]\r\nRID,"F1"\x1c\r\n'},
            "Feeder 2": {"Misc/Cfg.txt": cfg, "SET_1.TXT": b'[1]\r\nRID,"F2"\x1c\r\n'},
            "Empty": {"Misc/GL1.gle": b"\x00\x01"},
        },
    )

    relays = parse_rdb_relays(b"")
    assert list(relays) == ["Feeder 1", "Feeder 2"]
    assert 'RID,"F2"' in relays["Feeder 2"]
    assert parse_rdb(b"") == relays["Feeder 1"]


def test_parse_rdb_relays_fallback(mocker):
    mocker.patch.object(relay_parse, "read_rdb_streams", return_value={"": {"x": b"y"}})
    concat = mocker.patch.object(relay_parse, "_concat_rdb_streams", return_value="[INFO]")

    assert parse_rdb_relays(b"data") == {"": "[INFO]"}
    concat.assert_called_once_with(b"data")


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("SER.TXT", True),
        ("cser.txt", True),
        ("192.0.2.1_SER.TXT", True),
        ("HISTORY.TXT", True),
        ("CHISTORY.TXT", True),
        ("USER.TXT", False),
        ("SET_ALL.TXT", False),
        ("server_SET_ALL.TXT", False),
        ("SER.TXT.bak", False),
    ],
)
def test_is_event_filename(filename, expected):
    assert is_event_filename(filename) is expected


def test_parse_show_output_new_style():
    text = (
        "=>>SHO 1\r\n"
        "Group 1\r\n"
        'RID      := "RELAY 1"\r\n'
        "CTR      := 120              PTR      := 1.00\r\n"
        "TR       := 50P1T OR 51P1T OR\r\n"
        "            REMTRIP\r\n"
        "\r\n"
        "=>>SHO P 1\r\n"
        "TPORT    := 23\r\n"
    )

    assert looks_like_show_output(text)
    configs = parse_show_output(text)

    assert configs["INFO"] == {}
    assert set(configs) == {"INFO", "1", "P1"}
    assert configs["1"]["RID"]["value"] == "RELAY 1"
    assert configs["1"]["PTR"]["value"] == "1.00"
    assert configs["1"]["TR"]["value"] == "50P1T OR 51P1T OR REMTRIP"
    assert configs["P1"]["TPORT"]["value"] == "23"


def test_parse_show_output_old_style():
    text = (
        "=>SHO\r\n"
        "Group 1\r\n"
        "RID    =RELAY 1\r\n"
        "CTR    =120      PTR    =1.00\r\n"
        "\r\n"
        "SELogic group 1\r\n"
        "TR     =M1P + Z1G\r\n"
    )

    configs = parse_config_data(text)

    # "SHO" doesn't say which group, so it comes from the headings
    assert set(configs) == {"INFO", "1", "L1"}
    assert configs["1"]["RID"]["value"] == "RELAY 1"
    assert configs["1"]["PTR"]["value"] == "1.00"
    assert configs["L1"]["TR"]["value"] == "M1P + Z1G"


def test_parse_show_output_misc():
    text = (
        "=>>SHO G\r\n"
        "FID=SEL-751-R300-V3-Z008004-D20210104\r\n"
        'SID      := "STATION A"\r\n'
        "\r\n"
        "  this indented line follows a blank line and isn't a continuation\r\n"
        "=>>SHO P F\r\n"
        "Global\r\n"  # Heading doesn't override the command
        "SPEED    := 9600\r\n"
        "=>>SHO D1\r\n"
        "BI_00    := TRIP\r\n"
    )
    configs = parse_show_output(text)

    assert configs["INFO"] == {"FID": "SEL-751-R300-V3-Z008004-D20210104"}
    assert configs["G"]["SID"]["value"] == "STATION A"
    assert configs["PF"]["SPEED"]["value"] == "9600"
    assert configs["D1"]["BI_00"]["value"] == "TRIP"


def test_parse_set_all_show_output():
    text = (
        "=>>SHO 1\r\n"
        'RID      := "RELAY 1"\r\n'
        "TR       := 50P1T OR REMTRIP\r\n"
        "=>>SHO P 1\r\n"
        "IPADDR   := 192.0.2.75\r\n"
        "=>>SHO L 1\r\n"
        "OUT101   := TRIP\r\n"
    )
    device_info, dev = parse_set_all(text)

    assert dev.ip == "192.0.2.75"
    assert device_info["relay_id"] == "relay_1"
    assert device_info["trip_logic"]["1"]["TR"] == "50P1T OR REMTRIP"
    assert device_info["output_logic"]["L1"] == {"OUT101": "TRIP"}


def test_looks_like_show_output():
    assert not looks_like_show_output("[INFO]\r\nFID=SEL-351\r\n")
    assert not looks_like_show_output("")
    assert looks_like_show_output("RID     =FEEDER 1\r\n")


@pytest.mark.parametrize(
    ("fid", "expected"),
    [
        (
            "SEL-351-5-R510-V0-Z103103-D20110429",
            {"model": "351", "product": "SEL-351-5", "revision": "R510", "version": "V0"},
        ),
        (
            "SEL-710-Rxxx-Vx-Z008004-Dxxxxxxxx",
            {"model": "710", "product": "SEL-710", "release_date": None},
        ),
        ("SLBT-3CF1-R102-V0-Z100100-D20091207", {"revision": "R102"}),
        ("BOOTLDR-R501-V0-Z000000-D20140224", {"settings_version": "Z000000"}),
    ],
)
def test_parse_fid(fid, expected):
    result = parse_fid(fid)
    assert result["id"] == fid
    for key, value in expected.items():
        assert result[key] == value


@pytest.mark.parametrize(
    ("relaytype", "model"),
    [("0351", "351"), ("0710", "710"), ("SEL-710", "710"), ("SEL-487E-3", "487E")],
)
def test_process_info_relaytype(relaytype, model):
    dev = DeviceData()
    process_info_into_dev({"RELAYTYPE": relaytype}, dev)
    assert dev.description.model == model


def test_parse_ids_ini_style_values():
    # Values may be plain strings instead of dicts, e.g. INI-style sections
    ids = parse_ids({"1": {"RID": "RELAY A"}, "G1": {"SID": {"value": "STATION"}}})
    assert ids["relay_id"] == "relay_a"
    assert ids["station_id"] == "station"


def test_create_dev_from_configs_empty_ip():
    dev = create_dev_from_configs({"P5": {"IPADDR": {"value": ""}}, "1": {"RID": {"value": "R1"}}})
    assert dev.name == "R1"


def test_dnp3_and_modbus_single_letter_sections():
    dev = DeviceData()
    dev.description.model = "487E"
    configs = {
        # These used to raise an IndexError
        "D": {"BI_00": {"value": "TRIP", "description": ""}},
        "M": {"MOD_001": {"value": "IA", "description": ""}},
        # [M1] is metering on the 487E, not Modbus
        "M1": {"MOD_002": {"value": "IB", "description": ""}},
        "DATE": {"BI_01": {"value": "X", "description": ""}},
    }

    parse_and_process_dnp3(configs, dev)
    parse_and_process_modbus(configs, dev)

    assert sorted((r.protocol, r.name) for r in dev.registers) == [
        ("dnp3", "BI_00"),
        ("modbus", "MOD_001"),
    ]


def test_combine_settings_files_dnpb_other_sections():
    combined = combine_settings_files(
        {
            "SET_DNPB.TXT": (
                '[INFO]\r\nFID="SEL-311L"\r\n[DNPB]\r\nDNPB,"52A 52B"\r\n[D1]\r\nFOO,"1"\r\n'
            )
        }
    )
    assert combined == (
        '[INFO]\r\nFID="SEL-311L"\r\n[DNPB]\r\nBI_1,"52A"\r\nBI_2,"52B"\r\n[D1]\r\nFOO,"1"\r\n'
    )


def test_combine_settings_files_classes_order():
    combined = combine_settings_files(
        {
            "CFG.TXT": '[INFO]\r\nFID=X\r\n[CLASSES]\r\nP5,"Port 5"\r\n1,"Group 1"\r\n',
            "SET_1.TXT": "[1]\r\nRID,A\r\n",
            "SET_G.TXT": "[G]\r\nSID,B\r\n",
            "SET_P5.TXT": "[P5]\r\nEPORT,Y\r\n",
        }
    )
    assert [s for s, _ in split_raw_sections(combined)] == ["INFO", "CLASSES", "P5", "1", "G"]


@pytest.mark.parametrize(
    "path",
    [
        "sel-710_SET_ALL.TXT",
        "sel-710_rdb_streams/Misc/Cfg.txt",
        "sel-710_rdb_streams/set_1.txt",
        "sel-710_rdb_streams/set_P1.txt",
        "sel-710_rdb_streams/set_L1.txt",
    ],
)
def test_looks_like_show_output_false_positives(path):
    assert not looks_like_show_output((RELAY_DIR / path).read_text(encoding="latin-1"))


def test_show_output_regexes_are_fast():
    # These took tens of seconds with backtracking regexes
    looks_like_show_output(" \n" * 50000)
    parse_show_output("SHO" + " " * 5000 + "!\n" + " \n" * 50000)
    parse_show_output("RID" + " " * 5000 + "x\n")


def test_parse_show_output_setting_argument():
    # "SHO TR" shows the TR setting, it's not a settings class named "TR"
    configs = parse_show_output("=>>SHO TR\r\nTR       := 50P1T\r\n")
    assert configs["SHOW"]["TR"]["value"] == "50P1T"


def test_parse_fid_trailing_characters():
    result = parse_fid("SEL-351-5-R510-V0-Z103103-D20110429;")
    assert result["release_date"].year == 2011
