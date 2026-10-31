"""
Tests for the SEL relay settings records (settings.json), the SELOGIC
equations (logic-equations.json), and the CSV columns of settings files.

The SEL-710 settings are the real, MIT-licensed files in data_files/relay/
(see the README there). That relay's files only have two columns, so the
other layouts are short inline strings: the 400-series column layout is the
one in docs/sel.rst, and the free-form logic lines are hand-written examples
of the syntax in the SEL-421 Instruction Manual (Reference Manual Section 3,
"SELOGIC Control Equation Programming").
"""

import json
import shutil
from pathlib import Path

import pytest

from peat import SELRelay, config, datastore
from peat.modules.sel import relay_parse
from peat.modules.sel.relay_parse import (
    parse_config_data,
    parse_csv_style,
    parse_rdb,
    parse_set_all,
    settings_metadata,
    settings_to_records,
    split_logic,
)

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"
STREAMS_DIR = RELAY_DIR / "sel-710_rdb_streams"
SEL_710_SET_ALL = RELAY_DIR / "sel-710_SET_ALL.TXT"

#: Keys every settings record has
RECORD_KEYS = [
    "section",
    "class_name",
    "file",
    "line_number",
    "name",
    "value",
    "range",
    "type",
    "col5",
    "description",
    "description_raw",
    "kind",
]

#: Hand-written 400-series settings, in the layout documented in docs/sel.rst
SET_ALL_4XX = (
    "[INFO]\r\n"
    "RELAYTYPE=SEL-421\r\n"
    "FID=SEL-421-5-R000-V0-Z000000-D20000101\r\n"
    "[CLASSES]\r\n"
    '"P5","Port 5","\\SETTINGS\\SET_P5.TXT","0x1234ABCD"\r\n'
    '"L1","Protection 1","\\SETTINGS\\SET_L1.TXT","0x0000BEEF"\r\n'
    "[STORAGE]\r\n"
    '"\\SWCFG.ZIP"\r\n'
    "[P5]\r\n"
    '"TPORT",23,"23,1025-65534",I,"","Telnet Port (23,1025-65534)"\r\n'
    '"URETRY1",3,2~10,U,,"Unsolicited Message Max Retry Attempts (2-10)"\r\n'
    '"E50P","N","","","","      Phase"\r\n'
    "[L1]\r\n"
    '"PROTSEL1","PSV01 := R_TRIG 52AA1 # Pulse for each close",,S,"",""\r\n'
    '"PROTSEL2","PCN01PV := 500",,S,"",""\r\n'
    '"PROTSEL3","PCN01IN := PSV01 # Count closes",,S,"",""\r\n'
    '"PROTSEL4","PSV02 := PCN01CV > 400",,S,"",""\r\n'
    '"PROTSEL5","# Nothing else",,S,"",""\r\n'
    '"PROTSEL6","",,S,"",""\r\n'
    "[A1]\r\n"
    '"AUTO_1","",,S,"",""\r\n'
)


@pytest.fixture(autouse=True)
def parse_env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    # Prevent overwriting same device in the datastore with a different input file
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


def _find(records, section, name):
    return next(r for r in records if r["section"] == section and r["name"] == name)


def _read_json(directory, name):
    paths = list(directory.rglob(name))
    assert len(paths) == 1, f"Expected one {name}, found {paths}"
    return json.loads(paths[0].read_text(encoding="utf-8"))


# --- CSV columns (parse_csv_style) ---


def test_parse_csv_style_4xx_columns():
    configs = parse_csv_style(
        [
            '"TPORT",23,"23,1025-65534",I,"","Telnet Port (23,1025-65534)"',
            '"URETRY1",3,2~10,U,,"Unsolicited Message Max Retry Attempts (2-10)"',
            '"AUTO_1","",,S,"",""',
        ],
        "P5",
    )

    assert configs["TPORT"] == {
        "value": "23",
        "description": "Telnet Port (23,1025-65534)",
        "range": "23,1025-65534",
        "type": "I",
    }
    assert configs["URETRY1"] == {
        "value": "3",
        "description": "Unsolicited Message Max Retry Attempts (2-10)",
        "range": "2~10",
        "type": "U",
    }
    assert configs["AUTO_1"] == {"value": "", "description": "", "type": "S"}


def test_parse_csv_style_description_only_from_sixth_column():
    configs = parse_csv_style(['"URETRY1",3,2~10', '"X",1,"R","T"', '"Y",2,"R","T","C5"'], "P5")

    # The range was used as the description
    assert configs["URETRY1"] == {"value": "3", "description": "", "range": "2~10"}
    assert configs["X"] == {"value": "1", "description": "", "range": "R", "type": "T"}
    assert configs["Y"]["description"] == ""
    assert configs["Y"]["col5"] == "C5"


def test_parse_csv_style_3xx_columns():
    configs = parse_csv_style(
        [
            'RID,"FEEDER 7","","","","Relay Identifier (30 characters)"',
            'E50P,"N","","","","      Phase"',
            'OUT101,"TRIP"',
            "RST9",
        ],
        "1",
    )

    # Empty columns aren't added
    assert configs["RID"] == {
        "value": "FEEDER 7",
        "description": "Relay Identifier (30 characters)",
    }
    assert configs["E50P"] == {
        "value": "N",
        "description": "Phase",
        "description_raw": "      Phase",
    }
    # Two columns are the same as before
    assert configs["OUT101"] == {"value": "TRIP", "description": ""}
    assert configs["RST9"] == {"value": "", "description": ""}


def test_parse_csv_style_duplicates(caplog):
    configs = parse_csv_style(['ABCDEFG,"1"', 'ABCDEFG,"2"'], "G1")

    assert configs["ABCDEFG"]["value"] == "2"
    assert "ABCDEFG" in caplog.text
    assert "more than once" in caplog.text


def test_parse_csv_style_classes_and_storage_unchanged():
    configs = parse_config_data(SET_ALL_4XX)

    assert configs["CLASSES"]["P5"] == {
        "class": "P5",
        "name": "Port 5",
        "file": "/SETTINGS/SET_P5.TXT",
        "hex_id": "1234abcd",
    }
    assert configs["STORAGE"] == ["/SWCFG.ZIP"]
    assert set(configs) == {"INFO", "CLASSES", "STORAGE", "P5", "L1", "A1"}


def test_parse_config_data_sel_710_two_columns():
    configs = parse_config_data(SEL_710_SET_ALL.read_bytes())

    # The SEL-710 files only have two columns, so nothing is added
    assert configs["P1"]["NETMODE"] == {"value": "FAILOVER", "description": ""}
    assert all(
        set(setting) == {"value", "description"}
        for section, settings in configs.items()
        if section not in ("INFO", "CLASSES")
        for setting in settings.values()
    )


# --- Settings records ---


def test_settings_to_records_sel_710():
    text = SEL_710_SET_ALL.read_bytes()
    records = settings_to_records(text)
    lines = text.decode("utf-8").splitlines()

    # Every setting line, except for the [CLASSES] section
    num_settings = sum(1 for line in lines if line.strip() and not line.startswith("["))
    assert len(records) == num_settings - 15
    assert all(list(r) == RECORD_KEYS for r in records)
    assert not any(r["section"] == "CLASSES" for r in records)

    info = [r for r in records if r["section"] == "INFO"]
    assert [r["name"] for r in info] == ["RELAYTYPE", "FID", "BFID", "PARTNO"]
    assert info[0]["value"] == "SEL-710"
    assert info[0]["class_name"] is None

    netmode = _find(records, "P1", "NETMODE")
    assert netmode == {
        "section": "P1",
        "class_name": "Port 1",
        "file": None,
        "line_number": netmode["line_number"],
        "name": "NETMODE",
        "value": "FAILOVER",
        "range": None,
        "type": None,
        "col5": None,
        "description": None,
        "description_raw": None,
        "kind": "setting",
    }
    assert lines[netmode["line_number"] - 1] == 'NETMODE,"FAILOVER"'

    tr = _find(records, "1", "TR")
    assert tr["kind"] == "equation"
    assert tr["class_name"] == "Group 1"
    assert lines[tr["line_number"] - 1].startswith('TR,"49T OR LOSSTRIP OR JAMTRIP')


def test_settings_to_records_sel_710_kinds():
    records = settings_to_records(SEL_710_SET_ALL.read_bytes())

    def kind(section, name):
        return _find(records, section, name)["kind"]

    # The 15 settings with an equation that has operators. Only 5 of these
    # (TR, OUT101, OUT103, FAULT, ER) are in close/output/trip_logic.
    for section, name in [
        ("L1", "SV01"),
        ("L1", "OUT101"),
        ("L1", "OUT103"),
        ("1", "TR"),
        ("1", "87M2TC"),
        ("G", "FAULT"),
        ("G", "BFI"),
        ("R", "ER"),
        ("F", "T01_LED"),
        ("F", "T02_LED"),
        ("F", "T03_LED"),
        ("F", "T04_LED"),
        ("F", "T05_LED"),
        ("F", "T06_LED"),
        ("F", "PB3B_LED"),
    ]:
        assert kind(section, name) == "equation", (section, name)

    # Equations with a single Relay Word bit
    for section, name in [("1", "87M1TC"), ("1", "STREQ"), ("L1", "OUT102"), ("G", "BKMON")]:
        assert kind(section, name) == "equation", (section, name)

    for section, name in [
        ("1", "TDURD"),
        ("1", "TID"),
        ("1", "51AC"),
        ("L1", "SV01PU"),
        ("L1", "OUT101FS"),
        ("L1", "ESV"),
        ("G", "52ABF"),
        ("F", "DP01"),
        ("P1", "NETMODE"),
    ]:
        assert kind(section, name) == "setting", (section, name)

    assert kind("L1", "SET01") == "equation_unset"
    assert kind("R", "SER1") == "bit_list"
    assert kind("R", "ALIAS4") == "alias"

    # The same in each group
    for group in ["2", "3"]:
        assert kind(group, "TR") == "equation"
    for logic in ["L2", "L3"]:
        assert kind(logic, "SV01") == "equation"


@pytest.mark.parametrize(
    "streams",
    [
        lambda: parse_rdb((RELAY_DIR / "sel-710_Relay710.rdb").read_bytes()),
        lambda: relay_parse.combine_settings_files(
            {
                "CFG.TXT": (STREAMS_DIR / "Misc" / "Cfg.txt").read_bytes(),
                **{p.name: p.read_bytes() for p in STREAMS_DIR.glob("set_*.txt")},
            }
        ),
    ],
    ids=["rdb", "combined"],
)
def test_settings_to_records_same_from_rdb(streams):
    def without_line_numbers(records):
        return [{k: v for k, v in r.items() if k != "line_number"} for r in records]

    from_set_all = settings_to_records(SEL_710_SET_ALL.read_bytes())
    assert without_line_numbers(settings_to_records(streams())) == without_line_numbers(
        from_set_all
    )


def test_settings_to_records_4xx():
    records = settings_to_records(SET_ALL_4XX)

    assert {r["section"] for r in records} == {"INFO", "P5", "L1", "A1"}

    tport = _find(records, "P5", "TPORT")
    assert tport == {
        "section": "P5",
        "class_name": "Port 5",
        "file": "/SETTINGS/SET_P5.TXT",
        "line_number": 10,
        "name": "TPORT",
        "value": "23",
        "range": "23,1025-65534",
        "type": "I",
        "col5": "",
        "description": "Telnet Port (23,1025-65534)",
        "description_raw": "Telnet Port (23,1025-65534)",
        "kind": "setting",
    }

    uretry = _find(records, "P5", "URETRY1")
    assert uretry["range"] == "2~10"
    assert uretry["type"] == "U"
    assert uretry["col5"] == ""

    e50p = _find(records, "P5", "E50P")
    assert e50p["description"] == "Phase"
    assert e50p["description_raw"] == "      Phase"

    protsel1 = _find(records, "L1", "PROTSEL1")
    assert protsel1["kind"] == "equation"
    assert protsel1["type"] == "S"
    assert protsel1["value"] == "PSV01 := R_TRIG 52AA1 # Pulse for each close"
    assert protsel1["lhs"] == "PSV01"
    assert protsel1["rhs"] == "R_TRIG 52AA1"
    assert protsel1["comment"] == "Pulse for each close"

    assert _find(records, "L1", "PROTSEL5")["kind"] == "equation_unset"
    assert _find(records, "L1", "PROTSEL5")["comment"] == "Nothing else"
    assert _find(records, "L1", "PROTSEL6")["kind"] == "equation_unset"
    assert "lhs" not in _find(records, "L1", "PROTSEL6")
    assert _find(records, "A1", "AUTO_1")["kind"] == "equation_unset"

    # The counter preset is a constant, so it's a setting of the logic
    protsel2 = _find(records, "L1", "PROTSEL2")
    assert protsel2["kind"] == "setting"
    assert (protsel2["lhs"], protsel2["rhs"]) == ("PCN01PV", "500")

    equations, settings = split_logic(records)
    assert equations == {
        "L1": {
            "PSV01": "R_TRIG 52AA1",
            "PCN01IN": "PSV01",
            "PSV02": "PCN01CV > 400",
        }
    }
    assert settings == {"L1": {"PCN01PV": "500"}}


def test_settings_to_records_keeps_duplicates():
    text = '[INFO]\r\nFID=SEL-751\r\n[1]\r\nRID,"A"\r\nRID,"B"\r\n[INFO]\r\nFID=SEL-751\r\n'
    records = settings_to_records(text)

    # The repeated [INFO] section is only included once
    assert [(r["section"], r["name"], r["value"], r["line_number"]) for r in records] == [
        ("INFO", "FID", "SEL-751", 2),
        ("1", "RID", "A", 4),
        ("1", "RID", "B", 5),
    ]


def test_settings_to_records_odd_lines():
    text = (
        "[1]\r\n"
        'TID,"Line 1\r\n'  # A quoted value can continue onto the next line
        'and line 2"\r\n'
        ',"no name"\r\n'
        'A,"1","2","3","4","5","6","7"\r\n'
    )
    records = settings_to_records(text, model="751")

    # The value is the same as in parse_config_data()
    assert parse_config_data(text)["1"]["TID"]["value"] == "Line 1and line 2"
    assert [(r["name"], r["value"], r["line_number"]) for r in records] == [
        ("TID", "Line 1and line 2", 2),
        ("A", "1", 5),
    ]
    assert records[1]["description"] == "5"
    assert records[1]["extra_columns"] == ["6", "7"]


def test_settings_to_records_show_output():
    text = (
        "=>>SHO 1\r\n"
        'RID      := "RELAY 1"\r\n'
        "TR       := 50P1T OR REMTRIP\r\n"
        "TDURD    := 0.5\r\n"
        "=>>SHO L 1\r\n"
        "SV01     := IN101 AND NOT IN102\r\n"
        "SV01PU   := 0.00\r\n"
    )
    records = settings_to_records(text)

    assert [(r["section"], r["name"], r["kind"], r["line_number"]) for r in records] == [
        ("1", "RID", "setting", None),
        ("1", "TR", "equation", None),
        ("1", "TDURD", "setting", None),
        ("L1", "SV01", "equation", None),
        ("L1", "SV01PU", "setting", None),
    ]
    assert all(r["description"] is None for r in records)


def test_settings_to_records_family_from_model():
    text = '[L1]\r\nDP1,"52A"\r\n'

    # Every setting in the 300-series logic classes is an equation
    assert settings_to_records(text, model="351S")[0]["kind"] == "equation"
    assert settings_to_records(text, model="751")[0]["kind"] == "setting"
    # [INFO] takes priority
    info = "[INFO]\r\nRELAYTYPE=0351\r\n"
    assert settings_to_records(info + text, model="751")[-1]["kind"] == "equation"


def test_settings_metadata():
    meta = settings_metadata(parse_config_data(SET_ALL_4XX))

    assert meta == {
        "family": "4xx",
        "classes": {
            "P5": {
                "class": "P5",
                "name": "Port 5",
                "file": "/SETTINGS/SET_P5.TXT",
                "hex_id": "1234abcd",
            },
            "L1": {
                "class": "L1",
                "name": "Protection 1",
                "file": "/SETTINGS/SET_L1.TXT",
                "hex_id": "0000beef",
            },
        },
        "storage": ["/SWCFG.ZIP"],
    }

    rdb_meta = settings_metadata(
        parse_config_data(parse_rdb((RELAY_DIR / "sel-710_Relay710.rdb").read_bytes()))
    )
    assert rdb_meta["family"] == "7xx"
    assert rdb_meta["save_info"][-1] == "Saved on 30/08/2025 at 3:33:00 PM"
    assert "SAVE_INFO" not in rdb_meta["classes"]
    assert settings_metadata({}) == {}
    assert settings_metadata({}, model="710") == {"family": "7xx"}


def test_split_logic_sel_710():
    equations, settings = split_logic(settings_to_records(SEL_710_SET_ALL.read_bytes()))

    assert equations["1"]["TR"].startswith("49T OR LOSSTRIP OR JAMTRIP")
    assert equations["1"]["87M2TC"] == "NOT 50S"
    assert equations["L1"]["SV01"].startswith("WDGTRIP OR BRGTRIP")
    assert equations["F"]["T05_LED"] == "(NOT STOPPED AND 27P1T) OR 59P1T"
    assert "SET01" not in equations["L1"]  # NA
    assert "TDURD" not in equations["1"]

    # TDURD is in the trip logic keys, but it's a timer
    assert settings["1"] == {"TDURD": "0.5"}
    assert settings["L1"]["SV01PU"] == "0.00"
    assert settings["L1"]["OUT101FS"] == "Y"
    assert "SV02PU" not in settings["L1"]  # SV02 isn't used
    assert settings["F"]["T01LEDL"] == "Y"
    assert "G" not in settings


def test_parse_set_all_logic_keys_unchanged():
    device_info, _ = parse_set_all(SEL_710_SET_ALL.read_text(encoding="utf-8"))

    # The old logic outputs still have the timers, for compatibility
    assert list(device_info["trip_logic"]["1"]) == ["TR", "TDURD", "REMTRIP", "ULTRIP"]
    assert device_info["output_logic"]["L1"] == {
        "OUT101": "HALARM OR SALARM",
        "OUT102": "START",
        "OUT103": "TRIP OR PB04",
    }
    assert device_info["close_logic"] == {}
    assert "logic_equations" not in device_info  # Added by SELRelay.parse_config


# --- Output files ---


@pytest.mark.parametrize(
    "input_name",
    ["sel-710_Relay710.rdb", "sel-710_SET_ALL.TXT", "sel-710_rdb_streams"],
)
def test_parse_writes_settings_records(input_name, parse_env, caplog):
    dev = SELRelay.parse(RELAY_DIR / input_name)
    assert dev is not None

    devices = parse_env / "devices"
    records = _read_json(devices, "settings.json")
    assert len(records) == len(settings_to_records(SEL_710_SET_ALL.read_bytes()))
    assert _find(records, "P1", "NETMODE")["value"] == "FAILOVER"
    assert not list(devices.rglob("settings.1.json"))

    meta = _read_json(devices, "settings-meta.json")
    assert meta["family"] == "7xx"
    assert meta["classes"]["P1"]["name"] == "Port 1"

    logic = _read_json(devices, "logic-equations.json")
    assert logic["1"]["TR"]["value"].startswith("49T OR LOSSTRIP OR JAMTRIP")
    assert logic["L1"]["SV01"]["parts"] == {"SV01PU": "0.00", "SV01DO": "0.00"}
    assert logic["L1"]["OUT103"] == {"value": "TRIP OR PB04", "parts": {"OUT103FS": "Y"}}
    assert "LT01" not in logic["L1"]  # The latches aren't used
    assert set(logic) == {"1", "2", "3", "L1", "L2", "L3", "G", "F", "R"}

    parsed = _read_json(devices, "parsed-config.json")
    assert parsed["logic_settings"]["1"] == {"TDURD": "0.5"}
    assert parsed["logic_equations"]["G"]["BFI"] == "R_TRIG TRIP"
    assert "TDURD" in parsed["trip_logic"]["1"]  # Unchanged

    # The text listing of the equations, as a string
    equations_text = dev.logic.formats["selogic-equations"]
    assert isinstance(equations_text, str)
    assert equations_text.startswith("[1]\n51ATC := 1\n")
    assert "\nTR := 49T OR LOSSTRIP OR JAMTRIP" in equations_text
    assert "\nSV01 := WDGTRIP OR BRGTRIP" in equations_text
    assert "TDURD" not in equations_text

    # The existing logic output is the same
    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in dev.logic.parsed
    assert "OUT103=TRIP OR " in dev.logic.parsed
    formatted = next(devices.rglob("formatted-logic.txt")).read_text(encoding="utf-8")
    assert "logic_equations" not in formatted

    # The records aren't in the device data or Elasticsearch data
    assert not any("settings" in key.lower() for key in dev.extra)
    assert '"description_raw"' not in json.dumps(dev.export(), default=str)
    elastic_logic = dev.elastic().get("logic", {})
    assert set(elastic_logic.get("formats", {})) == {"selogic-equations"}

    assert "Traceback" not in caplog.text
    assert "ERROR" not in caplog.text


def test_parse_duplicate_warning_once(parse_env, caplog):
    # The settings are only parsed once, so the warning is only logged once
    path = parse_env / "SET_ALL.TXT"
    text = SEL_710_SET_ALL.read_text(encoding="utf-8")
    path.write_text(text.replace('TDURD,"0.5"', 'TDURD,"0.5"\r\nTDURD,"0.6"', 1), encoding="utf-8")

    dev = SELRelay.parse(path)
    assert dev is not None

    assert caplog.text.count("Setting 'TDURD' is in section [1] more than once") == 1
    records = _read_json(parse_env / "devices", "settings.json")
    assert [r["value"] for r in records if r["section"] == "1" and r["name"] == "TDURD"] == [
        "0.5",
        "0.6",
    ]
    parsed = _read_json(parse_env / "devices", "parsed-config.json")
    assert parsed["logic_settings"]["1"] == {"TDURD": "0.6"}


def test_parse_relay_files_dir_single_records_file(parse_env):
    # CFG.TXT is parsed with the SET_*.TXT files, its records aren't saved separately
    relay = parse_env / "relay"
    (relay / "SETTINGS").mkdir(parents=True)
    shutil.copyfile(STREAMS_DIR / "Misc" / "Cfg.txt", relay / "CFG.TXT")
    for path in STREAMS_DIR.glob("set_*.txt"):
        shutil.copyfile(path, relay / "SETTINGS" / path.name.upper())

    assert SELRelay.parse(relay) is not None

    records = _read_json(parse_env / "devices", "settings.json")
    assert {r["section"] for r in records} >= {"INFO", "1", "L1", "P1", "M"}
    assert not list((parse_env / "devices").rglob("settings.1.json"))


def test_parse_cfg_txt_records(parse_env):
    dev = SELRelay.parse(STREAMS_DIR / "Misc" / "Cfg.txt")
    assert dev is not None

    devices = parse_env / "devices"
    records = _read_json(devices, "settings.json")
    assert [r["name"] for r in records] == ["RELAYTYPE", "FID", "BFID", "PARTNO"]
    assert all(r["section"] == "INFO" for r in records)

    meta = _read_json(devices, "settings-meta.json")
    assert meta["family"] == "7xx"
    assert len(meta["classes"]) == 15

    assert _read_json(devices, "logic-equations.json") == {}
    assert "selogic-equations" not in dev.logic.formats


def test_parse_show_output_records(parse_env):
    path = parse_env / "sho_output.txt"
    path.write_text(
        "=>>SHO 1\r\n"
        'RID      := "RELAY 1"\r\n'
        "TR       := 50P1T OR REMTRIP\r\n"
        "=>>SHO P 1\r\n"
        "IPADDR   := 192.0.2.75\r\n",
        encoding="utf-8",
    )

    dev = SELRelay.parse(path)
    assert dev is not None
    assert dev.ip == "192.0.2.75"

    records = _read_json(parse_env / "devices", "settings.json")
    assert [(r["section"], r["name"], r["kind"]) for r in records] == [
        ("1", "RID", "setting"),
        ("1", "TR", "equation"),
        ("P1", "IPADDR", "setting"),
    ]
    assert dev.logic.formats["selogic-equations"] == "[1]\nTR := 50P1T OR REMTRIP\n"
    assert not list((parse_env / "devices").rglob("settings-meta.json"))


def test_pull_configs_single_records_file(parse_env, mocker):
    all_files = {}
    for path in [STREAMS_DIR / "Misc" / "Cfg.txt", *STREAMS_DIR.glob("set_*.txt")]:
        name = "CFG.TXT" if path.name == "Cfg.txt" else path.name.upper()
        all_files[name] = {
            "name": name,
            "data": path.read_text(encoding="utf-8"),
            "device_path": f"/SETTINGS/{name}",
            "local_path": None,
        }
    mocker.patch("peat.modules.sel.sel_relay.pull_files", return_value=all_files)

    dev = datastore.get("192.168.1.2", "ip")
    assert SELRelay.pull_configs(dev, comms=None) is True

    records = _read_json(parse_env / "devices", "settings.json")
    assert _find(records, "1", "TR")["kind"] == "equation"
    assert not list((parse_env / "devices").rglob("settings.1.json"))


def test_pull_configs_only_cfg_records(parse_env, mocker):
    cfg = (STREAMS_DIR / "Misc" / "Cfg.txt").read_text(encoding="utf-8")
    all_files = {
        "CFG.TXT": {"name": "CFG.TXT", "data": cfg, "device_path": None, "local_path": None},
        # What a failed download looks like
        "SET_ALL.TXT": {
            "name": "SET_ALL.TXT",
            "data": "=>",
            "device_path": None,
            "local_path": None,
        },
    }
    mocker.patch("peat.modules.sel.sel_relay.pull_files", return_value=all_files)

    dev = datastore.get("192.168.1.2", "ip")
    SELRelay.pull_configs(dev, comms=None)

    records = _read_json(parse_env / "devices", "settings.json")
    assert [r["name"] for r in records] == ["RELAYTYPE", "FID", "BFID", "PARTNO"]


def test_parse_records_failure_doesnt_break_parse(parse_env, mocker, caplog):
    mocker.patch.object(relay_parse, "settings_to_records", side_effect=ValueError("bad"))

    dev = SELRelay.parse(SEL_710_SET_ALL)

    assert dev is not None
    assert dev.ip == "192.168.1.2"
    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in dev.logic.parsed
    assert "Failed to export the settings records" in caplog.text
    assert not list((parse_env / "devices").rglob("settings.json"))
    parsed = _read_json(parse_env / "devices", "parsed-config.json")
    assert parsed["logic_equations"] == {}
    assert parsed["logic_settings"] == {}
