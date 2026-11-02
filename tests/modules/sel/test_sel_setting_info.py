"""
Tests for the annotations of SEL relay settings and SELOGIC equations
(sel_setting_info.py): full names, descriptions, allowed values, units,
the security summary, and the user's descriptions file.

The SEL-710 settings are the real, MIT-licensed files in data_files/relay/
(see the README there). That relay's files only have two columns, so the
400-series lines are short inline strings in the layout documented in
docs/sel.rst, with setting names from the SEL-421 Instruction Manual.
"""

import copy
import json
from pathlib import Path

import pytest

from peat import SELRelay, config, datastore
from peat.modules.sel import sel_setting_info
from peat.modules.sel.relay_parse import settings_to_records
from peat.modules.sel.sel_logic import group_logic
from peat.modules.sel.sel_setting_info import (
    ANNOTATION_FIELDS,
    SETTING_INFO,
    annotate_logic,
    annotate_record,
    annotate_records,
    class_name,
    format_annotated_equations,
    load_setting_descriptions,
    parse_allowed_values,
    parse_range,
    security_summary,
    setting_info,
)

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"
SEL_710_SET_ALL = RELAY_DIR / "sel-710_SET_ALL.TXT"

SET_ALL_4XX = (
    "[INFO]\r\n"
    "RELAYTYPE=SEL-421\r\n"
    "FID=SEL-421-5-R000-V0-Z000000-D20000101\r\n"
    "[P5]\r\n"
    '"TPORT",23,"23,1025-65534",I,"","Telnet Port (23,1025-65534)"\r\n'
    '"DNPTR1","TCP","",S,"","Transport Protocol (UDP,TCP)"\r\n'
    '"E50P","N","","","","      Phase"\r\n'
    '"NETMODE","FAILOVER"\r\n'
    '"FTPSERV","Y"\r\n'
    '"FTPANMS","N"\r\n'
    "[L1]\r\n"
    '"PROTSEL1","PSV01 := R_TRIG 52AA1 # Pulse for each close",,S,"",""\r\n'
    '"PROTSEL2","PCN01PV := 500",,S,"",""\r\n'
    '"PROTSEL3","PCN01IN := PSV01",,S,"",""\r\n'
    '"PROTSEL4","PCT03PU := 5.3",,S,"",""\r\n'
    '"PROTSEL5","# Nothing else",,S,"",""\r\n'
    "[M]\r\n"
    '"MOD_001","IA_MAG"\r\n'
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
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.dict(sel_setting_info._OVERRIDE_CACHE, clear=True)
    return tmp_path


@pytest.fixture(scope="module")
def records_710():
    return annotate_records(settings_to_records(SEL_710_SET_ALL.read_bytes()), "7xx", "710")


@pytest.fixture(scope="module")
def records_4xx():
    return annotate_records(settings_to_records(SET_ALL_4XX), "4xx", "421")


def _find(records, section, name):
    return next(r for r in records if r["section"] == section and r["name"] == name)


def _read_json(directory, name):
    paths = list(directory.rglob(name))
    assert len(paths) == 1, f"Expected one {name}, found {paths}"
    return json.loads(paths[0].read_text(encoding="utf-8"))


def _record(name, value="", section="P1", **fields):
    rec = {"section": section, "name": name, "value": value, "kind": "setting"}
    rec.update(fields)
    return rec


# --- Allowed values ---


@pytest.mark.parametrize(
    ("range_text", "description", "expected"),
    [
        ("2~10", None, ["2-10"]),
        ("23,1025-65534", None, ["23", "1025-65534"]),
        ("OFF, 1-30 min", None, ["OFF", "1-30"]),
        ("Y, N", None, ["Y", "N"]),
        ("N, 1-4, C1-C4", None, ["N", "1-4", "C1-C4"]),
        ("N, 1B, 2B", None, ["N", "1B", "2B"]),
        ("I, M, 1-32767", None, ["I", "M", "1-32767"]),
        ("@, #, $, %, &", None, ["@", "#", "$", "%", "&"]),
        ("\u201324.00 to 24.00", None, ["-24.00 to 24.00"]),
        ("0.00\u20132.00 cycles in 0.25-cycle steps", None, ["0.00-2.00"]),
        (None, "Transport Protocol (UDP,TCP)", ["UDP", "TCP"]),
        (None, "UDP Response Port (REQ, 1025-65534)", ["REQ", "1025-65534"]),
        (None, "Enable Telnet (Y,N)", ["Y", "N"]),
        ("", "Unsolicited Message Max Retry Attempts (2-10)", ["2-10"]),
        # The range column first
        ("2~10", "Retries (Y,N)", ["2-10"]),
        # Not lists of values
        (None, "Relay Identifier (30 characters)", None),
        (None, "IP Address (zzz.yyy.xxx.www)", None),
        (None, "Voltage elements (see Figure 3.22)", None),
        (None, "Telnet Port", None),
        ("SELOGIC", None, None),
        ("0.00-300.00 V secondary in 0.01 V steps", None, None),
        (None, None, None),
        ("", "", None),
    ],
)
def test_parse_allowed_values(range_text, description, expected):
    assert parse_allowed_values(range_text, description) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("OFF, 1-30 min", (["OFF", "1-30"], "min")),
        ("0.10\u201365.00 sec", (["0.10-65.00"], "s")),
        ("5\u201380%", (["5-80"], "%")),
        ("15, 64 cyc", (["15", "64"], "cycles")),
        ("AUTO, 10, 100 Mbps", (["AUTO", "10", "100"], "Mbps")),
        ("50, 60 Hz", (["50", "60"], "Hz")),
        ("1 - 30", (["1-30"], None)),
        ("IRIG1, IRIG2", (["IRIG1", "IRIG2"], None)),
        ("16 Characters", (None, None)),
    ],
)
def test_parse_range(text, expected):
    assert parse_range(text) == expected


# --- Setting information lookups ---


def test_setting_info_sources():
    assert setting_info("NETMODE", "P1", "7xx", "710") == {
        "name": "Ethernet operating mode",
        "desc": SETTING_INFO["NETMODE"]["desc"],
        "values": "FIXED, FAILOVER, SWITCHED",
        "sources": {"name": "peat", "desc": "peat", "values": "peat"},
    }
    assert setting_info("SV05", "L1", "7xx")["sources"]["name"] == "pattern"
    assert setting_info("XYZZY", "P1", "7xx") == {}
    assert setting_info("", "P1") == {}


@pytest.mark.parametrize(
    ("family", "model", "expected"),
    [
        ("7xx", "710", "FIXED, FAILOVER, SWITCHED"),
        ("7xx", "751A", "FIXED, FAILOVER, SWITCHED"),
        # The 351S has PRP. Model values take precedence over family values.
        ("3xx", "351S", "FIXED, FAILOVER, SWITCHED, PRP"),
        ("3xx", "SEL-0351S", "FIXED, FAILOVER, SWITCHED, PRP"),
        # Not known for other families
        ("4xx", "421", None),
        ("3xx", "311C", None),
        (None, None, None),
    ],
)
def test_setting_info_netmode_by_family_and_model(family, model, expected):
    assert setting_info("NETMODE", "P1", family, model).get("values") == expected


def test_setting_info_family_names():
    # The same setting has different values, or a different name, by family
    assert setting_info("MAXACC", "P5", "4xx", "421")["values"] == "1, B, P, A, O, 2, C"
    assert setting_info("MAXACC", "P5", "3xx", "351S")["values"] == "0, 1, B, 2, C"
    assert "values" not in setting_info("MAXACC", "P1", "7xx", "710")
    assert setting_info("T_OUT", "PF", "7xx")["values"] == "0-30"
    assert setting_info("TIMEOUT", "PF", "4xx")["values"] == "OFF, 1-60"
    assert setting_info("TIDLE", "P5", "4xx")["values"] == "0-255"
    assert setting_info("TIDLE", "P1", "7xx")["values"] == "1-30"
    assert setting_info("FTIME", "P5", "4xx")["units"] == "ms"
    assert setting_info("FTIME", "P1", "7xx")["units"] == "s"
    assert setting_info("EFTPSERV", "P1", "7xx")["name"] == setting_info("FTPSERV", "P5")["name"]
    # The SEL-451 truncates names to 7 characters
    assert setting_info("HTTPPOR", "P5")["name"] == "Web server port"


def test_setting_info_sections_and_families():
    # Port settings only apply in the port classes (or if the class isn't known)
    assert setting_info("PROTO", "PF", "7xx")["name"] == "Port protocol"
    assert setting_info("PROTO", "SHOW", "7xx")["name"] == "Port protocol"
    assert setting_info("PROTO", "", "7xx")["name"] == "Port protocol"
    assert setting_info("PROTO", "1", "7xx") == {}
    # LMD is only on 300-series relays
    assert setting_info("PREFIX", "P1", "3xx")["name"] == "LMD prefix"
    assert setting_info("PREFIX", "P1", "7xx") == {}
    # M is the Modbus map on 700-series relays and the breaker monitor on 400-series relays
    assert setting_info("MOD_001", "M", "7xx")["name"] == "Modbus map register 001"
    assert setting_info("MOD_001", "M", "4xx") == {}
    assert setting_info("MOD_001", "G", "7xx") == {}


@pytest.mark.parametrize(
    ("name", "section", "family", "full_name"),
    [
        ("SV05", "L1", "7xx", "SELOGIC variable SV05"),
        ("SV05PU", "L1", "7xx", "SV05 timer pickup time"),
        ("SET01", "L1", "7xx", "Latch LT01 set"),
        ("RST12", "L1", "7xx", "Latch LT12 reset"),
        ("OUT403", "L1", "7xx", "Output contact OUT403"),
        ("OUT101FS", "L1", "7xx", "Output OUT101 fail-safe"),
        ("IN101D", "G", "7xx", "Input IN101 debounce time"),
        ("SC03PV", "L1", "7xx", "Counter SC03 preset value"),
        ("MV07", "L1", "7xx", "Math variable MV07"),
        ("TMB4A", "L1", "3xx", "Transmit MIRRORED BIT TMB4A"),
        ("RMB2DO", "PF", "7xx", "Receive MIRRORED BIT RMB2 dropout"),
        ("T03_LED", "F", "7xx", "Target LED T03"),
        ("T03LEDL", "F", "7xx", "Target LED T03 latch"),
        ("PB3B_LED", "F", "7xx", "Pushbutton 3 LED B"),
        ("SS2", "G", "7xx", "Select settings group 2"),
        ("SER3", "R", "7xx", "SER trigger list 3"),
        ("ALIAS4", "R", "7xx", "Alias 4"),
        ("DNPIP2", "P1", "7xx", "DNP3 master IP address (DNP3 session 2)"),
        ("MODNUM1", "P1", "7xx", "Modbus TCP port (Modbus session 1)"),
        ("RTD3LOC", "1", "7xx", "RTD 3 location"),
        ("AI301NAM", "G", "7xx", "Analog input AI301 name"),
        ("PCT03PU", "L1", "4xx", "Protection conditioning timer PCT03 pickup time"),
        ("PSV12", "L1", "4xx", "Protection SELOGIC variable PSV12"),
        ("PLT02R", "L1", "4xx", "Protection latch PLT02 reset"),
        ("ACN05PV", "A1", "4xx", "Automation counter ACN05 preset value"),
        ("PROTSEL7", "L1", "4xx", "Protection logic line 7"),
        ("AUTO_3", "A1", "4xx", "Automation logic line 3"),
        # Protection element settings
        ("50P1P", "1", "7xx", "Phase instantaneous overcurrent level 1 pickup"),
        (
            "50G2D",
            "1",
            "7xx",
            "Residual-ground (3I0) instantaneous overcurrent level 2 time delay",
        ),
        ("51AC", "1", "7xx", "Phase A time-overcurrent curve"),
        ("51ACT", "1", "7xx", "Phase A time-overcurrent constant time adder"),
        ("51ATC", "1", "7xx", "Phase A time-overcurrent torque control"),
        ("51P1TD", "1", "7xx", "Phase time-overcurrent level 1 time dial"),
        ("87M1TD", "1", "7xx", "Motor differential level 1 time delay"),
        ("87M2TC", "1", "7xx", "Motor differential level 2 torque control"),
        ("81D1TP", "1", "7xx", "Definite-time over- or underfrequency level 1 trip pickup"),
        ("27V1P", "1", "3xx", "Positive-sequence undervoltage pickup"),
        # SEL-700G settings for the X and Y sides
        ("CFDX", "1", "7xx", "Close failure delay (X side)"),
        ("TRX", "L1", "7xx", "Trip equation (X side)"),
        ("ULCLY", "1", "7xx", "Unlatch close (Y side)"),
        # Torque control equations of other functions
        ("REF1TC", "1", "7xx", "REF1 torque control"),
        # Element enables
        ("E87M", "1", "7xx", "Motor differential enable"),
        ("E50P", "1", "3xx", "Phase instantaneous overcurrent enable"),
        ("E75", "1", "3xx", "Position Changing Mechanism enable"),
        ("E21MG", "1", "4xx", "Ground distance (mho) enable"),
        ("E25BK1", "1", "4xx", "Synchronism check for breaker 1 enable"),
        ("E81ACC", "1", "7xx", "Off-frequency time accumulators enable"),
        ("81ACCTC", "1", "7xx", "Off-frequency time accumulators torque control"),
        # Explicit entries win over the element enable pattern
        ("E2SPEED", "1", "7xx", "Two-speed motor"),
        ("E61850", "P1", "7xx", "IEC 61850"),
    ],
)
def test_setting_info_patterns(name, section, family, full_name):
    assert setting_info(name, section, family)["name"] == full_name


@pytest.mark.parametrize(
    "name",
    [
        "50P1C",  # Only inverse-time elements have a curve
        "55LGTP",  # The element isn't known
        "37PAP",
        "E55LG",
        "TTT105",
        "MOD_001X",
    ],
)
def test_setting_info_patterns_unknown(name):
    assert "name" not in setting_info(name, "1", "7xx")


def test_setting_info_pattern_values_and_units():
    assert setting_info("SV01PU", "L1", "7xx")["values"] == "0.00-3000.00"
    assert setting_info("SV01PU", "L1", "7xx")["units"] == "s"
    assert setting_info("SV01PU", "L1", "3xx")["units"] == "cycles"
    assert setting_info("IN101D", "G", "7xx")["units"] == "ms"
    assert setting_info("IN101D", "G", "3xx", "351S")["units"] == "cycles"
    assert setting_info("51AC", "1", "7xx")["values"].startswith("U1, U2")
    assert setting_info("51P1CT", "1", "3xx")["units"] == "cycles"
    assert setting_info("50P1D", "1", "7xx")["units"] == "s"
    # Element enables get their values from explicit entries
    assert setting_info("E79", "1", "3xx", "351S")["values"] == "N, 1-4, C1-C4"
    assert setting_info("E79", "1", "7xx", "751A")["values"] == "OFF, 1-4"
    assert setting_info("E79", "1", "7xx", "751A")["name"] == "Autoreclosing enable"


def test_setting_info_security_flags():
    for name in ["ETELNET", "EFTPSERV", "FTPANMS", "MAXACC", "FASTOP", "T_OUT", "EHTTP", "EDNP"]:
        assert setting_info(name, "P1")["security"] is True, name
    assert setting_info("DSABLSET", "G")["security"] is True
    for name in ["NETMODE", "IPADDR", "PARITY", "SV01"]:
        assert "security" not in setting_info(name, "P1"), name


def test_setting_info_entries_are_valid():
    allowed = {"name", "desc", "values", "units", "security", "sections", "only"}
    allowed |= {"by_family", "by_model"}
    for name, entry in SETTING_INFO.items():
        assert name == name.upper(), name
        assert set(entry) <= allowed, name
        for values in [entry.get("values")] + [
            v.get("values") for v in [*entry.get("by_family", {}).values()]
        ]:
            if values:
                assert parse_range(values)[0], (name, values)


# --- Annotating records ---


def test_annotate_records_sel_710_netmode(records_710):
    netmode = _find(records_710, "P1", "NETMODE")

    assert netmode["value"] == "FAILOVER"
    assert netmode["full_name"] == "Ethernet operating mode"
    assert netmode["description"].startswith("How the two Ethernet ports are used.")
    assert netmode["description_source"] == "peat"
    assert netmode["allowed_values"] == ["FIXED", "FAILOVER", "SWITCHED"]
    assert netmode["allowed_values_source"] == "peat"
    assert netmode["units"] is None
    assert netmode["security"] is False
    # The device doesn't have a description, and the class name is from [CLASSES]
    assert netmode["description_raw"] is None
    assert netmode["class_name"] == "Port 1"


def test_annotate_records_sel_710(records_710):
    keys = list(settings_to_records(SEL_710_SET_ALL.read_bytes())[0])
    assert all(list(r)[: len(keys)] == keys for r in records_710)
    assert all(set(ANNOTATION_FIELDS) <= set(r) for r in records_710)

    telnet = _find(records_710, "P1", "ETELNET")
    assert telnet["full_name"] == "Telnet server"
    assert telnet["security"] is True

    t_out = _find(records_710, "PF", "T_OUT")
    assert (t_out["allowed_values"], t_out["units"]) == (["0-30"], "min")

    sv05 = _find(records_710, "L1", "SV05")
    assert (sv05["full_name"], sv05["description_source"]) == ("SELOGIC variable SV05", "pattern")

    assert _find(records_710, "L1", "OUT403")["full_name"] == "Output contact OUT403"
    assert _find(records_710, "1", "50P1P")["full_name"] == (
        "Phase instantaneous overcurrent level 1 pickup"
    )
    assert _find(records_710, "1", "TR")["full_name"] == "Trip equation"
    assert _find(records_710, "1", "E47T")["allowed_values"] == ["Y", "N"]
    assert _find(records_710, "INFO", "FID")["full_name"] == "Firmware identifier"
    assert _find(records_710, "M", "MOD_001")["full_name"] == "Modbus map register 001"

    # Most of the settings are known
    known = [r for r in records_710 if r["full_name"]]
    assert len(known) / len(records_710) > 0.85


def test_annotate_records_device_description_wins(records_4xx):
    tport = _find(records_4xx, "P5", "TPORT")

    assert tport["description"] == "Telnet Port (23,1025-65534)"
    assert tport["description_source"] == "device"
    assert tport["full_name"] == "Telnet Port"
    assert tport["allowed_values"] == ["23", "1025-65534"]
    assert tport["allowed_values_source"] == "device"
    assert tport["security"] is True  # From PEAT

    # The values in the description
    dnptr = _find(records_4xx, "P5", "DNPTR1")
    assert dnptr["allowed_values"] == ["UDP", "TCP"]
    assert dnptr["allowed_values_source"] == "device"
    assert dnptr["full_name"] == "Transport Protocol"

    # An indented description is an item under a heading, not a full name
    e50p = _find(records_4xx, "P5", "E50P")
    assert e50p["description"] == "Phase"
    assert e50p["description_source"] == "device"
    assert e50p["full_name"] == "Phase instantaneous overcurrent enable"

    # No values for the 400-series in the table, and none from the device
    netmode = _find(records_4xx, "P5", "NETMODE")
    assert netmode["description_source"] == "peat"
    assert netmode["allowed_values"] is None


def test_annotate_records_4xx_logic(records_4xx):
    # Free-form logic lines are described by the variable they assign
    assert _find(records_4xx, "L1", "PROTSEL1")["full_name"] == "Protection SELOGIC variable PSV01"
    assert _find(records_4xx, "L1", "PROTSEL2")["full_name"] == (
        "Protection counter PCN01 preset value"
    )
    assert _find(records_4xx, "L1", "PROTSEL4")["full_name"] == (
        "Protection conditioning timer PCT03 pickup time"
    )
    assert _find(records_4xx, "L1", "PROTSEL4")["units"] == "cycles"
    # Only a comment
    assert _find(records_4xx, "L1", "PROTSEL5")["full_name"] == "Protection logic line 5"

    # M is the breaker monitor on 400-series relays
    mod = _find(records_4xx, "M", "MOD_001")
    assert mod["full_name"] is None
    assert mod["class_name"] == "Breaker monitor"
    assert _find(records_4xx, "L1", "PROTSEL1")["class_name"] == "Protection logic 1"


def test_annotate_record_user_overrides():
    rec = _record("NETMODE", "FAILOVER")
    overrides = {"NETMODE": {"name": "My mode", "desc": "Mine", "values": "A, B", "units": "x"}}

    annotated = annotate_record(rec, "7xx", "710", overrides)
    assert annotated["full_name"] == "My mode"
    assert annotated["description"] == "Mine"
    assert annotated["description_source"] == "user"
    assert annotated["allowed_values"] == ["A", "B"]
    assert annotated["allowed_values_source"] == "user"
    assert annotated["units"] == "x"

    # The rest is from PEAT
    annotated = annotate_record(rec, "7xx", "710", {"NETMODE": {"desc": "Mine"}})
    assert annotated["full_name"] == "Ethernet operating mode"
    assert annotated["description_source"] == "user"
    assert annotated["allowed_values_source"] == "peat"

    # By model, and for settings PEAT doesn't know
    overrides = {
        "NETMODE": {"by_model": {"710": {"values": ["FIXED"]}}},
        "XYZZY": {"name": "Something", "values": [1, 2]},
    }
    assert annotate_record(rec, "7xx", "710", overrides)["allowed_values"] == ["FIXED"]
    assert annotate_record(rec, "7xx", "751A", overrides)["allowed_values_source"] == "peat"
    xyzzy = annotate_record(_record("XYZZY"), "7xx", "710", overrides)
    assert (xyzzy["full_name"], xyzzy["allowed_values"]) == ("Something", ["1", "2"])

    # The device's description and range still win
    device = _record("NETMODE", "FIXED", description="Mode", range="FIXED,PRP")
    annotated = annotate_record(device, "7xx", "710", {"NETMODE": {"desc": "Mine", "values": "A"}})
    assert (annotated["description"], annotated["description_source"]) == ("Mode", "device")
    assert annotated["allowed_values"] == ["FIXED", "PRP"]


def test_annotate_record_doesnt_change_record():
    rec = _record("TPORT", "23", description="Telnet Port", range="23,1025-65534")
    original = copy.deepcopy(rec)

    annotated = annotate_record(rec, "4xx", "421")

    assert rec == original
    assert annotated is not rec
    assert annotated["allowed_values"] == ["23", "1025-65534"]


def test_annotate_record_unknown():
    annotated = annotate_record(_record("XYZZY", "1"), "7xx", "710")

    assert {k: annotated[k] for k in ANNOTATION_FIELDS} == {
        "full_name": None,
        "description_source": None,
        "allowed_values": None,
        "allowed_values_source": None,
        "units": None,
        "security": False,
    }
    assert annotated["description"] is None


@pytest.mark.parametrize(
    ("section", "family", "expected"),
    [
        ("M", "7xx", "Modbus map"),
        ("M", "3xx", "Modbus map"),
        ("M", "4xx", "Breaker monitor"),
        ("T", "3xx", "Text labels"),
        ("T", "4xx", "Alias"),
        ("O", "4xx", "Output"),
        ("L1", "4xx", "Protection logic 1"),
        ("L1", "7xx", "Logic 1"),
        ("A1", "4xx", "Automation logic 1"),
        ("P5", "3xx", "Port 5"),
        ("PF", "7xx", "Port F"),
        ("S1", "4xx", "Group 1"),
        ("2", "7xx", "Group 2"),
        ("D1", "3xx", "DNP3 map 1"),
        ("INFO", "7xx", None),
        ("A1", "7xx", None),
        ("", None, None),
    ],
)
def test_class_name(section, family, expected):
    assert class_name(section, family) == expected


# --- SELOGIC equations ---


def test_annotate_logic_sel_710(records_710):
    logic = annotate_logic(group_logic(records_710), records_710, "7xx", "710")

    assert logic["1"]["TR"]["full_name"] == "Trip equation"
    assert logic["1"]["TR"]["description"].startswith("SELOGIC equation with the conditions")
    assert logic["L1"]["SV01"]["full_name"] == "SELOGIC variable SV01"
    assert logic["L1"]["SV01"]["part_names"] == {
        "SV01PU": "SV01 timer pickup time",
        "SV01DO": "SV01 timer dropout time",
    }
    assert logic["L1"]["OUT103"] == {
        "value": "TRIP OR PB04",
        "parts": {"OUT103FS": "Y"},
        "full_name": "Output contact OUT103",
        "description": "SELOGIC equation that operates output contact OUT103.",
        "part_names": {"OUT103FS": "Output OUT103 fail-safe"},
    }
    assert logic["F"]["T05_LED"]["full_name"] == "Target LED T05"
    assert logic["G"]["BFI"]["full_name"] == "Breaker failure initiate"


def test_annotate_logic_4xx(records_4xx):
    logic = annotate_logic(group_logic(records_4xx), records_4xx, "4xx", "421")

    assert logic["L1"]["PSV01"]["full_name"] == "Protection SELOGIC variable PSV01"
    assert logic["L1"]["PSV01"]["comments"] == {"PSV01": "Pulse for each close"}
    assert logic["L1"]["PCN01"]["full_name"] == "Protection counter PCN01"
    assert logic["L1"]["PCN01"]["part_names"] == {
        "PCN01PV": "Protection counter PCN01 preset value",
        "PCN01IN": "Protection counter PCN01 input",
    }


def test_annotate_logic_variable_without_record():
    # Latches don't have a setting of their own
    records = annotate_records(
        [
            _record("SET01", "IN101", section="L1", kind="equation"),
            _record("RST01", "NA", section="L1", kind="equation_unset"),
        ],
        "7xx",
    )
    logic = annotate_logic(group_logic(records), records, "7xx")

    assert logic["L1"]["LT01"]["full_name"] == "Latch bit LT01"
    assert logic["L1"]["LT01"]["part_names"] == {
        "SET01": "Latch LT01 set",
        "RST01": "Latch LT01 reset",
    }


def test_format_annotated_equations(records_710, records_4xx):
    text = format_annotated_equations(records_710)

    assert text.startswith("[1]\n51ATC := 1\n    # Phase A time-overcurrent torque control: ")
    assert (
        "\nTR := 49T OR LOSSTRIP OR JAMTRIP OR 46UBT OR 50P1T OR 50G1T OR 59P1T OR 47T OR 55T "
        "OR SPDSTR OR 50N1T OR SMTRIP OR (27P1T AND NOT LOP) OR SV01T\n"
        "    # Trip equation: SELOGIC equation with the conditions that trip the breaker.\n"
    ) in text
    assert "TDURD" not in text
    assert "SV02" not in text  # Not set (NA)

    text = format_annotated_equations(records_4xx)
    assert (
        "PSV01 := R_TRIG 52AA1 # Pulse for each close\n"
        "    # Protection SELOGIC variable PSV01: Boolean variable of the protection logic.\n"
    ) in text
    assert format_annotated_equations([]) == ""


# --- Security summary ---


def test_security_summary_sel_710(records_710):
    summary = security_summary(records_710)

    assert summary["enabled_services"] == ["ftp", "telnet"]
    assert summary["fast_operate_ports"] == []
    assert summary["disabled_ports"] == []
    assert "anonymous_ftp" not in summary  # The 710 doesn't have the setting
    assert summary["P1.ETELNET"] == "Y"
    assert summary["P1.TPORT"] == "23"
    assert summary["P1.EFTPSERV"] == "Y"
    assert summary["P1.FTPUSER"] == "FTPUSER"
    assert summary["P1.E61850"] == "N"
    assert summary["P1.EMOD"] == "0"
    assert summary["PF.T_OUT"] == "5"
    assert summary["P4.PROTO"] == "DNET"
    assert summary["G.DSABLSET"] == "0"
    assert summary["G.BLKMBSET"] == "NONE"
    assert "P1.NETMODE" not in summary
    assert len(summary) < 50
    assert all(isinstance(v, (str, list)) for v in summary.values())


def test_security_summary_services():
    records = annotate_records(
        [
            _record("EPORT", "Y", section="P5"),
            _record("FTPSERV", "Y", section="P5"),
            _record("FTPANMS", "Y", section="P5"),
            _record("EHTTP", "Y", section="P5"),
            _record("E61850", "Y", section="P5"),
            _record("EGSE", "Y", section="P5"),
            _record("EMMSFS", "N", section="P5"),
            _record("EDNP", "2", section="P5"),
            _record("EMOD", "0", section="P5"),
            _record("T1RECV", "Y", section="P5"),
            _record("FASTOP", "Y", section="PF"),
            # Services on a disabled port aren't enabled
            _record("EPORT", "N", section="P1"),
            _record("ETELNET", "Y", section="P1"),
            _record("FASTOP", "Y", section="P1"),
        ],
        "4xx",
    )

    summary = security_summary(records)

    assert summary["enabled_services"] == [
        "dnp3",
        "ftp",
        "goose",
        "http",
        "iec61850",
        "telnet",
    ]
    assert summary["anonymous_ftp"] is True
    assert summary["fast_operate_ports"] == ["PF"]
    assert summary["disabled_ports"] == ["P1"]
    assert summary["P1.ETELNET"] == "Y"


def test_security_summary_nothing():
    records = annotate_records([_record("NETMODE", "FIXED"), _record("RID", "X", section="1")])
    assert security_summary(records) == {}
    assert security_summary([]) == {}


# --- User descriptions file ---


def test_load_setting_descriptions(tmp_path, caplog):
    path = tmp_path / "descriptions.json"
    path.write_text(
        json.dumps(
            {
                "netmode": {"name": "My mode", "by_model": {"SEL-0351S": {"values": "A"}}},
                "BAD": "not an object",
                "REGEX": {"name": "Bad regex", "sections": "[", "only": "4xx", "by_family": 3},
            }
        ),
        encoding="utf-8",
    )

    entries = load_setting_descriptions(path)

    assert set(entries) == {"NETMODE", "REGEX"}
    assert entries["NETMODE"]["by_model"] == {"351S": {"values": "A"}}
    assert entries["REGEX"] == {"name": "Bad regex", "only": ["4xx"]}
    assert "Skipping setting 'BAD'" in caplog.text
    assert "Ignoring the 'sections' of setting 'REGEX'" in caplog.text
    assert setting_info("NETMODE", "P1", "3xx", "351S", entries)["values"] == "A"
    # Cached until the file changes
    assert load_setting_descriptions(str(path)) is entries


def test_load_setting_descriptions_wrong_types(tmp_path, caplog):
    path = tmp_path / "descriptions.json"
    path.write_text(
        json.dumps(
            {
                "NETMODE": {
                    "only": 5,
                    "values": 5,
                    "security": "no",
                    "name": {"x": 1},
                    "desc": ["a"],
                    "sections": ["P1"],
                    "description": "Not a key (desc is)",
                    "units": None,
                    "by_family": {"7XX": {"units": "s", "values": {"a": 1}}, "4xx": "x"},
                    "by_model": {"SEL-710": {"security": 1, "values": ["FIXED", 2]}},
                },
                "TPORT": {"desc": "My Telnet port", "security": True, "only": ["7XX"]},
            }
        ),
        encoding="utf-8",
    )

    entries = load_setting_descriptions(path)

    assert entries["NETMODE"] == {
        "by_family": {"7xx": {"units": "s"}},
        "by_model": {"710": {"values": ["FIXED", 2]}},
    }
    assert entries["TPORT"] == {"desc": "My Telnet port", "security": True, "only": ["7xx"]}
    for message in [
        "Ignoring 'only' of setting 'NETMODE'",
        "Ignoring 'values' of setting 'NETMODE' in",
        "Ignoring 'security' of setting 'NETMODE' in",
        "Ignoring 'name' of setting 'NETMODE'",
        "Ignoring 'desc' of setting 'NETMODE'",
        "Ignoring 'sections' of setting 'NETMODE'",
        "Ignoring unknown key 'description' of setting 'NETMODE'",
        "Ignoring 'values' of setting 'NETMODE' (by_family '7XX')",
        "Ignoring setting 'NETMODE' (by_family '4xx')",
        "Ignoring 'security' of setting 'NETMODE' (by_model 'SEL-710')",
    ]:
        assert message in caplog.text, message

    # The fields that are valid are used
    netmode = setting_info("NETMODE", "P1", "7xx", "710", entries)
    assert netmode["values"] == ["FIXED", 2]
    assert netmode["units"] == "s"
    assert netmode["name"] == "Ethernet operating mode"
    assert "security" not in netmode
    assert setting_info("TPORT", "P1", "7xx", "710", entries)["desc"] == "My Telnet port"


@pytest.mark.parametrize("content", ["not json", "[1, 2]", None])
def test_load_setting_descriptions_bad_file(tmp_path, caplog, content):
    path = tmp_path / "descriptions.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")

    assert load_setting_descriptions(path) == {}
    assert "SEL setting descriptions file" in caplog.text


# --- Output files ---


def test_parse_writes_annotations(parse_env, caplog):
    dev = SELRelay.parse(SEL_710_SET_ALL)
    assert dev is not None
    devices = parse_env / "devices"

    records = _read_json(devices, "settings.json")
    netmode = _find(records, "P1", "NETMODE")
    assert netmode["full_name"] == "Ethernet operating mode"
    assert netmode["allowed_values"] == ["FIXED", "FAILOVER", "SWITCHED"]

    logic = _read_json(devices, "logic-equations.json")
    assert logic["1"]["TR"]["full_name"] == "Trip equation"
    assert logic["L1"]["SV01"]["part_names"]["SV01PU"] == "SV01 timer pickup time"

    summary = dev.extra["sel_security_settings"]
    assert summary["enabled_services"] == ["ftp", "telnet"]
    assert summary["P1.TPORT"] == "23"

    # The existing logic, then the equations with descriptions
    formatted = next(devices.rglob("formatted-logic.txt")).read_text(encoding="utf-8")
    assert formatted.startswith(dev.logic.parsed)
    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in dev.logic.parsed
    assert "# Trip equation: " not in dev.logic.parsed
    assert "\n    # Trip equation: SELOGIC equation with the conditions" in formatted

    parsed = _read_json(devices, "parsed-config.json")
    assert parsed["protection_schemes"] == {
        "47T": "Phase reversal (voltage) tripping",
        "49MOTOR": "Motor thermal model (thermal overload)",
    }
    assert set(parsed["protection_schemes_by_group"]) == {"1", "2", "3"}

    assert "Traceback" not in caplog.text
    assert "ERROR" not in caplog.text


def test_parse_user_descriptions_file(parse_env, mocker):
    path = parse_env / "my-descriptions.json"
    path.write_text(
        json.dumps({"NETMODE": {"desc": "Port redundancy", "values": "FIXED, FAILOVER"}}),
        encoding="utf-8",
    )
    mocker.patch.dict(datastore.global_options, {"sel": {"setting_descriptions_file": str(path)}})

    assert SELRelay.parse(SEL_710_SET_ALL) is not None

    netmode = _find(_read_json(parse_env / "devices", "settings.json"), "P1", "NETMODE")
    assert netmode["description"] == "Port redundancy"
    assert netmode["description_source"] == "user"
    assert netmode["allowed_values"] == ["FIXED", "FAILOVER"]
    assert netmode["full_name"] == "Ethernet operating mode"


def test_parse_user_descriptions_file_bad_entry(parse_env, mocker, caplog):
    # A mistake in one entry is ignored, and doesn't affect the other annotations
    path = parse_env / "my-descriptions.json"
    path.write_text(
        json.dumps(
            {
                "NETMODE": {"only": 5, "values": 5, "security": "no", "name": {"x": 1}},
                "TPORT": {"desc": "My Telnet port"},
            }
        ),
        encoding="utf-8",
    )
    mocker.patch.dict(datastore.global_options, {"sel": {"setting_descriptions_file": str(path)}})

    dev = SELRelay.parse(SEL_710_SET_ALL)

    assert dev is not None
    assert "Failed to annotate" not in caplog.text
    assert "Ignoring 'only' of setting 'NETMODE'" in caplog.text
    records = _read_json(parse_env / "devices", "settings.json")
    netmode = _find(records, "P1", "NETMODE")
    assert netmode["full_name"] == "Ethernet operating mode"
    assert netmode["allowed_values"] == ["FIXED", "FAILOVER", "SWITCHED"]
    assert netmode["allowed_values_source"] == "peat"
    assert netmode["security"] is False
    tport = _find(records, "P1", "TPORT")
    assert tport["description"] == "My Telnet port"
    assert tport["description_source"] == "user"
    assert dev.extra["sel_security_settings"]["enabled_services"] == ["ftp", "telnet"]


def test_parse_annotation_failure_keeps_records(parse_env, mocker, caplog):
    mocker.patch("peat.modules.sel.relay_parse.annotate_records", side_effect=ValueError("bad"))

    dev = SELRelay.parse(SEL_710_SET_ALL)

    assert dev is not None
    assert "Failed to annotate the settings records" in caplog.text
    records = _read_json(parse_env / "devices", "settings.json")
    assert "full_name" not in _find(records, "P1", "NETMODE")
    assert "sel_security_settings" not in dev.extra
    assert _read_json(parse_env / "devices", "logic-equations.json")["1"]["TR"]["value"]
