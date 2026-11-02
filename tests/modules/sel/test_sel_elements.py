"""
Tests for the SEL protection element names (sel_elements.py), the fixes to
ANSI_CODES, and the detection of enabled protection elements (protection schemes).

The SEL-710 settings are the real, MIT-licensed files in data_files/relay/
(see the README there). The other settings are short inline dicts with
setting names and values from the settings sheets of the public SEL-351S,
SEL-700G and SEL-751A instruction manuals.
"""

import ast
from pathlib import Path

import pytest

from peat.modules.sel import sel_consts
from peat.modules.sel.relay_parse import (
    element_enabled,
    parse_config_data,
    parse_protection_schemes,
    parse_protection_schemes_by_group,
    parse_set_all,
)
from peat.modules.sel.sel_consts import ANSI_CODES
from peat.modules.sel.sel_elements import ELEMENT_ENABLE_RE, ansi_name, element_name

SEL_710_SET_ALL = Path(__file__).resolve().parent / "data_files" / "relay" / "sel-710_SET_ALL.TXT"


def _group(**settings):
    return {name: {"value": value, "description": ""} for name, value in settings.items()}


# --- Element names ---


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("21", "Distance"),
        ("21P", "Phase distance (mho)"),
        ("50BF", "Breaker failure"),
        ("51G", "Residual-ground (3I0) time-overcurrent"),
        ("59N", "Neutral overvoltage"),
        ("64G", "Stator ground"),
        ("67Q", "Negative-sequence directional overcurrent"),
        ("81R", "Rate-of-change of frequency"),
        ("87T", "Transformer differential"),
        ("16ESM", "Data Communications Device (Ethernet: switch, network managed)"),
        # The synchronism-check channel, not "DC undervoltage"
        ("27S", "Undervoltage on the synchronism-check voltage channel (VS)"),
        ("94", "Trip"),
        ("97", "Used only for specific applications"),
        ("100", None),
        ("", None),
        # SEL meanings
        ("68", "Out-of-step (power swing) blocking"),
        ("78", "Out-of-step tripping"),
        ("87N", "Restricted earth fault (REF)"),
        ("60", "Loss of potential (LOP)"),
        # Levels and terminal sides
        ("50P1", "Phase instantaneous overcurrent level 1"),
        ("87M2", "Motor differential level 2"),
        ("27V1X", "Positive-sequence undervoltage (X side)"),
        ("81RX", "Rate-of-change of frequency (X side)"),
        ("25X", "Synchronism check (X side)"),
        # SEL-421 and SEL-700G elements, and SEL meanings of suffix letters
        ("21MG", "Ground distance (mho)"),
        ("25BK1", "Synchronism check for breaker 1"),
        ("25BK3", "Synchronism check (breaker) #3"),
        ("81ACC", "Off-frequency time accumulators"),
        ("32Q", "Directional element or directional power (negative sequence)"),
        # From ANSI_CODES
        ("64REF", "Restricted earth fault differential"),
        ("27TN/59N", "100% Stator Earth Fault"),
        # Combined, and generic names for the number
        ("51P/67P", "Phase time-overcurrent / Phase directional overcurrent"),
        ("75", "Position Changing Mechanism"),
    ],
)
def test_ansi_name(code, expected):
    assert ansi_name(code) == expected


def test_ansi_name_model():
    # 51C is phase C on the 710 and 751A, and voltage-controlled on the 700G
    assert ansi_name("51C") == "Phase C time-overcurrent"
    assert ansi_name("51C", "710") == "Phase C time-overcurrent"
    assert ansi_name("51C", "700G") == "Voltage-controlled time-overcurrent"
    assert ansi_name("51C", "SEL-700G") == "Voltage-controlled time-overcurrent"


def test_element_name_only_known_elements():
    assert element_name("50P1") == "Phase instantaneous overcurrent level 1"
    # Not fully known, so they can't be used to build a description
    assert element_name("55LG") is None
    assert element_name("97") is None
    assert element_name("50QF") is None
    assert element_name("16ESM") is None


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("E50P", "50P"),
        ("E87M", "87M"),
        ("E49MOTOR", "49MOTOR"),
        ("E27V1X", "27V1X"),
        ("E81", "81"),
    ],
)
def test_element_enable_re(name, code):
    assert ELEMENT_ENABLE_RE.match(name).group(1) == code


@pytest.mark.parametrize("name", ["E61850", "E2SPEED", "EDNP", "ETELNET", "E", "E5"])
def test_element_enable_re_not_elements(name):
    assert ELEMENT_ENABLE_RE.match(name) is None


# --- ANSI_CODES ---


def test_ansi_codes_no_duplicate_keys():
    # Duplicate keys in a dict literal silently replace the earlier value
    tree = ast.parse(Path(sel_consts.__file__).read_text(encoding="utf-8"))
    node = next(
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "ANSI_CODES"
    )
    keys = [k.value for k in node.keys]
    assert len(keys) == len(set(keys))


def test_ansi_codes_fixes():
    assert ANSI_CODES["51"] == "AC Inverse Time Overcurrent Relay"
    assert ANSI_CODES["27X"] == "Auxiliary Undervoltage"
    assert ANSI_CODES["87S"] == "Stator Differential"
    assert ANSI_CODES["13"] == "Synchronous-Speed Device"
    assert ANSI_CODES["85"] == "Pilot Communications, Carrier, or Pilot-Wire Relay"
    assert "DC" not in ANSI_CODES["27S"]
    assert not any(":" in name for name in ANSI_CODES.values())


# --- Protection schemes ---


@pytest.mark.parametrize(
    ("value", "enabled"),
    [
        ("Y", True),
        ("3", True),
        ("AUTO", True),
        ("C2", True),
        ("INT", True),
        ("GEN", True),
        ("1B", True),
        ("N", False),
        ("NO", False),
        ("OFF", False),
        ("NONE", False),
        ("none", False),
        ("0", False),
        ("", False),
        ({"value": "Y"}, True),
    ],
)
def test_element_enabled(value, enabled):
    assert element_enabled(value) is enabled


def test_parse_protection_schemes_enable_values():
    # SEL-710 group 1 enables, plus value domains from the 351S and 751A settings sheets
    configs = {
        "1": _group(
            E47T="Y",
            E49MOTOR="Y",
            E87M="N",
            E49RTD="NONE",
            E32="AUTO",
            E79="C2",
            E50P="3",
            E81R="OFF",
            E61850="Y",
            E2SPEED="Y",
            E32IV="1",  # A SELOGIC equation, not an element
            TID="MOTOR RELAY",
        ),
        "P1": _group(E61850="Y", ETELNET="Y"),
    }

    schemes = parse_protection_schemes(configs, "710")

    assert schemes == {
        "47T": "Phase reversal (voltage) tripping",
        "49MOTOR": "Motor thermal model (thermal overload)",
        "32": "Directional element or directional power",
        "79": "Autoreclosing",
        "50P": "Phase instantaneous overcurrent",
    }
    assert parse_protection_schemes_by_group(configs, "710") == {"1": schemes}


def test_parse_protection_schemes_sel_710():
    configs = parse_config_data(SEL_710_SET_ALL.read_bytes())

    # Before, nothing was found, since 47T and 49MOTOR aren't in ANSI_CODES
    expected = {
        "47T": "Phase reversal (voltage) tripping",
        "49MOTOR": "Motor thermal model (thermal overload)",
    }
    assert parse_protection_schemes(configs, "710") == expected
    assert parse_protection_schemes_by_group(configs, "710") == {
        "1": expected,
        "2": expected,
        "3": expected,
    }

    device_info, _ = parse_set_all(SEL_710_SET_ALL.read_bytes())
    assert device_info["protection_schemes"] == expected
    assert set(device_info["protection_schemes_by_group"]) == {"1", "2", "3"}


def test_parse_protection_schemes_400_and_700g_names():
    # Enables from the group settings of the SEL-421 and SEL-700G manuals
    configs_421 = {
        "1": _group(E21P="3", E21MG="2", E21XG="N", E25BK1="Y", E25BK2="N", E32="AUTO"),
    }
    assert parse_protection_schemes(configs_421, "421") == {
        "21P": "Phase distance (mho)",
        "21MG": "Ground distance (mho)",
        "25BK1": "Synchronism check for breaker 1",
        "32": "Directional element or directional power",
    }

    configs_700g = {"1": _group(E81ACC="2", E81X="N", E25X="Y")}
    assert parse_protection_schemes(configs_700g, "700G") == {
        "81ACC": "Off-frequency time accumulators",
        "25X": "Synchronism check (X side)",
    }


def test_parse_protection_schemes_groups():
    configs = {
        "1": _group(E25="Y", E81="N"),
        "2": _group(E25="N", E81="2"),
        "S3": _group(E50G="1"),
        "G": _group(E25="Y"),  # Not a settings group
    }

    assert parse_protection_schemes_by_group(configs) == {
        "1": {"25": "Synchronism check"},
        "2": {"81": "Frequency"},
        "S3": {"50G": "Residual-ground (3I0) instantaneous overcurrent"},
    }
    assert parse_protection_schemes(configs) == {
        "25": "Synchronism check",
        "81": "Frequency",
        "50G": "Residual-ground (3I0) instantaneous overcurrent",
    }


def test_parse_protection_schemes_voltage_elements():
    # 351S: voltage elements are enabled with EVOLT, and set with a pickup
    group = _group(EVOLT="Y", **{"27P1P": "50.00", "59P1P": "OFF", "59N1P": "0.00", "27S1P": "N"})
    assert parse_protection_schemes({"1": group}, "351S") == {"27P": "Phase undervoltage"}

    group["EVOLT"]["value"] = "N"
    assert parse_protection_schemes({"1": group}, "351S") == {}

    # No EVOLT setting, e.g. 700-series relays (this used to raise a KeyError that was ignored)
    del group["EVOLT"]
    assert parse_protection_schemes({"1": group}, "751A") == {}


def test_parse_protection_schemes_487e():
    configs = {
        "1": _group(E87="Y"),
        "L1": _group(PROTSEL1="PSV01 := IN101", PROTSEL2=""),
        "STORAGE": ["/SWCFG.ZIP"],
    }

    assert parse_protection_schemes(configs, "487E") == {
        "L1": ["PSV01 := IN101"],
        "87": "Differential",
    }
