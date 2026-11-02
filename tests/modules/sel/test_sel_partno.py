"""
Tests for decoding SEL part numbers (peat.modules.sel.sel_partno).

Sources of the part numbers (only the part numbers are used):

- SEL-751 data sheet, Figure 37 (``751091A1ACALA7LAF30``)
- SEL-700G data sheet, Figures 32-34, and SEL-700G Card Options
  instructions (``0700G...``)
- SEL-710 and SEL-751 Card Options instructions, "PART NUM" examples
  (``071001B5X1X7X86020X``, ``751001B5X1X7086020X``)
- SEL-787 Card Options instructions (``0 7 8 7 0 X 1 A 6 X 3 A 1 A 8 5 0 2 0 X``)
- SEL-751A dealer listings (``751A01A1A0X71850300``, ...)
- SEL AN2015-02 (``0241101A3A2X0X0X0130``, with a leading 0). The SEL-2411-1
  MOT (WI-7201) and the SEL-2411P MOT headers have no leading 0 (``24111``,
  ``2411P``), and neither does the relay's PARTNO.
- SEL IEC 61850 PIXIT documents (2023), lists of models: SEL-411L-A,
  SEL-421-7S, SEL-421-7P (letters in the variant)
- QuickSet settings templates: placeholder part numbers
  (``751A0XXXXXXXXXXXXXX``, ``0710XXXXXXXXXXXXXX``, ``0787XXXXXXXXXXXXXXXX``)
- SEL-351S Instruction Manual (date code 20171023): CFG.TXT figures in
  section 10 and the output contact examples in section 2
- SEL-751A Instruction Manual (date code 20130329), section 1, and SEL-700G
  Instruction Manual, section 1: layout of the STA output
- Dealer listings of SEL-451-5 and SEL-487E relays
- PEAT: docs/sel.rst (SEL-700G ID output), the PEAT docstring example
  (``035152B3A11XX1``), and the SEL-710 test files (``071001A5X6X71821210``)

Part numbers marked "synthetic" are made from the codes in the Model Option
Tables, to test each table.
"""

import random
from pathlib import Path

import pytest

from peat import DeviceData, SELRelay, config, datastore
from peat.modules.sel import sel_partno
from peat.modules.sel.relay_parse import parse_status_output, process_info_into_dev
from peat.modules.sel.sel_cascii import parse_id_output
from peat.modules.sel.sel_partno import (
    EXTRA_KEY,
    FAMILIES,
    LAYOUT_DOCUMENTED,
    LAYOUT_INFERRED,
    LAYOUT_PLACEHOLDER,
    LAYOUT_PREFIX_ONLY,
    LAYOUT_UNRECOGNIZED,
    RESULT_KEYS,
    UNKNOWN,
    decode_part_number,
    find_family,
    normalize_part_number,
    process_part_number,
)

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"


@pytest.fixture
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
    return tmp_path


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]


# ---------------------------------------------------------------------------
# Every example part number decodes without errors, with the expected layout
# and unknown codes
# ---------------------------------------------------------------------------

EXAMPLES = [
    # (part number, model, layout, unknown codes)
    ("751091A1ACALA7LAF30", "SEL-751", LAYOUT_DOCUMENTED, {}),
    ("751A01A1A0X71850300", "SEL-751A", LAYOUT_DOCUMENTED, {}),
    ("751A51ABA0X72850221", "SEL-751A", LAYOUT_DOCUMENTED, {}),
    ("751A11DCD1D74851320", "SEL-751A", LAYOUT_DOCUMENTED, {}),
    ("751A51A0X0X74850000", "SEL-751A", LAYOUT_DOCUMENTED, {}),
    ("751A02CBC0X71850201", "SEL-751A", LAYOUT_DOCUMENTED, {}),
    ("0241101A3A2X0X0X0130", "SEL-2411", LAYOUT_DOCUMENTED, {}),
    # Synthetic: the same without the leading 0 (the MOT and PARTNO form)
    ("241101A3A2X0X0X0130", "SEL-2411", LAYOUT_DOCUMENTED, {}),
    ("071001A5X6X71821210", "SEL-710", LAYOUT_DOCUMENTED, {}),
    ("0351S7XHD3J5442", "SEL-351S", LAYOUT_DOCUMENTED, {}),
    ("0351S7XHD4E5421", "SEL-351S", LAYOUT_DOCUMENTED, {}),
    ("0351S7XHD4E5441", "SEL-351S", LAYOUT_DOCUMENTED, {}),
    ("0351S7XHD4E5461", "SEL-351S", LAYOUT_DOCUMENTED, {}),
    ("0700G12B1B1B7281A230", "SEL-700G", LAYOUT_INFERRED, {}),
    ("0700G11ACA9X76850830", "SEL-700G", LAYOUT_INFERRED, {}),
    ("0700GW1A1A6X77870310", "SEL-700G", LAYOUT_INFERRED, {}),
    ("0700G11ACA1D7281020X", "SEL-700G", LAYOUT_INFERRED, {}),
    ("0700GT1B0X0X7181063X", "SEL-700G", LAYOUT_INFERRED, {}),
    ("04515611XC2X4H6444421", "SEL-451", LAYOUT_PREFIX_ONLY, {}),
    ("0487E3X411XXB4X4H5XXXXX", "SEL-487E", LAYOUT_PREFIX_ONLY, {}),
    ("0487E42615XXC4X43644XXX", "SEL-487E", LAYOUT_PREFIX_ONLY, {}),
    ("0487E0241111XXB43624XXX", "SEL-487E", LAYOUT_PREFIX_ONLY, {}),
    # Synthetic: a SEL-411L-A (letter variant)
    ("0411LAX7X6C5DDXH4D564XX", "SEL-411L", LAYOUT_PREFIX_ONLY, {}),
    # Older codes that aren't in the current tables
    (
        "035152B3A11XX1",
        "SEL-351",
        LAYOUT_DOCUMENTED,
        {"user_interface": "B", "comm_interface": "A"},
    ),
    ("0351S7XH34E5462", "SEL-351S", LAYOUT_DOCUMENTED, {"user_interface": "3"}),
    (
        "071001B5X1X7X86020X",
        "SEL-710",
        LAYOUT_DOCUMENTED,
        {"slot_d": "1X", "slot_e": "7X", "conformal_coat": "X"},
    ),
    ("07870X1A6X3A1A85020X", "SEL-787", LAYOUT_DOCUMENTED, {"conformal_coat": "X"}),
    (
        "751A01B1X0X7386163X",
        "SEL-751A",
        LAYOUT_DOCUMENTED,
        {"slot_c": "1X", "conformal_coat": "X"},
    ),
    # Older layouts and a misprint (18 characters)
    ("0351S61H4455421", "SEL-351S", LAYOUT_UNRECOGNIZED, {}),
    ("751001B5X1X7086020X", "SEL-751", LAYOUT_UNRECOGNIZED, {}),
    ("0700GT1A2X7585A630", "SEL-700G", LAYOUT_UNRECOGNIZED, {}),
    # Synthetic: SEL-351-0 to -4 (older firmware digits)
    ("03512C3E5411X1", "SEL-351", LAYOUT_UNRECOGNIZED, {}),
    # Placeholders in settings templates
    ("751A0XXXXXXXXXXXXXX", "SEL-751A", LAYOUT_PLACEHOLDER, {}),
    ("0710XXXXXXXXXXXXXX", "SEL-710", LAYOUT_PLACEHOLDER, {}),
    ("0787XXXXXXXXXXXXXXXX", "SEL-787", LAYOUT_PLACEHOLDER, {}),
]


@pytest.mark.parametrize(("part_number", "model", "layout", "unknown"), EXAMPLES)
def test_examples(part_number, model, layout, unknown):
    info = decode_part_number(part_number)

    assert info["part_number"] == part_number
    assert info["model"] == model
    assert info["layout"] == layout
    assert info["advisory"] is True
    assert info.get("unknown_codes", {}) == unknown

    if layout == LAYOUT_UNRECOGNIZED:
        assert "codes" not in info
        assert "Doesn't fit the known layout" in info["notes"][0]
    elif layout == LAYOUT_PLACEHOLDER:
        assert "codes" not in info
        assert "mot" not in info
        assert "Placeholder part number" in info["notes"][0]
    else:
        # Every code is recorded, and the unknown codes are "N/A"
        assert info["codes"]
        for name in info["codes"]:
            if name in info:
                assert (info[name] == UNKNOWN) == (name in unknown)

    if unknown:
        assert "older table or edited" in info["notes"][0]
    elif layout not in (LAYOUT_UNRECOGNIZED, LAYOUT_PLACEHOLDER):
        assert "notes" not in info


def test_unrecognized_notes():
    note = decode_part_number("0351S61H4455421")["notes"][0]
    assert "SEL-351S WI-8323 (2021-12-21): character 7 is '1', not 'X'" in note

    note = decode_part_number("751001B5X1X7086020X")["notes"][0]
    assert "character 19 is 'X', not one of '01'" in note

    note = decode_part_number("0700GT1A2X7585A630")["notes"][0]
    assert "SEL-700G (no public MOT): 18 characters, not 20" in note

    # Both SEL-787 layouts are listed
    note = decode_part_number("07870X1A")["notes"][0]
    assert "WI-7257 (2018-09-13): 8 characters, not 20" in note
    assert "WI-9842 (2024-10-21): 8 characters, not 21" in note

    note = decode_part_number("0451")["notes"][0]
    assert "no character 5" in note

    # SEL-351-0 to -4: a SEL-351 (not an unknown product), with the reason
    note = decode_part_number("03512C3E5411X1")["notes"][0]
    assert "SEL-351 WI-8349 (2017-02-23): character 5 is '2', not one of '567'" in note


def test_placeholders():
    # Placeholders in settings templates: only the model, and no options
    for part_number in ("0351XXXXXXXXXX", "0351S6XXXXXXXXX", "751XXXXXXXXXXXXXXXX"):
        info = decode_part_number(part_number)
        assert info["layout"] == LAYOUT_PLACEHOLDER, part_number
        assert "codes" not in info

    # The model is still compared with the FID
    assert "mismatches" not in decode_part_number("751A0XXXXXXXXXXXXXX", fid="SEL-751A-R100")
    assert decode_part_number("0710XXXXXXXXXXXXXX", fid="SEL-751A-R100")["mismatches"] == {
        "model": {"part_number": "710", "fid": "751A"}
    }

    # Other products aren't, even with the same start
    assert decode_part_number("0351RXXXXXXXXX") == {}  # SEL-351R
    assert decode_part_number("2411PXXXXXXXXXXXXX") == {}  # SEL-2411P
    # Too short to be a placeholder
    assert decode_part_number("0351XXX") == {}
    # Not every option is "X"
    assert decode_part_number("0787XXXXXXXXXXXXXXX0") == {}
    assert decode_part_number("751A0XXXXXXXXXXXXX0")["layout"] == LAYOUT_DOCUMENTED


# ---------------------------------------------------------------------------
# Decoded options, per product
# ---------------------------------------------------------------------------


def test_751_data_sheet_example():
    info = decode_part_number("751091A1ACALA7LAF30")

    assert info["mot"] == "WI-9222 (2026-05-20)"
    assert info["advanced_firmware"] == "None"
    assert info["language_extended_io"] == "English, extended I/O: 42 binary inputs, 24 DO"
    assert info["slot_a"] == "110-250 Vdc/110-240 Vac power supply, 125 V DI"
    assert info["slot_c"] == "4 DI/4 DO, 125 V DI"
    assert info["slot_d"] == "4 DI/4 DO fast high-current, 125 V DI"
    assert info["slot_e"] == "LEA Vsync, Vbat, 7 DI, 125 V DI"
    assert info["slot_z"] == "3 Rogowski/LPCT currents, 200 mA neutral ACI, 3 LEA voltages"
    assert info["front_panel"] == "5 inch touchscreen, 8 pushbuttons"
    assert info["slot_b"] == "2x 10/100BASE-T, no fiber serial, EIA-232"
    assert info["protocols"] == "IEC 61850, DNP3"
    assert info["conformal_coat"] == "Not coated"
    assert info["codes"] == {
        "advanced_firmware": "0",
        "language_extended_io": "9",
        "slot_a": "1A",
        "slot_c": "1A",
        "slot_d": "CA",
        "slot_e": "LA",
        "slot_z": "7L",
        "front_panel": "A",
        "slot_b": "F",
        "protocols": "3",
        "conformal_coat": "0",
    }


@pytest.mark.parametrize(
    ("code", "protocols"),
    [
        ("0", "None"),
        ("1", "IEC 61850"),
        ("4", "IEC 60870-5-103"),
        ("8", "EtherNet/IP"),
        # "B" and "C" don't follow the pattern of the other codes in the MOTs
        ("B", "IEC 60870-5-103, EtherNet/IP"),
        ("C", "IEC 61850, DNP3, EtherNet/IP"),
        ("F", "IEC 61850, DNP3, IEC 60870-5-103, EtherNet/IP"),
    ],
)
def test_751_protocols(code, protocols):
    # Synthetic: SEL-751 with reclosing, Spanish, no extended I/O, empty slots
    info = decode_part_number(f"7511S1A0X0X0XA11C{code}1")
    assert info["protocols"] == protocols
    assert info["advanced_firmware"] == "Reclosing"
    assert info["language_extended_io"] == "Spanish, extended I/O: none"
    assert info["slot_z"] == "3 ACI, neutral ACI (1 A phase, 1 A neutral)"
    assert info["front_panel"] == "2x16 LCD, 4 pushbuttons"
    assert info["conformal_coat"] == "Conformal coated"
    assert "unknown_codes" not in info


def test_751_newer_cards():
    # Synthetic: 8 DO (4 Form A, 4 Form B), 10 RTD, 8 arc-flash inputs, 14 DI
    info = decode_part_number("75100" + "2H" + "2G" + "9X" + "77" + "82" + "B600")
    assert info["layout"] == LAYOUT_DOCUMENTED
    assert info["slot_a"] == "24-48 Vdc power supply, 250 V DI"
    assert info["slot_c"] == "8 DO (4 Form A, 4 Form B)"
    assert info["slot_d"] == "10 RTD inputs"
    assert info["slot_e"] == "8 arc-flash inputs"
    assert info["slot_z"] == "3 ACI, neutral ACI (1 A phase, 5 A neutral), 3 AVI"
    assert info["front_panel"] == "5 inch touchscreen, 4 pushbuttons"
    assert info["slot_b"] == "2x 10/100BASE-T, fiber serial (ST), EIA-232"
    assert decode_part_number("75100" + "1A" + "4D" + "0X0XA5" + "0A00")["slot_c"] == (
        "14 DI, 110 V DI"
    )
    # The SEL-751A MOT doesn't have them
    assert decode_part_number("751A0" + "2H" + "2G" + "0X0X85" + "0000")["unknown_codes"] == {
        "slot_c": "2G"
    }

    # A serial card is only in Slot C, and RTD cards only in Slot D
    info = decode_part_number("75100" + "1A" + "9X" + "A0" + "0X" + "81" + "0A00")
    assert info["unknown_codes"] == {"slot_c": "9X", "slot_d": "A0"}


def test_751a_example():
    info = decode_part_number("751A01A1A0X71850300")

    assert info["mot"] == "WI-7074 (2018-09-13)"
    assert info["firmware"] == "Standard"
    assert info["slot_a"] == "110-250 Vdc/110-240 Vac power supply, 125 V DI"
    assert info["slot_c"] == "4 DI/4 DO, 125 V DI"
    assert info["slot_d"] == "Empty"
    assert info["slot_e"] == "3 AVI (300 V)"
    assert info["slot_z"] == "4 ACI (5 A phase, 5 A neutral)"
    assert info["slot_b_processor"] == "Standard"
    assert info["slot_b_ethernet"] == "1x 10/100BASE-T, EIA-485"
    assert info["protocols"] == "Standard"
    assert info["conformal_coat"] == "Not coated"

    info = decode_part_number("751A11DCD1D74851320")
    assert info["firmware"] == "Standard plus reclosing"
    assert info["slot_c"] == "4 DI/4 DO fast high-current, 110 V DI"
    assert info["slot_e"] == "3 AVI, 4 arc-flash inputs"
    assert info["slot_b_processor"] == "Standard plus fiber serial (ST)"
    assert info["protocols"] == "Standard plus DNP3"


def test_2411_an2015_02_example():
    info = decode_part_number("0241101A3A2X0X0X0130")

    assert info["mot"] == "WI-7201 (2008-12-08)"
    assert info["variant"] == "SEL-2411"
    assert info["slot_a"] == "125/250 Vdc/Vac power supply, 125 V DI"
    assert info["slot_c"] == "8 DI, 125 V DI"
    assert info["slot_d"] == "8 DO"
    assert info["slot_e"] == "Empty"
    assert info["slot_z"] == "Empty"
    assert info["slot_b_fiber_serial"] == "None"
    assert info["slot_b_ethernet"] == "1x 10/100BASE-T"
    assert info["protocols"] == "Standard plus DNP3"
    assert info["conformal_coat"] == "Not coated"


def test_2411_with_and_without_leading_0():
    # The relay's PARTNO and the MOT header have no leading 0 ("2411", then the
    # variant), AN2015-02 has one. Both are decoded the same way.
    relay_form = decode_part_number("241101A3A2X0X0X0130", fid="SEL-2411-R308-V0-Z005005-D2011")
    an_form = decode_part_number("0241101A3A2X0X0X0130")

    assert relay_form["layout"] == LAYOUT_DOCUMENTED
    assert relay_form["codes"] == an_form["codes"]
    assert {k: v for k, v in relay_form.items() if k != "part_number"} == {
        k: v for k, v in an_form.items() if k != "part_number"
    }
    assert "mismatches" not in relay_form

    # Synthetic (WI-7201 codes): SEL-2411-1 with a serial card, 3 ACI/3 AVI, and DNP3
    info = decode_part_number("24111" + "2BA01C7486" + "0631")
    assert info["variant"] == "SEL-2411-1 (surface mount)"
    assert info["slot_a"] == "24/48 Vdc power supply, 24 V DI"
    assert info["slot_c"] == "EIA-232/485 serial card"
    assert info["slot_d"] == "4 DI/4 DO, 48 V DI"
    assert info["slot_e"] == "3 ACI (5 A), 3 AVI (300 V)"
    assert info["slot_z"] == "4 ACI (5 A phase, 1 A neutral)"
    assert info["slot_b_ethernet"] == "2x 10/100BASE-T"
    assert info["protocols"] == "Standard plus DNP3"
    assert info["conformal_coat"] == "Conformal coated"
    assert "unknown_codes" not in info

    # Wrong length for both forms
    assert decode_part_number("241101A3A2X0X0X01300")["layout"] == LAYOUT_UNRECOGNIZED
    assert decode_part_number("0241101A3A2X0X0X013")["layout"] == LAYOUT_UNRECOGNIZED


def test_2411_cards_differ_from_700_series():
    # Synthetic: "B" is a fast high-current 4 DI/4 DO card on the SEL-2411,
    # but a 3 DI/4 DO/1 AO card on SEL-700 series relays
    info = decode_part_number("241112BBBCB7481" + "1640")
    assert info["variant"] == "SEL-2411-1 (surface mount)"
    assert info["slot_c"] == "4 DI/4 DO fast high-current, 24 V DI"
    assert info["slot_d"] == "4 DI/3 DO (2 Form C, 1 Form B), 24 V DI"
    assert info["slot_e"] == "3 ACI (5 A), 3 AVI (300 V)"
    assert info["slot_z"] == "4 ACI (1 A phase, 1 A neutral)"
    assert info["slot_b_fiber_serial"] == "Fiber serial (ST)"
    assert info["slot_b_ethernet"] == "2x 10/100BASE-T"
    assert info["protocols"] == "Standard plus IEC 61850"

    assert decode_part_number("751A01A" + "BB" + "0X0X85" + "0000")["slot_c"] == (
        "3 DI/4 DO/1 AO, 24 V DI"
    )


def test_700g_inferred():
    info = decode_part_number("0700G12B1B1B7281A230", fid="SEL-700G-R200-V0-Z006003-D20180629")

    assert info["layout"] == LAYOUT_INFERRED
    assert "mot" not in info
    assert info["slot_a"] == "24-48 Vdc power supply, 24 V DI"
    assert info["slot_c"] == "4 DI/4 DO, 24 V DI"
    assert info["slot_d"] == "4 DI/4 DO, 24 V DI"
    # Only recorded, there's no public table
    for name in ("variant", "slot_e", "slot_z", "slot_b", "conformal_coat"):
        assert name not in info
    assert info["codes"] == {
        "variant": "1",
        "slot_a": "2B",
        "slot_c": "1B",
        "slot_d": "1B",
        "slot_e": "72",
        "slot_z": "81",
        "slot_b": "A23",
        "conformal_coat": "0",
    }
    assert "mismatches" not in info


def test_710_pr20_fixture():
    info = decode_part_number("071001A5X6X71821210")

    assert info["mot"] == "WI-5180 (2018-12-07)"
    assert info["slot_a"] == "110-250 Vdc/110-240 Vac power supply, 125 V DI"
    assert info["slot_c"] == "8 AI"
    assert info["slot_d"] == "4 AI/4 AO"
    assert info["slot_e"] == "3 AVI (300 V)"
    assert info["slot_z"] == "4 ACI (1 A phase, 5 A neutral)"
    assert info["slot_b_time_input"] == "PTC thermistor input"
    assert info["slot_b_rear_port"] == "EIA-232, 1x 10/100BASE-T"
    assert info["protocols"] == "Standard plus IEC 61850"
    assert info["conformal_coat"] == "Not coated"


def test_351_families():
    # PEAT docstring example: older user interface and communications codes
    info = decode_part_number("035152B3A11XX1")
    assert info["mot"] == "WI-8349 (2017-02-23)"
    assert info["firmware"] == "Basic"
    assert info["housing"] == "2U horizontal rack"
    assert info["user_interface"] == UNKNOWN
    assert info["power_supply"] == "48/125 Vdc or 120 Vac"
    assert info["comm_interface"] == UNKNOWN
    assert info["nominal_current"] == "1 A phase, 1 A neutral"
    assert info["control_input_voltage"] == "24 Vdc"
    assert info["io_board"] == "None"
    assert info["conformal_coat"] == "Not coated"
    assert info["protocols"] == "Standard"

    # SEL-351S manual
    info = decode_part_number("0351S7XHD3J5442")
    assert info["mot"] == "WI-8323 (2021-12-21)"
    assert info["firmware"] == "Standard plus power elements and sag/swell/interruption"
    assert info["housing"] == "3U horizontal rack"
    assert info["user_interface"] == (
        "Standard with USB, indoor SafeLock pushbuttons, configurable labels"
    )
    assert info["comm_interface"] == "2x 10/100BASE-T, fiber serial (ST)"
    assert info["nominal_current"] == "5 A phase, 5 A neutral"
    assert info["control_input_voltage"] == "125 Vdc"
    assert info["io_board"] == "4 standard outputs, 16 inputs"
    assert info["protocols"] == "Standard plus IEC 61850"
    assert decode_part_number("0351S7XHD4E5461")["io_board"] == (
        "12 high-current interrupting outputs, 8 inputs"
    )

    # Synthetic SEL-351A and SEL-351A-1
    info = decode_part_number("0351A04" + "2X4E14X1")
    assert info["model"] == "SEL-351A"
    assert info["mot"] == "WI-8347 (2017-02-23)"
    assert info["firmware"] == "Standard (SEL-351A)"
    assert info["housing"] == "2U vertical panel (no LCD)"
    assert "unknown_codes" not in info

    info = decode_part_number("0351A1H6X3D5322")
    assert info["model"] == "SEL-351A-1"
    assert info["mot"] == "WI-8348 (2017-02-23)"
    assert info["user_interface"] == "Standard with USB, SafeLock pushbuttons"
    assert info["comm_interface"] == "1x 100BASE-FX (LC), EIA-485"
    assert info["conformal_coat"] == "Conformal coated"
    assert "unknown_codes" not in info

    # Vertical panels and SEF inputs aren't offered on the SEL-351A-1
    info = decode_part_number("0351A14" + "2X4E84X1")
    assert info["unknown_codes"] == {"housing": "4", "nominal_current": "8"}

    # Synthetic SEL-311C-2
    info = decode_part_number("0311C21HH4E14X2")
    assert info["mot"] == "WI-9285 (2017-02-23)"
    assert info["firmware"] == "Single-pole trip, three-pole reclose (SEL-311C-2)"
    assert info["chassis"] == "3U"
    assert info["housing"] == "Horizontal rack"
    assert info["user_interface"] == "Standard with USB"
    assert info["io_board"] == "None"
    assert info["protocols"] == "Standard plus IEC 61850"
    assert "unknown_codes" not in info


def test_787_layouts():
    # SEL-787 Card Options example, printed with spaces
    info = decode_part_number("0 7 8 7 0 X 1 A 6 X 3 A 1 A 8 5 0 2 0 X")
    assert info["part_number"] == "07870X1A6X3A1A85020X"
    assert info["mot"] == "WI-7257 (2018-09-13)"
    assert info["firmware"] == "Two-winding differential"
    assert info["slot_c"] == "4 AI/4 AO"
    assert info["slot_d"] == "8 DI, 125 V DI"
    assert info["slot_e"] == "4 DI/4 DO, 125 V DI"
    assert info["slot_z"] == "6 ACI (5 A winding 1, 5 A winding 2)"
    assert info["slot_b_ethernet"] == "1x 10/100BASE-T, EIA-232"

    # Slot E depends on the firmware option
    info = decode_part_number("07871X1A0X0XA181" + "0230")
    assert info["slot_e"] == "1 neutral ACI (1 A)"
    assert info["protocols"] == "Standard plus DNP3 and IEC 61850"
    info = decode_part_number("07871X1A0X0X1A81" + "0230")
    assert info["unknown_codes"] == {"slot_e": "1A"}

    # Synthetic SEL-787-3E
    info = decode_part_number("07873EE1A1A0X7281A630")
    assert info["mot"] == "WI-9842 (2024-10-21)"
    assert info["model_option"] == "Three-winding differential, 1 neutral current, 3 voltages"
    assert info["language"] == "English"
    assert info["slot_e"] == "3 ACI (1 A), 1 neutral ACI (1 A), 3 AVI (300 V)"
    assert info["slot_z"] == "6 ACI (1 A winding 1, 1 A winding 2)"
    assert info["front_panel"] == "5 inch touchscreen, 8 pushbuttons"
    assert info["slot_b_ethernet"] == "2x 10/100BASE-T, EIA-232"
    assert info["protocols"] == "IEC 61850, DNP3"
    assert "unknown_codes" not in info

    # A voltage card isn't offered with the two-winding model
    info = decode_part_number("07872XS1A1A0X7281A630")
    assert info["language"] == "Spanish"
    assert info["unknown_codes"] == {"slot_e": "72"}

    # Unknown model option: the codes of all of the models are accepted
    info = decode_part_number("07874EE1A1A0X7281A630")
    assert info["unknown_codes"] == {"model_option": "4E"}
    assert info["slot_e"] == "3 ACI (1 A), 1 neutral ACI (1 A), 3 AVI (300 V)"


def test_2440_and_2032():
    # Synthetic
    info = decode_part_number("24402H11B1B11630")
    assert info["mot"] == "WI-8148 (2018-11-14)"
    assert info["housing"] == "Horizontal rack"
    assert info["io"] == "32 DI, 16 DO, 24 V DI"
    assert info["serial_port_2"] == "EIA-232"
    assert info["ethernet"] == "2x 10/100BASE-T"
    assert info["protocols"] == "DNP3"
    assert decode_part_number("24402W12A6314841")["io"] == (
        "32 DI, 10 fast high-current DO, 125 V DI"
    )
    assert decode_part_number("24402312B1B1" + "4841")["io"] == "48 DI, 24 V DI"
    assert decode_part_number("24402312B1A1" + "4841")["unknown_codes"] == {"io": "2B1A"}

    info = decode_part_number("203233X444G0XX")
    assert info["mot"] == "WI-3644 (2014-07-01)"
    assert info["housing"] == "Horizontal panel"
    assert info["special_hardware"] == "None"
    assert info["power_supply"] == "85-350 Vdc, 85-264 Vac"
    assert info["io_board"] == "4 outputs, 16 inputs (125 Vdc)"
    assert info["protocol_card_1"] == "Ethernet card with DNP3, 2x 10/100BASE-T"
    assert info["protocol_card_2"] == "None"


def test_prefix_only():
    info = decode_part_number("04515611XC2X4H6444421", fid="SEL-451-5-R324-V1-Z027013-D20201009")
    assert info["layout"] == LAYOUT_PREFIX_ONLY
    assert info["codes"] == {"variant": "5"}
    assert "mot" not in info
    assert "variant" not in info  # Not described
    assert "mismatches" not in info

    info = decode_part_number("0487E3X411XXB4X4H5XXXXX", fid="SEL-487E-3-R317-V0-Z0-D2020")
    assert info["codes"] == {"variant": "3"}
    assert "mismatches" not in info

    # Synthetic: SEL-411L variants can be letters (SEL-411L-A)
    info = decode_part_number(
        "0411LAX7X6C5DDXH4D564XX", fid="SEL-411L-A-RXXX-VX-Z022004-DXXXXXXXX"
    )
    assert info["layout"] == LAYOUT_PREFIX_ONLY
    assert info["codes"] == {"variant": "A"}
    assert "mismatches" not in info

    # Other 400-series variants are digits
    note = decode_part_number("0451A611XC2X4H6444421")["notes"][0]
    assert "character 5 is 'A', not one of '0123456789'" in note


# ---------------------------------------------------------------------------
# FID cross-check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("part_number", "fid", "mismatches"),
    [
        ("0351S7XHD3J5442", "SEL-351S-7-R5xx-V0-Z106104-Dyyyymmdd", None),
        ("0351S7XHD3J5442", "SEL-351S-6-R514-V0-Z103103-D20110429", {"variant": ("7", "6")}),
        ("0351S7XHD3J5442", "SEL-351-7-R514-V0-Z103103-D20110429", {"model": ("351S", "351")}),
        ("035152B3A11XX1", "SEL-351-5-R510-V0-Z103103-D20110429", None),
        ("0311C21HH4E14X2", "SEL-311C-1-R508-V0-Z1-D2015", {"variant": ("2", "1")}),
        ("751091A1ACALA7LAF30", "SEL-751A-R400-V0-Z008003-D20150101", {"model": ("751", "751A")}),
        ("751A01A1A0X71850300", "SEL-751A-R400-V0-Z008003-D20150101", None),
        ("071001A5X6X71821210", "SEL-710-Rxxx-Vx-Z008004-Dxxxxxxxx", None),
        ("04515611XC2X4H6444421", "SEL-451-6-R101", {"variant": ("5", "6")}),
        ("04515611XC2X4H6444421", "SEL-487E-3-R317", {"model": ("451", "487E")}),
        ("0411LAX7X6C5DDXH4D564XX", "SEL-411L-1-R130", {"variant": ("A", "1")}),
        # Only the characters in the part number are compared (SEL-421-7S)
        ("04217611XC4X3H71X43XX", "SEL-421-7S-R410-V0", None),
        ("04217611XC4X3H71X43XX", "SEL-421-5-R410-V0", {"variant": ("7", "5")}),
        # SEL-2411: the model is compared, both forms
        ("241101A3A2X0X0X0130", "SEL-2411-R308-V0-Z005005-D20110902", None),
        ("0241101A3A2X0X0X0130", "SEL-2440-R100", {"model": ("2411", "2440")}),
        # Unrecognized layouts are still compared by model
        ("0351S61H4455421", "SEL-751-R300", {"model": ("351S", "751")}),
        # No variant in the FID, or an FID that can't be parsed
        ("0351S7XHD3J5442", "SEL-351S-R514-V0", None),
        ("0351S7XHD3J5442", "garbage", None),
        ("0351S7XHD3J5442", "", None),
    ],
)
def test_fid_mismatches(part_number, fid, mismatches):
    info = decode_part_number(part_number, fid=fid)
    if mismatches is None:
        assert "mismatches" not in info
    else:
        assert info["mismatches"] == {
            key: {"part_number": pn, "fid": fid_value}
            for key, (pn, fid_value) in mismatches.items()
        }


# ---------------------------------------------------------------------------
# Input handling: never raises
# ---------------------------------------------------------------------------


def test_normalize():
    assert normalize_part_number(" 0 351s7xhd3j5442\r\n") == "0351S7XHD3J5442"
    assert normalize_part_number(b"0351S7XHD3J5442") == "0351S7XHD3J5442"
    assert decode_part_number("0351s7xhd3j5442")["part_number"] == "0351S7XHD3J5442"
    assert decode_part_number(b"0351S7XHD3J5442")["model"] == "SEL-351S"


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        0,
        12345,
        b"\xff\xfe",
        "ABC",
        "FROM-STATUS",
        "0351S-7XHD3J5442",  # Not alphanumeric
        "0351²",  # Not ASCII
        "0351R0123456789",  # SEL-351R, not a SEL-351
        "0787Z0123456789",  # SEL-787Z
        "2411P0632012345678",  # SEL-2411P (MOT header "2411P"), not a SEL-2411
        "0311L1234567X",  # SEL-311L, not decoded
        "35304X1A2B3C4D",  # RTAC
        "0351S" + "X" * 100,  # Too long
        [],
        {"PARTNO": "0351S7XHD3J5442"},
    ],
)
def test_not_decoded(value):
    assert decode_part_number(value) == {}


def test_never_raises(mocker, caplog):
    mocker.patch.object(sel_partno, "_decode", side_effect=RuntimeError("bug"))
    assert decode_part_number("0351S7XHD3J5442") == {}
    assert any("Failed to decode SEL part number" in m for m in _warnings(caplog))


def test_fuzz_prefixes():
    # Random part numbers with every prefix, of every length, decode without errors
    rng = random.Random(53)
    alphabet = "0123456789ABCDEFGHJKLMNPRSTUVWXZ"
    for family in FAMILIES:
        for length in range(len(family.prefix), 26):
            for _ in range(20):
                suffix = "".join(rng.choice(alphabet) for _ in range(length - len(family.prefix)))
                info = decode_part_number(family.prefix + suffix, fid="SEL-351S-6-R514")
                assert info == {} or info["advisory"] is True


def test_find_family_longest_prefix():
    assert find_family("0351S7XHD3J5442").model == "SEL-351S"
    assert find_family("0351A0H2X4E14X1").model == "SEL-351A"
    assert find_family("035152B3A11XX1").model == "SEL-351"
    assert find_family("751A01A1A0X71850300").model == "SEL-751A"
    assert find_family("751091A1ACALA7LAF30").model == "SEL-751"
    assert find_family("751") is None  # The guard needs a 4th character
    assert find_family("0351R") is None
    assert find_family("03512C3E5411X1").model == "SEL-351"  # Any digit
    assert find_family("241101A3A2X0X0X0130").prefix == "2411"
    assert find_family("0241101A3A2X0X0X0130").prefix == "02411"
    assert find_family("2411P0632012345678") is None


# ---------------------------------------------------------------------------
# The tables are consistent (for maintainers editing them)
# ---------------------------------------------------------------------------


def test_tables_consistent():
    prefixes = [f.prefix for f in FAMILIES]
    assert len(prefixes) == len(set(prefixes))

    for family in FAMILIES:
        assert family.model.startswith("SEL-")
        assert family.layouts
        for layout in family.layouts:
            assert layout.kind in (LAYOUT_DOCUMENTED, LAYOUT_INFERRED, LAYOUT_PREFIX_ONLY)
            assert bool(layout.mot) == (layout.kind == LAYOUT_DOCUMENTED), layout.model

            names = [o.name for o in layout.options]
            assert len(names) == len(set(names)), layout.model
            assert not set(names) & RESULT_KEYS, layout.model
            if layout.fid_variant:
                assert layout.fid_variant in names

            used = set()
            for index, option in enumerate(layout.options):
                assert len(family.prefix) <= option.start < option.end
                if layout.length is not None:
                    assert option.end <= layout.length, (layout.model, option.name)
                positions = set(range(option.start, option.end))
                assert not positions & used, (layout.model, option.name)
                used |= positions

                tables = [option.codes] if option.codes is not None else []
                if option.depends_on:
                    assert option.depends_on in names[:index], (layout.model, option.name)
                    tables = list(option.tables.values())
                for table in tables:
                    for code, label in table.items():
                        assert len(code) == option.end - option.start, (option.name, code)
                        assert code == code.upper()
                        assert label, (option.name, code)
                        assert len(label) <= 80, (option.name, code)

            # Every position of a fixed-length layout is the prefix, an option,
            # or a fixed character
            if layout.length is not None:
                assert max(layout.match, default=0) < layout.length
                fixed = set(layout.match) | set(range(len(family.prefix)))
                assert used | fixed == set(range(layout.length)), layout.model


# ---------------------------------------------------------------------------
# Storing the result in the device
# ---------------------------------------------------------------------------


def test_process_part_number():
    dev = DeviceData()
    dev.part_number = " 0351s7xhd3j5442 "  # As reported (spaces are stripped by the model)
    dev.firmware.id = "SEL-351S-7-R5xx-V0-Z106104-Dyyyymmdd"

    info = process_part_number(dev)

    assert dev.extra[EXTRA_KEY] == info
    assert info["part_number"] == "0351S7XHD3J5442"
    assert info["comm_interface"] == "2x 10/100BASE-T, fiber serial (ST)"
    # The part number itself isn't changed
    assert dev.part_number == "0351s7xhd3j5442"


def test_process_part_number_no_part_number():
    dev = DeviceData()
    assert process_part_number(dev) == {}
    assert EXTRA_KEY not in dev.extra


def test_process_part_number_mismatch_warned_once(caplog):
    dev = DeviceData(ip="192.0.2.10")
    dev.part_number = "751091A1ACALA7LAF30"
    dev.firmware.id = "SEL-751A-R400-V0-Z008003-D20150101"

    process_part_number(dev)
    process_part_number(dev)
    SELRelay.update_dev(dev)

    warnings = [m for m in _warnings(caplog) if "SEL part number" in m]
    assert len(warnings) == 1
    assert "The model in the SEL part number (751" in warnings[0]
    assert "(751A, from SEL-751A-R400" in warnings[0]
    assert "192.0.2.10" in warnings[0]
    assert dev.extra[EXTRA_KEY]["mismatches"] == {"model": {"part_number": "751", "fid": "751A"}}

    # Fixed FID: the mismatch is removed
    dev.firmware.id = "SEL-751-R400-V0-Z008003-D20150101"
    assert "mismatches" not in process_part_number(dev)
    assert "mismatches" not in dev.extra[EXTRA_KEY]


def test_process_part_number_replaced_and_removed():
    dev = DeviceData()
    dev.part_number = "751A01A1A0X71850300"
    process_part_number(dev)
    assert dev.extra[EXTRA_KEY]["model"] == "SEL-751A"

    dev.part_number = "0351S7XHD3J5442"
    process_part_number(dev)
    assert dev.extra[EXTRA_KEY]["model"] == "SEL-351S"

    # A part number that isn't decoded removes the old result
    dev.part_number = "0311L1234567X"
    assert process_part_number(dev) == {}
    assert EXTRA_KEY not in dev.extra


def test_update_dev_decodes_web_part_number():
    # The web interface sets dev.part_number directly (SELHTTP)
    dev = DeviceData()
    dev.part_number = "0351S7XHD4E5421"
    SELRelay.update_dev(dev)
    assert dev.extra[EXTRA_KEY]["io_board"] == "12 standard outputs, 8 inputs"


# ---------------------------------------------------------------------------
# process_info_into_dev(): ID, STA, and settings files
# ---------------------------------------------------------------------------

#: Synthetic STA output in the layout of the SEL-751A Instruction Manual
#: (section 1, "Relay Status"), as lines without the blank lines
STA_751A = [
    "SEL-751A                         Date: 03/15/2024   Time: 10:00:00",
    "FEEDER 2                         Time Source: Internal",
    "Serial Num = 1234567890",
    "FID = SEL-751A-R400-V0-Z008003-D20150101               CID = 1A2B",
    "PART NUM = 751A01A1A0X71850300",
    "SELF TESTS (W=Warn)",
]

#: The same values with two per line (the layout the parser already handled)
STA_TWO_COLUMNS = [
    "SEL-751A                         Date: 03/15/2024   Time: 10:00:00",
    "FEEDER 2                         Time Source: Internal",
    "Serial Num = 1234567890      FID = SEL-751A-R400-V0-Z008003-D20150101",
    "CID = 1A2B      PART NUM = 751A01A1A0X71850300",
]


@pytest.mark.parametrize("lines", [STA_751A, STA_TWO_COLUMNS])
def test_parse_status_output_part_number(lines, caplog):
    info = parse_status_output(lines)

    assert info["serial_number"] == "1234567890"
    assert info["FID"] == "SEL-751A-R400-V0-Z008003-D20150101"
    assert info["CID"] == "1A2B"
    assert info["part_number"] == "751A01A1A0X71850300"
    assert info["device_name"] == "FEEDER 2"
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


@pytest.mark.parametrize(
    "serial_line",
    [
        "Serial Num =        FID = SEL-751A-R400-V0-Z008003-D20150101",
        "Serial Num =FID = SEL-751A-R400-V0-Z008003-D20150101",
    ],
)
def test_parse_status_output_empty_serial_number(serial_line, caplog):
    # Synthetic: an empty serial number isn't read as the next key
    lines = [*STA_TWO_COLUMNS[:2], serial_line, "CID =       PART NUM = 751A01A1A0X71850300"]
    info = parse_status_output(lines)

    assert "serial_number" not in info
    assert "CID" not in info
    assert info["FID"] == "SEL-751A-R400-V0-Z008003-D20150101"
    assert info["part_number"] == "751A01A1A0X71850300"
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


def test_status_part_number_reaches_dev():
    dev = DeviceData()
    process_info_into_dev(parse_status_output(STA_751A), dev)

    assert dev.part_number == "751A01A1A0X71850300"
    assert dev.serial_number == "1234567890"
    assert dev.description.model == "751A"
    # Still in extra, as before
    assert dev.extra["part_number"] == "751A01A1A0X71850300"
    assert dev.extra[EXTRA_KEY]["model"] == "SEL-751A"
    assert dev.extra[EXTRA_KEY]["slot_e"] == "3 AVI (300 V)"
    assert "mismatches" not in dev.extra[EXTRA_KEY]


def test_status_part_number_does_not_replace_partno(caplog):
    dev = DeviceData()
    process_info_into_dev({"PARTNO": "751A01A1A0X71850300"}, dev)
    process_info_into_dev({"part_number": "751a01a1a0x71850300"}, dev)  # Same
    assert not _warnings(caplog)

    process_info_into_dev({"part_number": "751A11DCD1D74851320"}, dev)
    assert dev.part_number == "751A01A1A0X71850300"
    assert dev.extra[EXTRA_KEY]["part_number"] == "751A01A1A0X71850300"
    assert any("different from the relay's part number" in m for m in _warnings(caplog))

    # An empty value (e.g. from VER output) is ignored
    dev = DeviceData()
    process_info_into_dev({"part_number": ""}, dev)
    assert dev.part_number == ""
    assert EXTRA_KEY not in dev.extra


def test_id_output_700g_docs_sample():
    # docs/sel.rst: ID output of an SEL-700G
    raw = "\r\n".join(
        [
            '"FID=SEL-700G-R200-V0-Z006003-D20180629","08F0"',
            '"DEVID=SEL-700G","0408"',
            '"PARTNO=0700G12B1B1B7281A230","06C2"',
        ]
    )
    dev = DeviceData()
    process_info_into_dev(parse_id_output(raw), dev)

    assert dev.part_number == "0700G12B1B1B7281A230"
    assert dev.extra[EXTRA_KEY]["layout"] == LAYOUT_INFERRED
    assert dev.extra[EXTRA_KEY]["slot_c"] == "4 DI/4 DO, 24 V DI"
    assert "mismatches" not in dev.extra[EXTRA_KEY]


def test_fid_after_part_number_is_compared(caplog):
    # STA (part number) can come before ID (FID): the result is updated
    dev = DeviceData()
    process_info_into_dev({"part_number": "751091A1ACALA7LAF30"}, dev)
    assert "mismatches" not in dev.extra[EXTRA_KEY]

    process_info_into_dev({"FID": "SEL-751A-R400-V0-Z008003-D20150101"}, dev)
    assert dev.extra[EXTRA_KEY]["mismatches"]["model"]["fid"] == "751A"
    assert len([m for m in _warnings(caplog) if "SEL part number" in m]) == 1


@pytest.mark.usefixtures("parse_env")
@pytest.mark.parametrize(
    "input_name",
    ["sel-710_Relay710.rdb", "sel-710_SET_ALL.TXT", "sel-710_rdb_streams"],
)
def test_parse_710_files(input_name):
    dev = SELRelay.parse(RELAY_DIR / input_name)

    assert dev.part_number == "071001A5X6X71821210"
    info = dev.extra[EXTRA_KEY]
    assert info["model"] == "SEL-710"
    assert info["layout"] == LAYOUT_DOCUMENTED
    assert info["slot_b_rear_port"] == "EIA-232, 1x 10/100BASE-T"
    assert info["protocols"] == "Standard plus IEC 61850"
    assert "mismatches" not in info
    assert "unknown_codes" not in info
