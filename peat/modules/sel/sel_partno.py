"""
Decode SEL part numbers into the ordering options they encode.

An SEL part number (``PARTNO`` in the ``ID`` command output and the settings
files, ``PART NUM`` in the ``STATUS`` output) is a fixed-position code
defined by the product's Model Option Table (MOT): a model prefix (e.g.
``0351S``), then one or two characters for each option (firmware, chassis,
power supply, I/O cards, Ethernet ports, protocols, conformal coating, ...).
For example, ``0351S6XHA4E54X2`` is an SEL-351S with standard firmware in a
3U rack chassis, a 125/250 V power supply, two 10/100BASE-T ports, 5 A
current inputs, 125 Vdc control inputs, no extra I/O, and IEC 61850.

The tables in this module are the codes from public SEL Model Option Tables
(identified by their SEL document number, e.g. ``WI-8323``), with short
descriptions written for PEAT. Each product has its own table, and the
layouts and codes change over time, so they need to be checked against the
current MOTs when they're updated. Products without a public MOT (the
SEL-700G and the 400-series relays) are only partially decoded.

.. warning::
   The decoded values are a hint, not an inventory of the hardware. The part
   number can be set by hand with the ``PARTNO`` command (Access Level C),
   and SELect relays (SEL-7xx and SEL-2411) rewrite the slot characters from
   the IDs of the cards they detect. A serial communication card in Slot C
   shows as empty, and two cards with the same ID (e.g. the standard and
   fast high-current 4 DI/4 DO cards) can't be told apart (SEL-751 Card
   Options instructions, "PARTNO" step). The result is marked ``advisory``.

The result of :func:`decode_part_number` follows the style of
:func:`~peat.modules.siemens.mlfb.decode_mlfb`: a flat :class:`dict` with a
description of each option (``"N/A"`` if the code isn't in the table), plus:

- ``part_number``: the part number, upper case and without spaces
- ``model``: the product, e.g. ``SEL-351S``
- ``layout``: ``documented`` (matches a public MOT), ``inferred`` (no public
  MOT, the positions are inferred from example part numbers), ``prefix_only``
  (only the model and variant are known), ``placeholder`` (the options are
  all ``X``, e.g. ``0710XXXXXXXXXXXXXX`` from a settings template), or
  ``unrecognized`` (the prefix is known but the part number doesn't fit the
  layout, e.g. it's from an older MOT or was edited)
- ``mot``: the MOT the layout is from (``WI-8323 (2021-12-21)``)
- ``advisory``: always ``True``
- ``codes``: the code of each option
- ``unknown_codes``: options with codes that aren't in the table, e.g. codes
  from older MOTs (only if there are any)
- ``mismatches``: model or variant that's different in the firmware ID (FID),
  e.g. ``{"model": {"part_number": "751", "fid": "751A"}}`` (only if there
  are any)
- ``notes``: explanations, e.g. why the layout wasn't recognized

:func:`process_part_number` stores it in ``dev.extra["part_number_info"]``.
``dev.part_number`` isn't changed.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from peat import DeviceData, log

#: Key in ``dev.extra`` with the decoded part number
EXTRA_KEY: Final = "part_number_info"

#: Description of an option whose code isn't in the table
#: (the same as :func:`~peat.modules.siemens.mlfb.decode_mlfb`)
UNKNOWN: Final = "N/A"

#: Longer values aren't decoded (SEL part numbers are at most 23 characters)
MAX_LENGTH: Final = 40

#: The part number fits the layout from a public Model Option Table
LAYOUT_DOCUMENTED: Final = "documented"
#: There's no public Model Option Table, the layout is inferred from examples
LAYOUT_INFERRED: Final = "inferred"
#: Only the model (and variant) is known
LAYOUT_PREFIX_ONLY: Final = "prefix_only"
#: The model is known, but the part number doesn't fit its layout
LAYOUT_UNRECOGNIZED: Final = "unrecognized"
#: The options are all "X" (e.g. "751A0XXXXXXXXXXXXXX" in a settings template)
LAYOUT_PLACEHOLDER: Final = "placeholder"

#: Placeholder part numbers have at least this many characters after the prefix
_PLACEHOLDER_MIN_OPTIONS: Final = 4

#: Keys of the result that aren't options (option names can't use them)
RESULT_KEYS: Final = frozenset(
    {
        "part_number",
        "model",
        "layout",
        "mot",
        "advisory",
        "codes",
        "unknown_codes",
        "mismatches",
        "notes",
    }
)


@dataclass(frozen=True)
class Option:
    """
    One ordering option: the characters ``start:end`` of the part number.
    """

    name: str
    start: int
    end: int
    #: Code to description. If ``None``, the code is recorded but not decoded.
    codes: Mapping[str, str] | None = None
    #: The table depends on the code of an earlier option (e.g. Slot E of the
    #: SEL-787-2/-3/-4 depends on the model option). ``tables`` maps that
    #: option's code to the table.
    depends_on: str = ""
    tables: Mapping[str, Mapping[str, str]] | None = None


@dataclass(frozen=True)
class Layout:
    """
    The layout of a product's part number, from one Model Option Table.
    """

    model: str
    #: Number of characters, or ``None`` for any length (prefix-only layouts)
    length: int | None
    options: tuple[Option, ...]
    #: SEL document number and date of the Model Option Table
    mot: str = ""
    kind: str = LAYOUT_DOCUMENTED
    #: Characters required at positions (fixed characters, and characters
    #: that tell layouts apart), e.g. ``{6: "X"}``
    match: Mapping[int, str] = field(default_factory=dict)
    #: The option with the variant in the FID, e.g. firmware "5" in "SEL-351-5"
    fid_variant: str = ""


@dataclass(frozen=True)
class Family:
    """
    A product with its part number prefix and layouts.
    """

    prefix: str
    model: str
    #: Model in the FID, e.g. "351S" in "SEL-351S-6-R514-..."
    fid_model: str
    #: Tried in order, the first one that fits is used
    layouts: tuple[Layout, ...]
    #: Characters required after the prefix, to tell this product from others
    #: whose part numbers start the same way (e.g. "0351" followed by 5, 6, or 7
    #: is a SEL-351, but "0351R" isn't)
    guard: Mapping[int, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Option tables
# --------------------------------------------------------------------------

#: Digital input voltage, the second character of SELect I/O card codes
DI_VOLTAGES: Final[Mapping[str, str]] = {
    "A": "125 V",
    "B": "24 V",
    "C": "48 V",
    "D": "110 V",
    "G": "220 V",
    "H": "250 V",
}


def _with_di_voltage(cards: Mapping[str, str]) -> dict[str, str]:
    """
    Codes for SELect cards with digital inputs: the card type, then the input
    voltage, e.g. ``{"1": "4 DI/4 DO"}`` -> ``{"1A": "4 DI/4 DO, 125 V DI", ...}``.
    """
    return {
        f"{card}{volt_code}": f"{label}, {volts} DI"
        for card, label in cards.items()
        for volt_code, volts in DI_VOLTAGES.items()
    }


def _merge(*tables: Mapping[str, str]) -> dict[str, str]:
    merged = {}
    for table in tables:
        merged.update(table)
    return merged


# SEL-3xx (SEL-351 WI-8349, SEL-351S WI-8323, SEL-351A WI-8347, SEL-351A-1 WI-8348,
# SEL-311C WI-9285)
FIRMWARE_351: Final = {
    "5": "Basic",
    "6": "Standard (MIRRORED BITS, load profile)",
    "7": "Standard plus power elements and sag/swell/interruption",
}
POWER_SUPPLY_3XX: Final = {
    "2": "24/48 Vdc",
    "3": "48/125 Vdc or 120 Vac",
    "4": "125/250 Vdc or 120/230 Vac",
}
COMM_3XX: Final = {
    "D": "1x 100BASE-FX (LC), EIA-485",
    "E": "2x 10/100BASE-T, EIA-485",
    "F": "2x 100BASE-FX (LC), EIA-485",
    "H": "1x 10/100BASE-T, 1x 100BASE-FX (LC), fiber serial (ST)",
    "J": "2x 10/100BASE-T, fiber serial (ST)",
    "K": "2x 100BASE-FX (LC), fiber serial (ST)",
}
NOMINAL_CURRENT_351: Final = {
    "1": "1 A phase, 1 A neutral",
    "5": "5 A phase, 5 A neutral",
    "6": "5 A phase, 1 A neutral",
    "8": "1 A phase, 0.05 A neutral (SEF)",
    "9": "5 A phase, 0.05 A neutral (SEF)",
    "A": "1 A phase, 0.2 A neutral (directional)",
    "B": "5 A phase, 0.2 A neutral (directional)",
}
CONTROL_INPUT_VOLTAGE: Final = {
    "1": "24 Vdc",
    "2": "48 Vdc",
    "3": "110 Vdc",
    "4": "125 Vdc",
    "5": "220 Vdc",
    "6": "250 Vdc",
}
IO_BOARD_351: Final = {
    "X": "None",
    "2": "12 standard outputs, 8 inputs",
    "4": "4 standard outputs, 16 inputs",
    "6": "12 high-current interrupting outputs, 8 inputs",
}
CONFORMAL_COAT_X2: Final = {"X": "Not coated", "2": "Conformal coated"}
PROTOCOLS_3XX: Final = {"1": "Standard", "2": "Standard plus IEC 61850"}

# SELect relays (SEL-751A WI-7074, SEL-751 WI-9222, SEL-710 WI-5180,
# SEL-787 WI-7257, SEL-787-2/-3/-4 WI-9842; cards: WI-5932)
CONFORMAL_COAT_01: Final = {"0": "Not coated", "1": "Conformal coated"}

#: Slot A: power supply with 2 DI/3 DO, then the DI voltage
SLOT_A_SELECT: Final = _with_di_voltage(
    {
        "1": "110-250 Vdc/110-240 Vac power supply",
        "2": "24-48 Vdc power supply",
    }
)

#: SELect I/O cards with digital inputs, in Slots C, D, and E
SELECT_DI_CARDS: Final = _with_di_voltage(
    {
        "B": "3 DI/4 DO/1 AO",
        "1": "4 DI/4 DO",
        "C": "4 DI/4 DO fast high-current",
        "D": "4 DI/3 DO (2 Form C, 1 Form B)",
        "3": "8 DI",
    }
)
EMPTY: Final = {"0X": "Empty"}
SERIAL_CARD: Final = {"A0": "EIA-232/485 serial card"}
RTD_CARD: Final = {"9X": "10 RTD inputs"}
ANALOG_8AI: Final = {"5X": "8 AI"}
ANALOG_4AI_4AO: Final = {"6X": "4 AI/4 AO"}
#: Cards added in later SELect MOTs (SEL-751, SEL-787-2/-3/-4)
SELECT_NEWER_CARDS: Final = _merge(
    _with_di_voltage({"4": "14 DI"}),
    {
        "2A": "8 DO (Form A)",
        "2B": "8 DO (Form B)",
        "2C": "8 DO (6 Form A, 2 Form B)",
        "2D": "8 DO (2 Form A, 6 Form B)",
        "2G": "8 DO (4 Form A, 4 Form B)",
    },
)

#: Ethernet and rear serial port in Slot B (SEL-751A, SEL-787, SEL-787-2/-3/-4)
SLOT_B_ETHERNET: Final = {
    "0": "No Ethernet, EIA-232",
    "1": "No Ethernet, EIA-485",
    "2": "1x 10/100BASE-T, EIA-232",
    "3": "1x 10/100BASE-T, EIA-485",
    "4": "1x 100BASE-FX (LC), EIA-232",
    "6": "2x 10/100BASE-T, EIA-232",
    "8": "2x 100BASE-FX (LC), EIA-232",
}
#: Protocols in Slot B (SEL-751A, SEL-787)
PROTOCOLS_751A: Final = {
    "0": "Standard",
    "1": "Standard plus IEC 61850",
    "2": "Standard plus DNP3",
    "3": "Standard plus DNP3 and IEC 61850",
}

_PROTOCOL_61850: Final = "IEC 61850"
_PROTOCOL_DNP3: Final = "DNP3"
_PROTOCOL_103: Final = "IEC 60870-5-103"
_PROTOCOL_EIP: Final = "EtherNet/IP"

#: Protocols of the SEL-751 (WI-9222) and SEL-787-2/-3/-4 (WI-9842). The codes
#: are a list in the MOTs, not a bit field: "B" and "C" don't follow the
#: pattern of the other codes.
PROTOCOLS_751: Final = {
    code: ", ".join(protocols) if protocols else "None"
    for code, protocols in {
        "0": (),
        "1": (_PROTOCOL_61850,),
        "2": (_PROTOCOL_DNP3,),
        "3": (_PROTOCOL_61850, _PROTOCOL_DNP3),
        "4": (_PROTOCOL_103,),
        "5": (_PROTOCOL_61850, _PROTOCOL_103),
        "6": (_PROTOCOL_DNP3, _PROTOCOL_103),
        "7": (_PROTOCOL_61850, _PROTOCOL_DNP3, _PROTOCOL_103),
        "8": (_PROTOCOL_EIP,),
        "9": (_PROTOCOL_61850, _PROTOCOL_EIP),
        "A": (_PROTOCOL_DNP3, _PROTOCOL_EIP),
        "B": (_PROTOCOL_103, _PROTOCOL_EIP),
        "C": (_PROTOCOL_61850, _PROTOCOL_DNP3, _PROTOCOL_EIP),
        "D": (_PROTOCOL_61850, _PROTOCOL_103, _PROTOCOL_EIP),
        "E": (_PROTOCOL_DNP3, _PROTOCOL_103, _PROTOCOL_EIP),
        "F": (_PROTOCOL_61850, _PROTOCOL_DNP3, _PROTOCOL_103, _PROTOCOL_EIP),
    }.items()
}


def _four_aci(currents: Mapping[str, str], prefix: str) -> dict[str, str]:
    """
    Codes of 4 ACI cards: ``prefix``, then the current rating code.
    """
    return {f"{prefix}{code}": f"4 ACI ({rating})" for code, rating in currents.items()}


#: Phase and neutral current ratings of 4 ACI cards (the last character of the code)
FOUR_ACI_RATINGS: Final = {
    "1": "1 A phase, 1 A neutral",
    "2": "1 A phase, 5 A neutral",
    "3": "1 A phase, 2.5 mA neutral",
    "4": "1 A phase, 50 mA neutral",
    "5": "5 A phase, 5 A neutral",
    "6": "5 A phase, 1 A neutral",
    "7": "5 A phase, 2.5 mA neutral",
    "8": "5 A phase, 50 mA neutral",
}
FOUR_ACI_RATINGS_751: Final = {
    "1": "1 A phase, 1 A neutral",
    "2": "1 A phase, 5 A neutral",
    "3": "1 A phase, 200 mA neutral",
    "5": "5 A phase, 5 A neutral",
    "6": "5 A phase, 1 A neutral",
    "7": "5 A phase, 200 mA neutral",
}

# SEL-751A (WI-7074)
FIRMWARE_751A: Final = {
    "0": "Standard",
    "1": "Standard plus reclosing",
    "5": "Standard, configurable labels",
    "6": "Standard plus reclosing, configurable labels",
}
SLOT_E_751A: Final = _merge(
    EMPTY,
    SELECT_DI_CARDS,
    ANALOG_8AI,
    ANALOG_4AI_4AO,
    {
        "71": "3 AVI (300 V)",
        "72": "3 AVI, Vsync, Vbat (monitoring package)",
        "73": "3 AVI, Vsync, Vbat (advanced metering and protection package)",
        "74": "3 AVI, 4 arc-flash inputs",
        "75": "3 AVI, Vsync, Vbat, 5 A residual current input",
        "76": "3 AVI, Vsync, Vbat, 1 A residual current input",
    },
)
SLOT_B_PROCESSOR_751A: Final = {"0": "Standard", "1": "Standard plus fiber serial (ST)"}

# SEL-751 (WI-9222)
ADVANCED_FIRMWARE_751: Final = {
    "0": "None",
    "1": "Reclosing",
    "2": "Directional",
    "3": "Arc Sense (high-impedance fault detection)",
    "4": "Reclosing, directional",
    "5": "Reclosing, directional, Arc Sense",
    "6": "Advanced directional",
    "7": "Reclosing, advanced directional",
    "8": "Reclosing, advanced directional, Arc Sense",
}
_EXTENDED_IO_751: Final = (
    "none",
    "21 binary inputs",
    "42 binary inputs",
    "63 binary inputs",
    "84 binary inputs",
    "21 binary inputs, 12 DO",
    "21 binary inputs, 24 DO",
    "21 binary inputs, 36 DO",
    "42 binary inputs, 12 DO",
    "42 binary inputs, 24 DO",
    "63 binary inputs, 12 DO",
    "12 DO",
    "24 DO",
    "36 DO",
    "48 DO",
)
#: Language of the user interface and the extended I/O modules
LANGUAGE_EXTENDED_IO_751: Final = {
    **{
        code: f"English, extended I/O: {io}"
        for code, io in zip("0123456789ABCDE", _EXTENDED_IO_751, strict=True)
    },
    **{
        code: f"Spanish, extended I/O: {io}"
        for code, io in zip("SFGHJKLMNPQRTUV", _EXTENDED_IO_751, strict=True)
    },
}
SELECT_CARDS_751: Final = _merge(
    EMPTY, SELECT_DI_CARDS, SELECT_NEWER_CARDS, ANALOG_8AI, ANALOG_4AI_4AO
)
SLOT_E_751: Final = _merge(
    SELECT_CARDS_751,
    {
        "70": "Vsync, Vbat, 4 arc-flash inputs",
        "L0": "LEA Vsync, Vbat, 4 arc-flash inputs",
        "77": "8 arc-flash inputs",
    },
    _with_di_voltage({"7": "Vsync, Vbat, 7 DI", "L": "LEA Vsync, Vbat, 7 DI"}),
)
SLOT_Z_751: Final = _merge(
    {f"A{c}": f"3 ACI, neutral ACI ({r})" for c, r in FOUR_ACI_RATINGS_751.items()},
    {f"8{c}": f"3 ACI, neutral ACI ({r}), 3 AVI" for c, r in FOUR_ACI_RATINGS_751.items()},
    {
        f"L{c}": f"3 ACI, neutral ACI ({r}), 3 LEA voltages"
        for c, r in FOUR_ACI_RATINGS_751.items()
    },
    {"7L": "3 Rogowski/LPCT currents, 200 mA neutral ACI, 3 LEA voltages"},
)
FRONT_PANEL_751: Final = {
    "1": "2x16 LCD, 4 pushbuttons",
    "0": "2x16 LCD, 8 pushbuttons",
    "B": "5 inch touchscreen, 4 pushbuttons",
    "A": "5 inch touchscreen, 8 pushbuttons",
}
#: Slot B: Ethernet (port 1), fiber serial (port 2), and rear serial (port 3)
SLOT_B_751: Final = {
    "A": "No Ethernet, no fiber serial, EIA-232",
    "B": "No Ethernet, no fiber serial, EIA-485",
    "C": "1x 10/100BASE-T, no fiber serial, EIA-232",
    "D": "1x 10/100BASE-T, no fiber serial, EIA-485",
    "E": "1x 100BASE-FX (LC), no fiber serial, EIA-232",
    "F": "2x 10/100BASE-T, no fiber serial, EIA-232",
    "G": "2x 100BASE-FX (LC), no fiber serial, EIA-232",
    "0": "No Ethernet, fiber serial (ST), EIA-232",
    "1": "No Ethernet, fiber serial (ST), EIA-485",
    "2": "1x 10/100BASE-T, fiber serial (ST), EIA-232",
    "3": "1x 10/100BASE-T, fiber serial (ST), EIA-485",
    "4": "1x 100BASE-FX (LC), fiber serial (ST), EIA-232",
    "6": "2x 10/100BASE-T, fiber serial (ST), EIA-232",
    "8": "2x 100BASE-FX (LC), fiber serial (ST), EIA-232",
}

# SEL-710 (WI-5180)
SLOT_E_710: Final = _merge(
    EMPTY,
    SELECT_DI_CARDS,
    ANALOG_8AI,
    ANALOG_4AI_4AO,
    {"71": "3 AVI (300 V)", "72": "3 ACI (motor differential), 3 AVI (300 V)"},
)
SLOT_Z_710: Final = _four_aci(
    {c: r for c, r in FOUR_ACI_RATINGS.items() if c not in ("4", "8")}, prefix="8"
)
TIME_INPUT_710: Final = {"0": "IRIG-B", "1": "PTC thermistor input"}
REAR_PORT_710: Final = {
    "0": "EIA-232",
    "1": "EIA-485",
    "2": "EIA-232, 1x 10/100BASE-T",
    "3": "EIA-485, 1x 10/100BASE-T",
    "4": "EIA-232, 1x 100BASE-FX (LC)",
    "6": "EIA-232, 2x 10/100BASE-T",
    "8": "EIA-232, 2x 100BASE-FX (LC)",
}
PROTOCOLS_710: Final = {
    "0": "Standard (Modbus TCP with Ethernet)",
    "1": "Standard plus IEC 61850",
    "3": "Standard plus IEC 61850",
}

# SEL-787 -0/-1/-E (WI-7257) and SEL-787-2/-3/-4 (WI-9842)
FIRMWARE_787: Final = {
    "0": "Two-winding differential",
    "1": "Two-winding differential, REF",
    "E": "Two-winding differential, REF, voltage, V/Hz, power elements",
}
SELECT_CARDS_787: Final = _merge(EMPTY, SELECT_DI_CARDS, ANALOG_4AI_4AO)
SLOT_E_787: Final = {
    "0": SELECT_CARDS_787,
    "1": {"A1": "1 neutral ACI (1 A)", "A5": "1 neutral ACI (5 A)"},
    "E": {
        "71": "1 neutral ACI (1 A), 3 AVI (300 V)",
        "75": "1 neutral ACI (5 A), 3 AVI (300 V)",
    },
}
SLOT_Z_787: Final = {
    "81": "6 ACI (1 A winding 1, 1 A winding 2)",
    "82": "6 ACI (1 A winding 1, 5 A winding 2)",
    "85": "6 ACI (5 A winding 1, 5 A winding 2)",
}
SLOT_B_PROCESSOR_787: Final = {"0": "Standard"}
MODEL_OPTION_787: Final = {
    "2X": "Two-winding differential",
    "21": "Two-winding differential, 1 neutral current",
    "2E": "Two-winding differential, 1 neutral current, 3 voltages",
    "3E": "Three-winding differential, 1 neutral current, 3 voltages",
    "3S": "Three-winding differential, 4 voltages (phase and Vsync/Vbat)",
    "4X": "Four-winding differential",
}
LANGUAGE: Final = {"E": "English", "S": "Spanish"}
SELECT_CARDS_787_2: Final = _merge(EMPTY, SELECT_DI_CARDS, SELECT_NEWER_CARDS, ANALOG_4AI_4AO)
SLOT_E_787_2: Final = {
    "2X": SELECT_CARDS_787_2,
    "21": {
        "A6": "1 neutral ACI (1 A)",
        "A7": "1 neutral ACI (5 A)",
        "L6": "1 neutral Rogowski/LPCT current",
    },
    "2E": {
        "78": "1 neutral ACI (1 A), 3 AVI (300 V)",
        "79": "1 neutral ACI (5 A), 3 AVI (300 V)",
        "L8": "1 neutral Rogowski/LPCT current, 3 LEA voltages",
    },
    "3E": {
        "72": "3 ACI (1 A), 1 neutral ACI (1 A), 3 AVI (300 V)",
        "73": "3 ACI (5 A), 1 neutral ACI (1 A), 3 AVI (300 V)",
        "76": "3 ACI (5 A), 1 neutral ACI (5 A), 3 AVI (300 V)",
        "77": "3 ACI (1 A), 1 neutral ACI (5 A), 3 AVI (300 V)",
        "L2": "3 phase and 1 neutral Rogowski/LPCT currents, 3 LEA voltages",
    },
    "3S": {
        "71": "3 ACI (1 A), 3 AVI (300 V), Vsync, Vbat",
        "75": "3 ACI (5 A), 3 AVI (300 V), Vsync, Vbat",
        "L1": "3 Rogowski/LPCT currents, 3 LEA voltages and Vsync",
    },
    "4X": {
        "A1": "6 ACI (1 A winding 3, 1 A winding 4)",
        "A2": "6 ACI (1 A winding 3, 5 A winding 4)",
        "A5": "6 ACI (5 A winding 3, 5 A winding 4)",
        "L0": "6 Rogowski/LPCT currents",
    },
}
SLOT_Z_787_2: Final = _merge(SLOT_Z_787, {"L0": "6 Rogowski/LPCT currents"})
FRONT_PANEL_787_2: Final = {
    "0": "2x16 LCD, 8 pushbuttons",
    "A": "5 inch touchscreen, 8 pushbuttons",
}

# SEL-2411 and SEL-2411-1 (WI-7201)
VARIANT_2411: Final = {"0": "SEL-2411", "1": "SEL-2411-1 (surface mount)"}
SLOT_A_2411: Final = _with_di_voltage(
    {
        "1": "125/250 Vdc/Vac power supply",
        "2": "24/48 Vdc power supply",
    }
)
CARDS_2411: Final = _merge(
    EMPTY,
    _with_di_voltage(
        {
            "1": "4 DI/4 DO",
            "B": "4 DI/4 DO fast high-current",
            "C": "4 DI/3 DO (2 Form C, 1 Form B)",
            "3": "8 DI",
        }
    ),
    {
        "2X": "8 DO",
        "5X": "8 AI",
        "52": "4 AI, 4 AI (300 V)",
        "6X": "4 AI/4 AO",
    },
)
SLOT_E_2411: Final = _merge(
    CARDS_2411,
    {
        "71": "3 AVI (300 V)",
        "73": "3 ACI (5 A), 3 AVI (8 V)",
        "74": "3 ACI (5 A), 3 AVI (300 V)",
    },
)
SLOT_Z_2411: Final = _merge(
    CARDS_2411,
    _four_aci({c: FOUR_ACI_RATINGS[c] for c in ("1", "2", "5", "6")}, prefix="8"),
)
FIBER_SERIAL_2411: Final = {"0": "None", "1": "Fiber serial (ST)"}
ETHERNET_2411: Final = {
    "0": "None",
    "1": "1x 10/100BASE-T",
    "4": "1x 100BASE-FX",
    "6": "2x 10/100BASE-T",
    "8": "2x 100BASE-FX",
}
PROTOCOLS_2411: Final = {
    "0": "Standard (Modbus)",
    "3": "Standard plus DNP3",
    "4": "Standard plus IEC 61850",
}

# SEL-2440 (WI-8148)
MOUNTING_2440: Final = {"H": "Horizontal rack", "W": "Horizontal surface", "3": "Horizontal panel"}
#: I/O option (4 characters, "{v}" is the DI voltage code)
IO_2440: Final = {
    code.format(v=volt_code): f"{label}, {volts} DI"
    for code, label in (
        ("2{v}1{v}", "48 DI"),
        ("1{v}1{v}", "32 DI, 16 DO"),
        ("1{v}6X", "16 DI, 32 DO"),
        ("1{v}61", "16 DI, 32 DO (16 high-current interrupting)"),
        ("1{v}62", "16 DI, 16 DO, 10 fast high-current DO"),
        ("2{v}63", "32 DI, 10 fast high-current DO"),
    )
    for volt_code, volts in DI_VOLTAGES.items()
}
SERIAL_PORT_2_2440: Final = {"1": "EIA-232", "2": "EIA-485", "4": "Fiber serial (ST)"}
ETHERNET_2440: Final = {"6": "2x 10/100BASE-T", "8": "2x 100BASE-FX (LC)"}
PROTOCOLS_2440: Final = {"3": "DNP3", "4": "DNP3 and IEC 61850"}

# SEL-2032 (WI-3644)
MOUNTING_2032: Final = {"0": "Horizontal rack", "3": "Horizontal panel", "5": "Projection panel"}
SPECIAL_HARDWARE_2032: Final = {"X": "None", "2": "Conformal coated circuit boards"}
POWER_SUPPLY_2032: Final = {
    "2": "20-60 Vdc",
    "3": "38-200 Vdc, 85-140 Vac",
    "4": "85-350 Vdc, 85-264 Vac",
}
IO_2032: Final = {
    "0X": "None",
    "41": "4 outputs, 16 inputs (24 Vdc)",
    "42": "4 outputs, 16 inputs (48 Vdc)",
    "44": "4 outputs, 16 inputs (125 Vdc)",
    "46": "4 outputs, 16 inputs (250 Vdc)",
}
PROTOCOL_CARD_2032: Final = _merge(
    {"XX": "None"},
    {
        f"{card}{conn}": f"Ethernet card with {protocols}, {ports}"
        for card, protocols in (("G", "DNP3"), ("E", "UCA2"), ("H", "DNP3 and UCA2"))
        for conn, ports in (
            ("0", "2x 10/100BASE-T"),
            ("2", "2x 100BASE-FX"),
            ("4", "1x 10/100BASE-T, 1x 100BASE-FX"),
        )
    },
)


# --------------------------------------------------------------------------
# Layouts
# --------------------------------------------------------------------------


#: A slot's table, ``(option name, tables)`` if it depends on another option,
#: or ``None`` if the codes are only recorded
_SlotTable = Mapping[str, str] | tuple[str, Mapping[str, Mapping[str, str]]] | None


def _select_slots(first: int, *tables: _SlotTable) -> tuple[Option, ...]:
    """
    Slots A, C, D, E, and Z of SELect relays, two characters each, starting
    at ``first``. The part number has them in this order, before Slot B,
    although the MOTs list Slot B second.
    """
    options = []
    for index, (name, table) in enumerate(zip("acdez", tables, strict=True)):
        start = first + 2 * index
        if isinstance(table, tuple):
            depends_on, by_code = table
            options.append(
                Option(f"slot_{name}", start, start + 2, depends_on=depends_on, tables=by_code)
            )
        else:
            options.append(Option(f"slot_{name}", start, start + 2, table))
    return tuple(options)


_DIGITS: Final = "0123456789"
_DIGITS_AND_LETTERS: Final = _DIGITS + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

LAYOUT_351: Final = Layout(
    model="SEL-351",
    length=14,
    mot="WI-8349 (2017-02-23)",
    # Older SEL-351 relays (SEL-351-0 to -4) have other digits and layouts
    match={4: "567"},
    fid_variant="firmware",
    options=(
        Option("firmware", 4, 5, FIRMWARE_351),
        Option(
            "housing",
            5,
            6,
            {
                "2": "2U horizontal rack",
                "3": "3U horizontal rack",
                "4": "2U horizontal panel",
                "5": "3U horizontal panel",
                "6": "2U horizontal projection panel",
                "7": "3U horizontal projection panel",
                "8": "3U vertical rack",
                "9": "3U vertical panel",
            },
        ),
        Option(
            "user_interface",
            6,
            7,
            {"C": "Standard with USB", "D": "Standard with USB, SafeLock pushbuttons"},
        ),
        Option("power_supply", 7, 8, POWER_SUPPLY_3XX),
        Option("comm_interface", 8, 9, COMM_3XX),
        Option("nominal_current", 9, 10, NOMINAL_CURRENT_351),
        Option("control_input_voltage", 10, 11, CONTROL_INPUT_VOLTAGE),
        Option("io_board", 11, 12, IO_BOARD_351),
        Option("conformal_coat", 12, 13, CONFORMAL_COAT_X2),
        Option("protocols", 13, 14, PROTOCOLS_3XX),
    ),
)

LAYOUT_351S: Final = Layout(
    model="SEL-351S",
    length=15,
    mot="WI-8323 (2021-12-21)",
    match={6: "X"},
    fid_variant="firmware",
    options=(
        Option("firmware", 5, 6, FIRMWARE_351),
        Option(
            "housing",
            7,
            8,
            {
                "H": "3U horizontal rack",
                "3": "3U horizontal panel",
                "4": "3U vertical panel",
                "5": "3U horizontal projection panel",
                "C": "3U horizontal rack, conformal coated",
                "7": "3U horizontal panel, conformal coated",
                "8": "3U vertical panel, conformal coated",
                "9": "3U horizontal projection panel, conformal coated",
            },
        ),
        Option(
            "user_interface",
            8,
            9,
            {
                "A": "Standard with USB",
                "B": "Standard with USB, configurable labels",
                "C": "Standard with USB, indoor SafeLock pushbuttons",
                "D": "Standard with USB, indoor SafeLock pushbuttons, configurable labels",
                "E": "Standard with USB, outdoor SafeLock pushbuttons, configurable labels",
            },
        ),
        Option("power_supply", 9, 10, POWER_SUPPLY_3XX),
        Option("comm_interface", 10, 11, COMM_3XX),
        Option("nominal_current", 11, 12, NOMINAL_CURRENT_351),
        Option("control_input_voltage", 12, 13, CONTROL_INPUT_VOLTAGE),
        Option("io_board", 13, 14, IO_BOARD_351),
        Option("protocols", 14, 15, PROTOCOLS_3XX),
    ),
)


def _layout_351a(model: str, mot: str, firmware: str, housing: dict, currents: dict) -> Layout:
    return Layout(
        model=model,
        length=15,
        mot=mot,
        match={5: firmware, 8: "X"},
        options=(
            Option(
                "firmware",
                5,
                6,
                {
                    "0": "Standard (SEL-351A)",
                    "1": "Non-directional, three voltages (SEL-351A-1)",
                },
            ),
            Option("housing", 6, 7, housing),
            Option(
                "user_interface",
                7,
                8,
                {"2": "Standard with USB", "6": "Standard with USB, SafeLock pushbuttons"},
            ),
            Option("power_supply", 9, 10, POWER_SUPPLY_3XX),
            Option("comm_interface", 10, 11, COMM_3XX),
            Option("nominal_current", 11, 12, currents),
            Option("control_input_voltage", 12, 13, CONTROL_INPUT_VOLTAGE),
            Option("conformal_coat", 13, 14, CONFORMAL_COAT_X2),
            Option("protocols", 14, 15, PROTOCOLS_3XX),
        ),
    )


_HOUSING_351A_1: Final = {
    "H": "2U horizontal rack",
    "3": "2U horizontal panel",
    "5": "2U horizontal projection panel",
}
LAYOUT_351A: Final = _layout_351a(
    "SEL-351A",
    "WI-8347 (2017-02-23)",
    "0",
    {**_HOUSING_351A_1, "4": "2U vertical panel (no LCD)"},
    NOMINAL_CURRENT_351,
)
LAYOUT_351A_1: Final = _layout_351a(
    "SEL-351A-1",
    "WI-8348 (2017-02-23)",
    "1",
    _HOUSING_351A_1,
    {c: NOMINAL_CURRENT_351[c] for c in ("1", "5", "6")},
)

LAYOUT_311C: Final = Layout(
    model="SEL-311C",
    length=15,
    mot="WI-9285 (2017-02-23)",
    fid_variant="firmware",
    # The "C" of the prefix is the protection option (the only one in the MOT)
    options=(
        Option(
            "firmware",
            5,
            6,
            {
                "1": "Three-pole trip and reclose (SEL-311C-1)",
                "2": "Single-pole trip, three-pole reclose (SEL-311C-2)",
                "3": "Single-pole trip, three-pole reclose, high-speed mho (SEL-311C-3)",
            },
        ),
        Option(
            "chassis",
            6,
            7,
            {
                "0": "2U",
                "1": "3U",
                "2": "2U, conformal coated",
                "3": "3U, conformal coated",
            },
        ),
        Option(
            "housing",
            7,
            8,
            {
                "H": "Horizontal rack",
                "3": "Horizontal panel",
                "5": "Horizontal projection panel",
                "V": "Vertical rack",
                "4": "Vertical panel",
                "6": "Vertical projection panel",
            },
        ),
        Option(
            "user_interface",
            8,
            9,
            {
                "H": "Standard with USB",
                "J": "Standard with USB, SafeLock pushbuttons",
                "P": "Standard with USB, programmable operator controls and LEDs",
                "R": "Standard with USB, SafeLock pushbuttons, programmable controls and LEDs",
            },
        ),
        Option("power_supply", 9, 10, POWER_SUPPLY_3XX),
        Option("comm_interface", 10, 11, COMM_3XX),
        Option("nominal_current", 11, 12, {c: NOMINAL_CURRENT_351[c] for c in ("1", "5")}),
        Option("control_input_voltage", 12, 13, CONTROL_INPUT_VOLTAGE),
        Option(
            "io_board",
            13,
            14,
            {
                **IO_BOARD_351,
                "5": "8 high-speed high-current interrupting outputs, 8 inputs",
            },
        ),
        Option("protocols", 14, 15, PROTOCOLS_3XX),
    ),
)

LAYOUT_751A: Final = Layout(
    model="SEL-751A",
    length=19,
    mot="WI-7074 (2018-09-13)",
    options=(
        Option("firmware", 4, 5, FIRMWARE_751A),
        *_select_slots(
            5,
            SLOT_A_SELECT,
            _merge(EMPTY, SERIAL_CARD, SELECT_DI_CARDS, ANALOG_8AI, ANALOG_4AI_4AO),
            _merge(EMPTY, SELECT_DI_CARDS, ANALOG_8AI, ANALOG_4AI_4AO, RTD_CARD),
            SLOT_E_751A,
            _four_aci(FOUR_ACI_RATINGS, prefix="8"),
        ),
        Option("slot_b_processor", 15, 16, SLOT_B_PROCESSOR_751A),
        Option("slot_b_ethernet", 16, 17, SLOT_B_ETHERNET),
        Option("protocols", 17, 18, PROTOCOLS_751A),
        Option("conformal_coat", 18, 19, CONFORMAL_COAT_01),
    ),
)

LAYOUT_751: Final = Layout(
    model="SEL-751",
    length=19,
    mot="WI-9222 (2026-05-20)",
    # Older SEL-751 part numbers have a different layout (e.g. "X" at the end)
    match={3: "012345678", 15: "01AB", 18: "01"},
    options=(
        Option("advanced_firmware", 3, 4, ADVANCED_FIRMWARE_751),
        Option("language_extended_io", 4, 5, LANGUAGE_EXTENDED_IO_751),
        *_select_slots(
            5,
            SLOT_A_SELECT,
            _merge(SELECT_CARDS_751, SERIAL_CARD),
            _merge(SELECT_CARDS_751, RTD_CARD),
            SLOT_E_751,
            SLOT_Z_751,
        ),
        Option("front_panel", 15, 16, FRONT_PANEL_751),
        Option("slot_b", 16, 17, SLOT_B_751),
        Option("protocols", 17, 18, PROTOCOLS_751),
        Option("conformal_coat", 18, 19, CONFORMAL_COAT_01),
    ),
)

LAYOUT_710: Final = Layout(
    model="SEL-710",
    length=19,
    mot="WI-5180 (2018-12-07)",
    match={4: "0"},
    options=(
        *_select_slots(
            5,
            SLOT_A_SELECT,
            _merge(EMPTY, SERIAL_CARD, SELECT_DI_CARDS, ANALOG_8AI, ANALOG_4AI_4AO),
            _merge(EMPTY, SELECT_DI_CARDS, ANALOG_8AI, ANALOG_4AI_4AO, RTD_CARD),
            SLOT_E_710,
            SLOT_Z_710,
        ),
        Option("slot_b_time_input", 15, 16, TIME_INPUT_710),
        Option("slot_b_rear_port", 16, 17, REAR_PORT_710),
        Option("protocols", 17, 18, PROTOCOLS_710),
        Option("conformal_coat", 18, 19, CONFORMAL_COAT_01),
    ),
)

LAYOUT_787: Final = Layout(
    model="SEL-787",
    length=20,
    mot="WI-7257 (2018-09-13)",
    match={4: "01E", 5: "X"},
    options=(
        Option("firmware", 4, 5, FIRMWARE_787),
        *_select_slots(
            6,
            SLOT_A_SELECT,
            _merge(SELECT_CARDS_787, SERIAL_CARD),
            _merge(SELECT_CARDS_787, RTD_CARD),
            ("firmware", SLOT_E_787),
            SLOT_Z_787,
        ),
        Option("slot_b_processor", 16, 17, SLOT_B_PROCESSOR_787),
        Option("slot_b_ethernet", 17, 18, SLOT_B_ETHERNET),
        Option("protocols", 18, 19, PROTOCOLS_751A),
        Option("conformal_coat", 19, 20, CONFORMAL_COAT_01),
    ),
)

LAYOUT_787_2: Final = Layout(
    model="SEL-787",
    length=21,
    mot="WI-9842 (2024-10-21)",
    match={4: "234", 5: "X1ES", 6: "ES"},
    options=(
        Option("model_option", 4, 6, MODEL_OPTION_787),
        Option("language", 6, 7, LANGUAGE),
        *_select_slots(
            7,
            SLOT_A_SELECT,
            _merge(SELECT_CARDS_787_2, SERIAL_CARD),
            _merge(SELECT_CARDS_787_2, RTD_CARD),
            ("model_option", SLOT_E_787_2),
            SLOT_Z_787_2,
        ),
        Option("front_panel", 17, 18, FRONT_PANEL_787_2),
        Option("slot_b_ethernet", 18, 19, SLOT_B_ETHERNET),
        Option("protocols", 19, 20, PROTOCOLS_751),
        Option("conformal_coat", 20, 21, CONFORMAL_COAT_01),
    ),
)

#: No public MOT. The slot positions are inferred from part numbers in the
#: SEL-700G data sheet and card instructions, and from PEAT's documentation.
#: Slots A, C, and D use the common SELect card codes, the other codes are
#: only recorded.
LAYOUT_700G: Final = Layout(
    model="SEL-700G",
    length=20,
    kind=LAYOUT_INFERRED,
    options=(
        Option("variant", 5, 6),
        *_select_slots(
            6,
            SLOT_A_SELECT,
            _merge(EMPTY, SERIAL_CARD, SELECT_DI_CARDS, ANALOG_8AI, ANALOG_4AI_4AO),
            _merge(EMPTY, SELECT_DI_CARDS, ANALOG_8AI, ANALOG_4AI_4AO, RTD_CARD),
            None,
            None,
        ),
        Option("slot_b", 16, 19),
        Option("conformal_coat", 19, 20),
    ),
)


def _layout_2411(variant: int) -> Layout:
    """
    The SEL-2411 layout, with the variant at ``variant`` (the end of the prefix).
    """
    return Layout(
        model="SEL-2411",
        length=variant + 15,
        mot="WI-7201 (2008-12-08)",
        match={variant: "01"},
        options=(
            Option("variant", variant, variant + 1, VARIANT_2411),
            *_select_slots(
                variant + 1,
                SLOT_A_2411,
                _merge(CARDS_2411, SERIAL_CARD),
                _merge(CARDS_2411, RTD_CARD),
                SLOT_E_2411,
                SLOT_Z_2411,
            ),
            Option("slot_b_fiber_serial", variant + 11, variant + 12, FIBER_SERIAL_2411),
            Option("slot_b_ethernet", variant + 12, variant + 13, ETHERNET_2411),
            Option("protocols", variant + 13, variant + 14, PROTOCOLS_2411),
            Option("conformal_coat", variant + 14, variant + 15, CONFORMAL_COAT_01),
        ),
    )


#: "2411", then the variant ("24111" is a SEL-2411-1): the form in the MOT
#: header and in the relay's PARTNO
LAYOUT_2411: Final = _layout_2411(4)
#: The same with a leading "0", as printed in SEL AN2015-02 ("0241101A3A2X...")
LAYOUT_2411_LEADING_0: Final = _layout_2411(5)

LAYOUT_2440: Final = Layout(
    model="SEL-2440",
    length=16,
    mot="WI-8148 (2018-11-14)",
    match={6: "1", 11: "1"},
    options=(
        Option("housing", 5, 6, MOUNTING_2440),
        Option("io", 7, 11, IO_2440),
        Option("serial_port_2", 12, 13, SERIAL_PORT_2_2440),
        Option("ethernet", 13, 14, ETHERNET_2440),
        Option("protocols", 14, 15, PROTOCOLS_2440),
        Option("conformal_coat", 15, 16, CONFORMAL_COAT_01),
    ),
)

LAYOUT_2032: Final = Layout(
    model="SEL-2032",
    length=14,
    mot="WI-3644 (2014-07-01)",
    match={5: "3"},
    options=(
        Option("housing", 4, 5, MOUNTING_2032),
        Option("special_hardware", 6, 7, SPECIAL_HARDWARE_2032),
        Option("power_supply", 7, 8, POWER_SUPPLY_2032),
        Option("io_board", 8, 10, IO_2032),
        Option("protocol_card_1", 10, 12, PROTOCOL_CARD_2032),
        Option("protocol_card_2", 12, 14, PROTOCOL_CARD_2032),
    ),
)


def _prefix_only(model: str, variant_position: int, variants: str = _DIGITS) -> Layout:
    """
    Products without a public MOT: only the variant after the prefix (e.g.
    "5" in "04515...", a SEL-451-5) is recorded. ``variants`` are the
    characters it can be.
    """
    return Layout(
        model=model,
        length=None,
        kind=LAYOUT_PREFIX_ONLY,
        match={variant_position: variants},
        fid_variant="variant",
        options=(Option("variant", variant_position, variant_position + 1),),
    )


#: Products that are decoded, by part number prefix. The longest matching
#: prefix is used.
FAMILIES: Final[tuple[Family, ...]] = (
    Family("0351S", "SEL-351S", "351S", (LAYOUT_351S,)),
    Family("0351A", "SEL-351A", "351A", (LAYOUT_351A, LAYOUT_351A_1)),
    # A digit, so the SEL-351R and SEL-351P ("0351R...") aren't decoded as a SEL-351
    Family("0351", "SEL-351", "351", (LAYOUT_351,), guard={4: _DIGITS}),
    Family("0311C", "SEL-311C", "311C", (LAYOUT_311C,)),
    Family("751A", "SEL-751A", "751A", (LAYOUT_751A,)),
    Family("751", "SEL-751", "751", (LAYOUT_751,), guard={3: _DIGITS}),
    Family("0710", "SEL-710", "710", (LAYOUT_710,)),
    Family("0787", "SEL-787", "787", (LAYOUT_787, LAYOUT_787_2), guard={4: "01234E"}),
    Family("0700G", "SEL-700G", "700G", (LAYOUT_700G,)),
    # The variant (0 or 1), so the SEL-2411P ("2411P...") isn't decoded as a SEL-2411
    Family("2411", "SEL-2411", "2411", (LAYOUT_2411,), guard={4: "01"}),
    Family("02411", "SEL-2411", "2411", (LAYOUT_2411_LEADING_0,)),
    Family("24402", "SEL-2440", "2440", (LAYOUT_2440,)),
    Family("2032", "SEL-2032", "2032", (LAYOUT_2032,)),
    Family("0421", "SEL-421", "421", (_prefix_only("SEL-421", 4),)),
    Family("0451", "SEL-451", "451", (_prefix_only("SEL-451", 4),)),
    Family("0487E", "SEL-487E", "487E", (_prefix_only("SEL-487E", 5),)),
    # Letter variants too, e.g. "0411LA..." is a SEL-411L-A
    Family("0411L", "SEL-411L", "411L", (_prefix_only("SEL-411L", 5, _DIGITS_AND_LETTERS),)),
)

# "SEL-351S-6-R514-V0-Z...", "SEL-700G-R200-...", "SEL-710-Rxxx-..." (templates)
_FID_RE: Final = re.compile(
    r"SEL-(?P<model>\d+[A-Z]*)(?:-(?P<variant>[0-9A-Z]{1,2}))?-R", re.ASCII
)


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------


def normalize_part_number(part_number: Any) -> str:
    """
    Upper case, without spaces (some documents print part numbers with spaces
    between the characters, e.g. ``0 7 8 7 0 X ...``).
    """
    if isinstance(part_number, bytes):
        part_number = part_number.decode("ascii", errors="replace")
    return "".join(str(part_number).split()).upper()


def find_family(part_number: str) -> Family | None:
    """
    The product with the longest prefix that matches the (normalized) part
    number, or ``None`` if it's not a known SEL product.
    """
    best = None
    for family in FAMILIES:
        if not part_number.startswith(family.prefix):
            continue
        rest = part_number[len(family.prefix) :]
        # A placeholder like "0787XXXXXXXXXXXXXXXX" has no character to check
        if not _matches(part_number, family.guard) and not (
            len(rest) >= _PLACEHOLDER_MIN_OPTIONS and set(rest) == {"X"}
        ):
            continue
        if best is None or len(family.prefix) > len(best.prefix):
            best = family
    return best


def decode_part_number(part_number: Any, fid: str = "") -> dict[str, Any]:
    """
    Decode an SEL part number into the ordering options it encodes.

    The result is described in the module documentation
    (:mod:`peat.modules.sel.sel_partno`). This never raises: an unknown
    product (or a value that isn't a part number) returns an empty
    :class:`dict`, and codes that aren't in the tables are ``"N/A"`` and are
    listed in ``unknown_codes``.

    Args:
        part_number: The part number, e.g. ``PARTNO`` from the ``ID`` command
        fid: The firmware ID (FID). If it's set, the model (and for some
            products, the variant) is compared with the part number, and any
            differences are in ``mismatches``.

    Returns:
        The decoded options, or an empty :class:`dict` if the product isn't
        known

    Example:
        >>> info = decode_part_number("0351S6XHA4E54X2", fid="SEL-351S-6-R514-V0")
        >>> info["model"], info["layout"], info["mot"]
        ('SEL-351S', 'documented', 'WI-8323 (2021-12-21)')
        >>> info["comm_interface"], info["codes"]["comm_interface"]
        ('2x 10/100BASE-T, EIA-485', 'E')
        >>> decode_part_number("035152B3A11XX1")["unknown_codes"]
        {'user_interface': 'B', 'comm_interface': 'A'}
    """
    try:
        return _decode(part_number, fid)
    except Exception as ex:  # The part number is only a hint, never fail on it
        log.warning(f"Failed to decode SEL part number {part_number!r}: {ex}")
        return {}


def _decode(part_number: Any, fid: str) -> dict[str, Any]:
    if not part_number:
        return {}

    pn = normalize_part_number(part_number)
    if not pn or len(pn) > MAX_LENGTH or not (pn.isascii() and pn.isalnum()):
        log.debug(f"Not decoding SEL part number {str(part_number)[:60]!r}: not a part number")
        return {}

    family = find_family(pn)
    if not family:
        log.debug(f"Not decoding SEL part number {pn}: unknown product")
        return {}

    result: dict[str, Any] = {
        "part_number": pn,
        "model": family.model,
        "layout": LAYOUT_UNRECOGNIZED,
        "advisory": True,
    }
    codes: dict[str, str] = {}

    layout = None
    if _is_placeholder(pn, family):
        result["layout"] = LAYOUT_PLACEHOLDER
        result["notes"] = [
            "Placeholder part number (e.g. from a settings template): the "
            "options are 'X', so they aren't decoded."
        ]
    elif (layout := next((lay for lay in family.layouts if _fits(pn, lay)), None)) is None:
        reasons = "; ".join(_misfit_reason(pn, lay) for lay in family.layouts)
        result["notes"] = [
            f"Doesn't fit the known layout ({reasons}). It may be from an "
            f"older model option table, or edited."
        ]
    else:
        result["model"] = layout.model
        result["layout"] = layout.kind
        if layout.mot:
            result["mot"] = layout.mot
        labels, codes, unknown = _decode_options(pn, layout)
        result.update(labels)
        result["codes"] = codes
        if unknown:
            result["unknown_codes"] = unknown
            result["notes"] = [
                "Some codes aren't in the model option table, they may be "
                "from an older table or edited."
            ]

    mismatches = _compare_fid(family, layout, codes, fid)
    if mismatches:
        result["mismatches"] = mismatches

    return result


def _is_placeholder(part_number: str, family: Family) -> bool:
    """
    The characters after the prefix are all "X", except maybe the first one
    (e.g. "751A0XXXXXXXXXXXXXX" and "0710XXXXXXXXXXXXXX" in settings templates).
    """
    rest = part_number[len(family.prefix) :]
    return len(rest) >= _PLACEHOLDER_MIN_OPTIONS and set(rest[1:]) == {"X"}


def _matches(part_number: str, positions: Mapping[int, str]) -> bool:
    return all(
        pos < len(part_number) and part_number[pos] in allowed
        for pos, allowed in positions.items()
    )


def _fits(part_number: str, layout: Layout) -> bool:
    if layout.length is not None and len(part_number) != layout.length:
        return False
    if layout.length is None and len(part_number) < max(o.end for o in layout.options):
        return False
    return _matches(part_number, layout.match)


def _misfit_reason(part_number: str, layout: Layout) -> str:
    """
    Why the part number doesn't fit the layout, e.g.
    ``"SEL-351S WI-8323 (2021-12-21): character 7 is '1', not 'X'"``.
    """
    name = f"{layout.model} {layout.mot or '(no public MOT)'}"
    if layout.length is not None and len(part_number) != layout.length:
        return f"{name}: {len(part_number)} characters, not {layout.length}"
    for pos, allowed in layout.match.items():
        if pos >= len(part_number):
            return f"{name}: no character {pos + 1}"
        if part_number[pos] not in allowed:
            expected = f"'{allowed}'" if len(allowed) == 1 else f"one of '{allowed}'"
            return f"{name}: character {pos + 1} is '{part_number[pos]}', not {expected}"
    return f"{name}: too short"


def _decode_options(
    part_number: str, layout: Layout
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """
    Returns:
        The descriptions, the codes, and the codes that aren't in the tables
    """
    labels: dict[str, str] = {}
    codes: dict[str, str] = {}
    unknown: dict[str, str] = {}

    for option in layout.options:
        code = part_number[option.start : option.end]
        codes[option.name] = code

        table = option.codes
        if option.depends_on and option.tables:
            table = option.tables.get(codes.get(option.depends_on, ""))
            if table is None:  # The other code is unknown, accept any of the codes
                table = _merge(*option.tables.values())
        if table is None:  # Recorded, but not decoded
            continue

        if code in table:
            labels[option.name] = table[code]
        else:
            labels[option.name] = UNKNOWN
            unknown[option.name] = code

    return labels, codes, unknown


def _compare_fid(
    family: Family, layout: Layout | None, codes: Mapping[str, str], fid: str
) -> dict[str, dict[str, str]]:
    """
    Compare the model (and variant, e.g. "SEL-351S-6") in the FID with the
    part number.
    """
    if not fid or not isinstance(fid, str):
        return {}

    fid_match = _FID_RE.search(fid.strip().upper())
    if not fid_match:
        return {}

    if fid_match["model"] != family.fid_model:
        return {"model": {"part_number": family.fid_model, "fid": fid_match["model"]}}

    # Only the characters that the part number has are compared, e.g. "7" in
    # "04217..." with "7S" in "SEL-421-7S-R..."
    pn_variant = codes.get(layout.fid_variant, "") if layout and layout.fid_variant else ""
    fid_variant = fid_match["variant"] or ""
    if pn_variant and fid_variant and not fid_variant.startswith(pn_variant):
        return {"variant": {"part_number": pn_variant, "fid": fid_variant}}

    return {}


def process_part_number(dev: DeviceData) -> dict[str, Any]:
    """
    Decode ``dev.part_number`` into ``dev.extra["part_number_info"]``.

    The firmware ID (``dev.firmware.id``) is used to check the model. A
    warning is logged if the part number and the firmware ID have different
    models or variants (the part number may have been edited, or be from
    another device). ``dev.part_number`` isn't changed. This can be called
    every time the part number or FID may have changed: the result is
    replaced, and warnings are only logged for new differences.

    Args:
        dev: The device

    Returns:
        The decoded part number (empty if it isn't known)
    """
    if not dev.part_number:
        return {}

    info = decode_part_number(dev.part_number, dev.firmware.id)
    previous = dev.extra.get(EXTRA_KEY)
    if info == previous:
        return info

    if not info:
        if previous is not None:  # From another part number
            del dev.extra[EXTRA_KEY]
        return {}

    dev.extra[EXTRA_KEY] = info

    old_mismatches = previous.get("mismatches", {}) if isinstance(previous, dict) else {}
    for key, values in info.get("mismatches", {}).items():
        if old_mismatches.get(key) != values:
            log.warning(
                f"The {key} in the SEL part number ({values['part_number']}, from "
                f"{info['part_number']}) is different from the firmware ID "
                f"({values['fid']}, from {dev.firmware.id}) on {dev.get_comm_id()}. "
                f"The part number may have been edited (PARTNO), or be from "
                f"another device."
            )

    log.debug(
        f"Decoded SEL part number {info['part_number']} on {dev.get_comm_id()}: "
        f"{info['model']} ({info['layout']} layout, "
        f"{len(info.get('unknown_codes', {}))} unknown codes)"
    )
    return info


__all__ = [
    "EXTRA_KEY",
    "FAMILIES",
    "LAYOUT_DOCUMENTED",
    "LAYOUT_INFERRED",
    "LAYOUT_PLACEHOLDER",
    "LAYOUT_PREFIX_ONLY",
    "LAYOUT_UNRECOGNIZED",
    "MAX_LENGTH",
    "RESULT_KEYS",
    "UNKNOWN",
    "Family",
    "Layout",
    "Option",
    "decode_part_number",
    "find_family",
    "normalize_part_number",
    "process_part_number",
]
