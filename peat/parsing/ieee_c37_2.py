"""
IEEE C37.2-2008 electrical power system device function numbers
(often called "ANSI device numbers"), and functions to parse and describe
device function codes such as ``51G``, ``87T``, ``50BF``, ``16ESM`` or ``50/51``.

This module is vendor-neutral. Vendor modules can pass their own names for
codes (``overrides``) and suffix letters (``suffixes``) to
:func:`describe_device_function`, since vendors use some letters
differently (e.g. ``Q`` for negative-sequence elements in SEL relays).

Sources:

- Device function numbers and names: IEEE Std C37.2-2008, as reproduced in
  U.S. Bureau of Reclamation Facilities Instructions, Standards, and
  Techniques (FIST) Volume 3-8, "Operation, Maintenance, and Field Test
  Procedures for Protective Relays and Associated Circuits" (May 2011),
  Appendix B, "Electrical Device Numbers Definitions and Functions". FIST is
  a work of the U.S. federal government. The names are the short function
  names printed there. The definitions in FIST and in the standard are not
  copied here.
- The device 16 suffix scheme is from the same appendix (item 16).
- The suffix letters and acronyms are commonly used abbreviations, written
  in PEAT's own words. The exact set of the 17 acronyms that C37.2-2008 added
  is inferred from the standard's abstract (medium confidence).

The 2008 edition differs from older lists in a few places, e.g. 16 is a data
communications device, 68 is a blocking or out-of-step relay, and 78 is only
a phase-angle measuring relay (out-of-step moved to 68).

Authors

- Christopher Goes
"""

import re
from collections.abc import Mapping
from typing import Final, TypedDict

#: Device function numbers and names, from IEEE Std C37.2-2008
#: (as printed in USBR FIST 3-8, Appendix B). 95-99 are left for specific
#: applications, for when none of the functions assigned to 1-94 are suitable.
DEVICE_NUMBERS: Final[dict[int, str]] = {
    1: "Master Element",
    2: "Time-Delay Starting or Closing Relay",
    3: "Checking or Interlocking Relay",
    4: "Master Contactor",
    5: "Stopping Device",
    6: "Starting Circuit Breaker",
    7: "Rate-of-Change Relay",
    8: "Control Power Disconnecting Device",
    9: "Reversing Device",
    10: "Unit Sequence Switch",
    11: "Multifunction Device",
    12: "Over-Speed Device",
    13: "Synchronous-Speed Device",
    14: "Under-Speed Device",
    15: "Speed or Frequency Matching Device",
    16: "Data Communications Device",
    17: "Shunting or Discharge Switch",
    18: "Accelerating or Decelerating Device",
    19: "Starting-to-Running Transition Contactor",
    20: "Electrically Operated Valve",
    21: "Distance Relay",
    22: "Equalizer Circuit Breaker",
    23: "Temperature Control Device",
    24: "Volts per Hertz Relay",
    25: "Synchronizing or Synchronism-Check Device",
    26: "Apparatus Thermal Device",
    27: "Undervoltage Relay",
    28: "Flame Detector",
    29: "Isolating Contactor or Switch",
    30: "Annunciator Relay",
    31: "Separate Excitation Device",
    32: "Directional Power Relay",
    33: "Position Switch",
    34: "Master Sequence Device",
    35: "Brush-Operating or Slip-Ring Short-Circuiting Device",
    36: "Polarity or Polarizing Voltage Device",
    37: "Undercurrent or Underpower Relay",
    38: "Bearing Protective Device",
    39: "Mechanical Condition Monitor",
    40: "Field Relay",
    41: "Field Circuit Breaker",
    42: "Running Circuit Breaker",
    43: "Manual Transfer or Selector Device",
    44: "Unit Sequence Starting Relay",
    45: "Atmospheric Condition Monitor",
    46: "Reverse-Phase or Phase-Balance Current Relay",
    47: "Phase-Sequence or Phase-Balance Voltage Relay",
    48: "Incomplete Sequence Relay",
    49: "Machine or Transformer Thermal Relay",
    50: "Instantaneous Overcurrent Relay",
    51: "AC Inverse Time Overcurrent Relay",
    52: "AC Circuit Breaker",
    53: "Field Excitation Relay",
    54: "Turning Gear Engaging Device",
    55: "Power Factor Relay",
    56: "Field Application Relay",
    57: "Short-Circuiting or Grounding Device",
    58: "Rectification Failure Relay",
    59: "Overvoltage Relay",
    60: "Voltage or Current Balance Relay",
    61: "Density Switch or Sensor",
    62: "Time-Delay Stopping or Opening Relay",
    63: "Pressure Switch",
    64: "Ground Protective Relay",
    65: "Governor",
    66: "Notching or Jogging Device",
    67: "AC Directional Overcurrent Relay",
    68: "Blocking or Out-of-Step Relay",
    69: "Permissive Control Device",
    70: "Rheostat",
    71: "Liquid Level Switch",
    72: "DC Circuit Breaker",
    73: "Load-Resistor Contactor",
    74: "Alarm Relay",
    75: "Position Changing Mechanism",
    76: "DC Overcurrent Relay",
    77: "Telemetering Device",
    78: "Phase-Angle Measuring Relay",
    79: "AC Reclosing Relay",
    80: "Flow Switch",
    81: "Frequency Relay",
    82: "DC Load-Measuring Reclosing Relay",
    83: "Automatic Selective Control or Transfer Relay",
    84: "Operating Mechanism",
    85: "Pilot Communications, Carrier, or Pilot-Wire Relay",
    86: "Lockout Relay",
    87: "Differential Protective Relay",
    88: "Auxiliary Motor or Motor Generator",
    89: "Line Switch",
    90: "Regulating Device",
    91: "Voltage Directional Relay",
    92: "Voltage and Power Directional Relay",
    93: "Field-Changing Contactor",
    94: "Tripping or Trip-Free Relay",
    95: "Used only for specific applications",
    96: "Used only for specific applications",
    97: "Used only for specific applications",
    98: "Used only for specific applications",
    99: "Used only for specific applications",
}

#: First suffix letter of a device 16 (data communications device): the interface
DEVICE_16_INTERFACES: Final[dict[str, str]] = {
    "S": "serial",
    "E": "Ethernet",
}

#: Other suffix letters of a device 16: the functions of the component.
#: Security processing is e.g. a VPN or encryption, a network-managed component
#: is e.g. configured with SNMP, and a telephone component is e.g. an auto-answer modem.
DEVICE_16_FUNCTIONS: Final[dict[str, str]] = {
    "C": "security processing",
    "F": "firewall or message filter",
    "M": "network managed",
    "R": "router",
    "S": "switch",
    "T": "telephone component",
}

#: Commonly used suffix letters that tell what a device applies to or how
#: it works, e.g. ``G`` in ``51G`` (ground). Many letters have more than one
#: meaning, and vendors use some of them differently. Written in PEAT's own words.
SUFFIXES: Final[dict[str, str]] = {
    "A": "alarm or auxiliary power",
    "AC": "alternating current",
    "B": "bus, battery or blower",
    "BF": "breaker failure",
    "BK": "brake",
    "BP": "bypass",
    "BT": "bus tie",
    "BU": "backup",  # codespell:ignore bu
    "C": "capacitor, condenser, compensator, carrier current, case or compressor",
    "D": "discharge",
    "DC": "direct current",
    "DCB": "directional comparison blocking",
    "DCUB": "directional comparison unblocking",
    "DD": "disturbance detector",
    "DUTT": "direct underreaching transfer trip",
    "E": "exciter",
    "F": "feeder, field, filament, filter or fan",
    "G": "ground or generator",
    "GC": "ground check",
    "H": "heater or housing",
    "L": "line or logic",
    "M": "motor or metering",
    "MOC": "mechanism-operated contact",
    "N": "neutral or network",
    "O": "over",
    "P": "phase or pump",
    "PC": "phase comparison",
    "POTT": "permissive overreaching transfer trip",
    "PUTT": "permissive underreaching transfer trip",
    "R": "reactor, rectifier or room",
    "S": "synchronizing, secondary, strainer, sump or suction",
    "SOTF": "switch onto fault",
    "T": "transformer or thyratron",
    "TD": "time delay",
    "TDC": "time-delay closing contact",
    "TDDO": "time-delayed dropout",
    "TDO": "time-delay opening contact",
    "TDPU": "time-delayed pickup",
    "TH": "transformer high-voltage side",
    "TL": "transformer low-voltage side",
    "TM": "telemeter",
    "TT": "transformer tertiary side",
    "U": "under or unit",
    "X": "auxiliary",
    "Y": "auxiliary",
    "Z": "auxiliary",
}

#: Acronyms for functions that don't have a device number, such as
#: recorders and synchrophasor devices. Written in PEAT's own words.
ACRONYMS: Final[dict[str, str]] = {
    "AFD": "Arc flash detector",
    "CLK": "Clock or timing source",
    "DDR": "Dynamic disturbance recorder",
    "DFR": "Digital fault recorder",
    "ENV": "Environmental data",
    "HIZ": "High-impedance fault detector",
    "HMI": "Human-machine interface",
    "HST": "Historian",
    "LGC": "Scheme logic",
    "MET": "Substation metering",
    "PDC": "Phasor data concentrator",
    "PMU": "Phasor measurement unit",
    "PQM": "Power quality monitor",
    "RIO": "Remote input/output device",
    "RTU": "Remote terminal unit or data concentrator",
    "SER": "Sequence of events recorder",
    "TCM": "Trip circuit monitor",
}

# Number, suffix letters, and an optional number that tells multiple devices
# with the same function apart (e.g. "51G", "51G2", "51G-2", "51-2"). The
# instance has to follow a letter or a "-", so "100" isn't device 10 #0.
_CODE_RE: Final = re.compile(
    r"^(?P<number>\d{1,2})(?P<letters>[A-Z]*)(?:(?<=[A-Z])(?P<instance>\d+)|-(?P<separate>\d+))?$"
)


class DeviceCode(TypedDict):
    """
    Parts of a device function code, e.g. ``51G2``.
    """

    #: Device function number, e.g. ``51``
    number: int
    #: Suffix letters, e.g. ``"G"`` (empty if there aren't any)
    letters: str
    #: Number that tells multiple devices with the same function apart,
    #: e.g. ``2`` (None if there isn't one)
    instance: int | None


def normalize_code(code: str) -> str:
    """
    Normalize a device function code: remove spaces and make it uppercase.
    """
    return re.sub(r"\s+", "", str(code)).upper()


def parse_device_code(code: str | int) -> DeviceCode | None:
    """
    Split a device function code into its number, suffix letters and instance.

    Examples: ``51`` => 51, ``""``, None; ``51G`` => 51, ``"G"``, None;
    ``87T2`` and ``87T-2`` => 87, ``"T"``, 2; ``16ESM`` => 16, ``"ESM"``, None.

    Args:
        code: Device function code, e.g. ``"51G"``. Case and spaces don't matter.

    Returns:
        The parts of the code, or None if it isn't a device function code
        (e.g. ``100``, ``0``, ``PMU`` or ``50/51``)
    """
    match = _CODE_RE.match(normalize_code(code))
    if not match:
        return None

    number = int(match.group("number"))
    if number not in DEVICE_NUMBERS:
        return None

    instance = match.group("instance") or match.group("separate")

    return {
        "number": number,
        "letters": match.group("letters"),
        "instance": int(instance) if instance else None,
    }


def _describe_16(letters: str) -> str | None:
    # Device 16: the first letter is the interface, the rest are functions,
    # e.g. "ESM" is a managed Ethernet switch.
    if not letters or letters[0] not in DEVICE_16_INTERFACES:
        return None

    interface = DEVICE_16_INTERFACES[letters[0]]
    functions = [DEVICE_16_FUNCTIONS.get(letter) for letter in letters[1:]]
    if not functions:
        return interface
    if not all(functions):
        return None

    return f"{interface}: {', '.join(functions)}"  # type: ignore[arg-type]


def describe_device_function(
    code: str | int,
    overrides: Mapping[str, str] | None = None,
    suffixes: Mapping[str, str] | None = None,
) -> str | None:
    """
    Describe a device function code, e.g. ``51G`` =>
    ``"AC Inverse Time Overcurrent Relay (ground or generator)"``.

    The name is looked up in this order:

    #. ``overrides``, for the whole code (e.g. a vendor's name for ``51G``)
    #. :data:`ACRONYMS` (e.g. ``PMU``)
    #. ``overrides`` for the number and the longest leading part of the
       suffix letters (e.g. ``51`` for ``51GT``), then the
       :data:`DEVICE_NUMBERS` name. The rest of the letters are described
       with ``suffixes`` and :data:`SUFFIXES`, or the device 16 suffix scheme
       (``16ESM`` is a managed Ethernet switch). Letters that aren't known as a
       whole are shown as-is, since they can't be split reliably (``50EF``
       isn't "exciter, feeder").

    Combined functions (``50/51``, ``27TN/59N``) are described part by part.
    The instance number, if there is one, is added at the end (``51G2`` =>
    ``"... (ground or generator) #2"``).

    Args:
        code: Device function code, e.g. ``"87T"``. Case and spaces don't matter.
        overrides: Names to use instead of the standard names, keyed by code
            (uppercase), e.g. ``{"27S": "Synchronism channel undervoltage"}``
        suffixes: Meanings of suffix letters to use instead of :data:`SUFFIXES`

    Returns:
        The description, or None if the code isn't a device function code
        or acronym (e.g. ``100`` or ``XYZ``)
    """
    code = normalize_code(code)
    if not code:
        return None

    names = {normalize_code(k): v for k, v in (overrides or {}).items()}
    if code in names:
        return names[code]

    if "/" in code:
        parts = [describe_device_function(part, overrides, suffixes) for part in code.split("/")]
        if not all(parts):
            return None
        return " / ".join(parts)  # type: ignore[arg-type]

    if code in ACRONYMS:
        return ACRONYMS[code]

    parsed = parse_device_code(code)
    if not parsed:
        return None

    number, letters = parsed["number"], parsed["letters"]
    name = DEVICE_NUMBERS[number]
    rest = letters

    for length in range(len(letters), -1, -1):
        key = f"{number}{letters[:length]}"
        if key in names:
            name, rest = names[key], letters[length:]
            break

    if rest:
        meanings = {**SUFFIXES, **(suffixes or {})}
        meaning = _describe_16(rest) if number == 16 else None
        if not meaning:
            meaning = meanings.get(rest, f"suffix {rest}")
        name = f"{name} ({meaning})"

    if parsed["instance"] is not None:
        name = f"{name} #{parsed['instance']}"

    return name


__all__ = [
    "ACRONYMS",
    "DEVICE_16_FUNCTIONS",
    "DEVICE_16_INTERFACES",
    "DEVICE_NUMBERS",
    "SUFFIXES",
    "DeviceCode",
    "describe_device_function",
    "normalize_code",
    "parse_device_code",
]
