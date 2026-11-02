"""
Names of SEL relay protection elements, by IEEE C37.2 device function code.

SEL names protection elements and their settings after the device function
number, followed by letters for what the element measures and a level
number, e.g. ``50P1`` (phase instantaneous overcurrent, level 1) with the
pickup setting ``50P1P``, or ``51G`` (residual ground time-overcurrent).
A few letters mean something specific in SEL relays that's different from
the generic suffix letters in :mod:`peat.parsing.ieee_c37_2`:

- ``P`` phase, ``G`` residual ground (3I0, calculated from the phase
  currents), ``N`` neutral (the IN current channel), ``Q`` negative sequence
- ``S`` in ``27S`` and ``59S`` is the synchronism-check voltage channel (VS),
  not "DC" or "synchronizing"
- ``V1`` is positive sequence (``27V1``, ``59V1``)
- ``BK`` is a breaker (``25BK1`` is synchronism check for breaker 1), not a brake
- ``X`` and ``Y`` at the end of an element (SEL-700G) are the X-side and
  Y-side terminals (e.g. ``81RX``, ``27V1X``)
- ``68`` is out-of-step blocking (power swing blocking, SEL Relay Word bit
  ``OSB``), ``78`` is out-of-step tripping (``OST``), and ``87N`` is
  restricted earth fault (REF)

The names are written by PEAT authors, from the element names in the public
SEL-351S (date code 20171023), SEL-421 (20130627), SEL-700G (20150521),
SEL-710 (20090327), SEL-751A (20130329) and SEL-787 (20150130) instruction
manuals. Codes that aren't here use the generic names in
:data:`~peat.modules.sel.sel_consts.ANSI_CODES` and IEEE C37.2-2008.

Authors

- Christopher Goes
"""

import functools
import re
from typing import Final

from peat.parsing.ieee_c37_2 import describe_device_function, normalize_code

from .sel_consts import ANSI_CODES

#: Names of SEL protection elements, keyed by device function code
SEL_ELEMENT_NAMES: Final[dict[str, str]] = {
    "21": "Distance",
    "21P": "Phase distance (mho)",
    "21G": "Ground distance (mho)",
    "21MG": "Ground distance (mho)",
    "21XG": "Ground distance (quadrilateral)",
    "24": "Volts per hertz (overexcitation)",
    "25": "Synchronism check",
    # SEL-421: one synchronism check for each of the two breakers
    "25BK1": "Synchronism check for breaker 1",
    "25BK2": "Synchronism check for breaker 2",
    "27": "Undervoltage",
    "27P": "Phase undervoltage",
    "27PP": "Phase-to-phase undervoltage",
    "27S": "Undervoltage on the synchronism-check voltage channel (VS)",
    "27V1": "Positive-sequence undervoltage",
    "32": "Directional element or directional power",
    "32P": "Directional power",
    "37": "Undercurrent or underpower",
    "37P": "Underpower (load loss)",
    "40": "Loss of field",
    "46": "Current unbalance (negative sequence)",
    "46Q": "Negative-sequence overcurrent",
    "46UB": "Current unbalance",
    "47": "Phase reversal (voltage)",
    "47T": "Phase reversal (voltage) tripping",
    "49": "Thermal overload",
    "49T": "Thermal overload",
    "49MOTOR": "Motor thermal model (thermal overload)",
    "49RTD": "RTD temperature protection",
    "50": "Instantaneous overcurrent",
    "50P": "Phase instantaneous overcurrent",
    "50PP": "Phase-to-phase instantaneous overcurrent",
    "50G": "Residual-ground (3I0) instantaneous overcurrent",
    "50N": "Neutral (IN channel) instantaneous overcurrent",
    "50Q": "Negative-sequence instantaneous overcurrent",
    "50BF": "Breaker failure",
    "51": "Time-overcurrent",
    "51P": "Phase time-overcurrent",
    "51A": "Phase A time-overcurrent",
    "51B": "Phase B time-overcurrent",
    "51C": "Phase C time-overcurrent",
    "51G": "Residual-ground (3I0) time-overcurrent",
    "51N": "Neutral (IN channel) time-overcurrent",
    "51Q": "Negative-sequence time-overcurrent",
    "51S": "Selectable-quantity time-overcurrent",
    "51V": "Voltage-restrained time-overcurrent",
    "52": "Circuit breaker",
    "55": "Power factor",
    "59": "Overvoltage",
    "59P": "Phase overvoltage",
    "59PP": "Phase-to-phase overvoltage",
    "59G": "Residual (zero-sequence) overvoltage",
    "59N": "Neutral overvoltage",
    "59Q": "Negative-sequence overvoltage",
    "59S": "Overvoltage on the synchronism-check voltage channel (VS)",
    "59V1": "Positive-sequence overvoltage",
    "60": "Loss of potential (LOP)",
    "64F": "Field ground",
    "64G": "Stator ground",
    "67": "Directional overcurrent",
    "67P": "Phase directional overcurrent",
    "67G": "Residual-ground directional overcurrent",
    "67N": "Neutral directional overcurrent",
    "67Q": "Negative-sequence directional overcurrent",
    "68": "Out-of-step (power swing) blocking",
    "78": "Out-of-step tripping",
    "79": "Autoreclosing",
    "81": "Frequency",
    "81D": "Definite-time over- or underfrequency",
    "81R": "Rate-of-change of frequency",
    "81RF": "Fast rate-of-change of frequency",
    # SEL-700G: time the generator has run in off-nominal frequency bands,
    # which can alarm or trip (E81ACC is N or the number of bands)
    "81ACC": "Off-frequency time accumulators",
    "85": "Communications-assisted (pilot) tripping",
    "86": "Lockout",
    "87": "Differential",
    "87B": "Bus differential",
    "87L": "Line current differential",
    "87M": "Motor differential",
    "87N": "Restricted earth fault (REF)",
    "87T": "Transformer differential",
    "89": "Disconnect switch",
    "94": "Trip",
}

#: Names that are different for some models, keyed by model (e.g. ``700G``)
#: and then by code. On the SEL-700G, 51C is the voltage-controlled
#: time-overcurrent element, not phase C.
MODEL_ELEMENT_NAMES: Final[dict[str, dict[str, str]]] = {
    "700G": {"51C": "Voltage-controlled time-overcurrent"},
}

#: Meanings of the letters at the end of an element (SEL-700G terminals)
SIDE_LETTERS: Final[dict[str, str]] = {
    "X": "X side",
    "Y": "Y side",
}

#: SEL meanings of suffix letters, used instead of the generic C37.2 meanings
#: for codes that aren't in :data:`SEL_ELEMENT_NAMES`. For example, ``BK`` is
#: a breaker in SEL relays (``25BK3``), not a brake.
SEL_SUFFIXES: Final[dict[str, str]] = {
    "BK": "breaker",
    "G": "residual ground",
    "N": "neutral",
    "P": "phase",
    "Q": "negative sequence",
}

#: Settings that enable a protection element: ``E`` and the device function
#: code, e.g. ``E50P``, ``E87M``, ``E49MOTOR`` or ``E27V1X``. The code has two
#: digits, so ``E2SPEED`` (two-speed motor) and ``E61850`` aren't elements.
ELEMENT_ENABLE_RE: Final = re.compile(r"^E(\d{2}(?:[A-Z][A-Z0-9_]*)?)$")

#: An element code: two digits, then letters and digits (e.g. 50P1, 27V1X)
_ELEMENT_RE: Final = re.compile(r"^(\d{2})([A-Z0-9]*)$")

#: What can follow a known element: a level number and a terminal side
_REMAINDER_RE: Final = re.compile(r"^(?P<level>\d{1,2})?(?P<side>[XY])?$")

# ANSI_CODES keyed by uppercase code, for the codes that have letters.
# The numbers use the IEEE C37.2-2008 names instead.
_GENERIC_NAMES: Final[dict[str, str]] = {
    normalize_code(k): v for k, v in ANSI_CODES.items() if not k.isdigit()
}


def _model_key(model: str | None) -> str:
    return normalize_code(model or "").removeprefix("SEL-").lstrip("0")


def _names(model: str | None = None) -> dict[str, str]:
    return _model_names(_model_key(model))


@functools.lru_cache(maxsize=32)
def _model_names(model_key: str) -> dict[str, str]:
    return {**SEL_ELEMENT_NAMES, **MODEL_ELEMENT_NAMES.get(model_key, {})}


def element_name(code: str, model: str | None = None) -> str | None:
    """
    Name of a SEL protection element, only if PEAT knows the element.

    The code can have a level number and a terminal side after the element,
    e.g. ``50P1`` => ``"Phase instantaneous overcurrent level 1"`` and
    ``81RX`` => ``"Rate-of-change of frequency (X side)"``.

    Unlike :func:`ansi_name`, this doesn't fall back to the generic names,
    so it's safe to build descriptions from (e.g. of the setting ``50P1P``).

    Args:
        code: Element code, e.g. ``"50P1"``
        model: Relay model (e.g. ``"700G"``), for names that are different on some models

    Returns:
        The name, or None if the element isn't known
    """
    code = normalize_code(code)
    names = _names(model)

    if code in names:
        return names[code]

    match = _ELEMENT_RE.match(code)
    if not match:
        return None

    number, rest = match.groups()
    for length in range(len(rest) - 1, -1, -1):
        key = f"{number}{rest[:length]}"
        remainder = _REMAINDER_RE.match(rest[length:])
        if key not in names or not remainder:
            continue

        name = names[key]
        if remainder.group("level"):
            name = f"{name} level {int(remainder.group('level'))}"
        if remainder.group("side"):
            name = f"{name} ({SIDE_LETTERS[remainder.group('side')]})"
        return name

    return None


def ansi_name(code: str, model: str | None = None) -> str | None:
    """
    Name of a protection element or device function, for SEL relays.

    The name is looked up in this order:

    #. SEL element names (:data:`SEL_ELEMENT_NAMES`, with the level and
       terminal side, see :func:`element_name`)
    #. The other names in :data:`~peat.modules.sel.sel_consts.ANSI_CODES`
       (e.g. ``64REF``, ``50EF``)
    #. The IEEE C37.2-2008 name for the number, with the meaning of the
       suffix letters (:func:`~peat.parsing.ieee_c37_2.describe_device_function`).
       The SEL meanings in :data:`SEL_SUFFIXES` are used for the letters
       (``25BK3`` => ``"Synchronism check (breaker) #3"``).

    Combined codes (``50/51``) are named part by part.

    Examples: ``27S`` => ``"Undervoltage on the synchronism-check voltage
    channel (VS)"``, ``87T`` => ``"Transformer differential"``,
    ``94`` => ``"Trip"``, ``97`` => ``"Used only for specific applications"``.

    Args:
        code: Device function code, e.g. ``"50P"`` or ``"87M"``
        model: Relay model (e.g. ``"700G"``), for names that are different on some models

    Returns:
        The name, or None if the code isn't a device function code (e.g. ``100``)
    """
    code = normalize_code(code)
    if not code:
        return None

    name = element_name(code, model)
    if name:
        return name

    if code in _GENERIC_NAMES:
        return _GENERIC_NAMES[code]

    if "/" in code:
        parts = [ansi_name(part, model) for part in code.split("/")]
        return " / ".join(parts) if all(parts) else None  # type: ignore[arg-type]

    return describe_device_function(code, overrides=_names(model), suffixes=SEL_SUFFIXES)


__all__ = [
    "ELEMENT_ENABLE_RE",
    "MODEL_ELEMENT_NAMES",
    "SEL_ELEMENT_NAMES",
    "SEL_SUFFIXES",
    "ansi_name",
    "element_name",
]
