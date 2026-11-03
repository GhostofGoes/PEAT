"""
Decoding of the CIP Identity object (class ``0x01``) ``Status`` word
(attribute 5) and ``State`` (attribute 8), as reported by ControlLogix
controllers and modules (and other EtherNet/IP devices) in ``ListIdentity``
and ``Get_Attributes_All`` responses.

The decoded values become :class:`~peat.data.models.Indicator` objects
(``type="status_flag"`` for decoded bits, ``type="switch"`` for the key switch),
:attr:`~peat.data.models.DeviceData.key_switch` and
:attr:`~peat.data.models.DeviceData.health` (NAMUR NE 107).

Status word bits

- ``0x0001``: Owned (an I/O connection owns the device)
- ``0x0004``: Configured (configured to something different than the
  out-of-the-box default; Logix controllers often leave it clear, so it is
  informational only)
- ``0x00F0``: Extended Device Status (I/O connection state, see
  :data:`EXTENDED_DEVICE_STATUS`). This is NOT the controller run mode.
- ``0x0100`` / ``0x0200``: Minor recoverable / unrecoverable fault
- ``0x0400`` / ``0x0800``: Major recoverable / unrecoverable fault
- ``0xF000``: Extended Device Status 2 (vendor-specific). On Logix
  controllers (product type ``0x0E``) bits 12-13 are the key switch position:
  ``0x1000`` RUN, ``0x2000`` PROG, ``0x3000`` REMOTE.

References

- ODVA, The CIP Networks Library, Volume 1, Identity Object
- Wireshark CIP dissector (``epan/dissectors/packet-cip.c``: identity status
  bits, extended device status values, ``cip_id_state_vals``)
- pycomm3 ``KEYSWITCH`` table (``pycomm3/cip/status_info.py``)

Worked example: a controller reporting status ``0x3160`` has the key switch in
REMOTE, at least one I/O connection in run mode (extended status 6) and a minor
recoverable fault (``health="maintenance_required"``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from peat import DeviceData, Indicator, utils
from peat.protocols.enip.enip_packets import PRODUCT_TYPES

PLC_PRODUCT_TYPE: Final[str] = PRODUCT_TYPES[0x0E]
"""Human-readable name of CIP product type ``0x0E`` (programmable logic controller)."""

EXTENDED_STATUS_MASK: Final[int] = 0x00F0
KEY_SWITCH_MASK: Final[int] = 0x3000

# (bit mask, indicator name, category, NE 107 health when the bit is set)
STATUS_FLAGS: Final[tuple[tuple[int, str, str, str], ...]] = (
    (0x0001, "owned", "", ""),
    (0x0004, "configured", "", ""),
    (0x0100, "minor_recoverable_fault", "fault", "maintenance_required"),
    (0x0200, "minor_unrecoverable_fault", "fault", "maintenance_required"),
    (0x0400, "major_recoverable_fault", "fault", "failure"),
    (0x0800, "major_unrecoverable_fault", "fault", "failure"),
)

EXTENDED_DEVICE_STATUS: Final[dict[int, str]] = {
    0: "self-testing or unknown",
    1: "firmware update in progress",
    2: "at least one faulted I/O connection",
    3: "no I/O connections established",
    4: "non-volatile configuration bad",
    5: "major fault",
    6: "at least one I/O connection in run mode",
    7: "at least one I/O connection established, all in idle mode",
    8: "reserved",
    9: "reserved",
}
"""CIP Extended Device Status (status word bits 4-7). Values 10-15 are vendor-specific."""

IDENTITY_STATES: Final[dict[int, str]] = {
    0: "Nonexistent",
    1: "Device Self Testing",
    2: "Standby",
    3: "Operational",
    4: "Major Recoverable Fault",
    5: "Major Unrecoverable Fault",
}
"""CIP Identity object ``State`` values (attribute 8)."""

STATE_HEALTH: Final[dict[int, str]] = {3: "normal", 4: "failure", 5: "failure"}

# Logix key switch position (status word bits 12-13): (raw value, DeviceData.key_switch)
KEY_SWITCH_POSITIONS: Final[dict[int, tuple[str, str]]] = {
    0x1000: ("RUN", "run"),
    0x2000: ("PROG", "program"),
    0x3000: ("REMOTE", "remote"),
}

KEY_SWITCH_HEALTH: Final[dict[str, str]] = {"run": "normal", "program": "check_function"}

# NE 107 values, most severe first ("most severe wins")
HEALTH_SEVERITY: Final[tuple[str, ...]] = (
    "failure",
    "check_function",
    "out_of_specification",
    "maintenance_required",
    "normal",
)


def most_severe_health(*values: str) -> str:
    """
    Most severe NAMUR NE 107 value of ``values`` (empty values are ignored).

    Returns:
        The most severe value, or an empty string if no value is set
    """
    for health in HEALTH_SEVERITY:
        if health in values:
            return health
    return ""


@dataclass
class IdentityStatus:
    """Result of :func:`decode_identity_status`."""

    indicators: list[Indicator] = field(default_factory=list)
    key_switch: str = ""
    """``run``, ``program``, ``remote`` or ``""`` (not a Logix controller or not reported)."""
    health: str = ""
    """NE 107 health derived from the state, fault bits and key switch."""
    status: str = ""
    """Text of the identity ``State`` (empty if unknown)."""


def decode_identity_status(
    status: int | None,
    state: int | None = None,
    product_type: str = "",
    timestamp: datetime | None = None,
) -> IdentityStatus:
    """
    Decode the CIP Identity ``Status`` word and ``State`` into indicators,
    the Logix key switch position and a NE 107 health value.

    Args:
        status: Identity status word (attribute 5), or :obj:`None` if not reported
        state: Identity state (attribute 8), or :obj:`None` if not reported
        product_type: Human-readable CIP product type (``PRODUCT_TYPES`` value).
            The key switch is only decoded for ``"PLC"`` (product type ``0x0E``),
            bits 12-15 of other modules are vendor-specific.
        timestamp: when the values were read (defaults to :func:`peat.utils.utc_now`)

    Returns:
        The decoded values
    """
    result = IdentityStatus()
    if timestamp is None:
        timestamp = utils.utc_now()
    is_plc = product_type == PLC_PRODUCT_TYPE
    healths = []

    if status is not None:
        status = int(status)
        status_word = f"0x{status:04X}"

        for bit, name, category, set_health in STATUS_FLAGS:
            is_set = bool(status & bit)
            health = ""
            if set_health:
                health = set_health if is_set else "normal"
                healths.append(health)
            result.indicators.append(
                Indicator(
                    name=name,
                    type="status_flag",
                    category=category,
                    state="on" if is_set else "off",
                    health=health,
                    position=f"bit_{bit.bit_length() - 1}",
                    timestamp=timestamp,
                    extra={"status_word": status_word},
                )
            )

        extended = (status & EXTENDED_STATUS_MASK) >> 4
        result.indicators.append(
            Indicator(
                name="cip_extended_status",
                type="status_flag",
                value=EXTENDED_DEVICE_STATUS.get(extended, "vendor specific"),
                position="bits_4_7",
                timestamp=timestamp,
                extra={"status_word": status_word, "code": extended},
            )
        )

        position = KEY_SWITCH_POSITIONS.get(status & KEY_SWITCH_MASK)
        if is_plc and position:
            raw, result.key_switch = position
            switch_health = KEY_SWITCH_HEALTH.get(result.key_switch, "")
            healths.append(switch_health)
            result.indicators.append(
                Indicator(
                    name="key_switch",
                    type="switch",
                    category="mode",
                    value=raw,
                    health=switch_health,
                    position="bits_12_13",
                    timestamp=timestamp,
                    extra={"status_word": status_word},
                )
            )

        # Logix controllers report program mode as "all I/O connections idle"
        if is_plc and extended == 7:
            healths.append("check_function")

    if state is not None:
        state = int(state)
        state_health = STATE_HEALTH.get(state, "")
        healths.append(state_health)
        result.status = IDENTITY_STATES.get(state, "")
        result.indicators.append(
            Indicator(
                name="cip_state",
                type="status_flag",
                value=IDENTITY_STATES.get(state, f"unknown ({state})"),
                health=state_health,
                timestamp=timestamp,
                extra={"state": state},
            )
        )

    # Only fault-free flags and no state: not enough to call the device "normal"
    if state is None or state not in STATE_HEALTH:
        healths = [h for h in healths if h != "normal"]

    result.health = most_severe_health(*healths)
    return result


def apply_identity_status(
    dev: DeviceData,
    status: int | None,
    state: int | None = None,
    product_type: str = "",
) -> IdentityStatus:
    """
    Decode the CIP Identity status/state with :func:`decode_identity_status`
    and store the results in ``dev``: the indicators, ``key_switch`` (Logix
    controllers only), ``health`` and ``status`` (if unset). ``run_mode`` is
    never set from the identity status.

    Args:
        dev: device (or module) the identity values were read from
        status: Identity status word, or :obj:`None` if not reported
        state: Identity state, or :obj:`None` if not reported
        product_type: Human-readable CIP product type, e.g. ``"PLC"``

    Returns:
        The decoded values
    """
    decoded = decode_identity_status(status, state, product_type)

    for indicator in decoded.indicators:
        dev.store("indicators", indicator)
    if decoded.key_switch:
        dev.key_switch = decoded.key_switch
    if decoded.health:
        dev.health = decoded.health
    if decoded.status and not dev.status:
        dev.status = decoded.status

    return decoded


__all__ = [
    "EXTENDED_DEVICE_STATUS",
    "IDENTITY_STATES",
    "KEY_SWITCH_POSITIONS",
    "PLC_PRODUCT_TYPE",
    "IdentityStatus",
    "apply_identity_status",
    "decode_identity_status",
    "most_severe_health",
]
