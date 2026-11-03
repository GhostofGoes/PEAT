"""
Read-only collection with the binary SEL Fast protocols: Fast Meter, the Fast
Operate configuration, Fast Message database reads, and (opt-in) Fast SER.

SEL relays share each port between two data streams: SEL ASCII commands and
binary messages, which a master (e.g. an RTAC or a SEL-2032) sends and receives
between the ASCII output. A binary message starts with ``0xA5`` (SEL ASCII is
7-bit, so this byte isn't in ASCII output), then the message type, and, in every
message that has data, the length of the whole message (header and check bytes
included):

- Fast Meter (``A5C0`` to ``A5D3``) and the Fast Operate configuration
  (``A5CE``): the requests are two bytes, and the responses end with a checksum,
  the sum of all of the other bytes modulo 256 (:func:`sel_checksum8`).
  These are documented in public SEL instruction manuals (e.g. SEL-351A IM
  20080213, Appendix D).
- Fast Message (``A546``): a header with a function code, a sequence byte for
  multi-frame transfers, and a response number, and a CRC-16 at the end
  (:func:`sel_crc16`). Fast SER (function codes ``01``, ``02``, ``18`` and
  ``98``) is documented in SEL-351A IM 20080213 Appendix J and SEL-487B RM
  20090519 Table 4.7. SEL doesn't publish the other function codes (the
  configuration block ``00``, reads ``10``, the device description ``30``,
  data formats ``31`` and bit labels ``33``). Their layouts are from the
  Wireshark dissector ``epan/dissectors/packet-selfm.c`` (GPL-2.0-or-later,
  Copyright 2012-2021 Chris Bontje), as facts: no code was copied from it.

Everything except :class:`FastLink` and :class:`SELFast` is pure (no I/O).

.. warning::
   Relay settings (``SHO``, ``SET_*.TXT``) can't be read with the Fast protocols.
   What they provide is the relay's self-description (the relay definition block,
   the Fast Meter channels, the Fast Operate configuration, and the Fast Message
   capabilities, regions, and data formats), identification (FID, BFID, serial
   number, part number, relay and station ID, active group) on relays that support
   Fast Message reads, the last events (``HISTORY`` region), self-test status, one
   Fast Meter sample, and SER records (Fast SER). Settings still come from SEL
   ASCII, files, FTP, or the web interface.

Safety (this is enforced in code, not just documented):

- Only the requests in :data:`ALLOWED_REQUESTS` can be built, and every write to
  a SEL ASCII session is checked with :func:`check_outgoing`, so data with
  a ``0xA5`` byte that isn't exactly one allowed request is refused.
- Nothing here builds the requests in :data:`NEVER_SENT`: Fast Operate commands
  (they operate breakers and remote bits), the Fast Meter status acknowledge
  (``A5B9``, which clears the ``STSET`` bit that SCADA masters use to notice
  settings changes), and the Fast Message ping, write, and management functions.
- The requests that change the state of the port (:data:`FAST_SER_REQUESTS`:
  enabling and disabling unsolicited Fast SER, and acknowledging its messages)
  are only allowed while :class:`SELFast` collects Fast SER, which PEAT only does
  if ``sel.fast_ser`` is enabled. Since any acknowledge also clears ``STSET``, Fast
  SER isn't enabled if ``STSET`` is set (or its state isn't known).
- The commands that a relay definition block says to send when a status bit is
  set (e.g. ``A5C1`` or ``SHO``) are recorded, but never sent.
"""

from __future__ import annotations

import math
import re
import struct
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timedelta
from time import monotonic
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from peat import Service, log

from .relay_parse import apply_uptime, process_events, process_info_into_dev
from .sel_cascii import FAST_FRAME_CODES, parse_records

if TYPE_CHECKING:
    from peat import DeviceData
    from peat.protocols.expect import ReadChunk

    from .sel_ascii import SELAscii

# ---------------------------------------------------------------------------
# Message identifiers and codes
# ---------------------------------------------------------------------------

#: First byte of every binary SEL message
FRAME_START: Final = 0xA5

#: Fast Message (with a function code and a CRC-16)
FAST_MESSAGE: Final = 0xA546
#: Relay definition block: protocols, Fast Meter messages, and status flags
RELAY_DEFINITION: Final = 0xA5C0
#: Fast Meter configuration block (the analog channels of ``A5D1``)
FAST_METER_CONFIG: Final = 0xA5C1
#: Demand Fast Meter configuration block
DEMAND_CONFIG: Final = 0xA5C2
#: Peak demand Fast Meter configuration block
PEAK_DEMAND_CONFIG: Final = 0xA5C3
#: Fast Meter data message
FAST_METER_DATA: Final = 0xA5D1
#: Demand Fast Meter data message
DEMAND_DATA: Final = 0xA5D2
#: Peak demand Fast Meter data message
PEAK_DEMAND_DATA: Final = 0xA5D3
#: Fast Operate configuration block. Reading it doesn't operate anything, and
#: the relay only answers if Fast Operate is enabled on the port (``FASTOP=Y``).
FAST_OPERATE_CONFIG: Final = 0xA5CE

#: Fast Meter configuration requests, and the data request of each
METER_DATA_COMMANDS: Final[Mapping[int, int]] = MappingProxyType(
    {
        FAST_METER_CONFIG: FAST_METER_DATA,
        DEMAND_CONFIG: DEMAND_DATA,
        PEAK_DEMAND_CONFIG: PEAK_DEMAND_DATA,
    }
)

#: Two-byte requests whose responses have a length and a checksum, which an
#: emulator or a test can build with :func:`build_meter_frame`
METER_RESPONSES: Final = frozenset(
    {
        RELAY_DEFINITION,
        FAST_METER_CONFIG,
        DEMAND_CONFIG,
        PEAK_DEMAND_CONFIG,
        FAST_METER_DATA,
        DEMAND_DATA,
        PEAK_DEMAND_DATA,
        FAST_OPERATE_CONFIG,
    }
)

# Fast Message function codes. A response has the function code of the request
# with the high bit set (RESPONSE), e.g. 0x90 for a read (0x10).
FC_CONFIG: Final = 0x00  #: Fast Message configuration block request
FC_ENABLE_UNSOLICITED: Final = 0x01  #: Enable unsolicited messages (Fast SER)
FC_DISABLE_UNSOLICITED: Final = 0x02  #: Disable unsolicited messages (Fast SER)
FC_PING: Final = 0x05  #: Ping (never sent: aborts an unsolicited message in progress)
FC_READ: Final = 0x10  #: Read words of a database region
FC_FAST_SER: Final = 0x18  #: Unsolicited Fast SER message (from the relay)
FC_DEVICE_DESCRIPTION: Final = 0x30  #: Device description: FID, RID, and regions
FC_DATA_FORMAT: Final = 0x31  #: Data format (items) of a region
FC_BIT_LABEL: Final = 0x33  #: Names of the 8 bits of a byte in a region
FC_FAST_SER_ACK: Final = 0x98  #: Acknowledge of an unsolicited Fast SER message
RESPONSE: Final = 0x80  #: Added to the function code of a request in its response

#: Names of the Fast Message function codes
FUNCTION_CODES: Final[Mapping[int, str]] = MappingProxyType(
    {
        0x00: "configuration block request",
        0x01: "enable unsolicited data",
        0x02: "disable unsolicited data",
        0x05: "ping",
        0x10: "read request",
        0x12: "generic unsolicited data",
        0x16: "SOE present state request",
        0x18: "unsolicited Fast SER",
        0x20: "unsolicited write",
        0x21: "unsolicited write request",
        0x30: "device description request",
        0x31: "data format request",
        0x32: "unsolicited data format response",
        0x33: "bit label request",
        0x40: "management",
        0x80: "configuration block response",
        0x81: "enable unsolicited data acknowledge",
        0x82: "disable unsolicited data acknowledge",
        0x85: "ping acknowledge",
        0x90: "read response",
        0x96: "SOE present state response",
        0x98: "unsolicited Fast SER acknowledge",
        0xB0: "device description response",
        0xB1: "data format response",
        0xB3: "bit label response",
    }
)

#: Function codes of the messages a relay sends, which :func:`build_fast_message`
#: builds for emulators and tests. PEAT never sends them (refer to :func:`check_request`).
RELAY_FUNCTIONS: Final = frozenset({0x18, 0x80, 0x81, 0x82, 0x90, 0xB0, 0xB1, 0xB3})

#: Response codes in acknowledge messages
RESPONSE_CODES: Final[Mapping[int, str]] = MappingProxyType(
    {
        0: "success",
        1: "function code not recognized",
        2: "function code supported but disabled",
        3: "invalid data address",
        4: "bad data",
        5: "insufficient memory",
        6: "busy",
    }
)

SEQ_FIR: Final = 0x80  #: Sequence byte: first frame
SEQ_FIN: Final = 0x40  #: Sequence byte: last frame
SEQ_COUNT: Final = 0x3F  #: Sequence byte: number of the frame
#: Sequence byte of a request for the first (or only) frame. A request for frame
#: ``n`` of a multi-frame response is the same request with ``SEQ_SINGLE | n``.
SEQ_SINGLE: Final = SEQ_FIR | SEQ_FIN

STATUS_ACK_REQUESTED: Final = 0x01  #: Status byte: an acknowledge is requested
#: Status byte of an unsolicited Fast SER message: the relay's settings changed,
#: and the SER element list may have changed (re-read SNS)
STATUS_SETTINGS_CHANGED: Final = 0x02

#: Fast SER element index of a power-up record
FAST_SER_POWER_UP: Final = 0xFE
#: Fast SER element index of a settings change record
FAST_SER_SETTINGS_CHANGE: Final = 0xFF
#: Fast SER element index of an element that's no longer in the SER trigger settings
FAST_SER_REMOVED: Final = 0xFD
#: End of the records in a Fast SER message
FAST_SER_END: Final = b"\xff\xff\xff\xfe"
#: Maximum number of records per Fast SER message
MAX_FAST_SER_RECORDS: Final = 32

#: Element names PEAT uses for the special Fast SER element indices. The power-up
#: name is recognized as a restart by the uptime calculation.
FAST_SER_SPECIAL_ELEMENTS: Final[Mapping[int, str]] = MappingProxyType(
    {
        FAST_SER_POWER_UP: "Power-up",
        FAST_SER_SETTINGS_CHANGE: "Settings changed",
        FAST_SER_REMOVED: "Element removed from the SER triggers",
    }
)

#: Protocols in the relay definition block (the low byte of each protocol word)
PROTOCOLS: Final[Mapping[int, tuple[str, str]]] = MappingProxyType(
    {
        0x00: ("SEL Fast Meter", "sel_fast_meter"),
        0x01: ("SEL Distributed Port Switch (LMD)", "sel_lmd"),
        0x02: ("Modbus", "modbus"),
        0x03: ("SY/MAX", "symax"),
        0x04: ("SEL relay-to-relay", "sel_relay_to_relay"),
        0x05: ("DNP3", "dnp3"),
        0x06: ("SEL MIRRORED BITS", "sel_mirrored_bits"),
        0x07: ("IEEE C37.118", "c37_118"),
        0x08: ("IEC 61850", "iec61850"),
    }
)

#: Fast Message data item types: name and bytes per item
ITEM_TYPES: Final[Mapping[int, tuple[str, int]]] = MappingProxyType(
    {
        0x11: ("char8", 1),
        0x12: ("char16", 2),
        0x21: ("dig8_labels", 1),
        0x22: ("dig8", 1),
        0x23: ("dig16_labels", 2),
        0x24: ("dig16", 2),
        0x31: ("int16", 2),
        0x32: ("uint16", 2),
        0x33: ("int32", 4),
        0x34: ("uint32", 4),
        0x41: ("float32", 4),
    }
)

#: Data item types whose bits have names (requested with :data:`FC_BIT_LABEL`)
LABELLED_ITEM_TYPES: Final = frozenset({0x21, 0x23})

_ITEM_FORMATS: Final[Mapping[int, str]] = MappingProxyType(
    {0x21: "B", 0x22: "B", 0x23: "H", 0x24: "H", 0x31: "h", 0x32: "H", 0x33: "i", 0x34: "I"}
)

#: Fast Meter value types (analog channels and scale factors): name, size, format
METER_VALUE_TYPES: Final[Mapping[int, tuple[str, int, str]]] = MappingProxyType(
    {
        0x00: ("int16", 2, ">h"),
        0x01: ("float32", 4, ">f"),
        0x02: ("float64", 8, ">d"),
        0x03: ("timestamp", 8, ""),
    }
)

#: Scale factor type of a channel that doesn't have one
NO_SCALE_FACTOR: Final = 0xFF
#: Offset of a Fast Meter field that isn't in the data message
NO_OFFSET: Final = 0xFFFF

#: What the samples of each Fast Meter channel are (by the number of samples).
#: With 2 samples, the first is the imaginary (Y) component and the second the
#: real (X) component (observed: the frequency is in the second set).
SAMPLE_LAYOUTS: Final[Mapping[int, str]] = MappingProxyType(
    {1: "value", 2: "y_x", 4: "quarter_cycles_1_2_5_6"}
)

# ---------------------------------------------------------------------------
# Allowed and forbidden requests
# ---------------------------------------------------------------------------

#: Every request PEAT can build and send, and what it does. A two-byte request is
#: its message ID, and a Fast Message is ``(FAST_MESSAGE, function code)``. All of
#: them only read, except :data:`FAST_SER_REQUESTS`.
ALLOWED_REQUESTS: Final[Mapping[int | tuple[int, int], str]] = MappingProxyType(
    {
        RELAY_DEFINITION: "Relay definition block (A5C0)",
        FAST_METER_CONFIG: "Fast Meter configuration block (A5C1)",
        DEMAND_CONFIG: "Demand Fast Meter configuration block (A5C2)",
        PEAK_DEMAND_CONFIG: "Peak demand Fast Meter configuration block (A5C3)",
        FAST_METER_DATA: "Fast Meter data (A5D1)",
        DEMAND_DATA: "Demand Fast Meter data (A5D2)",
        PEAK_DEMAND_DATA: "Peak demand Fast Meter data (A5D3)",
        FAST_OPERATE_CONFIG: "Fast Operate configuration block (A5CE), only read",
        (FAST_MESSAGE, FC_CONFIG): "Fast Message configuration block (function 00)",
        (FAST_MESSAGE, FC_READ): "Read a Fast Message database region (function 10)",
        (FAST_MESSAGE, FC_DEVICE_DESCRIPTION): "Fast Message device description (function 30)",
        (FAST_MESSAGE, FC_DATA_FORMAT): "Data format of a region (function 31)",
        (FAST_MESSAGE, FC_BIT_LABEL): "Bit labels of a byte in a region (function 33)",
        (FAST_MESSAGE, FC_ENABLE_UNSOLICITED): (
            "Enable unsolicited Fast SER on the port (function 01, for 18 only)"
        ),
        (FAST_MESSAGE, FC_DISABLE_UNSOLICITED): (
            "Disable unsolicited Fast SER on the port (function 02, for 18 only)"
        ),
        (FAST_MESSAGE, FC_FAST_SER_ACK): "Acknowledge an unsolicited Fast SER message (98)",
    }
)

#: Allowed requests that change the state of the port: enabling unsolicited Fast
#: SER sets the ``FSERx`` Relay Word bit, and an acknowledge marks the SER records
#: as delivered on the port. Any acknowledge (response code 0) also clears the
#: settings changed bits, including the Fast Meter ``STSET`` bit (SEL-351A IM
#: 20080213, the notes after Table J.5). They're only allowed while Fast SER is
#: collected.
FAST_SER_REQUESTS: Final = frozenset(
    {
        (FAST_MESSAGE, FC_ENABLE_UNSOLICITED),
        (FAST_MESSAGE, FC_DISABLE_UNSOLICITED),
        (FAST_MESSAGE, FC_FAST_SER_ACK),
    }
)

#: Requests PEAT never builds or sends, and why
NEVER_SENT: Final[Mapping[int | tuple[int, int], str]] = MappingProxyType(
    {
        0xA5B9: (
            "Fast Meter status acknowledge: clears the status byte, including STSET, "
            "which SCADA masters use to notice settings changes"
        ),
        0xA5E0: "Fast Operate remote bit control (sets, clears, or pulses a remote bit)",
        0xA5E3: "Fast Operate breaker control (opens or closes a breaker)",
        0xA5E5: "Alternate Fast Operate: open",
        0xA5E6: "Alternate Fast Operate: close",
        0xA5E7: "Alternate Fast Operate: set",
        0xA5E8: "Alternate Fast Operate: clear",
        0xA5E9: "Alternate Fast Operate: pulse",
        0xA5ED: "Fast Operate reset (e.g. a target reset)",
        (FAST_MESSAGE, FC_PING): "Ping: aborts an unsolicited message in progress",
        (FAST_MESSAGE, 0x20): "Unsolicited write",
        (FAST_MESSAGE, 0x21): "Unsolicited write request",
        (FAST_MESSAGE, 0x40): "Management",
    }
)

#: Element name prefixes of the regions that :class:`SELFast` reads by default
#: (identification, self-test status, the last events, and breaker monitoring)
INVENTORY_REGIONS: Final = ("LOCAL", "STATUS", "HISTORY", "BREAKER")

# Header of a Fast Message: A5 46, length, 5 routing bytes, status, function
# code, sequence (or response code), response number. Then the body and a CRC.
_HEADER_SIZE: Final = 12
_ACK_SIZE: Final = 14


class FastFrameError(ValueError):
    """A SEL Fast frame is invalid (e.g. too short, or its CRC or checksum is wrong)."""


class FastRequestRefused(ValueError):
    """
    PEAT refused to build or send data, because it isn't exactly one of the
    allowed SEL Fast requests (:data:`ALLOWED_REQUESTS`).
    """


# ---------------------------------------------------------------------------
# Integrity checks
# ---------------------------------------------------------------------------


def sel_checksum8(data: bytes | bytearray) -> int:
    """
    Checksum of the binary SEL messages other than Fast Message: the sum of
    the bytes, modulo 256. It's the last byte of a message, and covers all of
    the bytes before it (e.g. ``A5 E0 06 43 0D`` has the checksum ``DB``,
    SEL-351A IM 20080213 Table D.9).
    """
    return sum(data) & 0xFF


def sel_crc16(data: bytes | bytearray) -> int:
    """
    CRC-16 of a Fast Message (``A546``): polynomial ``x^16 + x^15 + x^2 + 1``
    (``0x8005``) reflected (``0xA001``), initial value ``0xFFFF``, no final XOR
    (the same math as the Modbus RTU CRC, check value ``0x4B37`` for
    ``b"123456789"``). It covers every byte before the CRC, and unlike Modbus it's
    sent big-endian (most significant byte first).
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def verify_frame(frame: bytes | bytearray) -> bool:
    """
    If a binary SEL frame is complete and its CRC (Fast Message) or checksum
    (other messages) is correct. The third byte must be the length of the frame.
    """
    if len(frame) < 4 or frame[0] != FRAME_START or frame[2] != len(frame):
        return False
    if frame[1] == 0x46:
        return len(frame) >= _ACK_SIZE and sel_crc16(frame[:-2]) == int.from_bytes(
            frame[-2:], "big"
        )
    return sel_checksum8(frame[:-1]) == frame[-1]


def message_id(frame: bytes | bytearray) -> int:
    """The two-byte message ID at the start of a frame, e.g. ``0xA5C0``."""
    if len(frame) < 2:
        raise FastFrameError("frame is shorter than 2 bytes")
    return (frame[0] << 8) | frame[1]


def describe_frame(frame: bytes | bytearray) -> str:
    """Short description of a frame for logs, e.g. ``A546 90 (read response)``."""
    try:
        mid = message_id(frame)
    except FastFrameError:
        return "empty"
    if mid == FAST_MESSAGE and len(frame) >= 10:
        fc = frame[9]
        return f"A546 {fc:02X} ({FUNCTION_CODES.get(fc, 'unknown function')})"
    return ALLOWED_REQUESTS.get(mid) or NEVER_SENT.get(mid) or f"{mid:04X}"


# ---------------------------------------------------------------------------
# Building requests (only the allowed ones), and checking outgoing data
# ---------------------------------------------------------------------------


def _refuse(what: str, reason: str = "") -> FastRequestRefused:
    message = f"PEAT doesn't send {what}"
    if reason:
        message += f": {reason}"
    return FastRequestRefused(message)


def build_meter_request(command: int) -> bytes:
    """
    Build a two-byte request, e.g. ``A5C0`` (relay definition) or ``A5D1``
    (Fast Meter data). Only the two-byte requests in :data:`ALLOWED_REQUESTS`
    can be built.

    Raises:
        FastRequestRefused: The request isn't allowed (e.g. ``A5B9`` or ``A5E0``)
    """
    if command not in ALLOWED_REQUESTS or not isinstance(command, int):
        reason = NEVER_SENT.get(command, "not an allowed request")
        raise _refuse(f"{command:04X}" if isinstance(command, int) else repr(command), reason)
    return command.to_bytes(2, "big")


def _fast_message(function_code: int, body: bytes, seq: int, resp_num: int, status: int) -> bytes:
    length = _HEADER_SIZE + len(body) + 2
    if length > 0xFF:
        raise ValueError(f"Fast Message is too long ({length} bytes, the maximum is 255)")
    header = bytes(
        [0xA5, 0x46, length, 0, 0, 0, 0, 0, status, function_code, seq & 0xFF, resp_num & 0xFF]
    )
    frame = header + bytes(body)
    return frame + sel_crc16(frame).to_bytes(2, "big")


def build_fast_message(
    function_code: int,
    body: bytes = b"",
    seq: int = SEQ_SINGLE,
    resp_num: int = 0,
    status: int = STATUS_ACK_REQUESTED,
) -> bytes:
    """
    Build a Fast Message (``A546``) frame, with the length and the CRC.

    The function code must be an allowed request (:data:`ALLOWED_REQUESTS`), or a
    message that relays send (:data:`RELAY_FUNCTIONS`, for emulators and tests;
    :func:`check_request` refuses to send those).

    Args:
        function_code: Function code, e.g. :data:`FC_READ`
        body: The data after the header
        seq: Sequence byte. For a request, ``SEQ_SINGLE | n`` asks for frame ``n``.
            For an acknowledge, it's the response code.
        resp_num: Response number (0 to 3), which the relay copies to its response
        status: Status byte (``0x01``: an acknowledge is requested)

    Raises:
        FastRequestRefused: The function code isn't allowed (e.g. ping or a write)
    """
    key = (FAST_MESSAGE, function_code)
    if key not in ALLOWED_REQUESTS and function_code not in RELAY_FUNCTIONS:
        reason = NEVER_SENT.get(key, "not an allowed function code")
        raise _refuse(f"Fast Message function {function_code:02X}", reason)
    return _fast_message(function_code, body, seq, resp_num, status)


def build_ack(function_code: int, response_code: int = 0, resp_num: int = 0) -> bytes:
    """
    Build an acknowledge message (14 bytes, status ``0x00``): the function code
    of the message that's acknowledged with the high bit set, the response
    code, and the response number of that message.

    Args:
        function_code: Function code of the acknowledged message: ``0x18`` (Fast
            SER, sent by PEAT), or ``0x01`` and ``0x02`` (sent by relays, for
            emulators and tests)
        response_code: Response code, refer to :data:`RESPONSE_CODES`
        resp_num: Response number of the acknowledged message
    """
    if function_code not in (FC_FAST_SER, FC_ENABLE_UNSOLICITED, FC_DISABLE_UNSOLICITED):
        raise _refuse(f"an acknowledge for function {function_code:02X}")
    return _fast_message(function_code | RESPONSE, b"", response_code, resp_num, 0x00)


def build_config_request(resp_num: int = 0) -> bytes:
    """Fast Message configuration block request (function ``00``)."""
    return build_fast_message(FC_CONFIG, resp_num=resp_num)


def build_device_description_request(frame: int = 0, resp_num: int = 0) -> bytes:
    """Device description request (function ``30``) for frame ``frame``."""
    return build_fast_message(FC_DEVICE_DESCRIPTION, seq=SEQ_SINGLE | frame, resp_num=resp_num)


def build_data_format_request(base: int, frame: int = 0, resp_num: int = 0) -> bytes:
    """Data format request (function ``31``) of the region at ``base``."""
    return build_fast_message(
        FC_DATA_FORMAT, struct.pack(">I", base), seq=SEQ_SINGLE | frame, resp_num=resp_num
    )


def build_read_request(base: int, words: int, frame: int = 0, resp_num: int = 0) -> bytes:
    """Read request (function ``10``) of ``words`` 16-bit words at ``base``."""
    if not 1 <= words <= 0xFFFF:
        raise ValueError(f"invalid number of words to read: {words}")
    return build_fast_message(
        FC_READ, struct.pack(">IH", base, words), seq=SEQ_SINGLE | frame, resp_num=resp_num
    )


def build_bit_label_request(address: int, resp_num: int = 0) -> bytes:
    """Bit label request (function ``33``) of the byte at ``address``."""
    return build_fast_message(FC_BIT_LABEL, struct.pack(">I", address), resp_num=resp_num)


def build_enable_fast_ser(max_records: int = MAX_FAST_SER_RECORDS, resp_num: int = 0) -> bytes:
    """
    Enable unsolicited Fast SER messages (function ``01`` for ``18``), with at
    most ``max_records`` records per message (1 to 32). This changes the state
    of the port (refer to :data:`FAST_SER_REQUESTS`).
    """
    if not 1 <= max_records <= MAX_FAST_SER_RECORDS:
        raise ValueError(f"max_records must be 1 to {MAX_FAST_SER_RECORDS}, not {max_records}")
    return build_fast_message(
        FC_ENABLE_UNSOLICITED, bytes([FC_FAST_SER, 0, 0, max_records]), resp_num=resp_num
    )


def build_disable_fast_ser(resp_num: int = 0) -> bytes:
    """Disable unsolicited Fast SER messages (function ``02`` for ``18``)."""
    return build_fast_message(FC_DISABLE_UNSOLICITED, bytes([FC_FAST_SER, 0]), resp_num=resp_num)


def build_meter_frame(command: int, body: bytes) -> bytes:
    """
    Build a response to a two-byte request (e.g. a relay definition block), with
    the length and the checksum, for emulators and tests. Only the responses in
    :data:`METER_RESPONSES` can be built, so Fast Operate commands, which have
    the same form, can't.
    """
    if command not in METER_RESPONSES:
        raise _refuse(f"{command:04X} frames", NEVER_SENT.get(command, "not a response block"))
    length = 2 + 1 + len(body) + 1
    if length > 0xFF:
        raise ValueError(f"frame is too long ({length} bytes, the maximum is 255)")
    frame = command.to_bytes(2, "big") + bytes([length]) + bytes(body)
    return frame + bytes([sel_checksum8(frame)])


def check_request(data: bytes | bytearray, allow_fast_ser: bool = False) -> str:
    """
    Check that data is exactly one allowed SEL Fast request (:data:`ALLOWED_REQUESTS`).

    Args:
        data: The data to send
        allow_fast_ser: Also allow the requests that collect Fast SER
            (:data:`FAST_SER_REQUESTS`)

    Returns:
        Description of the request

    Raises:
        FastRequestRefused: It isn't an allowed request. The message never
            includes the data, which could be a password.
    """
    data = bytes(data)
    if len(data) < 2 or data[0] != FRAME_START:
        raise _refuse("this data as a SEL Fast request", "it doesn't start with 0xA5")

    mid = message_id(data)
    if mid != FAST_MESSAGE:
        if mid not in ALLOWED_REQUESTS:
            raise _refuse(f"{mid:04X}", NEVER_SENT.get(mid, "not an allowed request"))
        if len(data) != 2:
            raise _refuse(f"{mid:04X} with extra data", "the request is two bytes")
        return ALLOWED_REQUESTS[mid]

    if not verify_frame(data) or data[3:8] != bytes(5):
        raise _refuse("an invalid Fast Message", "wrong length, CRC, or routing address")

    status, fc, seq = data[8], data[9], data[10]
    body = data[_HEADER_SIZE:-2]
    key = (FAST_MESSAGE, fc)
    if key not in ALLOWED_REQUESTS:
        raise _refuse(f"Fast Message function {fc:02X}", NEVER_SENT.get(key, "not allowed"))
    if key in FAST_SER_REQUESTS and not allow_fast_ser:
        raise _refuse(
            f"Fast Message function {fc:02X}",
            "it changes the state of the port, and is only sent while collecting "
            "Fast SER (sel.fast_ser)",
        )

    if fc == FC_FAST_SER_ACK:
        if body or status != 0:
            raise _refuse("this Fast SER acknowledge", "it must be 14 bytes with status 00")
        return ALLOWED_REQUESTS[key]

    if status not in (0x00, STATUS_ACK_REQUESTED):
        raise _refuse(f"a Fast Message request with status {status:02X}")
    if not seq & SEQ_FIR or not seq & SEQ_FIN:
        raise _refuse(f"a Fast Message request with sequence byte {seq:02X}")

    expected_sizes = {
        FC_CONFIG: 0,
        FC_DEVICE_DESCRIPTION: 0,
        FC_READ: 6,
        FC_DATA_FORMAT: 4,
        FC_BIT_LABEL: 4,
        FC_ENABLE_UNSOLICITED: 4,
        FC_DISABLE_UNSOLICITED: 2,
    }
    if len(body) != expected_sizes[fc]:
        raise _refuse(f"Fast Message function {fc:02X} with a {len(body)}-byte body")
    if fc == FC_READ and int.from_bytes(body[4:6], "big") == 0:
        raise _refuse("a read of 0 words")
    if fc == FC_ENABLE_UNSOLICITED and (
        body[:3] != bytes([FC_FAST_SER, 0, 0]) or not 1 <= body[3] <= MAX_FAST_SER_RECORDS
    ):
        raise _refuse("an enable request for anything but Fast SER (18, 1 to 32 records)")
    if fc == FC_DISABLE_UNSOLICITED and body != bytes([FC_FAST_SER, 0]):
        raise _refuse("a disable request for anything but Fast SER (18)")

    return ALLOWED_REQUESTS[key]


def check_outgoing(data: bytes | bytearray, allow_fast_ser: bool = False) -> str | None:
    """
    Check data before it's written to a SEL ASCII session (Telnet or serial).
    Data without a ``0xA5`` byte (e.g. an ASCII command) is allowed. Data with
    one must be exactly one allowed request (refer to :func:`check_request`).

    Returns:
        Description of the request, or :obj:`None` if it isn't a SEL Fast request

    Raises:
        FastRequestRefused: The data isn't allowed
    """
    if FRAME_START not in data:
        return None
    return check_request(data, allow_fast_ser=allow_fast_ser)


# ---------------------------------------------------------------------------
# Fast Message frames
# ---------------------------------------------------------------------------


@dataclass
class FastMessage:
    """
    A Fast Message (``A546``) frame.
    """

    #: Status byte (``0x01``: an acknowledge is requested, ``0x02``: settings changed)
    status: int
    #: Function code (``0x80`` is added in responses)
    function_code: int
    #: Sequence byte (FIR, FIN, and the number of the frame), or the response
    #: code in an acknowledge
    seq: int
    #: Response number (0 to 3)
    response_number: int
    #: The data after the header, without the CRC
    body: bytes
    #: The whole frame
    raw: bytes = b""
    #: Routing address (5 bytes, zero in every message seen so far)
    route: bytes = b"\x00" * 5

    @property
    def is_response(self) -> bool:
        """If it's a response (the high bit of the function code is set)."""
        return bool(self.function_code & RESPONSE)

    @property
    def is_ack(self) -> bool:
        """If it's an acknowledge (a response without a body), e.g. an error response."""
        return self.is_response and not self.body

    @property
    def response_code(self) -> int | None:
        """The response code of an acknowledge (refer to :data:`RESPONSE_CODES`)."""
        return self.seq if self.is_ack else None

    @property
    def fir(self) -> bool:
        """First frame of a response."""
        return bool(self.seq & SEQ_FIR)

    @property
    def fin(self) -> bool:
        """Last frame of a response."""
        return bool(self.seq & SEQ_FIN)

    @property
    def frame_number(self) -> int:
        """Number of the frame in a multi-frame response."""
        return self.seq & SEQ_COUNT


def parse_fast_message(frame: bytes | bytearray) -> FastMessage:
    """
    Parse a Fast Message (``A546``) frame. The length and CRC are checked.

    Raises:
        FastFrameError: The frame is invalid
    """
    frame = bytes(frame)
    if len(frame) < _ACK_SIZE or frame[:2] != b"\xa5\x46":
        raise FastFrameError(f"not a Fast Message frame: {frame[:16].hex()}")
    if frame[2] != len(frame):
        raise FastFrameError(f"Fast Message length is {frame[2]}, but the frame is {len(frame)}")
    if not verify_frame(frame):
        raise FastFrameError("Fast Message CRC is wrong")
    return FastMessage(
        status=frame[8],
        function_code=frame[9],
        seq=frame[10],
        response_number=frame[11],
        body=frame[_HEADER_SIZE:-2],
        raw=frame,
        route=frame[3:8],
    )


def _as_message(message: FastMessage | bytes | bytearray) -> FastMessage:
    if isinstance(message, FastMessage):
        return message
    return parse_fast_message(message)


def _check_meter_frame(frame: bytes | bytearray, allowed: Iterable[int]) -> bytes:
    frame = bytes(frame)
    if len(frame) < 4:
        raise FastFrameError(f"frame is too short ({len(frame)} bytes)")
    mid = message_id(frame)
    if mid not in allowed:
        raise FastFrameError(f"unexpected message {mid:04X}")
    if frame[2] != len(frame):
        raise FastFrameError(f"{mid:04X} length is {frame[2]}, but the frame is {len(frame)}")
    if sel_checksum8(frame[:-1]) != frame[-1]:
        raise FastFrameError(f"{mid:04X} checksum is wrong")
    return frame


def _text(data: bytes, encoding: str = "latin-1") -> str:
    return data.split(b"\x00", 1)[0].decode(encoding, errors="replace").strip()


def _clean_float(value: float) -> float | None:
    return None if math.isnan(value) or math.isinf(value) else value


# ---------------------------------------------------------------------------
# Relay definition block (A5C0)
# ---------------------------------------------------------------------------


@dataclass
class ProtocolWord:
    """A protocol in the relay definition block."""

    #: The protocol word: flags in the high byte, the protocol in the low byte
    raw: int

    @property
    def protocol(self) -> int:
        """Protocol ID (refer to :data:`PROTOCOLS`)."""
        return self.raw & 0xFF

    @property
    def name(self) -> str:
        """Name of the protocol."""
        return PROTOCOLS.get(self.protocol, (f"unknown protocol {self.protocol:02X}", ""))[0]

    @property
    def fast_operate(self) -> bool:
        """The relay supports Fast Operate with this protocol (it may be disabled)."""
        return bool(self.raw & 0x0100)

    @property
    def fast_message(self) -> bool:
        """The relay supports Fast Message (unsolicited Fast SER) with this protocol."""
        return bool(self.raw & 0x0200)

    def to_dict(self) -> dict:
        return {
            "word": f"{self.raw:04X}",
            "name": self.name,
            "fast_operate": self.fast_operate,
            "fast_message": self.fast_message,
        }


@dataclass
class StatusFlag:
    """
    A status flag in the relay definition block: what a master should send when
    a bit of the Fast Meter status byte is set (e.g. re-read the configuration
    after a settings change). PEAT records these, and never sends them.
    """

    #: Bit of the status byte (inferred from the SEL-321, SEL-351A, and SEL-351S)
    bit: int
    #: The command, 6 bytes padded with NUL bytes
    command: bytes

    @property
    def text(self) -> str:
        """The command as text, e.g. ``A5C1`` or ``SHO``."""
        stripped = self.command.rstrip(b"\x00")
        if stripped[:1] == bytes([FRAME_START]):
            return stripped[:2].hex().upper()
        return stripped.decode("latin-1").strip()

    def to_dict(self) -> dict:
        return {"bit": self.bit, "command": self.text, "raw": self.command.hex()}


@dataclass
class RelayDefinition:
    """The relay definition block (``A5C0``)."""

    #: Protocols the relay supports
    protocols: list[ProtocolWord] = field(default_factory=list)
    #: Fast Meter messages: (configuration request, data request), e.g. (A5C1, A5D1)
    meter_messages: list[tuple[int, int]] = field(default_factory=list)
    #: Status flags
    status_flags: list[StatusFlag] = field(default_factory=list)
    #: Reserved bytes before the checksum (some relays have a pad byte, others don't)
    reserved: bytes = b""
    #: The frame
    raw: bytes = b""

    @property
    def fast_message(self) -> bool:
        """If any protocol supports Fast Message."""
        return any(p.fast_message for p in self.protocols)

    @property
    def fast_operate(self) -> bool:
        """If any protocol supports Fast Operate."""
        return any(p.fast_operate for p in self.protocols)

    def to_dict(self) -> dict:
        return {
            "protocols": [p.to_dict() for p in self.protocols],
            "fast_meter_messages": [
                {"config": f"{config:04X}", "data": f"{data:04X}"}
                for config, data in self.meter_messages
            ],
            "status_flags": [f.to_dict() for f in self.status_flags],
            "fast_message": self.fast_message,
            "fast_operate": self.fast_operate,
        }


def parse_relay_definition(frame: bytes | bytearray) -> RelayDefinition:
    """
    Parse a relay definition block (``A5C0``): ``A5 C0``, length, the number of
    protocols, Fast Meter messages and status flags, the Fast Meter messages
    (configuration and data requests, 2 bytes each), the status flags (the bit,
    2 bytes, and the command, 6 bytes), the protocols (2 bytes each), reserved
    bytes, and the checksum. The checksum is found with the length, since some
    relays have a pad byte before it and others don't (SEL-351A IM 20080213 Table D.3).

    Raises:
        FastFrameError: The frame is invalid
    """
    frame = _check_meter_frame(frame, (RELAY_DEFINITION,))
    if len(frame) < 7:
        raise FastFrameError("relay definition block is too short")

    n_protocols, n_meter, n_flags = frame[3], frame[4], frame[5]
    needed = 6 + 4 * n_meter + 8 * n_flags + 2 * n_protocols + 1
    if needed > len(frame):
        raise FastFrameError(
            f"relay definition block lists {n_meter} messages, {n_flags} flags, and "
            f"{n_protocols} protocols, which don't fit in {len(frame)} bytes"
        )

    result = RelayDefinition(raw=frame)
    pos = 6
    for _ in range(n_meter):
        result.meter_messages.append(struct.unpack_from(">HH", frame, pos))
        pos += 4
    for _ in range(n_flags):
        bit = struct.unpack_from(">H", frame, pos)[0]
        result.status_flags.append(StatusFlag(bit=bit, command=frame[pos + 2 : pos + 8]))
        pos += 8
    for _ in range(n_protocols):
        result.protocols.append(ProtocolWord(struct.unpack_from(">H", frame, pos)[0]))
        pos += 2
    result.reserved = frame[pos:-1]

    return result


# ---------------------------------------------------------------------------
# Fast Meter (A5C1-A5C3 and A5D1-A5D3)
# ---------------------------------------------------------------------------


@dataclass
class AnalogChannel:
    """An analog channel of a Fast Meter message."""

    #: Name, e.g. ``IA`` or ``FREQ``
    name: str
    #: Value type (refer to :data:`METER_VALUE_TYPES`)
    type: int
    #: Scale factor type (``0xFF``: no scale factor)
    scale_factor_type: int
    #: Byte offset of the scale factor in the data message (``sf_location`` 0)
    #: or in the configuration message (``sf_location`` 1)
    scale_factor_offset: int
    #: The scale factor, if it's in the configuration message
    scale_factor: float | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": METER_VALUE_TYPES.get(self.type, (f"{self.type:02X}", 0, ""))[0],
            "scale_factor_type": self.scale_factor_type,
            "scale_factor_offset": self.scale_factor_offset,
            "scale_factor": self.scale_factor,
        }


@dataclass
class FastMeterConfig:
    """A Fast Meter configuration block (``A5C1``, ``A5C2``, or ``A5C3``)."""

    #: The request, e.g. ``0xA5C1``
    command: int
    #: Number of status bytes at the start of the data message
    status_bytes: int
    #: Where the scale factors are: 0 in the data message, 1 in this message
    scale_factor_location: int
    #: Number of scale factors
    scale_factor_count: int
    #: Number of samples of each channel (refer to :data:`SAMPLE_LAYOUTS`)
    samples: int
    #: Number of digital banks (bytes) in the data message
    digital_banks: int
    #: Byte offset of the analog values in the data message
    analog_offset: int
    #: Byte offset of the timestamp in the data message (``0xFFFF``: none)
    timestamp_offset: int
    #: Byte offset of the digital banks in the data message (``0xFFFF``: none)
    digital_offset: int
    #: The analog channels
    channels: list[AnalogChannel] = field(default_factory=list)
    #: Calculation blocks (line configuration, calculation type, offsets, and
    #: the channel indexes of IA, IB, IC, VA, VB, and VC)
    calculation_blocks: list[dict] = field(default_factory=list)
    #: The frame
    raw: bytes = b""

    @property
    def data_command(self) -> int:
        """The data request for this configuration, e.g. ``0xA5D1`` for ``0xA5C1``."""
        return METER_DATA_COMMANDS.get(self.command, self.command + 0x10)

    def to_dict(self) -> dict:
        return {
            "command": f"{self.command:04X}",
            "status_bytes": self.status_bytes,
            "scale_factor_location": self.scale_factor_location,
            "scale_factor_count": self.scale_factor_count,
            "samples": self.samples,
            "sample_layout": SAMPLE_LAYOUTS.get(self.samples, ""),
            "digital_banks": self.digital_banks,
            "analog_offset": self.analog_offset,
            "timestamp_offset": self.timestamp_offset,
            "digital_offset": self.digital_offset,
            "channels": [c.to_dict() for c in self.channels],
            "calculation_blocks": self.calculation_blocks,
        }


def _meter_value(data: bytes, offset: int, value_type: int) -> float | int | None:
    _, size, fmt = METER_VALUE_TYPES.get(value_type, ("", 0, ""))
    if not fmt or offset < 0 or offset + size > len(data):
        return None
    value = struct.unpack_from(fmt, data, offset)[0]
    return _clean_float(value) if isinstance(value, float) else value


def parse_fm_config(frame: bytes | bytearray) -> FastMeterConfig:
    """
    Parse a Fast Meter configuration block (``A5C1``, ``A5C2``, or ``A5C3``,
    SEL-351A IM 20080213 Tables D.4 and D.6): the number of status bytes, where
    the scale factors are, the number of scale factors, analog channels,
    samples, digital banks and calculation blocks, the offsets of the analog
    values, timestamp and digital banks in the data message, the channels (name,
    6 bytes; type; scale factor type; scale factor offset), the calculation
    blocks (14 bytes each), and the scale factors if they're in this message.

    Raises:
        FastFrameError: The frame is invalid
    """
    frame = _check_meter_frame(frame, METER_DATA_COMMANDS.keys())
    if len(frame) < 17:
        raise FastFrameError("Fast Meter configuration block is too short")

    n_status, sf_location, n_sf, n_analog, n_samples, n_digital, n_calc = frame[3:10]
    analog_offset, timestamp_offset, digital_offset = struct.unpack_from(">HHH", frame, 10)
    if 16 + 10 * n_analog + 14 * n_calc + 1 > len(frame):
        raise FastFrameError(
            f"Fast Meter configuration lists {n_analog} channels and {n_calc} "
            f"calculation blocks, which don't fit in {len(frame)} bytes"
        )

    config = FastMeterConfig(
        command=message_id(frame),
        status_bytes=n_status,
        scale_factor_location=sf_location,
        scale_factor_count=n_sf,
        samples=n_samples,
        digital_banks=n_digital,
        analog_offset=analog_offset,
        timestamp_offset=timestamp_offset,
        digital_offset=digital_offset,
        raw=frame,
    )

    pos = 16
    for _ in range(n_analog):
        name = _text(frame[pos : pos + 6], "ascii")
        channel = AnalogChannel(
            name=name,
            type=frame[pos + 6],
            scale_factor_type=frame[pos + 7],
            scale_factor_offset=struct.unpack_from(">H", frame, pos + 8)[0],
        )
        if sf_location == 1 and channel.scale_factor_type != NO_SCALE_FACTOR:
            # The offset is in this message
            value = _meter_value(frame, channel.scale_factor_offset, channel.scale_factor_type)
            channel.scale_factor = None if value is None else float(value)
        config.channels.append(channel)
        pos += 10

    for _ in range(n_calc):
        block = frame[pos : pos + 14]
        deskew, rs, xs = struct.unpack_from(">HHH", block, 2)
        config.calculation_blocks.append(
            {
                "line_configuration": block[0],
                "calculation_type": block[1],
                "deskew_offset": deskew,
                "rs_offset": rs,
                "xs_offset": xs,
                "channel_indexes": {
                    name: (index if index != 0xFF else None)
                    for name, index in zip(
                        ("IA", "IB", "IC", "VA", "VB", "VC"), block[8:14], strict=True
                    )
                },
            }
        )
        pos += 14

    return config


@dataclass
class FastMeterData:
    """A Fast Meter data message (``A5D1``, ``A5D2``, or ``A5D3``)."""

    #: The request, e.g. ``0xA5D1``
    command: int
    #: The status bytes (the bits are named by the ``BNA`` command, MSB first)
    status: bytes
    #: Values of the analog channels (scaled), by name. With more than one
    #: sample, each value is a list (refer to :data:`SAMPLE_LAYOUTS`).
    analogs: dict[str, Any] = field(default_factory=dict)
    #: The relay's time (local time on the relay) when the data was sampled
    timestamp: datetime | None = None
    #: The digital banks, one byte each (the bits are named by the ``DNA``
    #: command, MSB first)
    digital: bytes = b""
    #: The frame
    raw: bytes = b""

    def to_dict(self) -> dict:
        return {
            "command": f"{self.command:04X}",
            "status": self.status.hex(),
            "analogs": self.analogs,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "digital": self.digital.hex(),
        }


def parse_fm_timestamp(data: bytes) -> datetime | None:
    """
    Parse a Fast Meter timestamp (8 bytes: month, day, 2-digit year, hours,
    minutes, seconds, and milliseconds, 2 bytes). Returns :obj:`None` if it
    isn't a valid date.
    """
    if len(data) < 8:
        return None
    month, day, year, hour, minute, second = data[:6]
    millis = int.from_bytes(data[6:8], "big")
    try:
        return datetime(2000 + year, month, day, hour, minute, second, millis * 1000)
    except ValueError:
        return None


def parse_fm_data(frame: bytes | bytearray, config: FastMeterConfig) -> FastMeterData:
    """
    Parse a Fast Meter data message using its configuration block. The analog
    values are ordered by sample, then by channel. Integer values are signed.
    A value is multiplied by its channel's scale factor, which is read from the
    data message (``sf_location`` 0) or the configuration message (1), unless
    the channel has no scale factor.

    Raises:
        FastFrameError: The frame is invalid, or it doesn't match the configuration
    """
    frame = _check_meter_frame(frame, (config.data_command,))
    data = FastMeterData(
        command=message_id(frame),
        status=frame[3 : 3 + config.status_bytes],
        raw=frame,
    )

    scale_factors: list[float | None] = []
    for channel in config.channels:
        if channel.scale_factor_type == NO_SCALE_FACTOR:
            scale_factors.append(None)
        elif config.scale_factor_location == 0:
            value = _meter_value(frame, channel.scale_factor_offset, channel.scale_factor_type)
            scale_factors.append(None if value is None else float(value))
        else:
            scale_factors.append(channel.scale_factor)

    samples: dict[str, list] = {c.name: [] for c in config.channels}
    pos = config.analog_offset
    for _ in range(max(config.samples, 1)):
        for channel, scale in zip(config.channels, scale_factors, strict=True):
            size = METER_VALUE_TYPES.get(channel.type, ("", 2, ""))[1]
            if pos + size > len(frame) - 1:
                raise FastFrameError(
                    f"{data.command:04X} is too short for its configuration ({config.command:04X})"
                )
            value = _meter_value(frame, pos, channel.type)
            if value is not None and scale is not None:
                value = _clean_float(value * scale)
            samples[channel.name].append(value)
            pos += size

    for name, values in samples.items():
        data.analogs[name] = values[0] if len(values) == 1 else values

    if config.timestamp_offset != NO_OFFSET:
        data.timestamp = parse_fm_timestamp(
            frame[config.timestamp_offset : config.timestamp_offset + 8]
        )
    if config.digital_offset != NO_OFFSET:
        data.digital = frame[config.digital_offset : config.digital_offset + config.digital_banks]

    return data


# ---------------------------------------------------------------------------
# Fast Operate configuration (A5CE)
# ---------------------------------------------------------------------------


@dataclass
class FastOperateConfig:
    """
    The Fast Operate configuration block (``A5CE``). The relay only sends it if
    Fast Operate is enabled on the port (``FASTOP=Y``), so a response means that
    the breakers and remote bits listed can be operated from this port. PEAT
    never sends the operate commands.
    """

    #: Number of breakers that can be opened and closed
    breakers: int
    #: Number of remote bits that can be set and cleared
    remote_bits: int
    #: If remote bits can be pulsed
    pulse_supported: bool
    #: Operate codes of each breaker: (open, close)
    breaker_codes: list[tuple[int, int]] = field(default_factory=list)
    #: Operate codes of each remote bit: (clear, set, pulse or None)
    remote_bit_codes: list[tuple[int, int, int | None]] = field(default_factory=list)
    #: The frame
    raw: bytes = b""

    def to_dict(self) -> dict:
        return {
            "breakers": self.breakers,
            "remote_bits": self.remote_bits,
            "pulse_supported": self.pulse_supported,
            "breaker_codes": [{"open": o, "close": c} for o, c in self.breaker_codes],
            "remote_bit_codes": [
                {"clear": c, "set": s, "pulse": p} for c, s, p in self.remote_bit_codes
            ],
        }


def parse_fo_config(frame: bytes | bytearray) -> FastOperateConfig:
    """
    Parse a Fast Operate configuration block (``A5CE``, SEL-351A IM 20080213 Table
    D.8): the number of breakers (1 byte), remote bits (2 bytes), if pulses are
    supported, a reserved byte, the open and close codes of each breaker, the
    clear, set (and pulse) codes of each remote bit, reserved bytes, and the checksum.
    This only parses the block: PEAT never sends Fast Operate commands.

    Raises:
        FastFrameError: The frame is invalid
    """
    frame = _check_meter_frame(frame, (FAST_OPERATE_CONFIG,))
    if len(frame) < 9:
        raise FastFrameError("Fast Operate configuration block is too short")

    n_breakers = frame[3]
    n_bits = struct.unpack_from(">H", frame, 4)[0]
    pulse = bool(frame[6])
    per_bit = 3 if pulse else 2
    if 8 + 2 * n_breakers + per_bit * n_bits + 1 > len(frame):
        raise FastFrameError(
            f"Fast Operate configuration lists {n_breakers} breakers and {n_bits} "
            f"remote bits, which don't fit in {len(frame)} bytes"
        )

    config = FastOperateConfig(
        breakers=n_breakers, remote_bits=n_bits, pulse_supported=pulse, raw=frame
    )
    pos = 8
    for _ in range(n_breakers):
        config.breaker_codes.append((frame[pos], frame[pos + 1]))
        pos += 2
    for _ in range(n_bits):
        codes = frame[pos : pos + per_bit]
        config.remote_bit_codes.append((codes[0], codes[1], codes[2] if pulse else None))
        pos += per_bit

    return config


# ---------------------------------------------------------------------------
# Fast Message configuration block (function 80)
# ---------------------------------------------------------------------------


@dataclass
class FastMessageConfig:
    """
    The Fast Message configuration block (the response to function ``00``),
    which lists the function codes the relay accepts and sends.
    """

    routing_support: int
    rx_status: int
    tx_status: int
    rx_max_frames: int
    tx_max_frames: int
    #: Function codes the relay accepts
    rx_functions: list[int] = field(default_factory=list)
    #: Function codes the relay sends
    tx_functions: list[int] = field(default_factory=list)

    def accepts(self, function_code: int) -> bool:
        """If the relay accepts a function code."""
        return function_code in self.rx_functions

    def to_dict(self) -> dict:
        return {
            "routing_support": self.routing_support,
            "rx_status": self.rx_status,
            "tx_status": self.tx_status,
            "rx_max_frames": self.rx_max_frames,
            "tx_max_frames": self.tx_max_frames,
            "rx_functions": [f"{fc:02X}" for fc in self.rx_functions],
            "tx_functions": [f"{fc:02X}" for fc in self.tx_functions],
        }


def parse_fm_cfg_block_resp(message: FastMessage | bytes) -> FastMessageConfig:
    """
    Parse a Fast Message configuration block (function ``80``): routing support,
    receive and transmit status, the maximum frames received and transmitted,
    6 reserved bytes, then the number of function codes the relay accepts and the
    codes (2 bytes each, the code and a data byte), and the same for the codes it sends.

    Raises:
        FastFrameError: The message is invalid
    """
    message = _as_message(message)
    body = message.body
    if message.function_code != FC_CONFIG | RESPONSE or len(body) < 13:
        raise FastFrameError("not a Fast Message configuration block")

    config = FastMessageConfig(*body[:5])
    pos = 11
    for target in (config.rx_functions, config.tx_functions):
        if pos >= len(body):
            raise FastFrameError("Fast Message configuration block is too short")
        count = body[pos]
        pos += 1
        if pos + 2 * count > len(body):
            raise FastFrameError("Fast Message configuration block is too short")
        target.extend(body[pos + 2 * i] for i in range(count))
        pos += 2 * count

    return config


# ---------------------------------------------------------------------------
# Device description (function B0), data format (B1), reads (90), bit labels (B3)
# ---------------------------------------------------------------------------


@dataclass
class Region:
    """A Fast Message database region, e.g. ``LOCAL2``."""

    name: str
    #: Address of the first word
    base: int
    #: Number of 16-bit words
    words: int
    flags: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "base": f"{self.base:08X}",
            "words": self.words,
            "flags": f"{self.flags:04X}",
        }


@dataclass
class DeviceDescription:
    """The Fast Message device description (function ``B0``)."""

    #: Firmware ID (without a ``FID=`` prefix)
    fid: str = ""
    #: Relay ID, or the model on some devices (e.g. ``SEL-2411``)
    rid: str = ""
    #: Number of data regions the relay has
    region_count: int = 0
    #: Number of control regions the relay has (PEAT doesn't use them)
    control_count: int = 0
    regions: list[Region] = field(default_factory=list)
    #: If all of the frames were received
    complete: bool = True

    def to_dict(self) -> dict:
        return {
            "fid": self.fid,
            "rid": self.rid,
            "region_count": self.region_count,
            "control_count": self.control_count,
            "regions": [r.to_dict() for r in self.regions],
            "complete": self.complete,
        }


def parse_device_description(message: FastMessage | bytes) -> DeviceDescription:
    """
    Parse one frame of a device description (function ``B0``): FID (50 bytes,
    padded with NUL bytes, with or without a ``FID=`` prefix), RID (40 bytes),
    the number of data and control regions (2 bytes each, for the whole
    response), and up to 7 regions in the frame (18 bytes each: name, 10 bytes;
    base address, 4 bytes; words, 2 bytes; flags, 2 bytes). Some relays add 8
    zero bytes (reserved space for the control regions) to the last frame.

    Raises:
        FastFrameError: The message is invalid
    """
    message = _as_message(message)
    body = message.body
    if message.function_code != FC_DEVICE_DESCRIPTION | RESPONSE or len(body) < 94:
        raise FastFrameError("not a device description response")

    fid = _without_key(_text(body[:50]), "FID")
    region_count, control_count = struct.unpack_from(">HH", body, 90)
    description = DeviceDescription(
        fid=fid, rid=_text(body[50:90]), region_count=region_count, control_count=control_count
    )

    pos = 94
    while pos + 18 <= len(body):
        chunk = body[pos : pos + 18]
        if not any(chunk[:10]):
            break  # reserved (zero) bytes after the regions
        base, words, flags = struct.unpack_from(">IHH", chunk, 10)
        description.regions.append(Region(_text(chunk[:10]), base, words, flags))
        pos += 18

    return description


def merge_device_description(
    frames: Iterable[DeviceDescription], complete: bool = True
) -> DeviceDescription:
    """Combine the frames of a device description (each frame has some of the regions)."""
    merged = DeviceDescription(complete=complete)
    for frame in frames:
        if not merged.fid:
            merged.fid, merged.rid = frame.fid, frame.rid
            merged.region_count, merged.control_count = frame.region_count, frame.control_count
        merged.regions.extend(frame.regions)
    if merged.region_count and len(merged.regions) > merged.region_count:
        merged.regions = merged.regions[: merged.region_count]
    if merged.region_count and len(merged.regions) < merged.region_count:
        merged.complete = False
    return merged


@dataclass
class DataItem:
    """An item in the data format of a region, e.g. ``FID`` (char8, 48)."""

    name: str
    #: Number of values (characters for text)
    quantity: int
    #: Type (refer to :data:`ITEM_TYPES`)
    type: int
    #: Byte offset of the item in the region's data
    offset: int = 0

    @property
    def type_name(self) -> str:
        return ITEM_TYPES.get(self.type, (f"unknown_{self.type:04X}", 0))[0]

    @property
    def size(self) -> int:
        """Size of the item in bytes."""
        return ITEM_TYPES.get(self.type, ("", 0))[1] * self.quantity

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "quantity": self.quantity,
            "type": self.type_name,
            "offset": self.offset,
        }


@dataclass
class DataFormat:
    """The data format of a region (function ``B1``)."""

    #: Base address of the region
    base: int = 0
    #: Number of items in the region
    item_count: int = 0
    items: list[DataItem] = field(default_factory=list)
    #: If all of the frames were received
    complete: bool = True

    @property
    def size(self) -> int:
        """Size of the region's data in bytes, from the items."""
        return sum(item.size for item in self.items)

    def to_dict(self) -> dict:
        return {
            "base": f"{self.base:08X}",
            "item_count": self.item_count,
            "items": [i.to_dict() for i in self.items],
            "complete": self.complete,
        }


def parse_data_format(message: FastMessage | bytes) -> DataFormat:
    """
    Parse one frame of a data format response (function ``B1``): the base
    address (4 bytes), the number of items (2 bytes, for the whole response),
    and up to 16 items in the frame (14 bytes each: name, 10 bytes; quantity,
    2 bytes; type, 2 bytes).

    Raises:
        FastFrameError: The message is invalid
    """
    message = _as_message(message)
    body = message.body
    if message.function_code != FC_DATA_FORMAT | RESPONSE or len(body) < 6:
        raise FastFrameError("not a data format response")

    base, count = struct.unpack_from(">IH", body, 0)
    result = DataFormat(base=base, item_count=count)
    pos = 6
    while pos + 14 <= len(body):
        quantity, item_type = struct.unpack_from(">HH", body, pos + 10)
        result.items.append(DataItem(_text(body[pos : pos + 10]), quantity, item_type))
        pos += 14
    return result


def merge_data_format(frames: Iterable[DataFormat], complete: bool = True) -> DataFormat:
    """
    Combine the frames of a data format response, and calculate the offset of
    each item (the items are packed in order, without padding).
    """
    merged = DataFormat(complete=complete)
    for number, frame in enumerate(frames):
        if number == 0:
            merged.base, merged.item_count = frame.base, frame.item_count
        merged.items.extend(frame.items)
    if merged.item_count and len(merged.items) < merged.item_count:
        merged.complete = False

    offset = 0
    for item in merged.items:
        item.offset = offset
        offset += item.size
    return merged


def parse_read_response(message: FastMessage | bytes) -> tuple[int, bytes]:
    """
    Parse one frame of a read response (function ``90``): the base address of the
    read (4 bytes, the same in every frame), the number of words in this frame
    (2 bytes), and the words.

    Returns:
        The base address and the data of the frame

    Raises:
        FastFrameError: The message is invalid
    """
    message = _as_message(message)
    body = message.body
    if message.function_code != FC_READ | RESPONSE or len(body) < 6:
        raise FastFrameError("not a read response")
    base, words = struct.unpack_from(">IH", body, 0)
    data = body[6:]
    if len(data) < 2 * words:
        raise FastFrameError(f"read response has {len(data)} bytes, not {words} words")
    return base, data[: 2 * words]


def join_read_frames(frames: Iterable[FastMessage | bytes]) -> tuple[int, bytes]:
    """Combine the frames of a read response into the base address and the data."""
    base = None
    data = b""
    for frame in frames:
        frame_base, frame_data = parse_read_response(frame)
        if base is None:
            base = frame_base
        elif frame_base != base:
            raise FastFrameError(f"read response frames are for {base:X} and {frame_base:X}")
        data += frame_data
    return base or 0, data


def parse_bit_labels(message: FastMessage | bytes) -> list[str]:
    """
    Parse a bit label response (function ``B3``): 8 labels separated by NUL bytes.
    The first label is bit 0 (the least significant bit).

    Raises:
        FastFrameError: The message is invalid
    """
    message = _as_message(message)
    if message.function_code != FC_BIT_LABEL | RESPONSE:
        raise FastFrameError("not a bit label response")
    labels = [label.decode("latin-1").strip() for label in message.body.split(b"\x00")]
    labels = labels[:8]
    return labels + [""] * (8 - len(labels))


def _decode_item(item: DataItem, raw: bytes) -> Any:
    if item.type == 0x11:  # char8
        return _text(raw)
    if item.type == 0x12:  # char16
        return raw.decode("utf-16-be", errors="replace").split("\x00", 1)[0].strip()
    if item.type == 0x41:
        values = [_clean_float(v) for v in struct.unpack(f">{item.quantity}f", raw)]
    else:
        values = list(struct.unpack(f">{item.quantity}{_ITEM_FORMATS[item.type]}", raw))
    return values[0] if item.quantity == 1 else values


def region_item_bytes(data: bytes, items: Iterable[DataItem]) -> dict[str, bytes]:
    """The bytes of each item of a region (refer to :func:`decode_region`)."""
    result = {}
    for item in items:
        name = item.name
        suffix = 2
        while name in result:
            name = f"{item.name}_{suffix}"
            suffix += 1
        result[name] = data[item.offset : item.offset + item.size]
    return result


def decode_region(data: bytes, items: Iterable[DataItem]) -> dict[str, Any]:
    """
    Decode the data of a region with its data format (:func:`merge_data_format`).
    Text items are strings (without padding), and numbers and digital words are a
    number if the quantity is 1, otherwise a list. Items of an unknown type (their
    size isn't known) and items that aren't in the data (it's too short) are left
    out. A name that's in the format twice gets a ``_2`` suffix.
    """
    items = list(items)
    values = {}
    for (name, raw), item in zip(region_item_bytes(data, items).items(), items, strict=True):
        if len(raw) < item.size or not item.size:
            continue
        values[name] = _decode_item(item, raw)
    return values


# ---------------------------------------------------------------------------
# Fast SER (function 18)
# ---------------------------------------------------------------------------


@dataclass
class FastSerRecord:
    """A record in a Fast SER message."""

    #: Element index (the order of the ``SNS`` names, or :data:`FAST_SER_POWER_UP`,
    #: :data:`FAST_SER_SETTINGS_CHANGE`, or :data:`FAST_SER_REMOVED`)
    index: int
    #: Microseconds after the time of the message
    offset_us: int
    #: New state of the element (1 asserted, 0 deasserted)
    state: int
    #: When it happened (relay local time)
    timestamp: datetime | None = None
    #: Name of the element, from ``SNS`` (or the special records)
    name: str = ""

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "state": self.state,
            "offset_us": self.offset_us,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class FastSerMessage:
    """An unsolicited Fast SER message (function ``18``)."""

    #: Status byte (``STATUS_SETTINGS_CHANGED``: re-read the SER names)
    status: int
    response_number: int
    #: Time of the message (relay local time)
    timestamp: datetime | None
    records: list[FastSerRecord] = field(default_factory=list)
    #: Packed states (bit ``k`` is the state of record ``k``)
    status_word: int = 0
    #: The frame
    raw: bytes = b""

    @property
    def settings_changed(self) -> bool:
        """The relay's settings changed (the SER names may have changed)."""
        return bool(self.status & STATUS_SETTINGS_CHANGED)

    @property
    def records_lost(self) -> bool:
        """A message without records means that the relay lost SER records."""
        return not self.records

    def to_dict(self) -> dict:
        return {
            "status": f"{self.status:02X}",
            "settings_changed": self.settings_changed,
            "records_lost": self.records_lost,
            "response_number": self.response_number,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "status_word": f"{self.status_word:08X}",
            "records": [r.to_dict() for r in self.records],
        }


def fast_ser_time(day_of_year: int, year: int, millis: int) -> datetime | None:
    """Time of a Fast SER message (day of the year, year, ms since midnight)."""
    try:
        return datetime(year, 1, 1) + timedelta(days=day_of_year - 1, milliseconds=millis)
    except (ValueError, OverflowError):
        return None


def parse_fast_ser(message: FastMessage | bytes, names: list[str] | None = None) -> FastSerMessage:
    """
    Parse an unsolicited Fast SER message (function ``18``, SEL-351A IM 20080213
    Table J.3): the return routing address (4 bytes), the day of the year and the
    year (2 bytes each), milliseconds since midnight (4 bytes), records (element
    index, 1 byte; microseconds after that time, 3 bytes), ``FF FF FF FE``, and
    the states (4 bytes, bit ``k`` is the new state of record ``k``). A message
    without records means that records were lost (Table J.4).

    Args:
        message: The message
        names: Element names (from the ``SNS`` command), in order

    Raises:
        FastFrameError: The message is invalid
    """
    message = _as_message(message)
    body = message.body
    if message.function_code != FC_FAST_SER or len(body) < 20:
        raise FastFrameError("not a Fast SER message")

    end = body.find(FAST_SER_END, 12)
    while end >= 0 and (end - 12) % 4:
        end = body.find(FAST_SER_END, end + 1)
    if end < 0 or end + 8 > len(body):
        raise FastFrameError("Fast SER message has no end-of-records flag")

    day_of_year, year, millis = struct.unpack_from(">HHI", body, 4)
    status_word = struct.unpack_from(">I", body, end + 4)[0]
    result = FastSerMessage(
        status=message.status,
        response_number=message.response_number,
        timestamp=fast_ser_time(day_of_year, year, millis),
        status_word=status_word,
        raw=message.raw,
    )

    names = names or []
    for number, pos in enumerate(range(12, end, 4)):
        index = body[pos]
        offset = int.from_bytes(body[pos + 1 : pos + 4], "big")
        if index in FAST_SER_SPECIAL_ELEMENTS:
            name = FAST_SER_SPECIAL_ELEMENTS[index]
        elif index < len(names):
            name = names[index]
        else:
            name = f"SER element {index}"
        result.records.append(
            FastSerRecord(
                index=index,
                offset_us=offset,
                state=(status_word >> number) & 1 if number < 32 else 0,
                timestamp=(
                    result.timestamp + timedelta(microseconds=offset) if result.timestamp else None
                ),
                name=name,
            )
        )

    return result


def fast_ser_events(messages: Iterable[FastSerMessage]) -> list[dict]:
    """
    Convert Fast SER records into the events that
    :func:`~peat.modules.sel.relay_parse.process_events` takes. Power-up records
    are named ``Power-up``, which the uptime calculation recognizes, and they have
    no state (like in ``SER`` output).
    """
    events = []
    for message in messages:
        for record in message.records:
            if record.timestamp is None:
                continue
            special = record.index in FAST_SER_SPECIAL_ELEMENTS
            state = "" if special else ("Asserted" if record.state else "Deasserted")
            events.append(
                {
                    "created": record.timestamp,
                    "element": record.name,
                    "state": state,
                    "original": (
                        f"Fast SER {record.timestamp.isoformat()} index {record.index} "
                        f"{record.name} {state}".strip()
                    ),
                }
            )
    return events


# ---------------------------------------------------------------------------
# HISTORY region
# ---------------------------------------------------------------------------


def history_events(data: bytes, items: list[DataItem]) -> list[dict]:
    """
    Convert the data of a ``HISTORY`` region into the events that
    :func:`~peat.modules.sel.relay_parse.process_events` takes.

    The region has one array per column (e.g. ``MONTH``, ``DAY``, ``YEAR``,
    ``HOUR``, ``MIN``, ``SEC``, ``MSEC``, ``EVENT``, ``GROUP``, ``FREQ``, ``CURR``,
    ``FAULT_LOC``, ``SHOT``, ``TARGETS``), with one value per event (10 on the
    SEL-421), and text columns are split into one string per event. Slots without
    a date or an event are empty. This layout is from the SEL-421 (the regions
    are described by the relay, so other relays may differ), and isn't validated
    on hardware.
    """
    values = decode_region(data, items)
    raw_items = region_item_bytes(data, items)
    month = values.get("MONTH")
    if not isinstance(month, list) or not month:
        return []
    count = len(month)

    def column(*names: str) -> list | None:
        for name in names:
            value = values.get(name)
            if isinstance(value, list) and len(value) == count:
                return value
        return None

    def text_column(*names: str) -> list[str] | None:
        for name in names:
            raw = raw_items.get(name)
            if raw and len(raw) % count == 0:
                size = len(raw) // count
                return [_text(raw[i * size : (i + 1) * size]) for i in range(count)]
        return None

    days, years = column("DAY"), column("YEAR")
    hours, minutes, seconds = column("HOUR"), column("MIN", "MINUTE"), column("SEC", "SECOND")
    millis = column("MSEC")
    names = text_column("EVENT")
    if not (days and years and hours and minutes and seconds and names):
        return []

    extras = {
        "group": column("GROUP", "GRP"),
        "frequency": column("FREQ"),
        "current": column("CURR", "CURRENT"),
        "locat": column("FAULT_LOC", "LOCAT"),
        "shot": column("SHOT"),
        "targets": text_column("TARGETS"),
    }
    refs = column("REF_NUM")

    events = []
    for i in range(count):
        if not years[i] or not month[i] or not names[i]:
            continue
        year = years[i] + 2000 if years[i] < 100 else years[i]
        try:
            created = datetime(
                year,
                month[i],
                days[i],
                hours[i],
                minutes[i],
                seconds[i],
                (millis[i] if millis else 0) * 1000,
            )
        except (ValueError, TypeError):
            continue
        event = {
            "created": created,
            "event": names[i],
            "original": f"Fast Message HISTORY {created.isoformat()} {names[i]}"
            + (f" (ref {refs[i]})" if refs else ""),
        }
        for key, column_values in extras.items():
            if column_values and column_values[i] not in (None, ""):
                event[key] = column_values[i]
        events.append(event)
    return events


# ---------------------------------------------------------------------------
# Splitting a byte stream into ASCII data and binary frames
# ---------------------------------------------------------------------------

#: Kinds of the chunks :class:`FrameExtractor` returns
KIND_ASCII: Final = "ascii"
KIND_BINARY: Final = "binary"
#: Bytes that started like a frame, but aren't one (e.g. the echo of a two-byte
#: request, or a frame with a wrong checksum)
KIND_INVALID: Final = "invalid"


def _frame_at(buf: bytes | bytearray, start: int) -> tuple[str, int]:
    """
    What starts at ``buf[start]``: ``("frame", length)``, ``("text", 1)`` (it
    isn't ``0xA5``, or the next byte isn't a message type), ``("invalid", 2)``,
    or ``("partial", 0)`` (more data is needed to know).
    """
    available = len(buf) - start
    if available < 1 or buf[start] != FRAME_START:
        return "text", 1
    if available < 2:
        return "partial", 0
    if buf[start + 1] not in FAST_FRAME_CODES:
        return "text", 1
    if available < 3:
        return "partial", 0
    length = buf[start + 2]
    if length < (_ACK_SIZE if buf[start + 1] == 0x46 else 4):
        return "invalid", 2
    if available < length:
        return "partial", 0
    if verify_frame(buf[start : start + length]):
        return "frame", length
    return "invalid", 2


class FrameExtractor:
    """
    Split data from a SEL port into ASCII data and binary SEL Fast frames.

    A frame is ``0xA5``, a message type (:data:`FAST_FRAME_CODES`), and the length
    of the frame, and its CRC or checksum must be correct. A frame that isn't
    complete is kept until more data arrives. Bytes that start like a frame but
    aren't one (e.g. a request that was echoed, which has no length) are returned
    as :data:`KIND_INVALID` (two bytes), and the search for frames continues after
    them. A ``0xA5`` followed by another byte is text.

    .. code-block:: python

       >>> extractor = FrameExtractor()
       >>> extractor.feed(b"=>" + build_meter_frame(0xA5C0, bytes([0, 0, 0, 0])))
       [('ascii', b'=>'), ('binary', b'\\xa5\\xc0\\x08\\x00\\x00\\x00\\x00m')]
    """

    def __init__(self) -> None:
        self._buffer = bytearray()
        #: Number of times bytes that started like a frame weren't a frame
        self.rejected: int = 0

    @property
    def pending(self) -> bytes:
        """Data kept until more arrives (the start of a frame that isn't complete)."""
        return bytes(self._buffer)

    def feed(self, data: bytes) -> list[tuple[str, bytes]]:
        """
        Add data, and return the chunks that are complete:
        ``(KIND_ASCII, data)``, ``(KIND_BINARY, frame)``, or ``(KIND_INVALID, data)``.
        """
        self._buffer += data
        return self._extract(final=False)

    def flush(self) -> list[tuple[str, bytes]]:
        """
        Return everything that's pending: a frame that isn't complete won't be
        (e.g. no more data arrived), so its first bytes are invalid.
        """
        return self._extract(final=True)

    def _extract(self, final: bool) -> list[tuple[str, bytes]]:
        buf = self._buffer
        out: list[tuple[str, bytes]] = []
        text_start = 0
        pos = 0
        keep_from = len(buf)

        while True:
            start = buf.find(FRAME_START, pos)
            if start < 0:
                break

            kind, length = _frame_at(buf, start)
            if kind == "partial":
                # A two-byte request that was echoed, followed by the response
                if _frame_at(buf, start + 2)[0] == "frame":
                    kind, length = "invalid", 2
                elif final:
                    kind, length = ("invalid", 2) if len(buf) - start >= 2 else ("text", 1)
                else:
                    keep_from = start
                    break

            if kind == "text":
                pos = start + 1
                continue

            if start > text_start:
                out.append((KIND_ASCII, bytes(buf[text_start:start])))
            if kind == "frame":
                out.append((KIND_BINARY, bytes(buf[start : start + length])))
            else:
                out.append((KIND_INVALID, bytes(buf[start : start + length])))
                self.rejected += 1
            pos = text_start = start + length

        if keep_from > text_start:
            out.append((KIND_ASCII, bytes(buf[text_start:keep_from])))
        del buf[:keep_from]
        return out


#: Characters removed from the ASCII data of a binary session: NUL, XON, and
#: XOFF (the flow control characters only apply to the ASCII data stream)
_ASCII_NOISE: Final = re.compile(rb"[\x00\x11\x13]")


class FastLink:
    """
    Split the data read from a transport into ASCII data, for the SEL ASCII
    session (its :class:`~peat.protocols.expect.Expecter`), and binary frames,
    for :class:`SELFast`. One :class:`FrameExtractor` is used for both, so
    frames are found wherever they are in the ASCII data.

    NUL, XON, and XOFF characters are removed from the ASCII data (the transport
    keeps them, since they can be in binary frames).
    """

    def __init__(self, read_chunk: ReadChunk, pending_timeout: float = 1.0) -> None:
        """
        Args:
            read_chunk: Function that reads from the transport (refer to
                :mod:`peat.protocols.expect`), which must keep every byte
            pending_timeout: Seconds without new data after which the start of
                a frame that isn't complete is given up on
        """
        self._read_chunk = read_chunk
        self.pending_timeout = pending_timeout
        self.extractor = FrameExtractor()
        #: Frames that were received, but not read yet
        self.frames: deque[bytes] = deque()
        #: Number of chunks that started like a frame, but weren't one
        self.invalid: int = 0
        #: The transport reported that the connection is closed
        self.eof: bool = False
        self._ascii = bytearray()
        self._last_data = monotonic()

    def _route(self, chunk: bytes, final: bool = False) -> bytes:
        now = monotonic()
        if chunk:
            self._last_data = now
            parts = self.extractor.feed(chunk)
        elif self.extractor.pending and (final or now - self._last_data >= self.pending_timeout):
            parts = self.extractor.flush()
        else:
            return b""

        ascii_data = bytearray()
        for kind, data in parts:
            if kind == KIND_BINARY:
                self.frames.append(data)
            elif kind == KIND_ASCII:
                ascii_data += _ASCII_NOISE.sub(b"", data)
            else:
                self.invalid += 1
                log.trace(f"Ignoring {len(data)} bytes that aren't a SEL Fast frame: {data.hex()}")
        return bytes(ascii_data)

    def read_ascii(self, wait: float) -> bytes:
        """
        :data:`~peat.protocols.expect.ReadChunk` for the ASCII data: ASCII that
        arrived while waiting for frames comes first.
        """
        if self._ascii:
            data = bytes(self._ascii)
            self._ascii.clear()
            return data
        if self.eof:
            raise EOFError("connection closed")
        try:
            chunk = self._read_chunk(wait)
        except EOFError:
            self.eof = True
            return self._route(b"", final=True)
        return self._route(chunk)

    def read_frame(self, timeout: float) -> bytes | None:
        """
        Return the next binary frame, waiting up to ``timeout`` seconds for one.
        ASCII data that arrives meanwhile is kept for :meth:`read_ascii`.
        """
        deadline = monotonic() + timeout
        while True:
            if self.frames:
                return self.frames.popleft()
            remaining = deadline - monotonic()
            if remaining <= 0 or self.eof:
                return None
            try:
                chunk = self._read_chunk(min(remaining, self.pending_timeout))
            except EOFError:
                self.eof = True
                self._ascii += self._route(b"", final=True)
                continue
            self._ascii += self._route(chunk)


# ---------------------------------------------------------------------------
# Collection (SELFast)
# ---------------------------------------------------------------------------


def _jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, float):
        return _clean_float(value)
    return value


def bit_names(names: list[str], data: bytes) -> dict[str, int]:
    """
    States of named bits: ``names`` has 8 names per byte of ``data``, most
    significant bit first (e.g. from ``BNA`` or ``DNA``). Unused bits (``*``)
    are left out.
    """
    states = {}
    for number, byte in enumerate(data):
        for bit, name in enumerate(names[number * 8 : number * 8 + 8]):
            if name and name != "*":
                states[name] = (byte >> (7 - bit)) & 1
    return states


#: Commands of the relay definition status flags that tell a master to read the
#: Fast Meter configuration again, which the relay asks for when its settings
#: changed (SEL-351A IM 20080213 Table D.3: the settings change bit, ``A5C1``)
RECONFIGURE_COMMANDS: Final = ("A5C1", "A5C2", "A5C3")


def settings_changed_bits(
    definition: RelayDefinition | None, status_names: list[str]
) -> set[tuple[int, int]]:
    """
    The bits of the Fast Meter status bytes that say that the relay's settings
    changed (``STSET``), as ``(byte, bit)``, with bit 0 the least significant bit:

    - The bit named ``STSET`` by ``BNA`` (the names are MSB first).
    - The bits of the relay definition status flags with a command in
      :data:`RECONFIGURE_COMMANDS`. The bit number of a flag counts from the least
      significant bit (inferred: on the SEL-351A, the flag is ``0004`` and
      ``STSET`` is bit 4; on the SEL-351S, ``0001`` and ``STSET`` is the
      seventh name of ``BNA``).

    Returns:
        The bits (empty if the relay doesn't say which bit it is)
    """
    bits = set()
    for index, name in enumerate(status_names):
        if name.strip().upper() == "STSET":
            bits.add((index // 8, 7 - index % 8))
    if definition is not None:
        for flag in definition.status_flags:
            if flag.text.upper() in RECONFIGURE_COMMANDS:
                bits.add((flag.bit // 8, flag.bit % 8))
    return bits


def settings_changed(status: bytes, bits: Iterable[tuple[int, int]]) -> bool | None:
    """
    If one of ``bits`` (from :func:`settings_changed_bits`) is set in the Fast
    Meter status bytes ``status``.

    Returns:
        :obj:`True` or :obj:`False`, or :obj:`None` if a bit isn't in ``status``
        (e.g. the status wasn't read) and none of the others is set
    """
    unknown = False
    for byte, bit in bits:
        if byte >= len(status):
            unknown = True
        elif (status[byte] >> bit) & 1:
            return True
    return None if unknown else False


@dataclass
class FastResults:
    """What :class:`SELFast` collected. Fields are empty if it wasn't available."""

    relay_definition: RelayDefinition | None = None
    #: Fast Meter messages: ``{"config": FastMeterConfig, "data": FastMeterData}``
    meter: list[dict] = field(default_factory=list)
    fast_operate: FastOperateConfig | None = None
    message_config: FastMessageConfig | None = None
    device_description: DeviceDescription | None = None
    #: Data formats of the regions, by region name
    data_formats: dict[str, DataFormat] = field(default_factory=dict)
    #: Decoded data of the regions that were read, by region name
    regions: dict[str, dict] = field(default_factory=dict)
    #: Data of the regions that were read, by region name
    region_data: dict[str, bytes] = field(default_factory=dict)
    #: Bit labels: ``{region: {"item[byte]": [8 labels, bit 0 first]}}``
    bit_labels: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    #: Names of the bits of the Fast Meter status byte (``BNA``), MSB first
    status_names: list[str] = field(default_factory=list)
    #: Names of the bits of the Fast Meter digital banks (``DNA``), MSB first
    digital_names: list[str] = field(default_factory=list)
    #: Names of the SER elements (``SNS``), in Fast SER index order
    ser_names: list[str] = field(default_factory=list)
    #: Fast SER messages (only if Fast SER was collected)
    fast_ser: list[FastSerMessage] = field(default_factory=list)
    #: If PEAT enabled unsolicited Fast SER (and disabled it again)
    fast_ser_enabled: bool = False
    #: Response code of the relay to the Fast SER enable request
    fast_ser_response: int | None = None
    #: Unsolicited Fast SER messages that arrived without PEAT enabling them (e.g.
    #: another master enabled Fast SER on the port). They aren't acknowledged.
    unsolicited_ignored: int = 0
    #: The relay's time from the Fast Meter data, and when it was read (monotonic)
    device_time: datetime | None = None
    device_time_read_at: float | None = None
    #: Problems, e.g. a request that wasn't answered
    errors: list[str] = field(default_factory=list)

    @property
    def supported(self) -> bool:
        """If the relay answered the relay definition block request."""
        return self.relay_definition is not None

    def device_now(self) -> datetime | None:
        """The relay's current time, from the Fast Meter timestamp."""
        if self.device_time is None or self.device_time_read_at is None:
            return None
        return self.device_time + timedelta(seconds=monotonic() - self.device_time_read_at)

    def to_dict(self) -> dict:
        """Everything that was collected, as JSON-compatible values."""
        return {
            "relay_definition": _jsonable(self.relay_definition),
            "fast_meter": [
                {"config": _jsonable(m.get("config")), "data": _jsonable(m.get("data"))}
                for m in self.meter
            ],
            "fast_operate": _jsonable(self.fast_operate),
            "fast_message_config": _jsonable(self.message_config),
            "device_description": _jsonable(self.device_description),
            "data_formats": _jsonable(self.data_formats),
            "regions": _jsonable(self.regions),
            "region_data": _jsonable(self.region_data),
            "bit_labels": self.bit_labels,
            "status_names": self.status_names,
            "digital_names": self.digital_names,
            "ser_names": self.ser_names,
            "fast_ser": _jsonable(self.fast_ser),
            "fast_ser_enabled": self.fast_ser_enabled,
            "fast_ser_response": self.fast_ser_response,
            "unsolicited_ignored": self.unsolicited_ignored,
            "device_time": _jsonable(self.device_time),
            "errors": self.errors,
        }


class SELFast:
    """
    Read-only collection with the SEL Fast protocols, on a SEL ASCII session
    (:class:`~peat.modules.sel.sel_telnet.SELTelnet` or
    :class:`~peat.modules.sel.sel_serial.SELSerial`) that was created with
    ``binary=True``.

    :meth:`collect` sends, in order (each request waits up to
    :attr:`request_timeout` seconds, and no answer means it isn't supported):

    #. ``A5C0`` (relay definition block). If there's no answer at access level 0,
       it calls ``elevate`` (if given) and tries once more.
    #. For each Fast Meter message in the relay definition (only ``A5C1``,
       ``A5C2``, and ``A5C3``): the configuration block, then one data message.
    #. ``BNA`` and ``DNA`` (ASCII), the names of the status and digital bits.
    #. ``A5CE`` (Fast Operate configuration, only read).
    #. If the relay supports Fast Message: function ``00`` (configuration
       block), and if it accepts function ``30``, the device description (all
       frames), the data format of each region (``31``), and reads (``10``) of
       the regions in :data:`INVENTORY_REGIONS`. Bit labels (``33``, one request
       per labelled byte) only if ``bit_labels`` is set.
    #. Fast SER, only if ``fast_ser`` is set (refer to :meth:`collect_fast_ser`).

    Unsolicited Fast SER messages that arrive otherwise aren't acknowledged.
    """

    #: Seconds to wait for the response to a request
    REQUEST_TIMEOUT: float = 2.0
    #: Maximum frames of a multi-frame response (the frame number is 6 bits)
    MAX_FRAMES: int = 64
    #: Maximum number of bit label requests
    MAX_BIT_LABEL_REQUESTS: int = 1024
    #: Maximum seconds to collect Fast SER messages
    FAST_SER_DURATION: float = 30.0
    #: Stop collecting Fast SER messages after this many seconds without one
    FAST_SER_IDLE: float = 2.0

    def __init__(
        self,
        comm: SELAscii,
        request_timeout: float | None = None,
        bit_labels: bool = False,
        ascii_names: bool = True,
    ) -> None:
        """
        Args:
            comm: SEL ASCII session created with ``binary=True``
            request_timeout: Seconds to wait for each response
                (default: :attr:`REQUEST_TIMEOUT`)
            bit_labels: Also read the bit labels of the regions that are read
                (one request per labelled byte, e.g. 384 for the SEL-421
                ``TARGET`` region)
            ascii_names: Read the names of the Fast Meter status and digital
                bits with the ``BNA`` and ``DNA`` ASCII commands
        """
        if not getattr(comm, "binary", False):
            raise ValueError(f"{comm!r} wasn't created with binary=True")
        self.comm = comm
        self.request_timeout = request_timeout or self.REQUEST_TIMEOUT
        self.bit_labels = bit_labels
        self.ascii_names = ascii_names
        self.log = log.bind(classname=self.__class__.__name__, target=comm.address)
        self.results = FastResults()
        #: Every frame sent and received: time (seconds since the start),
        #: direction (``tx`` or ``rx``), description, and the frame as hex
        self.transcript: list[dict] = []
        self._started = monotonic()
        self._resp_num = 3
        # Fast SER collection must stop (a "settings changed" message arrived)
        self._fast_ser_stopped = False

    # -- sending and receiving ----------------------------------------------

    def _next_resp_num(self) -> int:
        self._resp_num = (self._resp_num + 1) % 4
        return self._resp_num

    def _record(self, direction: str, frame: bytes) -> None:
        self.transcript.append(
            {
                "time": round(monotonic() - self._started, 3),
                "direction": direction,
                "type": describe_frame(frame),
                "frame": frame.hex(),
            }
        )

    def _send(self, frame: bytes) -> None:
        self.comm.write_fast(frame)
        self._record("tx", frame)

    def _receive(self, timeout: float) -> bytes | None:
        frame = self.comm.read_fast_frame(max(timeout, 0.0))
        if frame is not None:
            self._record("rx", frame)
        return frame

    def _stray(self, frame: bytes) -> None:
        """A frame that isn't the response that's waited for."""
        if frame[:2] == b"\xa5\x46" and len(frame) > 9 and frame[9] == FC_FAST_SER:
            if not self.results.unsolicited_ignored:
                self.log.warning(
                    f"{self.comm.address} sent an unsolicited Fast SER message that PEAT "
                    f"didn't enable (another master may have enabled Fast SER on this "
                    f"port). PEAT doesn't acknowledge it."
                )
            self.results.unsolicited_ignored += 1
        else:
            self.log.debug(f"Ignoring unexpected frame: {describe_frame(frame)}")

    def request_meter(self, command: int, timeout: float | None = None) -> bytes | None:
        """
        Send a two-byte request (e.g. ``A5C0``), and wait for the response (a
        frame that starts with the same two bytes).

        Returns:
            The response, or :obj:`None` if there wasn't one before the timeout
        """
        request = build_meter_request(command)
        self._send(request)
        deadline = monotonic() + (timeout or self.request_timeout)
        while (remaining := deadline - monotonic()) > 0:
            frame = self._receive(remaining)
            if frame is None:
                break
            if frame[:2] == request:
                return frame
            self._stray(frame)
        self.log.debug(f"No response to {describe_frame(request)}")
        return None

    def request_message(
        self,
        function_code: int,
        body: bytes = b"",
        frame: int = 0,
        timeout: float | None = None,
    ) -> FastMessage | None:
        """
        Send a Fast Message request (for frame ``frame``), and wait for the
        response: the function code with the high bit set, and the response number
        of the request (an acknowledge with an error code is a response too).

        Returns:
            The response, or :obj:`None` if there wasn't one before the timeout
        """
        resp_num = self._next_resp_num()
        request = build_fast_message(
            function_code, body, seq=SEQ_SINGLE | (frame & SEQ_COUNT), resp_num=resp_num
        )
        self._send(request)
        deadline = monotonic() + (timeout or self.request_timeout)
        while (remaining := deadline - monotonic()) > 0:
            raw = self._receive(remaining)
            if raw is None:
                break
            if raw[:2] != b"\xa5\x46":
                self._stray(raw)
                continue
            message = parse_fast_message(raw)
            if (
                message.function_code == function_code | RESPONSE
                and message.response_number == resp_num
            ):
                return message
            self._stray(raw)
        self.log.debug(f"No response to {describe_frame(request)} (frame {frame})")
        return None

    def request_frames(
        self, function_code: int, body: bytes = b""
    ) -> tuple[list[FastMessage], bool]:
        """
        Get all of the frames of a multi-frame response: frame ``n`` is requested by
        sending the request again with the frame number in the sequence byte,
        until the relay sends the last frame (FIN).

        Returns:
            The frames, and if the response is complete
        """
        frames: list[FastMessage] = []
        name = FUNCTION_CODES.get(function_code, f"{function_code:02X}")
        for number in range(self.MAX_FRAMES):
            message = self.request_message(function_code, body, frame=number)
            if message is None:
                if number:
                    self.results.errors.append(f"no response for frame {number} of {name}")
                return frames, False
            if message.is_ack:
                code = message.response_code
                self.results.errors.append(
                    f"{name}: response code {code} ({RESPONSE_CODES.get(code, 'unknown')})"
                )
                return frames, False
            if message.frame_number != number or (number == 0 and not message.fir):
                self.results.errors.append(
                    f"{name}: frame {message.frame_number} arrived instead of frame {number}"
                )
                return frames, False
            frames.append(message)
            if message.fin:
                return frames, True
        self.results.errors.append(f"{name}: more than {self.MAX_FRAMES} frames")
        return frames, False

    def _ascii_names(self, command: str) -> list[str]:
        """Run an ASCII command that answers with names (BNA, DNA, SNS)."""
        response = self.comm.run_command(command)
        if response.error or not response.complete:
            self.log.debug(f"No names from '{command}': {response.error or 'no prompt'}")
            return []
        names = []
        for record in parse_records(response.body):
            if record.fields and record.all_quoted:
                names.extend(record.labels)
        return names

    # -- collection ---------------------------------------------------------

    def collect(
        self,
        fast_ser: bool = False,
        elevate: Callable[[], bool] | None = None,
        fast_ser_duration: float | None = None,
    ) -> FastResults:
        """
        Collect everything that's available (refer to the class docstring).

        Args:
            fast_ser: Also collect Fast SER (refer to :meth:`collect_fast_ser`)
            elevate: Function that logs in to access level 1, called if the
                relay doesn't answer ``A5C0`` at level 0
            fast_ser_duration: Maximum seconds to collect Fast SER

        Returns:
            The results (also in :attr:`results`)
        """
        results = self.results

        # The relay must have shown a SEL prompt before anything binary is sent
        # (this also completes the Telnet option negotiation)
        if not self.comm.access_level:
            self.comm.sync_access_level()
        if not self.comm.access_level:
            results.errors.append("no SEL prompt, so no binary messages were sent")
            self.log.warning(f"Not sending SEL Fast messages to {self.comm.address}: no prompt")
            return results

        raw = self.request_meter(RELAY_DEFINITION)
        if raw is None and elevate is not None and self.comm.priv_level < 1:
            self.log.info("No relay definition block at access level 0, logging in to level 1")
            if elevate():
                raw = self.request_meter(RELAY_DEFINITION)
        if raw is None:
            results.errors.append("no response to A5C0 (relay definition block)")
            self.log.warning(f"{self.comm.address} didn't answer the A5C0 request")
            return results

        try:
            results.relay_definition = parse_relay_definition(raw)
        except FastFrameError as ex:
            results.errors.append(f"invalid relay definition block: {ex}")
            return results

        self._collect_meter()
        self._collect_fast_operate()
        if results.relay_definition.fast_message:
            self._collect_messages()
        if fast_ser:
            self.collect_fast_ser(duration=fast_ser_duration)

        return results

    def _collect_meter(self) -> None:
        results = self.results
        for config_cmd, data_cmd in results.relay_definition.meter_messages:
            if METER_DATA_COMMANDS.get(config_cmd) != data_cmd:
                # Only the documented pairs are requested, never what a relay lists
                results.errors.append(
                    f"skipped Fast Meter message {config_cmd:04X}/{data_cmd:04X}"
                )
                continue
            entry: dict[str, Any] = {"config": None, "data": None}
            raw = self.request_meter(config_cmd)
            if raw is None:
                results.errors.append(f"no response to {config_cmd:04X}")
                continue
            try:
                entry["config"] = parse_fm_config(raw)
                data_raw = self.request_meter(data_cmd)
                if data_raw is not None:
                    entry["data"] = parse_fm_data(data_raw, entry["config"])
            except FastFrameError as ex:
                results.errors.append(f"invalid Fast Meter message {config_cmd:04X}: {ex}")
            results.meter.append(entry)

            data = entry["data"]
            if data is not None and data.timestamp and results.device_time is None:
                results.device_time = data.timestamp
                results.device_time_read_at = monotonic()

        if self.ascii_names and results.meter:
            results.status_names = self._ascii_names("BNA")
            if any(m["config"] and m["config"].digital_banks for m in results.meter):
                results.digital_names = self._ascii_names("DNA")

    def _collect_fast_operate(self) -> None:
        raw = self.request_meter(FAST_OPERATE_CONFIG)
        if raw is None:
            return  # Fast Operate is disabled on the port, or isn't supported
        try:
            self.results.fast_operate = parse_fo_config(raw)
        except FastFrameError as ex:
            self.results.errors.append(f"invalid Fast Operate configuration: {ex}")
            return
        self.log.warning(
            f"Fast Operate is enabled on the port of {self.comm.address} that PEAT is "
            f"connected to (FASTOP=Y): {self.results.fast_operate.breakers} breakers and "
            f"{self.results.fast_operate.remote_bits} remote bits can be operated from it"
        )

    def _collect_messages(self) -> None:
        results = self.results
        message = self.request_message(FC_CONFIG)
        if message is None or message.is_ack:
            results.errors.append("no Fast Message configuration block")
            return
        try:
            results.message_config = config = parse_fm_cfg_block_resp(message)
        except FastFrameError as ex:
            results.errors.append(f"invalid Fast Message configuration block: {ex}")
            return

        if not config.accepts(FC_DEVICE_DESCRIPTION):
            return
        frames, complete = self.request_frames(FC_DEVICE_DESCRIPTION)
        if not frames:
            return
        try:
            description = merge_device_description(
                [parse_device_description(f) for f in frames], complete
            )
        except FastFrameError as ex:
            results.errors.append(f"invalid device description: {ex}")
            return
        results.device_description = description

        for region in description.regions:
            self._collect_region(region, config)

    def _collect_region(self, region: Region, config: FastMessageConfig) -> None:
        results = self.results
        if not config.accepts(FC_DATA_FORMAT):
            return
        frames, complete = self.request_frames(FC_DATA_FORMAT, struct.pack(">I", region.base))
        if not frames:
            return
        try:
            data_format = merge_data_format([parse_data_format(f) for f in frames], complete)
        except FastFrameError as ex:
            results.errors.append(f"invalid data format of {region.name}: {ex}")
            return
        results.data_formats[region.name] = data_format

        if not region.name.upper().startswith(INVENTORY_REGIONS) or not config.accepts(FC_READ):
            return
        if not region.words or not data_format.complete:
            return

        frames, complete = self.request_frames(
            FC_READ, struct.pack(">IH", region.base, region.words)
        )
        if not frames:
            return
        try:
            _, data = join_read_frames(frames)
        except FastFrameError as ex:
            results.errors.append(f"invalid read response for {region.name}: {ex}")
            return
        if not complete or len(data) < data_format.size:
            results.errors.append(
                f"{region.name}: {len(data)} of {data_format.size} bytes were read"
            )
        results.region_data[region.name] = data
        results.regions[region.name] = decode_region(data, data_format.items)

        if self.bit_labels and config.accepts(FC_BIT_LABEL):
            self._collect_bit_labels(region, data_format)

    def _collect_bit_labels(self, region: Region, data_format: DataFormat) -> None:
        labels: dict[str, list[str]] = {}
        sent = sum(len(v) for v in self.results.bit_labels.values())
        for item in data_format.items:
            if item.type not in LABELLED_ITEM_TYPES:
                continue
            for index in range(item.size):
                if sent >= self.MAX_BIT_LABEL_REQUESTS:
                    self.results.errors.append("stopped reading bit labels (too many)")
                    self.results.bit_labels[region.name] = labels
                    return
                address = region.base + item.offset // 2 + index
                message = self.request_message(FC_BIT_LABEL, struct.pack(">I", address))
                sent += 1
                if message is None or message.is_ack:
                    continue
                try:
                    labels[f"{item.name}[{index}]"] = parse_bit_labels(message)
                except FastFrameError:
                    continue
        self.results.bit_labels[region.name] = labels

    def collect_fast_ser(
        self,
        duration: float | None = None,
        idle: float | None = None,
        max_records: int = MAX_FAST_SER_RECORDS,
    ) -> list[FastSerMessage]:
        """
        Collect unsolicited Fast SER messages, which the relay sends after they're
        enabled: first the records it has stored for the port, then new ones.

        This changes the state of the port: enabling them sets the ``FSERx`` Relay
        Word bit, and each acknowledge marks the records as delivered on the port.
        PEAT disables them again when it's done (even after an error). Any
        acknowledge (response code 0) clears the relay's settings changed bits,
        including the Fast Meter ``STSET`` bit that SCADA masters use to notice
        settings changes (SEL-351A IM 20080213, the notes after Table J.5). So
        Fast SER isn't enabled if ``STSET`` is set (or its state isn't known), and
        a message that says that the settings changed (status ``03``) isn't
        acknowledged, and collection stops. The ping (function ``05``) is never
        sent.

        #. ``SNS`` (ASCII), the names of the SER elements, in index order.
        #. The Fast Meter data message (``A5D1``) is read again, and if the
           ``STSET`` bit is set (refer to :func:`settings_changed_bits`), or it
           can't be read, Fast SER isn't enabled.
        #. Function ``01`` for ``18`` (enable, up to ``max_records`` per message).
        #. Each message (function ``18``) is acknowledged (``98``, response code
           0, the message's response number), until no message arrives for
           ``idle`` seconds, or for at most ``duration`` seconds.
        #. Function ``02`` for ``18`` (disable).

        Returns:
            The messages (also in :attr:`results`)
        """
        results = self.results
        duration = duration or self.FAST_SER_DURATION
        idle = idle or self.FAST_SER_IDLE

        config = results.message_config
        if config is not None and not config.accepts(FC_ENABLE_UNSOLICITED):
            results.errors.append("the relay doesn't accept unsolicited Fast SER requests")
            return results.fast_ser
        if config is None and not (
            results.relay_definition and results.relay_definition.fast_message
        ):
            results.errors.append("the relay doesn't support Fast SER")
            return results.fast_ser

        results.ser_names = self._ascii_names("SNS")

        # Just before enabling, since an acknowledge would clear STSET
        changed = self._fast_meter_settings_changed()
        if changed is not False:
            if changed:
                reason = "the Fast Meter settings changed bit (STSET) is set"
            else:
                reason = "the state of the Fast Meter settings changed bit (STSET) isn't known"
            results.errors.append(
                f"Fast SER wasn't enabled: {reason}, and acknowledging Fast SER "
                f"messages would clear it (SCADA masters use it to notice settings changes)"
            )
            self.log.warning(f"Not collecting Fast SER from {self.comm.address}: {reason}")
            return results.fast_ser

        self.comm.fast_ser_allowed = True
        enabled = False
        try:
            resp_num = self._next_resp_num()
            self._send(build_enable_fast_ser(max_records, resp_num))
            enabled = True
            results.fast_ser_enabled = True
            ack = self._wait_for_ack(FC_ENABLE_UNSOLICITED, resp_num)
            if ack is None:
                results.errors.append("no acknowledge of the Fast SER enable request")
            else:
                results.fast_ser_response = ack.response_code
                if ack.response_code:
                    code = ack.response_code
                    results.errors.append(
                        f"Fast SER enable: response code {code} "
                        f"({RESPONSE_CODES.get(code, 'unknown')})"
                    )
            self._receive_fast_ser(duration, idle)
        finally:
            if enabled:
                try:
                    resp_num = self._next_resp_num()
                    self._send(build_disable_fast_ser(resp_num))
                    if self._wait_for_ack(FC_DISABLE_UNSOLICITED, resp_num) is None:
                        results.errors.append("no acknowledge of the Fast SER disable request")
                except Exception as ex:
                    results.errors.append(f"failed to disable Fast SER: {ex}")
                    self.log.error(f"Failed to disable Fast SER on {self.comm.address}: {ex}")
            self.comm.fast_ser_allowed = False

        return results.fast_ser

    def _fast_meter_settings_changed(self) -> bool | None:
        """
        If the Fast Meter ``STSET`` bit is set now: the first documented Fast Meter
        data message the relay lists (e.g. ``A5D1``) is read again (if it doesn't
        answer, the status that was read before is used).

        Returns:
            :obj:`False` if the relay has no Fast Meter messages, or neither its
            status flags nor the ``BNA`` names have a ``STSET`` bit, and
            :obj:`None` if the status can't be read (or ``BNA`` wasn't read and
            there's no status flag for it)
        """
        results = self.results
        definition = results.relay_definition
        if definition is None or not definition.meter_messages:
            return False
        bits = settings_changed_bits(definition, results.status_names)
        if not bits:
            return False if results.status_names else None

        pair = next(
            ((c, d) for c, d in definition.meter_messages if METER_DATA_COMMANDS.get(c) == d),
            None,
        )
        if pair is None:
            return None  # PEAT doesn't send the requests the relay lists
        config_cmd, data_cmd = pair
        entry = next(
            (m for m in results.meter if m.get("config") and m["config"].command == config_cmd),
            {},
        )
        count = entry["config"].status_bytes if entry.get("config") else 1

        status = b""
        raw = self.request_meter(data_cmd)
        if raw is not None:
            try:
                frame = _check_meter_frame(raw, (data_cmd,))
                status = frame[3 : min(3 + count, len(frame) - 1)]
            except FastFrameError as ex:
                self.log.debug(f"Invalid {data_cmd:04X} response: {ex}")
        if not status and entry.get("data") is not None:
            status = entry["data"].status
        return settings_changed(status, bits)

    def _wait_for_ack(self, function_code: int, resp_num: int) -> FastMessage | None:
        deadline = monotonic() + self.request_timeout
        while (remaining := deadline - monotonic()) > 0:
            raw = self._receive(remaining)
            if raw is None:
                break
            if raw[:2] != b"\xa5\x46":
                continue
            message = parse_fast_message(raw)
            if (
                message.function_code == function_code | RESPONSE
                and message.response_number == resp_num
            ):
                return message
            if message.function_code == FC_FAST_SER and not self._fast_ser_stopped:
                # Records can arrive before the acknowledge
                self._handle_fast_ser(message)
        return None

    def _handle_fast_ser(self, message: FastMessage) -> bool:
        """
        Store and acknowledge a Fast SER message. Returns :obj:`False` if
        collection must stop (the settings changed).
        """
        results = self.results
        try:
            parsed = parse_fast_ser(message, results.ser_names)
        except FastFrameError as ex:
            results.errors.append(f"invalid Fast SER message: {ex}")
            return True

        # The relay sends a message again if the acknowledge was late
        if all(m.raw != parsed.raw for m in results.fast_ser):
            results.fast_ser.append(parsed)

        if parsed.settings_changed:
            if not self._fast_ser_stopped:
                results.errors.append(
                    "the relay's settings changed: stopped collecting Fast SER, without "
                    "acknowledging the message (that would clear the settings changed bits)"
                )
            self._fast_ser_stopped = True
            return False

        self._send(build_ack(FC_FAST_SER, 0, parsed.response_number))
        return True

    def _receive_fast_ser(self, duration: float, idle: float) -> None:
        if self._fast_ser_stopped:
            return
        stop_at = monotonic() + duration
        last = monotonic()
        while True:
            now = monotonic()
            remaining = min(stop_at - now, last + idle - now)
            if remaining <= 0:
                return
            raw = self._receive(remaining)
            if raw is None:
                continue
            if raw[:2] != b"\xa5\x46" or len(raw) < 10 or raw[9] != FC_FAST_SER:
                continue
            last = monotonic()
            if not self._handle_fast_ser(parse_fast_message(raw)):
                return


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


def _region(results: FastResults, prefix: str) -> tuple[str, dict] | tuple[None, None]:
    for name, values in results.regions.items():
        if name.upper().startswith(prefix):
            return name, values
    return None, None


def _without_key(value: Any, key: str) -> str:
    """``FID=SEL-421-...`` (as in the SEL-421 ``LOCAL2`` region) to ``SEL-421-...``."""
    text = str(value or "").strip()
    if text.upper().startswith(f"{key}="):
        text = text[len(key) + 1 :].strip()
    return text


def _small_values(values: dict) -> dict:
    """Values of a region that are short enough for ``extra`` (not large arrays or text)."""
    small = {}
    for key, value in values.items():
        if isinstance(value, str) and len(value) <= 160:
            small[key] = value
        elif isinstance(value, (int, float)) or value is None:
            small[key] = value
    return small


def process_fast_results(results: FastResults, dev: DeviceData, port: int | None = None) -> None:
    """
    Put what :class:`SELFast` collected into the device data model. Values that the
    device already has (e.g. from the ``ID`` command or the settings) aren't changed.

    - The ``LOCAL`` region (or the device description): FID (``firmware``, and the
      model), BFID (``boot_firmware``), ``serial_number``, ``part_number``, the relay
      ID (``extra.RID``, and ``name``), the station ID (``extra.TID``), and the
      active settings group (``extra.active_settings_group``).
    - Protocols: ``related.protocols`` gets ``sel_fast_meter``, ``sel_fast_message``
      and ``sel_fast_operate`` (if they answered), and the protocols the relay
      definition block lists (e.g. ``dnp3``). The Telnet service (if ``port`` is
      given) has the SEL Fast protocols in ``extra.sel_fast``.
    - Events: the ``HISTORY`` region (``history`` events) and Fast SER
      (``ser`` events), and the uptime from Fast SER power-up records.
    - A summary is saved in ``extra.sel_fast``.

    Args:
        results: The results
        dev: The device
        port: Telnet port the results were collected on (:obj:`None` for serial)
    """
    summary: dict[str, Any] = {"errors": list(results.errors)}
    protocols: list[str] = []

    definition = results.relay_definition
    if definition is not None:
        protocols.append("sel_fast_meter")
        summary["supported_protocols"] = [p.name for p in definition.protocols]
        summary["fast_meter_messages"] = [f"{c:04X}" for c, _ in definition.meter_messages]
        summary["status_flags"] = [f.text for f in definition.status_flags]
        for word in definition.protocols:
            slug = PROTOCOLS.get(word.protocol, ("", ""))[1]
            if slug:
                dev.related.protocols.add(slug)

    if results.meter:
        summary["fast_meter_channels"] = {
            f"{m['config'].command:04X}": [c.name for c in m["config"].channels]
            for m in results.meter
            if m.get("config")
        }
        if results.status_names:
            data = next((m["data"] for m in results.meter if m.get("data")), None)
            if data is not None:
                summary["fast_meter_status"] = bit_names(results.status_names, data.status)
    if results.device_time:
        summary["device_time"] = results.device_time

    if results.fast_operate is not None:
        protocols.append("sel_fast_operate")
        summary["fast_operate"] = {
            "enabled_on_port": True,
            "breakers": results.fast_operate.breakers,
            "remote_bits": results.fast_operate.remote_bits,
            "pulse_supported": results.fast_operate.pulse_supported,
        }

    if results.message_config is not None:
        protocols.append("sel_fast_message")
        summary["fast_message_functions"] = {
            "accepted": [f"{fc:02X}" for fc in results.message_config.rx_functions],
            "sent": [f"{fc:02X}" for fc in results.message_config.tx_functions],
        }

    description = results.device_description
    info: dict[str, Any] = {}
    if description is not None:
        summary["regions"] = [r.name for r in description.regions]
        if description.fid:
            info["FID"] = description.fid
        if description.rid:
            summary["device_description_rid"] = description.rid

    local_name, local = _region(results, "LOCAL")
    if local:
        # The values may have the key as a prefix ("FID=SEL-421-5-R310-...")
        for key in ("FID", "BFID"):
            if _without_key(local.get(key), key):
                info[key] = _without_key(local[key], key)
        for key, target in (
            ("DEVICE_ID", "RID"),
            ("NODE_ID", "TID"),
            ("CONFIG", "CONFIG"),
            ("SPECIAL", "SPECIAL"),
        ):
            if local.get(key) and not dev.extra.get(target):
                dev.extra[target] = local[key]
        if local.get("SER_NUM") and not dev.serial_number:
            dev.serial_number = local["SER_NUM"]
        if local.get("PART_NUM") and not dev.part_number:
            dev.part_number = local["PART_NUM"]
        if isinstance(local.get("GROUP"), int) and not dev.extra.get("active_settings_group"):
            dev.extra["active_settings_group"] = str(local["GROUP"])
        if isinstance(local.get("STATUS"), int):
            summary["local_status"] = local["STATUS"]
            if local["STATUS"]:
                log.warning(
                    f"{dev.get_id()} reports self-test failures in its {local_name} "
                    f"region (STATUS {local['STATUS']:#06x})"
                )
        if not dev.name and local.get("DEVICE_ID"):
            dev.name = local["DEVICE_ID"]

    if info.get("FID") and not dev.firmware.id:
        process_info_into_dev({"FID": info["FID"]}, dev)
    if info.get("BFID") and not dev.boot_firmware.id:
        process_info_into_dev({"BFID": info["BFID"]}, dev)

    status_name, status = _region(results, "STATUS")
    if status:
        summary["status_region"] = {status_name: _small_values(status)}

    history_name, _ = _region(results, "HISTORY")
    if history_name and history_name in results.data_formats:
        events = history_events(
            results.region_data.get(history_name, b""),
            results.data_formats[history_name].items,
        )
        if events:
            process_events(events, dev, dataset=f"Fast Message {history_name}")
            summary["history_events"] = len(events)

    if results.fast_ser:
        events = fast_ser_events(results.fast_ser)
        summary["fast_ser_records"] = len(events)
        if events:
            process_events(events, dev, dataset="Fast SER")
            try:
                apply_uptime(dev, device_now=results.device_now())
            except Exception as ex:
                log.warning(f"Failed to calculate the uptime of {dev.get_id()}: {ex}")
    if results.fast_ser_enabled:
        summary["fast_ser_enabled"] = True

    for protocol in protocols:
        dev.related.protocols.add(protocol)
    summary["protocols"] = protocols

    if port is not None and protocols:
        dev.store(
            "service",
            Service(
                protocol="telnet",
                port=port,
                transport="tcp",
                status="verified",
                extra={"sel_fast": protocols},
            ),
            lookup="protocol",
        )

    dev.extra["sel_fast"] = summary


__all__ = [
    "ALLOWED_REQUESTS",
    "FAST_SER_REQUESTS",
    "INVENTORY_REGIONS",
    "NEVER_SENT",
    "DataFormat",
    "DataItem",
    "DeviceDescription",
    "FastFrameError",
    "FastLink",
    "FastMessage",
    "FastMessageConfig",
    "FastMeterConfig",
    "FastMeterData",
    "FastOperateConfig",
    "FastRequestRefused",
    "FastResults",
    "FastSerMessage",
    "FrameExtractor",
    "RelayDefinition",
    "SELFast",
    "build_ack",
    "build_fast_message",
    "build_meter_frame",
    "build_meter_request",
    "check_outgoing",
    "check_request",
    "decode_region",
    "parse_bit_labels",
    "parse_data_format",
    "parse_device_description",
    "parse_fast_message",
    "parse_fast_ser",
    "parse_fm_cfg_block_resp",
    "parse_fm_config",
    "parse_fm_data",
    "parse_fo_config",
    "parse_relay_definition",
    "process_fast_results",
    "sel_checksum8",
    "sel_crc16",
]
