#!/usr/bin/env python3
"""
Convert a ``socat -x -v`` transcript of a serial session into a pcap file.

socat can sit between an application (PEAT, AcSELerator QuickSet, a terminal) and
an SEL device on a serial port, and log every byte in both directions:

.. code-block:: bash

   socat -x -v PTY,link=/tmp/ttySEL,rawer /dev/ttyUSB0,b9600,cs8,rawer 2> sel.log
   # point the application at /tmp/ttySEL, then stop socat with Ctrl+C
   python3 socat2pcap.py sel.log sel.pcap

Blocks marked ``>`` went from the first socat address to the second one, so with
the command above they are requests to the device and ``<`` blocks are responses.
Use ``--swap`` if the device is the first address.

The default output is LINKTYPE_WIRESHARK_UPPER_PDU (252): every block becomes one
record that names the ``selascii`` dissector and carries the direction, so
Wireshark decodes it as SEL ASCII without any configuration. ``--rtac`` writes
LINKTYPE_RTAC_SERIAL (250) instead, the format of SEL RTAC Communication Monitor
captures.

Only the Python standard library is used.
"""

import argparse
import re
import struct
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

LINKTYPE_RTAC_SERIAL = 250
LINKTYPE_WIRESHARK_UPPER_PDU = 252

# Exported PDU tags (wsutil/exported_pdu_tlvs.h)
EXP_PDU_TAG_END_OF_OPT = 0
EXP_PDU_TAG_DISSECTOR_NAME = 12
EXP_PDU_TAG_P2P_DIRECTION = 35
P2P_DIR_SENT = 0
P2P_DIR_RECV = 1

# LINKTYPE_RTAC_SERIAL event types
RTAC_DATA_TX_START = 0x01
RTAC_DATA_RX_START = 0x02

# "> 2026/10/31 16:25:21.000118675  length=4 from=0 to=3"
HEADER_RE = re.compile(r"^([<>]) (\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)\.(\d+)\s+length=(\d+)")
# Hex dump lines: a space, then up to 16 "hh " groups in columns 1-48
HEX_LINE_RE = re.compile(r"^ ((?:[0-9a-fA-F]{2} ){1,16})")


@dataclass
class Chunk:
    """One block of bytes that socat forwarded in one direction."""

    to_device: bool
    seconds: int
    microseconds: int
    data: bytes


def _microseconds(fraction: str) -> int:
    """
    Sub-second part of a socat timestamp, in microseconds.

    socat 1.7 prints six digits. socat 1.8.0 prints the microsecond count
    zero-padded to nine digits (".000118675" is 118675 microseconds).
    """
    if len(fraction) <= 6:
        return int(fraction.ljust(6, "0"))
    value = int(fraction)
    return value if value < 1_000_000 else value // 1000


def parse_transcript(lines: Iterable[str], swap: bool = False, utc: bool = False) -> list[Chunk]:
    """
    Parse the stderr output of ``socat -x -v``.

    Args:
        lines: Lines of the transcript
        swap: Treat ``<`` blocks as requests (the device is the first socat address)
        utc: The timestamps are UTC. By default they are read as local time, which
            is what socat writes.

    Returns:
        The blocks in the order socat logged them

    Raises:
        ValueError: If the transcript has no hex dump (``-x`` missing) or a block's
            byte count does not match its ``length=`` header
    """
    chunks: list[Chunk] = []
    expected: list[int] = []
    current: bytearray | None = None

    for line in lines:
        header = HEADER_RE.match(line)
        if header:
            arrow, year, month, day, hour, minute, second, fraction, length = header.groups()
            stamp = datetime(
                int(year),
                int(month),
                int(day),
                int(hour),
                int(minute),
                int(second),
                tzinfo=UTC if utc else None,
            )
            current = bytearray()
            chunks.append(
                Chunk(
                    to_device=(arrow == ">") != swap,
                    seconds=int(stamp.timestamp()),
                    microseconds=_microseconds(fraction),
                    data=b"",
                )
            )
            expected.append(int(length))
            continue
        if line.startswith("--"):
            if current is not None:
                chunks[-1].data = bytes(current)
            current = None
            continue
        if current is not None:
            hex_line = HEX_LINE_RE.match(line)
            if hex_line:
                current += bytes.fromhex(hex_line.group(1))

    if current is not None:  # transcript ended without the closing "--"
        chunks[-1].data = bytes(current)

    for index, (chunk, length) in enumerate(zip(chunks, expected, strict=True)):
        if len(chunk.data) != length:
            raise ValueError(
                f"block {index + 1}: header says {length} bytes but the hex dump has "
                f"{len(chunk.data)} (was socat run with -x?)"
            )
    return chunks


def pcap_header(linktype: int, snaplen: int = 262144) -> bytes:
    """Classic pcap global header (microsecond timestamps, little-endian)."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)


def pcap_record(seconds: int, microseconds: int, data: bytes) -> bytes:
    """One pcap record: header plus the captured bytes."""
    return struct.pack("<IIII", seconds, microseconds, len(data), len(data)) + data


def exported_pdu(data: bytes, to_device: bool, dissector: str = "selascii") -> bytes:
    """
    LINKTYPE_WIRESHARK_UPPER_PDU payload: the dissector name and the direction
    (P2P_DIR_SENT for requests to the device), then the data.
    """
    name = dissector.encode("ascii")
    direction = P2P_DIR_SENT if to_device else P2P_DIR_RECV
    tags = (
        struct.pack(">HH", EXP_PDU_TAG_DISSECTOR_NAME, len(name))
        + name
        + struct.pack(">HHi", EXP_PDU_TAG_P2P_DIRECTION, 4, direction)
        + struct.pack(">HH", EXP_PDU_TAG_END_OF_OPT, 0)
    )
    return tags + data


def rtac_serial(data: bytes, to_device: bool, seconds: int, microseconds: int) -> bytes:
    """
    LINKTYPE_RTAC_SERIAL payload: a 12-byte header (big-endian timestamp, event
    type, control lines, footer), then the data. Requests to the device are
    recorded as RTAC transmit events.
    """
    event = RTAC_DATA_TX_START if to_device else RTAC_DATA_RX_START
    return struct.pack(">IIBBH", seconds, microseconds, event, 0, 0) + data


def write_pcap(chunks: Iterable[Chunk], path: Path, rtac: bool = False) -> int:
    """
    Write the blocks to a pcap file.

    Returns:
        Number of records written
    """
    count = 0
    with path.open("wb") as out:
        out.write(pcap_header(LINKTYPE_RTAC_SERIAL if rtac else LINKTYPE_WIRESHARK_UPPER_PDU))
        for chunk in chunks:
            if rtac:
                payload = rtac_serial(
                    chunk.data, chunk.to_device, chunk.seconds, chunk.microseconds
                )
            else:
                payload = exported_pdu(chunk.data, chunk.to_device)
            out.write(pcap_record(chunk.seconds, chunk.microseconds, payload))
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a 'socat -x -v' transcript into a pcap for the SEL ASCII dissector"
    )
    parser.add_argument("transcript", type=Path, help="socat stderr output (socat -x -v ...)")
    parser.add_argument("pcap", type=Path, help="pcap file to write")
    parser.add_argument(
        "--rtac",
        action="store_true",
        help="write LINKTYPE_RTAC_SERIAL (250) instead of exported PDUs (252)",
    )
    parser.add_argument(
        "--swap",
        action="store_true",
        help="the device is the first socat address ('<' blocks are requests)",
    )
    parser.add_argument(
        "--utc",
        action="store_true",
        help="the transcript timestamps are UTC (default: local time, as socat writes them)",
    )
    args = parser.parse_args(argv)

    with args.transcript.open(encoding="latin-1") as transcript:
        try:
            chunks = parse_transcript(transcript, swap=args.swap, utc=args.utc)
        except ValueError as err:
            parser.error(str(err))
    if not chunks:
        parser.error(f"no socat -x -v blocks found in {args.transcript}")
    count = write_pcap(chunks, args.pcap, rtac=args.rtac)
    sys.stderr.write(f"Wrote {count} records to {args.pcap}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
