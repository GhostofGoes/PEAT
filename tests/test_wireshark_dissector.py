"""
Tests for the SEL ASCII Wireshark dissector (``distribution/wireshark/selascii.lua``).

Synthetic captures are built at test time with the standard library, so no capture
files are committed. tshark dissects them with ``-X lua_script:`` and the
``-T fields`` output is compared with the golden files in ``tests/wireshark/golden``,
for one pass and for two passes (``-2``). After an intended change, rewrite the
golden files with ``SELASCII_UPDATE_GOLDEN=1`` and review the diff.

The tshark tests are skipped when tshark is missing, and when running as root,
because Wireshark silently ignores Lua scripts for the superuser. CI sets
``SELASCII_REQUIRE_TOOLS=1`` to turn those skips into failures. The plain Lua unit
tests (``tests/wireshark/selascii_unit.lua``) run with every Lua interpreter found.

All message content is synthetic, except the SEL-700G ID output, which is the
sample already shown in ``docs/sel.rst``.
"""

import binascii
import importlib.util
import os
import random
import re
import shutil
import struct
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
WIRESHARK_DIR = TESTS_DIR.parent / "distribution" / "wireshark"
PLUGIN = WIRESHARK_DIR / "selascii.lua"
GOLDEN_DIR = TESTS_DIR / "wireshark" / "golden"
LUA_UNIT_TESTS = TESTS_DIR / "wireshark" / "selascii_unit.lua"

TSHARK = shutil.which("tshark")
_geteuid = getattr(os, "geteuid", None)  # not available on Windows
RUNNING_AS_ROOT = _geteuid is not None and _geteuid() == 0
REQUIRE_TOOLS = os.environ.get("SELASCII_REQUIRE_TOOLS", "") not in ("", "0")
UPDATE_GOLDEN = os.environ.get("SELASCII_UPDATE_GOLDEN", "") not in ("", "0")

LINKTYPE_ETHERNET = 1
LINKTYPE_USER0 = 147
LINKTYPE_USB_LINUX_MMAPPED = 220
LINKTYPE_USBPCAP = 249


def _load_socat2pcap():
    spec = importlib.util.spec_from_file_location(
        "selascii_socat2pcap", WIRESHARK_DIR / "socat2pcap.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up
    spec.loader.exec_module(module)
    return module


socat2pcap = _load_socat2pcap()


def _skip_or_fail(reason: str) -> None:
    if REQUIRE_TOOLS:
        pytest.fail(f"{reason} (SELASCII_REQUIRE_TOOLS is set)")
    pytest.skip(reason)


# ---------------------------------------------------------------------------
# SEL ASCII content
# ---------------------------------------------------------------------------
def cascii(body: str) -> bytes:
    """A Compressed ASCII record: the body (ending in a comma) and its checksum."""
    return f'{body}"{sum(body.encode()) & 0xFFFF:04X}"'.encode()


def message(lines: list[bytes]) -> bytes:
    """A framed device message: STX, CRLF-terminated lines, ETX."""
    return b"\x02\r\n" + b"".join(line + b"\r\n" for line in lines) + b"\x03"


def prompt(level_prompt: bytes) -> bytes:
    return b"\x02\r\n" + level_prompt + b"\x03"


# SEL-700G ID output from docs/sel.rst, with a synthetic iedName
ID_LINES = [
    b'"FID=SEL-700G-R200-V0-Z006003-D20180629","08F0"',
    b'"BFID=BOOTLDR-R501-V0-Z000000-D20140224","0947"',
    b'"CID=59A0","025C"',
    b'"DEVID=SEL-700G","0408"',
    b'"DEVCODE=74","0312"',
    b'"PARTNO=0700G12B1B1B7281A230","06C2"',
    b'"CONFIG=112222010","041E"',
    b'"SEL DISPLAY PACKAGE=1.0.50700.2000","087C"',
    cascii('"iedName=SEL_700G_1",'),
    b'"LIB61850ID=5C9A14CB","04F1"',
]
ID_RESPONSE = b"ID\r\n" + message(ID_LINES)

CAS_LINES = [
    cascii('"CAS",3,'),
    cascii('"CST",1,'),
    cascii('"1H","FID",'),
    cascii('"1D","45S",'),
    cascii('"CHI",1,'),
    b'"1H","REC_NUM","DATE","TIME","EVENT","0000"',  # wrong checksum on purpose
]

SER_LINES = [
    b"SEL-700G                 Date: 01/02/2026    Time: 10:00:00.000",
    b"FEEDER 1",
    b"",
    b"#      DATE       TIME          ELEMENT          STATE",
    b"3   01/02/2026  09:58:01.004  Relay Powered Up",
    b"2   01/02/2026  09:58:03.512  IN101            Asserted",
    b"1   01/02/2026  09:59:12.250  IN101            Deasserted",
]

STA_LINES = [
    b"SEL-700G                 Date: 01/02/2026    Time: 10:00:01.000",
    b"FEEDER 1",
    b"",
    b"SELF TESTS",
    b"Relay Enabled",
]


def fast_frame(message_type: int, body: bytes) -> bytes:
    """SEL Fast binary frame: type, total length, body, 8-bit checksum."""
    frame = struct.pack(">HB", message_type, 2 + 1 + len(body) + 1) + body
    return frame + bytes([sum(frame) & 0xFF])


# Relay definition block (A5C0): 4 protocols, 3 Fast Meter message pairs, one
# status flag, pad byte 0xFF (escaped as FF FF on Telnet).
RELAY_DEFINITION = fast_frame(
    0xA5C0,
    bytes.fromhex("040301A5C1A5D1A5C2A5D2A5C3A5D30004A5C100000000")
    + bytes.fromhex("0300030100050006")
    + b"\xff",
)


def ymodem_block(number: int, data: bytes) -> bytes:
    """YMODEM block (SOH for 128 bytes, STX for 1024) with its CRC-16."""
    size = 128 if len(data) <= 128 else 1024
    data = data.ljust(size, b"\x00" if number == 0 else b"\x1a")
    header = bytes([0x01 if size == 128 else 0x02, number, 255 - number])
    return header + data + struct.pack(">H", binascii.crc_hqx(data, 0))


# ---------------------------------------------------------------------------
# Capture writers (classic pcap, standard library only)
# ---------------------------------------------------------------------------
class PcapWriter:
    """A classic pcap file with one record per call to ``add``."""

    def __init__(self, linktype: int) -> None:
        self.parts = [socat2pcap.pcap_header(linktype)]
        self.usec = 1_767_348_000 * 1_000_000  # 2026-01-02 10:00:00 UTC

    def add(self, data: bytes) -> None:
        self.usec += 10_000
        self.parts.append(socat2pcap.pcap_record(*divmod(self.usec, 1_000_000), data))

    @property
    def now(self) -> tuple[int, int]:
        sec, usec = divmod(self.usec + 10_000, 1_000_000)
        return sec, usec

    def write(self, path: Path) -> Path:
        path.write_bytes(b"".join(self.parts))
        return path


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class TcpSession:
    """Ethernet, IPv4 and TCP frames of one connection, with valid checksums."""

    CLIENT = (bytes.fromhex("020000000001"), bytes([10, 0, 0, 1]))
    SERVER = (bytes.fromhex("0030a7000002"), bytes([10, 0, 0, 2]))  # SEL's OUI

    def __init__(
        self, pcap: PcapWriter, server_port: int, telnet: bool = False, client_port: int = 50000
    ) -> None:
        self.pcap = pcap
        self.ports = {True: (client_port, server_port), False: (server_port, client_port)}
        self.seq = {True: 1000, False: 5000}
        self.telnet = telnet
        self.ip_id = 1

    def _frame(self, to_server: bool, flags: int, payload: bytes = b"") -> None:
        (src_mac, src_ip), (dst_mac, dst_ip) = (
            (self.CLIENT, self.SERVER) if to_server else (self.SERVER, self.CLIENT)
        )
        sport, dport = self.ports[to_server]
        seq, ack = self.seq[to_server], self.seq[not to_server]
        tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack("!H", _ip_checksum(pseudo + tcp + payload)) + tcp[18:]
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + len(tcp) + len(payload), self.ip_id, 0x4000, 64, 6, 0, src_ip, dst_ip,
        )  # fmt: skip
        ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
        self.ip_id += 1
        self.pcap.add(dst_mac + src_mac + b"\x08\x00" + ip + tcp + payload)
        self.seq[to_server] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xFFFFFFFF

    def handshake(self) -> None:
        self._frame(True, 0x02)  # SYN
        self._frame(False, 0x12)  # SYN, ACK
        self._frame(True, 0x10)  # ACK

    def _escape(self, data: bytes) -> bytes:
        return data.replace(b"\xff", b"\xff\xff") if self.telnet else data

    def client(self, data: bytes) -> None:
        self._frame(True, 0x18, self._escape(data))

    def server(self, data: bytes) -> None:
        self._frame(False, 0x18, self._escape(data))

    def client_raw(self, data: bytes) -> None:
        self._frame(True, 0x18, data)

    def server_raw(self, data: bytes) -> None:
        self._frame(False, 0x18, data)


def usbmon_record(pcap: PcapWriter, urb_id: int, kind: str, endpoint: int, data: bytes) -> None:
    """LINKTYPE_USB_LINUX_MMAPPED (usbmon) bulk record on bus 1, device 5."""
    sec, usec = pcap.now
    no_data = ord("<" if endpoint & 0x80 else ">")
    header = struct.pack(
        "<QBBBBHbbqiiII8siiII",
        urb_id, ord(kind), 3, endpoint, 5, 1, ord("-"), 0 if data else no_data,
        sec, usec, 0, len(data) if data else 64, len(data), b"\0" * 8, 0, 0, 0, 0,
    )  # fmt: skip
    pcap.add(header + data)


def usbpcap_record(
    pcap: PcapWriter, irp: int, completion: bool, endpoint: int, data: bytes
) -> None:
    """LINKTYPE_USBPCAP bulk record on bus 1, device 5 (bit 0 of info: completion)."""
    header = struct.pack(
        "<HQIHBHHBBI", 27, irp, 0, 0x0009, 1 if completion else 0, 1, 5, endpoint, 3, len(data)
    )
    pcap.add(header + data)


def chunks(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
def build_telnet(path: Path) -> Path:
    """Telnet session on port 23: access levels, typing, pipelining, questions."""
    pcap = PcapWriter(LINKTYPE_ETHERNET)
    tcp = TcpSession(pcap, 23, telnet=True)
    tcp.handshake()  # 1-3
    tcp.server_raw(b"\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00")  # 4 negotiation
    tcp.client_raw(b"\xff\xfd\x01\xff\xfd\x03\xff\xfd\x00\xff\xfb\x00")  # 5
    tcp.server(prompt(b"="))  # 6 level 0
    tcp.client(b"ID\r\n")  # 7
    response = ID_RESPONSE + prompt(b"=")
    tcp.server(response[:150])  # 8 response split over two segments
    tcp.server(response[150:])  # 9
    tcp.client(b"ACC\r\n")  # 10
    tcp.server(b"ACC\r\n\x02\r\nPassword: ?\x03")  # 11
    tcp.client(b"otter\r\n")  # 12 wrong (passwords are case-sensitive)
    tcp.server(b"\r\n\x02\r\nPassword: ?\x03")  # 13 asked again
    tcp.client(b"OTTER\r\n")  # 14 factory default
    tcp.server(  # 15 banner and prompt in one message
        b"\r\n\x02\r\nSEL-700G                 Date: 01/02/2026    Time: 10:00:00.000\r\n"
        b"FEEDER 1\r\n\r\nLevel 1\r\n=>\x03"
    )
    for char in b"CAS":  # 16-21 typed one character at a time, echoed
        tcp.client(bytes([char]))
        tcp.server(bytes([char]))
    tcp.client(b"\r\n")  # 22
    tcp.server(b"\r\n" + message(CAS_LINES) + prompt(b"=>"))  # 23
    tcp.client(b"SER 3\r\nXYZ\r\n")  # 24 two commands in one segment
    tcp.server(b"SER 3\r\n" + message(SER_LINES) + prompt(b"=>"))  # 25
    tcp.server(b"XYZ\r\n" + message([b"Invalid Command"]) + prompt(b"=>"))  # 26
    tcp.client(b"2AC\r\n")  # 27
    tcp.server(b"2AC\r\n\x02\r\nPassword: ?\x03")  # 28
    tcp.client(b"TAIL\r\n")  # 29 factory default
    tcp.server(b"\r\n\x02\r\nLevel 2\r\n=>>\x03")  # 30
    tcp.client(b"STA C\r\n")  # 31 restart: asks for confirmation
    tcp.server(b"STA C\r\n\x02\r\nRestart the relay (Y,N)?\x03")  # 32
    tcp.client(b"N\r\n")  # 33
    tcp.server(b"\r\n\x02\r\nCanceled\r\n=>>\x03")  # 34
    tcp.client(b"PUL OUT101\r\n")  # 35 operates an output
    tcp.server(b"PUL OUT101\r\n\x02\r\nPulse OUT101 (Y,N)?\x03")  # 36
    tcp.client(b"N\r\n")  # 37
    tcp.server(b"\r\n" + prompt(b"=>>"))  # 38
    tcp.client(b"\xa5\xc0")  # 39 SEL Fast relay definition request
    tcp.server(RELAY_DEFINITION)  # 40 contains an escaped 0xFF
    tcp.client(b"QUI\r\n")  # 41
    tcp.server(b"QUI\r\n" + prompt(b"="))  # 42
    return pcap.write(path)


def build_telnet_split(path: Path) -> Path:
    """Segments that end one message and start the next.

    TCP hands the second pass only the bytes that the first pass consumed, so
    pass 2 sees shorter reassembled data and must still find the same results.
    """
    pcap = PcapWriter(LINKTYPE_ETHERNET)
    tcp = TcpSession(pcap, 23, telnet=True)
    tcp.handshake()  # 1-3
    tcp.server(prompt(b"="))  # 4
    tcp.client(b"ID\r\n")  # 5
    response = ID_RESPONSE + prompt(b"=")
    cut = len(ID_RESPONSE) + 3
    tcp.server(response[:100])  # 6
    tcp.server(response[100:cut])  # 7 end of the ID message and start of the prompt
    tcp.server(response[cut:])  # 8
    tcp.client(b"ACC\r\n")  # 9
    tcp.server(b"ACC\r\n\x02\r\nPassword: ?\x03")  # 10
    tcp.client(b"OT")  # 11
    tcp.client(b"TER\r\nI")  # 12 end of the password and start of the next command
    tcp.client(b"D\r\n")  # 13 typed before the level prompt: a command, not a password
    tcp.server(b"\r\n\x02\r\nLevel 1\r\n=>\x03")  # 14
    tcp.server(ID_RESPONSE + prompt(b"=>"))  # 15
    tcp.client(b"QUI\r\n")  # 16
    tcp.server(b"QUI\r\n" + prompt(b"="))  # 17
    return pcap.write(path)


def build_telnet_bad_sb(path: Path) -> Path:
    """A stray Telnet IAC SB without IAC SE must not hide the rest of the session."""
    pcap = PcapWriter(LINKTYPE_ETHERNET)
    tcp = TcpSession(pcap, 23, telnet=True)
    tcp.handshake()  # 1-3
    tcp.server_raw(prompt(b"=>") + b"\xff\xfa\x18")  # 4 IAC SB TERMINAL-TYPE, never ended
    tcp.client(b"ID\r\n")  # 5
    tcp.server(ID_RESPONSE + prompt(b"=>"))  # 6 waited for one segment, then unterminated
    tcp.client(b"STA\r\n")  # 7
    tcp.server(b"STA\r\n" + message(STA_LINES) + prompt(b"=>"))  # 8
    tcp.client_raw(b"\xff\xfa\x1f\x00\x50")  # 9 window size, split over two segments
    tcp.client_raw(b"\x00\x18\xff\xf0QUI\r\n")  # 10
    tcp.server(b"QUI\r\n" + prompt(b"="))  # 11
    return pcap.write(path)


CEV_SETTINGS = '"Group 1\r\nRID      := FEEDER 1\r\nTID      := STATION A\r\n",'
CEV_LINES = [
    cascii('"FID","SER NUM","DATE","TIME",'),
    cascii('"SEL-421-5-R100-V0-Z000000-D20260101","1234567890","01/02/2026","09:59:12.250",'),
    cascii('"IA","IB","IC","TRIGGER",'),
    cascii('-8,-106,1,">",'),
    cascii('"SETTINGS",'),
    cascii(CEV_SETTINGS),  # one record over several lines
    b'"Logic 1\r\nTR := 50P1T\r\n","0000"',  # several lines, checksum not matching
]


def build_tunnel(path: Path) -> Path:
    """Raw TCP (no Telnet) to an SEL-400 series relay, found by the heuristic."""
    pcap = PcapWriter(LINKTYPE_ETHERNET)
    tcp = TcpSession(pcap, 2300)
    tcp.handshake()  # 1-3
    tcp.client(b"\r\n")  # 4 not recognizable yet
    tcp.server(prompt(b"="))  # 5 claimed by the heuristic
    tcp.client(b"ACC\r\n")  # 6
    tcp.server(b"ACC\r\n\x02\r\nPassword: ?\x03")  # 7
    tcp.client(b"Secret-1\r\n")  # 8
    tcp.server(b"\r\n\x02\r\nLevel 1\r\n=>\x03")  # 9
    tcp.client(b"PAC\r\n")  # 10
    tcp.server(b"PAC\r\n\x02\r\nPassword: ?\x03")  # 11
    tcp.client(b"AMPERE\r\n")  # 12 factory default for level P
    tcp.server(b"\r\n\x02\r\nLevel P\r\nP=>\x03")  # 13
    tcp.client(b"CEV 1\r\n")  # 14
    response = b"CEV 1\r\n" + message(CEV_LINES)
    tcp.server(response[:200])  # 15
    tcp.server(response[200:] + prompt(b"P=>"))  # 16
    tcp.client(b"\xa5\xc0")  # 17
    tcp.server(RELAY_DEFINITION)  # 18 the 0xFF pad byte is not escaped here
    tcp.client(b"QUI\r\n")  # 19
    tcp.server(b"QUI\r\n" + prompt(b"="))  # 20
    return pcap.write(path)


def build_ymodem(path: Path) -> Path:
    """FILE READ over Telnet: YMODEM blocks with ETX and 0xFF bytes in the data."""
    pcap = PcapWriter(LINKTYPE_ETHERNET)
    tcp = TcpSession(pcap, 23, telnet=True)
    tcp.handshake()  # 1-3
    tcp.server(prompt(b"=>"))  # 4
    tcp.client(b"FIL READ SET_1.TXT\r\n")  # 5
    tcp.server(b"FIL READ SET_1.TXT\r\n")  # 6 echo
    tcp.client(b"C")  # 7 receiver starts the transfer
    tcp.server(ymodem_block(0, b"SET_1.TXT\x001100\x00"))  # 8 0xFF in the header
    tcp.client(b"\x06")  # 9 ACK
    tcp.client(b"C")  # 10
    content = b'[1]\r\nRID,"FEEDER 1"\r\n' + bytes(range(256)) + b"\x02\r\n=>\x03" * 20
    block = ymodem_block(1, content)
    tcp.server(block[:700])  # 11
    tcp.server(block[700:])  # 12
    tcp.client(b"\x06")  # 13
    tcp.server(b"\x04")  # 14 EOT
    tcp.client(b"\x15")  # 15 NAK
    tcp.server(b"\x04")  # 16 EOT
    tcp.client(b"\x06")  # 17
    tcp.client(b"C")  # 18
    tcp.server(ymodem_block(0, b""))  # 19 end of batch
    tcp.client(b"\x06")  # 20
    tcp.server(b"\r\n" + prompt(b"=>"))  # 21
    return pcap.write(path)


def build_rtac(path: Path) -> Path:
    """RTAC Communication Monitor capture (LINKTYPE_RTAC_SERIAL)."""
    pcap = PcapWriter(socat2pcap.LINKTYPE_RTAC_SERIAL)

    def record(to_device: bool, data: bytes, event: int | None = None) -> None:
        sec, usec = pcap.now
        if event is None:
            pcap.add(socat2pcap.rtac_serial(data, to_device, sec, usec))
        else:
            pcap.add(struct.pack(">IIBBH", sec, usec, event, 0x1F, 0) + data)

    record(False, b"", event=0x00)  # 1 STATUS_CHANGE, no payload
    record(True, b"ID\r\n")  # 2 RTAC transmits
    response = ID_RESPONSE + prompt(b"=>")
    for part in chunks(response, 120):  # 3-6, the middle parts have no STX/ETX
        record(False, part)
    record(True, b"\xa5\xc0")  # 7
    record(False, RELAY_DEFINITION[:10])  # 8
    record(False, RELAY_DEFINITION[10:])  # 9
    record(True, b"\xa5\xd1")  # 10 Fast Meter data request
    return pcap.write(path)


def build_exported(path: Path) -> Path:
    """Exported PDUs (LINKTYPE_WIRESHARK_UPPER_PDU), as socat2pcap.py writes them."""
    pcap = PcapWriter(socat2pcap.LINKTYPE_WIRESHARK_UPPER_PDU)

    def record(to_device: bool, data: bytes) -> None:
        pcap.add(socat2pcap.exported_pdu(data, to_device))

    record(True, b"ACC\r\n")  # 1
    record(False, b"ACC\r\n\x02\r\nPassword: ?\x03")  # 2
    record(True, b"OTTER\r\n")  # 3
    record(False, b"\r\n\x02\r\nLevel 1\r\n=>\x03")  # 4
    record(True, b"STA\r\n")  # 5
    for part in chunks(b"STA\r\n" + message(STA_LINES) + prompt(b"=>"), 25):  # 6-10
        record(False, part)
    record(True, b"\x13")  # 11 XOFF
    record(True, b"\x11")  # 12 XON
    record(True, b"QUI\r\n")  # 13
    record(False, b"QUI\r\n" + prompt(b"="))  # 14
    return pcap.write(path)


def _usb_session() -> list[tuple[bool, bytes]]:
    response = ID_RESPONSE + prompt(b"=>")
    return [(True, b"ID\r\n"), *[(False, part) for part in chunks(response, 64)]]


def build_usbmon(path: Path) -> Path:
    """SEL USB port (CDC class) captured with Linux usbmon."""
    pcap = PcapWriter(LINKTYPE_USB_LINUX_MMAPPED)
    urb = 1
    for to_device, data in _usb_session():
        if to_device:  # bulk OUT: data in the submission
            usbmon_record(pcap, urb, "S", 0x02, data)
            usbmon_record(pcap, urb, "C", 0x02, b"")
        else:  # bulk IN: data in the completion
            usbmon_record(pcap, urb, "S", 0x81, b"")
            usbmon_record(pcap, urb, "C", 0x81, data)
        urb += 1
    return pcap.write(path)


def build_usbpcap(path: Path) -> Path:
    """SEL USB port (CDC class) captured with USBPcap on Windows."""
    pcap = PcapWriter(LINKTYPE_USBPCAP)
    irp = 0x1000
    for to_device, data in _usb_session():
        if to_device:
            usbpcap_record(pcap, irp, False, 0x02, data)
            usbpcap_record(pcap, irp, True, 0x02, b"")
        else:
            usbpcap_record(pcap, irp, False, 0x81, b"")
            usbpcap_record(pcap, irp, True, 0x81, data)
        irp += 1
    return pcap.write(path)


def build_dlt_user(path: Path) -> Path:
    """Serial capture without direction (for example SerialPCAP, DLT_USER0)."""
    pcap = PcapWriter(LINKTYPE_USER0)
    pcap.add(b"ID\r\n")
    pcap.add(ID_RESPONSE + prompt(b"=>"))
    pcap.add(b"STA\r\n")
    pcap.add(b"STA\r\n" + message(STA_LINES) + prompt(b"=>"))
    return pcap.write(path)


def socat_transcript(blocks: list[tuple[bool, bytes]]) -> str:
    """Text that ``socat -x -v`` (version 1.8) writes for these blocks."""
    out, offsets, usec = [], {True: 0, False: 0}, 118675
    for to_device, data in blocks:
        start = offsets[to_device]
        offsets[to_device] += len(data)
        out.append(
            f"{'>' if to_device else '<'} 2026/01/02 10:00:00.{usec:09d}  "
            f"length={len(data)} from={start} to={start + len(data) - 1}"
        )
        usec += 1500
        lines, line = [], b""
        for byte in data:  # 16 bytes per line, and a new line after each LF
            line += bytes([byte])
            if len(line) == 16 or byte == 0x0A:
                lines.append(line)
                line = b""
        if line:
            lines.append(line)
        for part in lines:
            hex_part = " ".join(f"{b:02x}" for b in part)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in part)
            out.append(f" {hex_part:<48}  {text}")
        out.append("--")
    return "\n".join(out) + "\n"


SOCAT_BLOCKS = [
    (True, b"ID\r\n"),
    (False, ID_RESPONSE[:90]),
    (False, ID_RESPONSE[90:] + prompt(b"=")),
    (True, b"ACC\r\n"),
    (False, b"ACC\r\n\x02\r\nPassword: ?\x03"),
    (True, b"OTTER\r\n"),
    (False, b"\r\n\x02\r\nLevel 1\r\n=>\x03"),
]


def build_socat(path: Path, rtac: bool) -> Path:
    transcript = path.with_suffix(".log")
    transcript.write_text(socat_transcript(SOCAT_BLOCKS), encoding="latin-1")
    with transcript.open(encoding="latin-1") as fh:
        blocks = socat2pcap.parse_transcript(fh, utc=True)
    socat2pcap.write_pcap(blocks, path, rtac=rtac)
    return path


# name: (builder, extra tshark arguments)
SCENARIOS: dict[str, tuple[Callable[[Path], Path], list[str]]] = {
    "telnet": (build_telnet, []),
    "telnet_split": (build_telnet_split, []),
    "telnet_bad_sb": (build_telnet_bad_sb, []),
    "tunnel": (build_tunnel, []),
    "tunnel_port_pref": (
        build_tunnel,
        ["-o", "selascii.tcp_ports:2300", "--disable-heuristic", "selascii_tcp"],
    ),
    "ymodem": (build_ymodem, []),
    "rtac_default": (build_rtac, ["-o", "selascii.rtac_default:TRUE"]),
    "rtac_decode_as": (build_rtac, ["-d", "rtacser.data,selascii"]),
    "exported": (build_exported, []),
    "usbmon": (build_usbmon, []),
    "usbpcap": (build_usbpcap, []),
    "dlt_user": (
        build_dlt_user,
        ["-o", 'uat:user_dlts:"User 0 (DLT=147)","selascii","0","","0",""'],
    ),
    "socat_exported": (lambda p: build_socat(p, rtac=False), []),
    "socat_rtac": (lambda p: build_socat(p, rtac=True), ["-o", "selascii.rtac_default:TRUE"]),
}

GOLDEN_FIELDS = [
    "frame.number",
    "selascii.direction",
    "selascii.type",
    "selascii.cmd",
    "selascii.cmd.category",
    "selascii.response_to",
    "selascii.request_in",
    "selascii.prompt",
    "selascii.access_level",
    "selascii.line_count",
    "selascii.error",
    "selascii.id.fid",
    "selascii.id.iedname",
    "selascii.cascii.checksum.status",
    "selascii.password",
    "selascii.input",
    "selascii.question",
    "selascii.fast.type",
    "selfm.msgtype",
    "selascii.ymodem.block",
    "selascii.ymodem.filename",
    "selascii.reassembled_in",
    "selascii.password.factory_default",
    "selascii.cmd.operates_equipment",
    "selascii.cmd.state_change",
    "selascii.access_level.changed",
    "selascii.cascii.bad_checksum",
    "selascii.telnet_sb_unterminated",
    "_ws.lua.error",
    "_ws.malformed",
]


# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def tshark(tmp_path_factory) -> Callable[..., str]:
    """Run tshark with the plugin and return the ``-T fields`` output."""
    if TSHARK is None:
        _skip_or_fail("tshark is not installed")
    if RUNNING_AS_ROOT:
        _skip_or_fail("Wireshark ignores Lua scripts when running as root")

    # Keep personal preferences and plugins (maybe another selascii.lua) out
    home = tmp_path_factory.mktemp("wireshark-home")
    env = dict(os.environ)
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), APPDATA=str(home))
    env["WIRESHARK_CONFIG_DIR"] = str(home / "wireshark")

    def run(pcap: Path, *args: str, two_pass: bool = False, fields=None, display_filter=None):
        fields = GOLDEN_FIELDS if fields is None else fields
        display_filter = display_filter or "selascii || _ws.lua.error || _ws.malformed"
        cmd = [TSHARK, "-n", "-X", f"lua_script:{PLUGIN}", "-r", str(pcap)]
        if two_pass:
            cmd.append("-2")
        cmd += [*args, "-Y", display_filter, "-T", "fields", "-E", "header=n"]
        cmd += ["-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=;"]
        for field in fields:
            cmd += ["-e", field]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, env=env, timeout=120, check=False
        )
        # tshark exits 0 on Lua errors, so check the error output as well
        assert proc.returncode == 0, proc.stderr
        assert "Lua: Error" not in proc.stderr, proc.stderr
        assert "Lua Error" not in proc.stderr, proc.stderr
        return proc.stdout.replace("\r\n", "\n")

    return run


def _golden_text(output: str) -> str:
    return "# " + "|".join(GOLDEN_FIELDS) + "\n" + output


@pytest.mark.parametrize("two_pass", [False, True], ids=["pass1", "pass2"])
@pytest.mark.parametrize("name", list(SCENARIOS))
def test_golden_output(tshark, tmp_path, name, two_pass):
    builder, args = SCENARIOS[name]
    pcap = builder(tmp_path / f"{name}.pcap")
    output = tshark(pcap, *args, two_pass=two_pass)
    golden = GOLDEN_DIR / f"{name}.{'pass2' if two_pass else 'pass1'}.txt"
    if UPDATE_GOLDEN:
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(_golden_text(output), encoding="utf-8", newline="\n")
    assert golden.is_file(), f"missing {golden}; run with SELASCII_UPDATE_GOLDEN=1"
    expected = golden.read_text(encoding="utf-8")
    assert _golden_text(output) == expected
    for line in output.splitlines():
        lua_error, malformed = line.split("|")[-2:]
        assert not lua_error, line
        assert not malformed, line


def _column(output: str, index: int) -> list[str]:
    return [line.split("|")[index] for line in output.splitlines()]


def test_show_passwords_preference(tshark, tmp_path):
    pcap = build_telnet(tmp_path / "telnet.pcap")
    fields = ["frame.number", "selascii.password"]
    masked = tshark(pcap, fields=fields, display_filter="selascii.password")
    assert _column(masked, 1) == ["*****", "*****", "****"]
    shown = tshark(
        pcap,
        "-o",
        "selascii.show_passwords:TRUE",
        fields=fields,
        display_filter="selascii.password",
    )
    assert _column(shown, 1) == ["otter", "OTTER", "TAIL"]


def test_telnet_can_stay_with_the_telnet_dissector(tshark, tmp_path):
    pcap = build_telnet(tmp_path / "telnet.pcap")
    fields = ["frame.number", "selascii.cmd"]
    off = tshark(pcap, "-o", "selascii.wrap_telnet:FALSE", fields=fields)
    assert off == ""
    telnet = tshark(
        pcap, "-o", "selascii.wrap_telnet:FALSE", fields=["frame.number"], display_filter="telnet"
    )
    assert len(telnet.splitlines()) > 30
    # With heuristics first, the TCP heuristic still finds the session
    heuristic = tshark(
        pcap,
        "-o",
        "selascii.wrap_telnet:FALSE",
        "-o",
        "tcp.try_heuristic_first:TRUE",
        fields=fields,
        display_filter="selascii.cmd",
    )
    assert "ACC" in _column(heuristic, 1)
    assert "QUI" in _column(heuristic, 1)


def test_other_sessions_are_left_alone(tshark, tmp_path):
    """Other Telnet sessions on port 23 and other line protocols are not decoded."""
    pcap = PcapWriter(LINKTYPE_ETHERNET)
    telnet = TcpSession(pcap, 23, telnet=True)
    telnet.handshake()
    telnet.server_raw(b"\xff\xfd\x18\xff\xfd\x20")
    telnet.client_raw(b"\xff\xfb\x18")
    telnet.server(b"Ubuntu 24.04 LTS\r\nhost login: ")
    telnet.client(b"admin\r\n")
    telnet.server(b"admin\r\nPassword: ")
    telnet.client(b"hunter2\r\n")
    telnet.server(b"\r\nWelcome\r\n$ ")
    for command in (b"id", b"set", b"ls"):
        telnet.client(command + b"\r\n")
        telnet.server(command + b"\r\nok\r\n$ ")
    text = TcpSession(pcap, 4000)  # a memcached-like text protocol
    text.handshake()
    for line in (b"set k 0 0 5\r\n", b"hello\r\n", b"get k\r\n"):
        text.client(line)
        text.server(b"STORED\r\n")
    path = pcap.write(tmp_path / "other.pcap")
    for two_pass in (False, True):
        assert tshark(path, two_pass=two_pass, fields=["frame.number"]) == ""
        protocols = tshark(
            path,
            two_pass=two_pass,
            fields=["_ws.col.Protocol"],
            display_filter="tcp.port == 23 && tcp.len > 0",
        )
        assert set(protocols.split()) == {"TELNET"}


# A session whose messages are cut into segments at random points
SPLIT_SESSION = [
    (False, prompt(b"=")),
    (True, b"ID\r\n"),
    (False, ID_RESPONSE + prompt(b"=")),
    (True, b"ACC\r\n"),
    (False, b"ACC\r\n\x02\r\nPassword: ?\x03"),
    (True, b"otter\r\n"),
    (False, b"\r\n\x02\r\nPassword: ?\x03"),
    (True, b"OTTER\r\n"),
    (False, b"\r\n\x02\r\nLevel 1\r\n=>\x03"),
    (True, b"SER 3\r\n"),
    (False, b"SER 3\r\n" + message(SER_LINES) + prompt(b"=>")),
    (True, b"CAS\r\n"),
    (False, b"CAS\r\n" + message(CAS_LINES) + prompt(b"=>")),
    (True, b"STA C\r\n"),
    (False, b"STA C\r\n\x02\r\nRestart the relay (Y,N)?\x03"),
    (True, b"N\r\n"),
    (False, b"\r\n\x02\r\nCanceled\r\n=>\x03"),
    (True, b"\xa5\xc0"),
    (False, RELAY_DEFINITION),
    (True, b"QUI\r\n"),
    (False, b"QUI\r\n" + prompt(b"=")),
]


def test_random_segmentation_gives_the_same_result_on_both_passes(tshark, tmp_path):
    """Pass 2 (and the GUI) gets less reassembled data than pass 1, never other results."""
    rng = random.Random(53)
    pcap = PcapWriter(LINKTYPE_ETHERNET)
    streams = 0
    for _ in range(9):
        for port, telnet in ((23, True), (2300, False)):
            tcp = TcpSession(pcap, port, telnet=telnet, client_port=50000 + streams)
            tcp.handshake()
            streams += 1
            for to_device, data in SPLIT_SESSION:
                pos = 0
                while pos < len(data):
                    size = rng.choice([1, 2, 3, 5, 8, 20, 64, 1000])
                    (tcp.client if to_device else tcp.server)(data[pos : pos + size])
                    pos += size
    path = pcap.write(tmp_path / "split.pcap")
    fields = [
        "tcp.stream",
        "selascii.type",
        "selascii.cmd",
        "selascii.password",
        "selascii.command",
        "selascii.response_to",
        "selascii.request_in",
        "selascii.access_level",
    ]
    one, two = (tshark(path, two_pass=two_pass, fields=fields) for two_pass in (False, True))
    assert one == two
    commands: dict[str, list[str]] = {}
    passwords: dict[str, int] = {}
    for line in one.splitlines():
        stream, _, cmd, password, command = line.split("|")[:5]
        commands.setdefault(stream, []).extend(c for c in cmd.split(";") if c)
        passwords[stream] = passwords.get(stream, 0) + len([p for p in password.split(";") if p])
        assert "OTTER" not in command
        assert "otter" not in command
    assert len(commands) == streams
    for stream, cmds in commands.items():
        assert cmds == ["ID", "ACC", "SER", "CAS", "STA", "QUI"], stream
        assert passwords[stream] == 2, stream


def _random_payload(rng: random.Random) -> bytes:
    pieces = [
        b"\x02",
        b"\x03",
        b"\r\n",
        b"\xff",
        b"\xff\xfb",
        b"\xa5\xc0",
        b"\xa5\xc0\x24",
        b"\x01",
    ]
    pieces += [b"=>", b'"', b",", b"ID", b"ACC", b"Password: ?", b'"0000"', b"\x06", b"?"]
    parts = []
    for _ in range(rng.randint(1, 40)):
        if rng.random() < 0.5:
            parts.append(rng.choice(pieces))
        else:
            parts.append(bytes([rng.randrange(256)]))
    return b"".join(parts)


@pytest.mark.parametrize("two_pass", [False, True], ids=["pass1", "pass2"])
def test_random_input_has_no_lua_errors(tshark, tmp_path, two_pass):
    rng = random.Random(53)
    telnet = PcapWriter(LINKTYPE_ETHERNET)
    session = TcpSession(telnet, 23)
    raw = PcapWriter(LINKTYPE_ETHERNET)
    tunnel = TcpSession(raw, 2300)
    exported = PcapWriter(socat2pcap.LINKTYPE_WIRESHARK_UPPER_PDU)
    session.handshake()
    tunnel.handshake()
    tunnel.server(prompt(b"=>"))
    for _ in range(150):
        to_device = rng.random() < 0.5
        data = _random_payload(rng)
        (session.client_raw if to_device else session.server_raw)(data)
        (tunnel.client_raw if to_device else tunnel.server_raw)(data)
        exported.add(socat2pcap.exported_pdu(data, to_device))
    for pcap, args in (
        (telnet.write(tmp_path / "telnet.pcap"), []),
        (raw.write(tmp_path / "tunnel.pcap"), []),
        (raw.write(tmp_path / "tunnel_port.pcap"), ["-o", "selascii.tcp_ports:2300"]),
        (exported.write(tmp_path / "exported.pcap"), []),
    ):
        errors = tshark(
            pcap, *args, two_pass=two_pass, fields=["frame.number"], display_filter="_ws.lua.error"
        )
        assert errors == "", f"Lua errors in {pcap.name}, frames: {errors.split()}"
        decoded = tshark(pcap, *args, two_pass=two_pass, fields=["frame.number"])
        assert decoded, f"nothing decoded in {pcap.name}"


@pytest.mark.skipif(shutil.which("socat") is None, reason="socat is not installed")
def test_live_socat_transcript(tshark, tmp_path):
    """socat2pcap.py converts a real socat transcript of a scripted fake relay."""
    relay = tmp_path / "fake_relay.py"
    reply = ID_RESPONSE + prompt(b"=")
    relay.write_text(
        "import sys\n"
        "data = b''\n"
        "while not data.endswith(b'\\r\\n'):\n"
        "    chunk = sys.stdin.buffer.read(1)\n"
        "    if not chunk:\n"
        "        break\n"
        "    data += chunk\n"
        f"sys.stdout.buffer.write({reply!r})\n"
        "sys.stdout.buffer.flush()\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["socat", "-t", "2", "-x", "-v", "-", f"EXEC:{sys.executable} -I {relay}"],
        input=b"ID\r\n",
        capture_output=True,
        timeout=30,
        check=True,
    )
    log = tmp_path / "socat.log"
    log.write_bytes(proc.stderr)
    pcap = tmp_path / "socat.pcap"
    assert socat2pcap.main([str(log), str(pcap)]) == 0
    output = tshark(
        pcap,
        fields=["selascii.cmd", "selascii.id.fid"],
        display_filter="selascii.cmd || selascii.id.fid",
    )
    assert output.splitlines() == ["ID|", "|SEL-700G-R200-V0-Z006003-D20180629"]


# ---------------------------------------------------------------------------
# Plain Lua unit tests and Lua version compatibility
# ---------------------------------------------------------------------------
def _lua_interpreters() -> list[str]:
    """Lua 5.2 or newer interpreters on the PATH (Wireshark 4.2+ never uses 5.1)."""
    found, seen = [], set()
    for name in ("lua5.2", "lua5.3", "lua5.4", "lua"):
        path = shutil.which(name)
        if not path or os.path.realpath(path) in seen:
            continue
        seen.add(os.path.realpath(path))
        try:
            proc = subprocess.run(
                [path, "-v"], capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        version = re.match(r"Lua (\d+)\.(\d+)", (proc.stdout + proc.stderr).strip())
        if version and (int(version.group(1)), int(version.group(2))) >= (5, 2):
            found.append(path)
    return found


@pytest.mark.parametrize("lua", _lua_interpreters() or [None])
def test_lua_unit_tests(lua):
    if lua is None:
        _skip_or_fail("no Lua interpreter (lua5.2, lua5.3, lua5.4 or lua) is installed")
    proc = subprocess.run(
        [lua, str(LUA_UNIT_TESTS), str(PLUGIN)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ALL OK" in proc.stdout


def _lua_code_only(source: str) -> str:
    """Lua source without comments and string literals."""
    out, i, n = [], 0, len(source)
    long_bracket = re.compile(r"\[(=*)\[")
    while i < n:
        if source.startswith("--", i):
            match = long_bracket.match(source, i + 2)
            if match:
                end = source.find("]" + match.group(1) + "]", match.end())
                i = n if end < 0 else end + len(match.group(1)) + 2
            else:
                end = source.find("\n", i)
                i = n if end < 0 else end
            continue
        match = long_bracket.match(source, i)
        if match:
            end = source.find("]" + match.group(1) + "]", match.end())
            i = n if end < 0 else end + len(match.group(1)) + 2
            out.append('""')
            continue
        char = source[i]
        if char in "'\"":
            j = i + 1
            while j < n and source[j] != char:
                j += 2 if source[j] == "\\" else 1
            i = j + 1
            out.append('""')
            continue
        out.append(char)
        i += 1
    return "".join(out)


def test_no_lua_53_operators():
    """Wireshark 4.2 uses Lua 5.2, which has no bitwise or floor division operators."""
    code = _lua_code_only(PLUGIN.read_text(encoding="utf-8"))
    for operator in ("//", "&", "|", "<<", ">>"):
        assert operator not in code, f"Lua 5.3+ operator {operator!r} in {PLUGIN.name}"
    assert not re.search(r"~(?!=)", code), f"Lua 5.3+ operator '~' in {PLUGIN.name}"
    assert "goto" not in code.split(), "avoid goto"


# ---------------------------------------------------------------------------
# socat2pcap.py
# ---------------------------------------------------------------------------
def test_socat_transcript_parsing():
    blocks = socat2pcap.parse_transcript(socat_transcript(SOCAT_BLOCKS).splitlines(), utc=True)
    assert [(b.to_device, b.data) for b in blocks] == SOCAT_BLOCKS
    assert blocks[0].seconds == 1_767_348_000
    assert blocks[0].microseconds == 118675  # socat 1.8 prints microseconds in 9 digits
    swapped = socat2pcap.parse_transcript(
        socat_transcript(SOCAT_BLOCKS[:1]).splitlines(), swap=True
    )
    assert swapped[0].to_device is False


def test_socat_six_digit_timestamps():
    text = "> 2026/01/02 10:00:00.5  length=2 from=0 to=1\n 49 44  ID\n--\n"
    (block,) = socat2pcap.parse_transcript(text.splitlines(), utc=True)
    assert block.microseconds == 500000
    assert block.data == b"ID"


def test_socat_length_mismatch_is_an_error():
    text = "> 2026/01/02 10:00:00.000001  length=3 from=0 to=2\n 49 44  ID\n--\n"
    with pytest.raises(ValueError, match="header says 3 bytes"):
        socat2pcap.parse_transcript(text.splitlines())


def test_socat2pcap_writes_exported_pdus(tmp_path, capsys):
    log = tmp_path / "sel.log"
    log.write_text(socat_transcript(SOCAT_BLOCKS[:2]), encoding="latin-1")
    pcap = tmp_path / "sel.pcap"
    assert socat2pcap.main([str(log), str(pcap), "--utc"]) == 0
    assert "Wrote 2 records" in capsys.readouterr().err
    data = pcap.read_bytes()
    magic, _, _, _, _, _, linktype = struct.unpack("<IHHiIII", data[:24])
    assert (magic, linktype) == (0xA1B2C3D4, 252)
    first_len = struct.unpack("<I", data[32:36])[0]
    first = data[40 : 40 + first_len]
    assert first == (
        b"\x00\x0c\x00\x08selascii"  # dissector name
        b"\x00\x23\x00\x04\x00\x00\x00\x00"  # direction: sent
        b"\x00\x00\x00\x00"  # end of tags
        b"ID\r\n"
    )


def test_socat2pcap_writes_rtac_serial(tmp_path):
    log = tmp_path / "sel.log"
    log.write_text(socat_transcript(SOCAT_BLOCKS[:2]), encoding="latin-1")
    pcap = tmp_path / "sel.pcap"
    assert socat2pcap.main([str(log), str(pcap), "--rtac", "--utc"]) == 0
    data = pcap.read_bytes()
    assert struct.unpack("<I", data[20:24])[0] == 250
    first = data[40 : 40 + struct.unpack("<I", data[32:36])[0]]
    sec, usec, event, lines, footer = struct.unpack(">IIBBH", first[:12])
    assert (sec, usec, event, lines, footer) == (1_767_348_000, 118675, 1, 0, 0)
    assert first[12:] == b"ID\r\n"


def test_socat2pcap_rejects_empty_transcript(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("socat started\n", encoding="latin-1")
    with pytest.raises(SystemExit):
        socat2pcap.main([str(log), str(tmp_path / "out.pcap")])
