"""
Builders for synthetic RSLogix 500 project files (``.RSS``), used by the tests.

No real project files are used or committed: every byte here is generated
from the structure documented in :mod:`peat.modules.rockwell.rss_parse`.
This includes a minimal MS-CFB (OLE2) version 3 writer, since ``olefile``
can't create compound files, and a literal-only PKWARE DCL encoder.

Rungs are described with :func:`ins` and :func:`branch`, for example::

    [ins(XIC, "I:1/0"), branch([ins(XIC, "B3:0/1")], [ins(XIO, "B3:0/2")]), ins(OTE, "O:0/3")]

SOR and EOR are added automatically.
"""

import itertools
import struct
import uuid
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from peat.modules.rockwell.rss_const import BND, BST, EOR, LEG_END, LEG_START, SOR

# Opcodes used in the tests
XIC = 0x39
XIO = 0x3A
OTE = 0x2F
OTL = 0x30
MOV = 0x1C
MVM = 0x26
EQU = 0x32
COP = 0x22
JSR = 0x15
END = 0x0C

# ----------------------------------------------------------------------------
# MS-CFB (OLE2) writer
# ----------------------------------------------------------------------------

_SECTOR = 512
_MINI_SECTOR = 64
_MINI_CUTOFF = 4096
_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF
_DIR_ENTRY = struct.Struct("<64sHBBIII16sIQQIQ")


def _pad(data: bytes, size: int) -> bytes:
    return data + b"\x00" * (-len(data) % size)


def build_cfb(tree: dict[str, Any]) -> bytes:
    """
    Build a MS-CFB version 3 compound file.

    Args:
        tree: Nested :class:`dict`. Keys are names, values are either
            :class:`bytes` (a stream) or a :class:`dict` (a storage).
    """
    entries: list[dict[str, Any]] = [{"name": "Root Entry", "type": 5, "kids": [], "data": b""}]

    def _add(parent: int, node: dict[str, Any]) -> None:
        for name, value in node.items():
            index = len(entries)
            if isinstance(value, dict):
                entries.append({"name": name, "type": 1, "kids": [], "data": b""})
                entries[parent]["kids"].append(index)
                _add(index, value)
            else:
                entries.append({"name": name, "type": 2, "kids": [], "data": bytes(value)})
                entries[parent]["kids"].append(index)

    _add(0, tree)

    for entry in entries:
        entry.update(left=_NOSTREAM, right=_NOSTREAM, child=_NOSTREAM, start=0, size=0)

    # Siblings are a binary search tree in CFB name order. A chain of
    # right siblings is a valid (if unbalanced) tree.
    for entry in entries:
        kids = sorted(
            entry["kids"],
            key=lambda k: (len(entries[k]["name"]), entries[k]["name"].upper()),
        )
        if kids:
            entry["child"] = kids[0]
            for left, right in itertools.pairwise(kids):
                entries[left]["right"] = right

    sectors: list[bytes] = []
    fat: list[int] = []

    def _alloc(blob: bytes) -> int:
        blob = _pad(blob, _SECTOR)
        start = len(sectors)
        count = len(blob) // _SECTOR
        for i in range(count):
            sectors.append(blob[i * _SECTOR : (i + 1) * _SECTOR])
            fat.append(start + i + 1)
        fat[-1] = _ENDOFCHAIN
        return start

    # Reserve the directory sectors first
    num_dir = -(-len(entries) * 128 // _SECTOR)
    sectors.extend([b""] * num_dir)
    fat.extend(range(1, num_dir + 1))
    fat[num_dir - 1] = _ENDOFCHAIN

    # Small streams go in the mini stream
    mini_stream = bytearray()
    mini_fat: list[int] = []
    for entry in entries:
        if entry["type"] != 2:
            continue
        data = entry["data"]
        entry["size"] = len(data)
        if not data:
            entry["start"] = _ENDOFCHAIN
        elif len(data) < _MINI_CUTOFF:
            start = len(mini_stream) // _MINI_SECTOR
            count = -(-len(data) // _MINI_SECTOR)
            entry["start"] = start
            mini_stream += _pad(data, _MINI_SECTOR)
            mini_fat.extend(start + i + 1 for i in range(count - 1))
            mini_fat.append(_ENDOFCHAIN)
        else:
            entry["start"] = None  # Allocated below

    mini_fat_start = _ENDOFCHAIN
    num_mini_fat = 0
    if mini_fat:
        mini_fat_blob = b"".join(struct.pack("<I", x) for x in mini_fat)
        mini_fat_start = _alloc(mini_fat_blob)
        num_mini_fat = len(_pad(mini_fat_blob, _SECTOR)) // _SECTOR
    if mini_stream:
        entries[0]["start"] = _alloc(bytes(mini_stream))
        entries[0]["size"] = len(mini_stream)
    else:
        entries[0]["start"] = _ENDOFCHAIN

    for entry in entries:
        if entry["type"] == 2 and entry["start"] is None:
            entry["start"] = _alloc(entry["data"])

    # FAT sectors (the header DIFAT has room for 109)
    num_fat = 1
    while len(fat) + num_fat > num_fat * (_SECTOR // 4):
        num_fat += 1
    assert num_fat <= 109, "test file is too large for the header DIFAT"
    fat_start = len(sectors)
    fat.extend([_FATSECT] * num_fat)
    fat.extend([_FREESECT] * (num_fat * (_SECTOR // 4) - len(fat)))
    fat_blob = b"".join(struct.pack("<I", x) for x in fat)
    for i in range(num_fat):
        sectors.append(fat_blob[i * _SECTOR : (i + 1) * _SECTOR])

    directory = bytearray()
    for entry in entries:
        name = entry["name"].encode("utf-16-le") + b"\x00\x00"
        directory += _DIR_ENTRY.pack(
            name,
            len(name),
            entry["type"],
            1,  # Black
            entry["left"],
            entry["right"],
            entry["child"],
            b"\x00" * 16,
            0,
            0,
            0,
            entry["start"],
            entry["size"],
        )
    while len(directory) % _SECTOR:
        directory += _DIR_ENTRY.pack(
            b"", 0, 0, 0, _NOSTREAM, _NOSTREAM, _NOSTREAM, b"\x00" * 16, 0, 0, 0, 0, 0
        )
    for i in range(num_dir):
        sectors[i] = bytes(directory[i * _SECTOR : (i + 1) * _SECTOR])

    difat = [fat_start + i for i in range(num_fat)] + [_FREESECT] * (109 - num_fat)
    header = struct.pack(
        "<8s16sHHHHH6sIIIIIIIII",
        bytes.fromhex("d0cf11e0a1b11ae1"),
        b"\x00" * 16,
        0x3E,  # Minor version
        3,  # Major version
        0xFFFE,  # Byte order
        9,  # Sector shift (512 bytes)
        6,  # Mini sector shift (64 bytes)
        b"\x00" * 6,
        0,  # Directory sectors (always 0 for version 3)
        num_fat,
        0,  # First directory sector
        0,  # Transaction signature
        _MINI_CUTOFF,
        mini_fat_start,
        num_mini_fat,
        _ENDOFCHAIN,  # First DIFAT sector
        0,  # DIFAT sectors
    )
    header += b"".join(struct.pack("<I", x) for x in difat)
    return header + b"".join(sectors)


# ----------------------------------------------------------------------------
# SummaryInformation property set
# ----------------------------------------------------------------------------

_SUMMARY_FMTID = uuid.UUID("F29F85E0-4FF9-1068-AB91-08002B27B3D9").bytes_le


def _filetime(value: datetime) -> int:
    delta = value - datetime(1601, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def summary_info_stream(props: dict[int, Any]) -> bytes:
    """
    Build a ``\\x05SummaryInformation`` property set stream.

    Values may be :class:`str` (VT_LPSTR), :class:`int` (VT_I4) or
    :class:`datetime` (VT_FILETIME). Property 1 (codepage) is always VT_I2.
    """
    values = []
    for prop_id, value in sorted(props.items()):
        if prop_id == 1:
            blob = struct.pack("<HHhH", 2, 0, value, 0)
        elif isinstance(value, str):
            raw = value.encode("cp1252") + b"\x00"
            blob = _pad(struct.pack("<HHI", 30, 0, len(raw)) + raw, 4)
        elif isinstance(value, datetime):
            blob = struct.pack("<HHQ", 64, 0, _filetime(value))
        else:
            blob = struct.pack("<HHi", 3, 0, value)
        values.append((prop_id, blob))

    offset = 8 + 8 * len(values)
    table = b""
    body = b""
    for prop_id, blob in values:
        table += struct.pack("<II", prop_id, offset + len(body))
        body += blob
    section = struct.pack("<II", 8 + len(table) + len(body), len(values)) + table + body

    header = struct.pack("<HHI16sI", 0xFFFE, 0, 0x00020005, b"\x00" * 16, 1)
    header += _SUMMARY_FMTID + struct.pack("<I", 48)
    return header + section


# ----------------------------------------------------------------------------
# MFC CArchive and RSS payloads
# ----------------------------------------------------------------------------


def cstr(text: str) -> bytes:
    """Serialize a narrow MFC CString."""
    raw = text.encode("cp1252")
    if len(raw) < 0xFF:
        return bytes([len(raw)]) + raw
    if len(raw) < 0xFFFF:
        return b"\xff" + struct.pack("<H", len(raw)) + raw
    return b"\xff\xff\xff" + struct.pack("<I", len(raw)) + raw


def mfc_class(name: str, schema: int = 0x80) -> bytes:
    """Serialize a MFC new-class definition."""
    return b"\xff\xff" + struct.pack("<HH", schema, len(name)) + name.encode("ascii")


def object_data(payload: bytes, mode: int = 2, **overrides: int) -> bytes:
    """
    Build an ``ObjectData`` stream: the 16-byte header and the payload.

    Args:
        payload: Decoded payload
        mode: 0 (stored), 1 (PKWARE DCL) or 2 (zlib)
        overrides: Replacement values for ``header_mode``, ``header_size``,
            ``stored_size`` or ``decoded_size`` in the header
    """
    if mode == 2:
        body = zlib.compress(payload)
    elif mode == 1:
        body = implode_literals(payload)
    else:
        body = payload
    header = {
        "header_mode": mode,
        "header_size": 16,
        "stored_size": len(body),
        "decoded_size": len(payload),
    }
    header.update(overrides)
    return struct.pack("<4I", *header.values()) + body


def implode_literals(data: bytes) -> bytes:
    """
    Encode data as a PKWARE DCL stream that uses only uncoded literals.

    Header: literals are uncoded (0), 4K dictionary (6). Each byte is a
    0 bit followed by the 8 bits of the byte. The end code is a 1 bit, the
    length code for symbol 15 (canonical code ``1111111``, which is stored
    inverted as ``0000000``), then 8 extra bits of 0xFF (264 + 255 = 519,
    the end marker).
    """
    bits: list[tuple[int, int]] = [(0, 8), (6, 8)]
    for byte in data:
        bits.append((0, 1))
        bits.append((byte, 8))
    bits.append((1, 1))
    bits.extend([(0, 1)] * 7)
    bits.append((0xFF, 8))

    out = bytearray()
    acc = 0
    count = 0
    for value, width in bits:
        acc |= value << count
        count += width
        while count >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            count -= 8
    if count:
        out.append(acc & 0xFF)
    return bytes(out)


class MfcWriter:
    """Serialize objects with MFC class and object numbering."""

    def __init__(self, schema: int = 0x80, index_gaps: dict[str, int] | None = None) -> None:
        self.buf = bytearray()
        self.schema = schema
        self.classes: dict[str, int] = {}
        self.next_index = 1
        #: Extra indexes to skip before a class is first defined, to
        #: simulate other objects being written first
        self.index_gaps = index_gaps or {}

    def obj(self, class_name: str) -> "MfcWriter":
        """Write the tag for a new object of a class."""
        if class_name in self.classes:
            index = self.classes[class_name]
            if index < 0x7FFF:
                self.buf += struct.pack("<H", 0x8000 | index)
            else:
                self.buf += b"\xff\x7f" + struct.pack("<I", 0x80000000 | index)
        else:
            self.next_index += self.index_gaps.get(class_name, 0)
            self.buf += mfc_class(class_name, self.schema)
            self.classes[class_name] = self.next_index
            self.next_index += 1
        self.next_index += 1
        return self

    def raw(self, data: bytes) -> "MfcWriter":
        self.buf += data
        return self

    def u16(self, value: int) -> "MfcWriter":
        return self.raw(struct.pack("<H", value))

    def u32(self, value: int) -> "MfcWriter":
        return self.raw(struct.pack("<I", value))

    def cstr(self, text: str) -> "MfcWriter":
        return self.raw(cstr(text))

    def bytes(self) -> bytes:
        return bytes(self.buf)


def ins(opcode: int, *operands: str, blob: bytes | None = None) -> tuple:
    """An instruction in a rung."""
    return ("ins", opcode, list(operands), blob)


def branch(*legs: list) -> tuple:
    """A branch with one or more legs (lists of items)."""
    return ("branch", list(legs))


def _write_ins(w: MfcWriter, opcode: int, operands: list[str], blob: bytes | None) -> None:
    w.obj("CIns").u16(len(operands))
    for operand in operands:
        w.cstr(operand)
    if blob is None:
        blob = bytes([opcode & 0xFF, 0x01, 0x02, 0x03])
    w.u16(1 if blob else 0).u16(opcode).u32(0)
    if blob:
        w.u16(len(blob)).raw(blob)


def _write_items(w: MfcWriter, items: list) -> None:
    for item in items:
        if item[0] == "ins":
            _write_ins(w, item[1], item[2], item[3])
        else:
            legs = item[1]
            w.obj("CBranch").u16(len(legs) + 2)
            _write_ins(w, BST, [], None)
            for leg in legs:
                w.obj("CBranchLeg").u16(len(leg) + 2)
                _write_ins(w, LEG_START, [], None)
                _write_items(w, leg)
                _write_ins(w, LEG_END, [], None)
            _write_ins(w, BND, [], None)


def ladder_payload(
    files: list[dict[str, Any]],
    schema: int = 0x80,
    declared_count: int | None = None,
    index_gaps: dict[str, int] | None = None,
) -> bytes:
    """
    Build a ``PROGRAM FILES`` payload.

    Args:
        files: Program files, each a :class:`dict` with ``number``,
            ``name``, ``type`` and ``rungs`` (a list of item lists). An
            optional ``declared_rungs`` overrides the rung count in the header.
        schema: MFC class schema
        declared_count: Override the number of program files in ``CProgHolder``
        index_gaps: See :class:`MfcWriter`
    """
    w = MfcWriter(schema, index_gaps)
    w.obj("CProgHolder").u16(len(files) if declared_count is None else declared_count)
    for pfile in files:
        rungs = pfile.get("rungs", [])
        declared = pfile.get("declared_rungs", len(rungs))
        name = pfile.get("name", "").encode("ascii").ljust(10, b"\x00")
        w.obj("CLadFile")
        w.raw(
            struct.pack("<HH10sHBH", declared, pfile["type"], name, pfile["number"], 0, declared)
        )
        for index, items in enumerate(rungs):
            w.obj("CRung")
            w.obj("CBranchLeg").u16(len(items) + 2)
            _write_ins(w, SOR, [], b"" if index == 0 else None)
            _write_items(w, items)
            _write_ins(w, EOR, [], b"" if index == 0 else None)
            w.raw(struct.pack("<III", index * 3, 0, index + 5))  # Unknown rung fields
        if rungs:
            w.raw(b"\x00\x00\x00\x00")  # Unknown file trailer
    return w.bytes()


def default_program_files() -> list[dict[str, Any]]:
    """Program files with the system files, a main ladder file and a subroutine."""
    return [
        {"number": 0, "name": "", "type": 0},
        {"number": 1, "name": "", "type": 2},
        {
            "number": 2,
            "name": "MAIN",
            "type": 1,
            "rungs": [
                [ins(OTE, "B3:0/2")],
                [ins(MVM, "N7:2", "0", "00FFh", "255", "N7:3", "0")],
                [
                    branch(
                        [ins(XIC, "I:1/0"), ins(XIO, "B3:2/4")],
                        [ins(XIO, "I:1/0"), ins(XIC, "B3:2/4")],
                    ),
                    ins(OTE, "O:0/2"),
                ],
                [ins(0x7E, "ALPHA", "BETA")],
                [ins(EQU, "N7:2", "5", "3", "3"), ins(JSR, "U:3")],
                [ins(END)],
            ],
        },
        {
            "number": 3,
            "name": "SUB_A",
            "type": 1,
            "rungs": [
                [
                    ins(XIC, "S:1/13"),
                    branch(
                        [ins(XIC, "B3:1/0"), branch([ins(XIO, "T4:1/DN")], [ins(XIC, "C5:2/DN")])],
                        [ins(OTL, "B3:1/1")],
                    ),
                    ins(COP, "#N10:4", "#O:2.0", "4"),
                ],
                [ins(MOV, "N7:2", "0", "F8:1", "0.0")],
            ],
        },
    ]


def processor_payload(
    type_code: int = 0x2B,
    name: str = "PUMP_CTL",
    driver: str = "AB_DF1-1%SYNTHETIC%D",
    comms_path: str | None = "ENGWS01!AB_ETH-1\\192.0.2.10",
    schema: int = 0x80,
) -> bytes:
    """Build a ``PROCESSOR`` payload (class ``CProc``)."""
    w = MfcWriter(schema).obj("CProc").u16(type_code).u16(type_code).cstr(driver)
    w.raw(b"\x00" * 6).cstr(name).raw(b"\x00\x02\x00\x00\x00")
    if comms_path is not None:
        w.cstr(comms_path)
    return w.raw(b"\x00" * 5).bytes()


def version_payload(version: str = "9.99.00.01") -> bytes:
    """Build a ``Version`` payload (class ``CVersionData``)."""
    short, _, build = version.rpartition(".")
    w = MfcWriter().obj("CVersionData").cstr(version).cstr(short).cstr(build)
    return w.bytes()


def first_u16_payload(class_name: str, value: int, size: int = 32) -> bytes:
    """Build a payload with a class definition, a WORD, and padding."""
    return MfcWriter().obj(class_name).u16(value).raw(b"\x00" * size).bytes()


def memdb_payload(
    entries: list[tuple[str, str, list[str]]],
    comments: list[tuple[int, int, str]],
    declared_entries: int | None = None,
    declared_comments: int | None = None,
) -> bytes:
    """
    Build a ``MEM DATABASE`` payload (class ``DBXMemMap``).

    Args:
        entries: (padded address, symbol, description lines) of each entry
        comments: (file, rung, text) of each rung comment
        declared_entries: Override the entry count in the header
        declared_comments: Override the rung comment count
    """
    w = MfcWriter().obj("DBXMemMap")
    for value in (1, 20, 5, 20, 0, 5):
        w.u32(value)
    w.cstr("Synthetic DB").u32(40)
    w.u32(len(entries) if declared_entries is None else declared_entries)
    w.raw(struct.pack("<IIIHH", 0, 3, 0, len(entries), 1) + b"\x00" * 10)
    for index, (address, symbol, lines) in enumerate(entries):
        w.cstr(address).cstr(symbol)
        for line in (lines + [""] * 5)[:5]:
            w.cstr(line)
        if index + 1 < len(entries):
            w.raw(struct.pack("<IIII", 0, index + 1, 0, index + 2) + b"\x00" * 8)
        else:
            w.raw(struct.pack("<IIII", 0, index + 1, 0, 0))
    w.u16(len(comments) if declared_comments is None else declared_comments)
    for index, (file_num, rung, text) in enumerate(comments):
        w.u32(index + 100).cstr(text).cstr("").cstr(f"RUNG{file_num:06d}-{rung:06d}")
    return w.u16(0).bytes()


def default_entries() -> list[tuple[str, str, list[str]]]:
    return [
        ("S0002:001/13", "", ["First", "Pass"]),
        ("B0003:000/02", "", ["Pump", "enable", "latch"]),
        ("N0007:002", "SPEED", ["Speed", "setpoint"]),
        ("I0001:000/00", "", ["Start", "button"]),
        ("O0000:000/02", "", ["Pump", "motor"]),
        ("PFILE:00003", "", ["Subroutine", "A"]),
        ("N0007:003", "", []),
    ]


def default_comments() -> list[tuple[int, int, str]]:
    # Keys are written in descending order, like the real files
    return [
        (3, 0, "Latch the alarm when\r\nthe first pass bit is set."),
        (2, 2, "Exclusive OR of the start button and B3:2/4"),
        (2, 0, "Always energize the pump enable bit"),
    ]


def vba_project_text(modules: list[str] | None = None) -> bytes:
    lines = [
        'ID="{00000000-0000-0000-0000-000000000000}"',
        "Document=RSLogix_500_Project/&H00000000",
    ]
    lines += [f"Module={m}" for m in modules or []]
    lines += ['Name="VBASynthetic"', "", "[Host Extender Info]", "&H00000001={0};VBE;&H0"]
    return "\r\n".join(lines).encode("cp1252")


def default_summary() -> dict[int, Any]:
    return {
        1: 1252,
        4: "jdoe",
        8: "operator2",
        9: "7",
        12: datetime(2011, 3, 4, 5, 6, 7, tzinfo=UTC),
        13: datetime(2012, 8, 9, 10, 11, 12, tzinfo=UTC),
        18: "RSLogix 500",
        20: "PUMP_CTL",
        21: 0,
        25: 4,
        32: 9,
    }


def default_tree(mode: int = 2) -> dict[str, Any]:
    """The storages and streams of a synthetic project file."""
    programs = ladder_payload(default_program_files())
    online = default_program_files()
    online[2]["rungs"].insert(5, [ins(XIC, "B3:0/2"), ins(OTE, "O:0/5")])
    return {
        "\x05SummaryInformation": summary_info_stream(default_summary()),
        "Contents": struct.pack("<III", 0x80, 1, 0),
        "PROCESSOR": {"ObjectData": object_data(processor_payload(), 0)},
        "PROGRAM FILES": {"ObjectData": object_data(programs, mode)},
        "DATA FILES": {"ObjectData": object_data(first_u16_payload("CDataHolder", 9), mode)},
        "IO CONFIGURATION": {"ObjectData": object_data(first_u16_payload("CIOInfo", 0x2B), 0)},
        "MEM DATABASE": {
            "ObjectData": object_data(memdb_payload(default_entries(), default_comments()), mode)
        },
        "Version": {"ObjectData": object_data(version_payload(), mode)},
        "ONLINEIMAGE": {
            "PROCESSOR": {"ObjectData": object_data(processor_payload(), 0)},
            "PROGRAM FILES": {"ObjectData": object_data(ladder_payload(online), mode)},
        },
        "apc": {"The VBA Project": {"_VBA_Project": {"PROJECT": vba_project_text()}}},
    }


def make_rss(directory: Path, name: str = "project.RSS", tree: dict | None = None) -> Path:
    """Write a synthetic project file and return its path."""
    path = directory / name
    path.write_bytes(build_cfb(default_tree() if tree is None else tree))
    return path
