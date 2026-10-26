"""
Minimal reader for dBASE (``.dbf``) tables and their memo (``.dbt``) files.

SIMATIC Manager (STEP 7 V5.x) stores most of a project in dBASE III/IV
tables, such as the block list (``BAUSTEIN.DBF``), block contents
(``SUBBLK.DBF``), and symbol tables (``SYMLIST.DBF``). Only reading is
supported, and only the field types used by STEP 7.

References

- dBASE file format: https://www.dbase.com/Knowledgebase/INT/db7_file_fmt.htm
- https://www.clicketyclick.dk/databases/xbase/format/dbf.html

Authors

- Christopher Goes
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path

from peat import ParseError

ENCODING = "latin-1"


@dataclass
class DBFField:
    name: str
    type: str
    length: int
    decimals: int


@dataclass
class DBFTable:
    """Records of a dBASE table, as a list of dicts keyed by field name."""

    version: int
    fields: list[DBFField]
    records: list[dict[str, str | int | float | bool | bytes | None]] = field(default_factory=list)


def _read_memo(memo: bytes, block_num: int, block_size: int) -> bytes:
    """Read a memo from a ``.dbt`` file, given the starting block number."""
    start = block_num * block_size
    if block_num <= 0 or start >= len(memo):
        return b""

    # dBASE IV memos have a 8-byte header: 0xFFFF0800 + length (incl. header)
    if memo[start : start + 4] == b"\xff\xff\x08\x00":
        length = struct.unpack("<I", memo[start + 4 : start + 8])[0]
        return memo[start + 8 : start + length]

    # dBASE III memos are terminated by 0x1A 0x1A
    end = memo.find(b"\x1a\x1a", start)
    return memo[start : end if end != -1 else len(memo)]


def _convert(raw: bytes, fld: DBFField, memo: bytes | None, block_size: int):
    if fld.type == "C":
        return raw.decode(ENCODING).rstrip(" \x00")
    if fld.type in {"N", "F"}:
        text = raw.decode(ENCODING).strip()
        if not text:
            return None
        try:
            return float(text) if fld.decimals or "." in text else int(text)
        except ValueError:
            return None
    if fld.type == "L":
        return {b"T": True, b"Y": True, b"F": False, b"N": False}.get(raw.upper()[:1])
    if fld.type == "M":
        text = raw.decode(ENCODING).strip()
        if not text or memo is None:
            return b""
        return _read_memo(memo, int(text), block_size)
    if fld.type == "D":
        return raw.decode(ENCODING).strip()
    return raw


def read_dbf(
    dbf: bytes | Path, memo: bytes | Path | None = None, raw_fields: set[str] | None = None
) -> DBFTable:
    """
    Read a dBASE table.

    Args:
        dbf: Contents or path of the ``.dbf`` file
        memo: Contents or path of the ``.dbt`` memo file, if any. If a path to
            the ``.dbf`` is given and this is :obj:`None`, a ``.dbt`` file with the
            same name is used if it exists.
        raw_fields: Names of fields to return as raw :class:`bytes` instead
            of decoding them, e.g. fields holding binary timestamps.

    Raises:
        ParseError: If the file is not a valid dBASE table
    """
    if isinstance(dbf, Path):
        if memo is None:
            for suffix in (".DBT", ".dbt"):
                if dbf.with_suffix(suffix).is_file():
                    memo = dbf.with_suffix(suffix)
                    break
        dbf = dbf.read_bytes()
    if isinstance(memo, Path):
        memo = memo.read_bytes()
    raw_fields = raw_fields or set()

    if len(dbf) < 33:
        raise ParseError(f"Not a dBASE table, file is too short ({len(dbf)} bytes)")

    version = dbf[0]
    num_records, header_len, record_len = struct.unpack("<IHH", dbf[4:12])

    fields = []
    offset = 32
    while offset + 32 <= header_len and dbf[offset] != 0x0D:
        name = dbf[offset : offset + 11].split(b"\x00")[0].decode(ENCODING)
        fields.append(
            DBFField(
                name=name,
                type=chr(dbf[offset + 11]),
                length=dbf[offset + 16],
                decimals=dbf[offset + 17],
            )
        )
        offset += 32

    if not fields or 1 + sum(f.length for f in fields) > record_len:
        raise ParseError("Not a dBASE table, invalid field descriptors")

    block_size = 512
    if memo and len(memo) >= 22:
        block_size = struct.unpack("<H", memo[20:22])[0] or 512

    table = DBFTable(version=version, fields=fields)
    for i in range(num_records):
        start = header_len + i * record_len
        raw_record = dbf[start : start + record_len]
        if len(raw_record) < record_len:
            break  # truncated file

        record = {"_deleted": raw_record[0:1] == b"*"}
        pos = 1
        for fld in fields:
            raw = raw_record[pos : pos + fld.length]
            pos += fld.length
            if fld.name in raw_fields:
                record[fld.name] = raw
            else:
                record[fld.name] = _convert(raw, fld, memo, block_size)  # type: ignore[arg-type]
        table.records.append(record)

    return table


__all__ = ["DBFField", "DBFTable", "read_dbf"]
