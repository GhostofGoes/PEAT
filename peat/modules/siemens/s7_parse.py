"""
Parsers for Siemens SIMATIC S7 engineering (project and program) files.

S7 PLCs are programmed with Siemens engineering software, which stores
programs in several formats:

- **STEP 7 V5.x (SIMATIC Manager)** projects, used for S7-300 and S7-400
  PLCs. A project is a directory with a ``.s7p`` file and subdirectories of
  dBASE tables, usually shared as a ``.zip`` archive. See
  :func:`parse_step7_project`.
- **TIA Portal (STEP 7 Basic/Professional V11+)** projects, used for
  S7-1200, S7-1500, and newer S7-300/400 projects. A project is a directory
  with a ``.apNN`` file (where ``NN`` is the TIA Portal version, e.g.
  ``.ap19``), usually shared as a ``.zapNN`` archive. The project contents are
  stored in an undocumented binary format (``System/PEData.plf``), so only
  metadata and some strings are extracted. See :func:`parse_tia_archive`.
- **TIA Portal Openness XML** ("SimaticML"), the XML format that TIA Portal
  exports blocks, user-defined types, and tag tables to. See
  :func:`parse_simaticml`.
- **STL/AWL and SCL source files** (``.awl``, ``.scl``, ``.db``, ``.udt``),
  the plain text sources exported by STEP 7 V5.x and TIA Portal. See
  :func:`parse_s7_source`.
- **STEP 7 symbol tables** exported as ``.asc`` (fixed-width) or
  ``.sdf`` (CSV) files. See :func:`parse_symbol_table`.

All the parsers return plain dicts and lists, which are then mapped into the
PEAT data model by :class:`~peat.modules.siemens.s7.S7`.

References

- DotNetSiemensPLCToolBoxLibrary (STEP 7 V5 project structure):
  https://github.com/dotnetprojects/DotNetSiemensPLCToolBoxLibrary
- TIA Portal Openness system manual (SimaticML format):
  https://support.industry.siemens.com/cs/document/109826004/
- Siemens "Statement List (STL) for S7-300 and S7-400 Programming" manual,
  appendix "Source File Syntax"

Authors

- Christopher Goes
"""

import csv
import io
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

from peat import ParseError, log, utils

from .dbf import DBFTable, read_dbf

S7_EPOCH = datetime(1984, 1, 1, tzinfo=UTC)
OLE_EPOCH = datetime(1899, 12, 30, tzinfo=UTC)

# Block types, as used in the STEP 7 V5 "BAUSTEIN.DBF" block table
STEP7_BLOCK_TYPES: dict[int, str] = {
    0x00: "UDT",
    0x08: "OB",
    0x0A: "DB",
    0x0B: "SDB",
    0x0C: "FC",
    0x0D: "SFC",
    0x0E: "FB",
    0x0F: "SFB",
    0x1B: "VAT",
}

# Programming languages, as used in the STEP 7 V5 "SUBBLK.DBF" block table
STEP7_LANGUAGES: dict[int, str] = {
    0: "",
    1: "STL",
    2: "LAD",
    3: "FBD",
    4: "SCL",
    5: "DB",
    6: "GRAPH",
    7: "CFC",
    8: "SFC",
    31: "F-STL",
    32: "F-LAD",
    33: "F-FBD",
    34: "F-DB",
    35: "F-CALL",
}

# Password value in SUBBLK.DBF for blocks with "know-how protection"
STEP7_KNOW_HOW_PROTECTED = 3

# Siemens order numbers ("MLFB"), e.g. "6ES7 315-2EH14-0AB0" or "6ES7515-2AN03-0AB0"
MLFB_RE = re.compile(rb"6(?:ES7|AV\d|GK\d|ED\d|EP\d) ?\d{3}-[0-9A-Z]{5}-[0-9A-Z]{4}")
CPU_NAME_RE = re.compile(rb"CPU \d{3,4}[A-Z]*(?:[- ]\d[A-Z]*)?(?: [A-Z]{2,3}(?:/[A-Z]{2})?)?")
IPV4_RE = re.compile(
    rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
TIA_PROJECT_RE = re.compile(r"\.ap\d{2}$", re.IGNORECASE)
TIA_ARCHIVE_RE = re.compile(r"\.zap\d{2}$", re.IGNORECASE)


def convert_s7_timestamp(raw: bytes) -> datetime | None:
    """
    Convert a 6-byte S7 timestamp to a :class:`~datetime.datetime`.

    The timestamp is the number of milliseconds since midnight (4 bytes,
    big-endian), followed by the number of days since 1984-01-01 (2 bytes,
    big-endian). It's in the local time of the engineering station, the
    timezone of which isn't recorded, so it's treated as UTC.
    """
    if not isinstance(raw, bytes) or len(raw) != 6 or not any(raw):
        return None
    millis, days = struct.unpack(">IH", raw)
    if millis >= 86_400_000:
        return None
    return S7_EPOCH + timedelta(days=days, milliseconds=millis)


def convert_ole_date(raw: str) -> datetime | None:
    """
    Convert an OLE Automation date string (days since 1899-12-30, as a
    decimal number) to a :class:`~datetime.datetime`.

    SIMATIC Manager writes these with the decimal separator of the
    Windows locale, so both ``.`` and ``,`` are accepted.
    """
    try:
        return OLE_EPOCH + timedelta(days=float(raw.replace(",", ".")))
    except (ValueError, OverflowError, AttributeError):
        return None


def _clean(value: object) -> str:
    """Normalize a DBF string field, which may be padded with null bytes."""
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return str(value or "").replace("\x00", "").strip()


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# --- STEP 7 V5.x (SIMATIC Manager) projects ---


class _ProjectFiles:
    """
    Read-only access to the files of a STEP 7 V5 project, either from a
    project directory or from a ``.zip`` archive of the project.

    File lookups are case-insensitive, since STEP 7 is a Windows program and
    the case of file names isn't consistent between projects.
    """

    def __init__(self, source: Path):
        self.source = source
        self._zip: zipfile.ZipFile | None = None
        self._files: dict[str, str | Path] = {}

        if source.is_file() and zipfile.is_zipfile(source):
            self._zip = zipfile.ZipFile(source)
            names = [n for n in self._zip.namelist() if not n.endswith("/")]
            self._files = {n.lower(): n for n in names}
        else:
            root = source.parent if source.is_file() else source
            for pth in root.rglob("*"):
                if pth.is_file():
                    self._files[pth.relative_to(root).as_posix().lower()] = pth

        s7p_files = sorted(n for n in self._files if n.endswith(".s7p"))
        if not s7p_files:
            raise ParseError(f"No STEP 7 project file (.s7p) found in '{source}'")
        if len(s7p_files) > 1:
            log.warning(
                f"Found {len(s7p_files)} STEP 7 projects in '{source.name}', "
                f"only parsing the first one ({s7p_files[0]})"
            )

        self.s7p_name = s7p_files[0]
        entry = self._files[self.s7p_name]
        self.s7p_original_name = (
            entry.name if isinstance(entry, Path) else PurePosixPath(entry).name
        )
        parent = PurePosixPath(self.s7p_name).parent.as_posix()
        self.prefix = "" if parent == "." else f"{parent}/"

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()

    def names(self, pattern: str = "") -> list[str]:
        """Project-relative (lower case) names of files matching a regex."""
        regex = re.compile(pattern, re.IGNORECASE)
        return sorted(
            n[len(self.prefix) :]
            for n in self._files
            if n.startswith(self.prefix) and regex.fullmatch(n[len(self.prefix) :])
        )

    def exists(self, name: str) -> bool:
        return (self.prefix + name).lower() in self._files

    def read(self, name: str) -> bytes:
        key = (self.prefix + name).lower()
        if key not in self._files:
            raise FileNotFoundError(name)
        entry = self._files[key]
        if self._zip is not None:
            return self._zip.read(str(entry))
        return Path(entry).read_bytes()

    def read_dbf(self, name: str, raw_fields: set[str] | None = None) -> DBFTable | None:
        """Read a DBF table and its memo file, if they exist."""
        if not self.exists(name):
            return None
        memo_name = re.sub(r"\.dbf$", ".dbt", name, flags=re.IGNORECASE)
        memo = self.read(memo_name) if self.exists(memo_name) else None
        try:
            return read_dbf(self.read(name), memo, raw_fields=raw_fields)
        except ParseError as ex:
            log.warning(f"Failed to read STEP 7 table '{name}': {ex}")
            return None


def _parse_programs(files: _ProjectFiles) -> list[dict]:
    """S7 programs ("resources") in the project, from ``hrs/S7RESOFF.DBF``."""
    table = files.read_dbf("hrs/s7resoff.dbf", raw_fields={"CREATDATE", "LASTMODIF"})
    if table is None:
        return []

    links = files.read("hrs/linkhrs.lnk") if files.exists("hrs/linkhrs.lnk") else b""
    programs = []

    for row in table.records:
        if row["_deleted"]:
            continue
        program = {
            "id": _to_int(row.get("ID")),
            "name": _clean(row.get("NAME")),
            "type": _clean(row.get("HWTYPE")),
            "author": _clean(row.get("CREATOR")),
            "comment": _clean(row.get("COMMENT")),
            "created": convert_s7_timestamp(row.get("CREATDATE")),  # type: ignore[arg-type]
            "last_modified": convert_s7_timestamp(row.get("LASTMODIF")),  # type: ignore[arg-type]
        }

        # Each program has a 512-byte record in "linkhrs.lnk" at the offset
        # stored in the RSRVD4_L field (RSRVD3_L in older versions), which
        # references the ID of the program's offline block folder.
        offset = _to_int(row.get("RSRVD4_L")) or _to_int(row.get("RSRVD3_L"))
        record = links[offset : offset + 512] if links and offset else b""
        marker = record.find(b"\x01\x60\x11\x00")
        if marker != -1 and len(record) >= marker + 6:
            program["block_folder_id"] = struct.unpack("<H", record[marker + 4 : marker + 6])[0]

        programs.append(program)

    return programs


def _parse_block_folders(files: _ProjectFiles) -> list[dict]:
    """Offline block folders and their blocks, from ``ombstx/offline/``."""
    table = files.read_dbf("ombstx/offline/bstcntof.dbf", raw_fields={"CRDATE", "LASTMOD"})
    if table is None:
        return []

    folders = []
    for row in table.records:
        if row["_deleted"]:
            continue
        folder_id = _to_int(row.get("ID"))
        folder = {
            "id": folder_id,
            "name": _clean(row.get("NAME")),
            "created": convert_s7_timestamp(row.get("CRDATE")),  # type: ignore[arg-type]
            "last_modified": convert_s7_timestamp(row.get("LASTMOD")),  # type: ignore[arg-type]
            "total_size": _to_int(row.get("GESLEN")),
            "load_size": _to_int(row.get("LOADLEN")),
            "blocks": _parse_blocks(files, f"ombstx/offline/{folder_id:08x}/"),
        }
        folders.append(folder)

    return folders


def _parse_blocks(files: _ProjectFiles, folder: str) -> list[dict]:
    """
    Blocks in a block folder.

    ``BAUSTEIN.DBF`` lists the blocks (type and number). Each block is made of
    several sub-blocks in ``SUBBLK.DBF`` (code, interface, comments, etc.).
    The sub-block with the same type as the block holds the block header
    (name, family, author, version, language, timestamps) and the compiled
    MC7 code.
    """
    blocks_table = files.read_dbf(folder + "baustein.dbf")
    sub_table = files.read_dbf(
        folder + "subblk.dbf", raw_fields={"TIMESTAMP1", "TIMESTAMP2", "USERNAME"}
    )
    if blocks_table is None:
        return []

    sub_blocks: dict[int, list[dict]] = {}
    for row in sub_table.records if sub_table else []:
        if not row["_deleted"]:
            sub_blocks.setdefault(_to_int(row.get("OBJECTID")), []).append(row)

    blocks = []
    for row in blocks_table.records:
        block_type_num = _to_int(row.get("TYP"), default=-1)
        if row["_deleted"] or block_type_num not in STEP7_BLOCK_TYPES:
            continue

        block_type = STEP7_BLOCK_TYPES[block_type_num]
        block = {
            "type": block_type,
            "number": _to_int(row.get("NUMMER")),
            "id": _to_int(row.get("ID")),
        }
        block["name"] = f"{block_type}{block['number']}"

        subs = sub_blocks.get(block["id"], [])
        header = next((s for s in subs if _to_int(s.get("SUBBLKTYP")) == block_type_num), None)
        if header is None and subs:
            header = subs[0]

        if header is not None:
            mc7_code = header.get("MC5CODE") or b""
            block.update(
                {
                    "symbolic_name": _clean(header.get("BLOCKNAME")),
                    "family": _clean(header.get("BLOCKFNAME")),
                    "author": _clean(header.get("USERNAME")),
                    "version": _format_block_version(_to_int(header.get("VERSION"))),
                    "language": STEP7_LANGUAGES.get(_to_int(header.get("BLKLANG")), ""),
                    "checksum": f"{_to_int(header.get('CHECKSUM')):04X}",
                    "know_how_protected": (
                        _to_int(header.get("PASSWORD")) == STEP7_KNOW_HOW_PROTECTED
                    ),
                    "code_last_modified": convert_s7_timestamp(header.get("TIMESTAMP1")),  # type: ignore[arg-type]
                    "interface_last_modified": convert_s7_timestamp(header.get("TIMESTAMP2")),  # type: ignore[arg-type]
                    "size": _to_int(header.get("BLKTOTLEN")),
                    "code_size": _to_int(header.get("MC5LEN")),
                    "local_data_size": _to_int(header.get("LOCDATALEN")),
                }
            )
            if isinstance(mc7_code, bytes) and mc7_code:
                block["code_sha256"] = utils.calc_hash(mc7_code, "sha256")
        blocks.append(block)

    return sorted(blocks, key=lambda b: (b["type"], b["number"]))


def _format_block_version(raw: int) -> str:
    """Block versions are stored as one byte, with the major version in the high nibble."""
    return f"{raw >> 4}.{raw & 0x0F}" if raw else ""


def _parse_symbol_tables(files: _ProjectFiles) -> list[dict]:
    """Symbol tables, from ``YDBs/SYMLISTS.DBF`` and ``YDBs/<id>/SYMLIST.DBF``."""
    table = files.read_dbf("ydbs/symlists.dbf")
    if table is None:
        return []

    # Maps each symbol table to the S7 program it belongs to
    links = {}
    link_table = files.read_dbf("ydbs/ylnklist.dbf")
    for row in link_table.records if link_table else []:
        if not row["_deleted"]:
            links[_to_int(row.get("SOI"))] = _to_int(row.get("TOI"))

    symbol_tables = []
    for row in table.records:
        if row["_deleted"] or row.get("_DELETED"):
            continue
        table_id = _to_int(row.get("_ID"))
        db_path = _clean(row.get("_DBPATH")) or str(table_id)
        symbols_table = files.read_dbf(f"ydbs/{db_path}/symlist.dbf")

        symbols = []
        for sym in symbols_table.records if symbols_table else []:
            if sym["_deleted"]:
                continue
            symbols.append(
                {
                    "name": _clean(sym.get("_SKZ")),
                    "address": re.sub(r"\s+", " ", _clean(sym.get("_OPHIST"))),
                    "address_iec": re.sub(r"\s+", " ", _clean(sym.get("_OPIEC"))),
                    "data_type": re.sub(r"\s+", " ", _clean(sym.get("_DATATYP"))),
                    "comment": _clean(sym.get("_COMMENT")),
                }
            )

        symbol_tables.append(
            {
                "id": table_id,
                "name": _clean(row.get("_UNAME")),
                "program_id": links.get(table_id),
                "last_modified": (
                    datetime.fromtimestamp(_to_int(row.get("_TIME")), tz=UTC)
                    if _to_int(row.get("_TIME"))
                    else None
                ),
                "symbols": symbols,
            }
        )

    return symbol_tables


def _parse_change_log(files: _ProjectFiles) -> list[dict]:
    """
    Project change log, from ``siprom/CHANGELOG.DBF``.

    This records the Windows computer and user name for changes made
    to the project, which is valuable for forensics.
    """
    table = files.read_dbf("siprom/changelog.dbf")
    if table is None:
        return []

    entries = []
    for row in table.records:
        if row["_deleted"]:
            continue
        cause = row.get("CAUSE")
        event = row.get("EVENT")
        entries.append(
            {
                "id": _to_int(row.get("ID")),
                "timestamp": convert_ole_date(_clean(row.get("DATETIME"))),
                "computer": _clean(row.get("COMPUTER")),
                "user": _clean(row.get("USER")),
                "action": _to_int(row.get("ACTION")),
                "object_path": _clean(row.get("OBJECTPATH")),
                "event": _clean(event) if isinstance(event, bytes) else "",
                "cause": _clean(cause) if isinstance(cause, bytes) else "",
            }
        )
    return entries


def parse_step7_project(source: Path) -> dict:
    """
    Parse a STEP 7 V5.x (SIMATIC Manager) project.

    Args:
        source: Path to the ``.s7p`` file, the project directory, or a
            ``.zip`` archive of the project (as created by
            "File > Archive" in SIMATIC Manager)

    Returns:
        Project information, S7 programs, block folders with blocks,
        symbol tables, and the project change log

    Raises:
        ParseError: If the source isn't a STEP 7 project
    """
    files = _ProjectFiles(source)
    try:
        s7p_data = files.read(files.s7p_name.rsplit("/", 1)[-1])
        project = {
            "format": "STEP 7 V5 project",
            "name": Path(files.s7p_original_name).stem,
            "s7p_file": files.s7p_original_name,
        }

        # The .s7p file starts with the length-prefixed project name and GUID
        if len(s7p_data) > 5 and s7p_data[4] < len(s7p_data) - 5:
            name_len = s7p_data[4]
            internal_name = s7p_data[5 : 5 + name_len].decode("latin-1", "replace")
            if internal_name.isprintable():
                project["name"] = internal_name.strip() or project["name"]
            guid = re.search(rb"\{[0-9A-Fa-f-]{36}\}", s7p_data)
            if guid:
                project["guid"] = guid.group().decode()

        project["programs"] = _parse_programs(files)
        project["block_folders"] = _parse_block_folders(files)
        project["symbol_tables"] = _parse_symbol_tables(files)
        project["change_log"] = _parse_change_log(files)
        project["has_hardware_config"] = bool(files.names(r"homsave7/.*"))
        project["source_files"] = files.names(r"s7asrcom/.*\.(awl|scl|gr7|inp|txt)")
    finally:
        files.close()

    return project


# --- TIA Portal projects and archives ---


def parse_tia_archive(source: Path) -> dict:
    """
    Parse a TIA Portal project (``.apNN``) or archive (``.zapNN``).

    The project file is a small XML document with the project name and
    TIA Portal version. The actual project data (``System/PEData.plf``)
    is an undocumented binary format, so the order numbers, CPU names,
    and IPv4 addresses found in it are extracted with regular expressions.
    These extracted values are best-effort and may include values from
    hardware catalog data that isn't part of the configuration.

    Args:
        source: Path to a ``.zapNN`` archive, a ``.apNN`` project
            file, or a TIA Portal project directory

    Raises:
        ParseError: If the source isn't a TIA Portal project
    """
    project_xml = b""
    pe_data = b""
    contents: list[dict] = []
    name = ""

    if source.is_file() and zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                contents.append({"name": info.filename, "size": info.file_size})
                if TIA_PROJECT_RE.search(info.filename) and "/" not in info.filename.strip("/"):
                    project_xml = zf.read(info)
                    name = info.filename
                elif info.filename.lower().endswith("system/pedata.plf"):
                    pe_data = zf.read(info)
    else:
        root = source.parent if source.is_file() else source
        project_files = [source] if source.is_file() else sorted(root.glob("*.ap[0-9][0-9]"))
        if project_files:
            project_xml = project_files[0].read_bytes()
            name = project_files[0].name
        plf = root / "System" / "PEData.plf"
        if plf.is_file():
            pe_data = plf.read_bytes()
        for pth in sorted(root.rglob("*")):
            if pth.is_file():
                contents.append(
                    {"name": pth.relative_to(root).as_posix(), "size": pth.stat().st_size}
                )

    if not project_xml:
        raise ParseError(f"No TIA Portal project file (.apNN) found in '{source}'")

    project: dict = {"format": "TIA Portal project", "project_file": name, "contents": contents}
    try:
        root_el = ET.fromstring(project_xml)
        project["name"] = root_el.get("Name", "")
        project["compatibility_version"] = root_el.get("ProjectCompatibilityVersion", "")
        for child in root_el:
            if _local_name(child.tag) == "ProjectVersion":
                project["version"] = (child.text or "").strip()
    except ET.ParseError as ex:
        raise ParseError(f"Invalid TIA Portal project file '{name}': {ex}") from None

    match = re.search(r"\d{2}$", Path(name).suffix)
    if match:
        project["tia_portal_version"] = f"V{int(match.group())}"

    if pe_data:
        project["pe_data_sha256"] = utils.calc_hash(pe_data, "sha256")
        project["order_numbers"] = _unique_strings(MLFB_RE.findall(pe_data))
        project["cpu_names"] = _unique_strings(CPU_NAME_RE.findall(pe_data))
        project["ipv4_addresses"] = _find_prefixed_ipv4(pe_data)

    return project


def _find_prefixed_ipv4(data: bytes) -> list[str]:
    """
    Find IPv4 addresses in PEData, which stores strings with a 4-byte
    little-endian length prefix. Requiring the prefix avoids matching the
    many version numbers (e.g. ``15.0.0.0``) that are also in the file.
    """
    found = []
    for match in IPV4_RE.finditer(data):
        start = match.start()
        value = match.group()
        if (
            start >= 4
            and data[start - 4 : start] == struct.pack("<I", len(value))
            and value != b"0.0.0.0"  # Unset address, e.g. no gateway
        ):
            found.append(value)
    return _unique_strings(found)


def _unique_strings(values: list[bytes]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value.decode("latin-1").strip(), None)
    return list(seen)


# --- TIA Portal Openness XML (SimaticML) ---


def _local_name(tag: str) -> str:
    """Strip the XML namespace from a tag name."""
    return tag.rsplit("}", 1)[-1]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == name:
            return child
    return None


def _child_text(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    child = _child(element, name)
    return (child.text or "").strip() if child is not None else ""


def _multilingual_text(element: ET.Element, composition_name: str) -> dict[str, str]:
    """Texts of a MultilingualText object (e.g. a block title or comment), by culture."""
    texts = {}
    for mlt in element.iter():
        if (
            _local_name(mlt.tag) != "MultilingualText"
            or mlt.get("CompositionName") != composition_name
        ):
            continue
        for item in mlt.iter():
            if _local_name(item.tag) == "MultilingualTextItem":
                attrs = _child(item, "AttributeList")
                text = _child_text(attrs, "Text")
                if text:
                    texts[_child_text(attrs, "Culture")] = text
        break
    return texts


def _interface_members(section: ET.Element) -> list[dict]:
    members = []
    for member in section:
        if _local_name(member.tag) != "Member":
            continue
        entry = {"name": member.get("Name", ""), "data_type": member.get("Datatype", "")}
        start_value = _child_text(member, "StartValue")
        if start_value:
            entry["start_value"] = start_value
        comment = _child(member, "Comment")
        if comment is not None:
            texts = [t.text.strip() for t in comment if t.text and t.text.strip()]
            if texts:
                entry["comment"] = texts[0]
        nested = [m for m in member if _local_name(m.tag) in ("Member", "Sections")]
        if nested:
            entry["members"] = _interface_members(member)
        members.append(entry)
    return members


def _parse_interface(attributes: ET.Element) -> dict[str, list[dict]]:
    interface = _child(attributes, "Interface")
    if interface is None:
        return {}
    sections = {}
    for element in interface.iter():
        if _local_name(element.tag) == "Section" and element.get("Name"):
            members = _interface_members(element)
            if members:
                sections[element.get("Name", "")] = members
    return sections


def _network_source(compile_unit: ET.Element) -> tuple[str, str]:
    """
    Get the language and a text representation of a network (CompileUnit).

    Structured Text (SCL) and STL networks are stored as a sequence of
    tokens, which are joined back into source code. Graphical networks
    (LAD, FBD, GRAPH) are stored as a graph of parts and wires, which isn't
    converted to text, so the source is empty for those.
    """
    attrs = _child(compile_unit, "AttributeList")
    language = _child_text(attrs, "ProgrammingLanguage")
    source = _child(attrs, "NetworkSource") if attrs is not None else None
    if source is None or not len(source):
        return language, ""

    body = source[0]
    if _local_name(body.tag) == "StructuredText":
        return language, _structured_text(body)
    if _local_name(body.tag) == "StatementList":
        return language, _statement_list(body)
    return language, ""


def _token_text(element: ET.Element) -> str:
    name = _local_name(element.tag)
    if name in ("Token", "Text"):
        return element.get("Text", element.text or "")
    if name == "Blank":
        return " " * int(element.get("Num", "1"))
    if name == "NewLine":
        return "\n" * int(element.get("Num", "1"))
    if name == "LineComment":
        return "//" + "".join(_token_text(c) for c in element)
    if name == "Comment":
        return "(*" + "".join(_token_text(c) for c in element) + "*)"
    if name == "Access":
        scope = element.get("Scope", "")
        inner = "".join(_token_text(c) for c in element)
        if scope == "LocalVariable":
            return f"#{inner}"
        if scope == "GlobalVariable":
            return f'"{inner}"' if not inner.startswith('"') else inner
        return inner
    if name == "Symbol":
        return ".".join(_token_text(c) for c in element if _local_name(c.tag) == "Component")
    if name == "Component":
        return element.get("Name", "")
    if name == "Constant":
        value = _child(element, "ConstantValue")
        return (value.text or "") if value is not None else ""
    if name == "Address":
        return f"%{element.get('Area', '')}{element.get('BitOffset', '')}"
    return "".join(_token_text(c) for c in element)


def _structured_text(body: ET.Element) -> str:
    return "".join(_token_text(child) for child in body).strip()


def _statement_list(body: ET.Element) -> str:
    lines = []
    for statement in body:
        if _local_name(statement.tag) == "StlStatement":
            lines.append(" ".join(_token_text(t) for t in statement if _token_text(t).strip()))
    return "\n".join(lines)


def _parse_block(element: ET.Element) -> dict:
    attrs = _child(element, "AttributeList")
    block_class = _local_name(element.tag).split(".", 2)[-1]  # e.g. "FB", "GlobalDB"
    block = {
        "type": block_class,
        "name": _child_text(attrs, "Name"),
        "number": _to_int(_child_text(attrs, "Number"), default=0) or None,
        "language": _child_text(attrs, "ProgrammingLanguage"),
        "memory_layout": _child_text(attrs, "MemoryLayout"),
        "interface": _parse_interface(attrs) if attrs is not None else {},
    }
    for optional in ("HeaderAuthor", "HeaderFamily", "HeaderName", "HeaderVersion",
                     "InstanceOfName", "Namespace"):  # fmt: skip
        value = _child_text(attrs, optional)
        if value:
            block[utils.convert_to_snake_case(optional)] = value

    title = _multilingual_text(element, "Title")
    comment = _multilingual_text(element, "Comment")
    if title:
        block["title"] = title
    if comment:
        block["comment"] = comment

    networks = []
    object_list = _child(element, "ObjectList")
    for unit in object_list if object_list is not None else []:
        if _local_name(unit.tag) != "SW.Blocks.CompileUnit":
            continue
        language, source = _network_source(unit)
        network = {"language": language}
        net_title = _multilingual_text(unit, "Title")
        if net_title:
            network["title"] = net_title
        if source:
            network["source"] = source
        networks.append(network)
    if networks:
        block["networks"] = networks

    return block


def _parse_tag_table(element: ET.Element) -> dict:
    attrs = _child(element, "AttributeList")
    table = {"name": _child_text(attrs, "Name"), "tags": [], "constants": []}
    object_list = _child(element, "ObjectList")
    for item in object_list if object_list is not None else []:
        kind = _local_name(item.tag)
        item_attrs = _child(item, "AttributeList")
        if kind == "SW.Tags.PlcTag":
            tag = {
                "name": _child_text(item_attrs, "Name"),
                "data_type": _child_text(item_attrs, "DataTypeName"),
                "address": _child_text(item_attrs, "LogicalAddress"),
            }
            comment = _multilingual_text(item, "Comment")
            if comment:
                tag["comment"] = next(iter(comment.values()))
            table["tags"].append(tag)
        elif kind in ("SW.Tags.PlcUserConstant", "SW.Tags.PlcSystemConstant"):
            table["constants"].append(
                {
                    "name": _child_text(item_attrs, "Name"),
                    "data_type": _child_text(item_attrs, "DataTypeName"),
                    "value": _child_text(item_attrs, "Value"),
                }
            )
    return table


def parse_simaticml(data: str | bytes) -> dict:
    """
    Parse a TIA Portal Openness XML ("SimaticML") export.

    Exports contain a single object: a block (OB, FB, FC, global or instance
    DB), a PLC data type (UDT), or a PLC tag table.

    Raises:
        ParseError: If the data isn't a valid SimaticML document
    """
    try:
        root = ET.fromstring(data)
    except ET.ParseError as ex:
        raise ParseError(f"Invalid SimaticML XML: {ex}") from None

    if _local_name(root.tag) != "Document":
        raise ParseError(f"Not a SimaticML document (root element is '{root.tag}')")

    engineering = _child(root, "Engineering")
    doc_info = _child(root, "DocumentInfo")
    result: dict = {
        "format": "TIA Portal Openness XML",
        "engineering_version": engineering.get("version", "") if engineering is not None else "",
        "blocks": [],
        "types": [],
        "tag_tables": [],
    }

    created = _child_text(doc_info, "Created")
    if created:
        result["created"] = utils.parse_date(created)

    products = []
    installed = _child(doc_info, "InstalledProducts") if doc_info is not None else None
    for product in installed if installed is not None else []:
        products.append(
            {
                "name": _child_text(product, "DisplayName"),
                "version": _child_text(product, "DisplayVersion"),
                "type": _local_name(product.tag),
            }
        )
    if products:
        result["installed_products"] = products

    for element in root:
        name = _local_name(element.tag)
        if name.startswith("SW.Blocks."):
            result["blocks"].append(_parse_block(element))
        elif name in ("SW.Types.PlcStruct", "SW.Types.PlcType"):
            attrs = _child(element, "AttributeList")
            result["types"].append(
                {
                    "name": _child_text(attrs, "Name"),
                    "interface": _parse_interface(attrs) if attrs is not None else {},
                }
            )
        elif name == "SW.Tags.PlcTagTable":
            result["tag_tables"].append(_parse_tag_table(element))

    if not (result["blocks"] or result["types"] or result["tag_tables"]):
        raise ParseError("SimaticML document doesn't contain any blocks, types, or tag tables")

    return result


# --- STL (AWL) and SCL source files ---

BLOCK_KEYWORDS: dict[str, str] = {
    "ORGANIZATION_BLOCK": "OB",
    "FUNCTION_BLOCK": "FB",
    "FUNCTION": "FC",
    "DATA_BLOCK": "DB",
    "TYPE": "UDT",
}

BLOCK_START_RE = re.compile(
    r"^\s*(ORGANIZATION_BLOCK|FUNCTION_BLOCK|FUNCTION|DATA_BLOCK|TYPE)\s+"
    r"(\"[^\"]+\"|[A-Za-z_][\w]*(?:\s*\d+)?)"
    r"(?:\s*:\s*([\w\"]+))?",
    re.IGNORECASE | re.MULTILINE,
)
VAR_SECTION_RE = re.compile(
    r"^\s*(VAR_INPUT|VAR_OUTPUT|VAR_IN_OUT|VAR_TEMP|VAR_STAT|VAR\s+CONSTANT|VAR)\b",
    re.IGNORECASE,
)
MEMBER_RE = re.compile(
    r"^\s*\"?([A-Za-z_][\w]*)\"?\s*(?:\{[^}]*\})?\s*(?:AT\s+\w+\s*)?:\s*"
    r"([^;:=]+?)\s*(?::=\s*([^;]+?))?\s*;?\s*$",
)
COMMENT_RE = re.compile(r"//\s*(.*)$|\(\*\s*(.*?)\s*\*\)")
SECTION_NAMES: dict[str, str] = {
    "VAR_INPUT": "Input",
    "VAR_OUTPUT": "Output",
    "VAR_IN_OUT": "InOut",
    "VAR_TEMP": "Temp",
    "VAR_STAT": "Static",
    "VAR CONSTANT": "Constant",
    "VAR": "Static",
}


def _parse_source_block(keyword: str, name: str, return_type: str, body: str) -> dict:
    block_type = BLOCK_KEYWORDS[keyword.upper()]
    block: dict = {"type": block_type, "name": name.strip().strip('"')}
    number = re.fullmatch(r"(OB|FB|FC|DB|UDT|SFB|SFC)\s*(\d+)", block["name"], re.IGNORECASE)
    if number:
        block["number"] = int(number.group(2))
    if return_type and block_type == "FC":
        block["return_type"] = return_type.strip('"')

    for prop, key in (("TITLE", "title"), ("AUTHOR", "author"), ("FAMILY", "family"),
                      ("NAME", "header_name"), ("VERSION", "version")):  # fmt: skip
        match = re.search(
            rf"^[ \t]*{prop}[ \t]*[:=][ \t]*(.*?)[ \t]*$", body, re.IGNORECASE | re.MULTILINE
        )
        value = match.group(1).strip().strip("'\"").strip() if match else ""
        if value:
            block[key] = value

    if re.search(r"^\s*KNOW_HOW_PROTECT\b", body, re.IGNORECASE | re.MULTILINE):
        block["know_how_protected"] = True

    attributes = re.search(r"^\s*\{([^}]*)\}", body, re.MULTILINE)
    if attributes and ":=" in attributes.group(1):
        pairs = (a.partition(":=") for a in attributes.group(1).split(";"))
        block["attributes"] = {k.strip(): v.strip().strip("'") for k, _, v in pairs if k.strip()}

    interface: dict[str, list[dict]] = {}
    section = None
    depth = 0
    for line in body.splitlines():
        stripped = line.strip()
        upper = stripped.upper()
        if section is None:
            match = VAR_SECTION_RE.match(stripped)
            if match:
                section = SECTION_NAMES[re.sub(r"\s+", " ", match.group(1).upper())]
                if block_type == "DB" and section == "Static":
                    section = "Static"
            elif upper.startswith("STRUCT") and block_type in ("DB", "UDT"):
                section = "Static"
            continue
        if upper.startswith("END_VAR") or (upper.startswith("END_STRUCT") and depth == 0):
            section = None
            continue
        if upper.startswith("END_STRUCT"):
            depth -= 1
            continue
        if upper.rstrip(";") == "STRUCT":  # e.g. "ARRAY[0..9] OF" on the previous line
            depth += 1
            continue

        comment = COMMENT_RE.search(stripped)
        declaration = COMMENT_RE.sub("", stripped).strip()
        match = MEMBER_RE.match(declaration)
        if not match:
            continue
        data_type = match.group(2).strip()
        if depth == 0:
            member = {"name": match.group(1), "data_type": data_type}
            if match.group(3):
                member["start_value"] = match.group(3).strip()
            if comment and (comment.group(1) or comment.group(2)):
                member["comment"] = (comment.group(1) or comment.group(2)).strip()
            interface.setdefault(section, []).append(member)
        if data_type.upper() == "STRUCT":
            depth += 1

    if interface:
        block["interface"] = interface

    code = re.split(r"^\s*BEGIN\b", body, maxsplit=1, flags=re.IGNORECASE | re.MULTILINE)
    if len(code) == 2:
        networks = re.findall(r"^\s*NETWORK\b", code[1], re.IGNORECASE | re.MULTILINE)
        if networks:
            block["network_count"] = len(networks)
        code_lines = sum(
            1 for ln in code[1].splitlines() if ln.strip() and not ln.strip().startswith("//")
        )
        if code_lines:
            block["code_lines"] = code_lines

    return block


def parse_s7_source(text: str, filename: str = "") -> dict:
    """
    Parse a STL (AWL) or SCL source file, as exported from STEP 7 V5.x
    or TIA Portal.

    A source file can contain several blocks. For each block, the block
    type and name, header attributes (title, author, family, name, version),
    know-how protection, and the declared interface are extracted.

    Raises:
        ParseError: If no blocks are found in the source
    """
    starts = list(BLOCK_START_RE.finditer(text))
    blocks = []
    for i, match in enumerate(starts):
        end_keyword = f"END_{match.group(1).upper()}"
        stop = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        body = text[match.end() : stop]
        end = re.search(rf"^\s*{end_keyword}\b", body, re.IGNORECASE | re.MULTILINE)
        if end:
            body = body[: end.start()]
        elif match.group(1).upper() == "TYPE" and "STRUCT" not in body.upper():
            continue  # "TYPE" used as an identifier, not a UDT declaration
        blocks.append(_parse_source_block(match.group(1), match.group(2), match.group(3), body))

    if not blocks:
        raise ParseError(f"No S7 blocks found in source file '{filename}'")

    suffix = Path(filename).suffix.lower()
    if suffix == ".awl":
        language = "STL"
    elif suffix == ".scl":
        language = "SCL"
    elif re.search(r"^\s*NETWORK\b", text, re.IGNORECASE | re.MULTILINE):
        language = "STL"
    else:
        language = "SCL" if ":=" in text else ""

    for block in blocks:
        if block["type"] in ("DB", "UDT"):
            block["language"] = "DB"
        elif language:
            block["language"] = language

    return {"format": f"{language} source".strip(), "blocks": blocks}


# --- Symbol tables ---


def parse_symbol_table(text: str, filename: str = "") -> list[dict]:
    """
    Parse a STEP 7 symbol table export.

    Supported formats:

    - ``.asc``: fixed-width columns, each line starts with ``126,``, followed
      by the symbol (24 characters), address (12), data type (10), and
      comment (80).
    - ``.sdf``: "System Data Format", a CSV file with quoted values in the
      order symbol, address, data type, comment.

    Raises:
        ParseError: If no symbols are found
    """
    symbols = []
    lines = [ln for ln in text.splitlines() if ln.strip()]

    if lines and all(ln.startswith("126,") for ln in lines):
        for line in lines:
            row = line[4:]
            symbols.append(
                {
                    "name": row[0:24].strip(),
                    "address": re.sub(r"\s+", " ", row[24:36].strip()),
                    "data_type": re.sub(r"\s+", " ", row[36:46].strip()),
                    "comment": row[46:126].strip(),
                }
            )
    else:
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 3 and row[0].strip():
                symbols.append(
                    {
                        "name": row[0].strip(),
                        "address": re.sub(r"\s+", " ", row[1].strip()),
                        "data_type": row[2].strip(),
                        "comment": row[3].strip() if len(row) > 3 else "",
                    }
                )

    if not symbols:
        raise ParseError(f"No symbols found in symbol table '{filename}'")
    return symbols


# --- File type detection ---


def is_step7_archive(source: Path) -> bool:
    """If a file is a ``.zip`` archive with a STEP 7 V5 project in it."""
    try:
        with zipfile.ZipFile(source) as zf:
            return any(n.lower().endswith(".s7p") for n in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


def is_tia_archive(source: Path) -> bool:
    """If a file is a ``.zip`` archive with a TIA Portal project in it."""
    try:
        with zipfile.ZipFile(source) as zf:
            return any(TIA_PROJECT_RE.search(n) for n in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


def detect_file_type(source: Path) -> str:
    """
    Determine the type of a S7 engineering file.

    Returns:
        One of ``step7_project``, ``tia_project``, ``simaticml``,
        ``source``, ``symbol_table``, or an empty string if unknown
    """
    suffix = source.suffix.lower()

    if source.is_dir():
        if any(source.glob("*.[sS]7[pP]")):
            return "step7_project"
        if any(source.glob("*.ap[0-9][0-9]")):
            return "tia_project"
        return ""

    if suffix == ".s7p":
        return "step7_project"
    if TIA_PROJECT_RE.search(source.name) or TIA_ARCHIVE_RE.search(source.name):
        return "tia_project"
    if zipfile.is_zipfile(source):
        if is_step7_archive(source):
            return "step7_project"
        if is_tia_archive(source):
            return "tia_project"
        return ""

    head = source.read_bytes()[:4096]
    if b"DataInfoValueData" in head and b'Type="Project"' in head:
        return "tia_project"
    if b"<Document" in head and (b"<Engineering" in head or b"<SW." in head):
        return "simaticml"
    if suffix in (".asc", ".sdf") or head.startswith(b"126,"):
        return "symbol_table"
    if suffix in (".awl", ".scl", ".db", ".udt", ".stl") or BLOCK_START_RE.search(
        head.decode("latin-1")
    ):
        return "source"
    return ""


__all__ = [
    "convert_ole_date",
    "convert_s7_timestamp",
    "detect_file_type",
    "parse_s7_source",
    "parse_simaticml",
    "parse_step7_project",
    "parse_symbol_table",
    "parse_tia_archive",
]
