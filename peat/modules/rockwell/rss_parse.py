"""
Parse Rockwell RSLogix 500 project files (``.RSS``).

RSLogix 500 (and RSLogix Micro) is the engineering software for the
Allen-Bradley SLC 500 and MicroLogix PLCs. A project file (``*.RSS``,
including automatic backups like ``PROJECT_BAK000.RSS``) is an undocumented
binary format. The layout below was reverse engineered from a handful of
real project files, so parts of it are **inferred**. Everything that can't
be decoded is still extracted raw.

Container (confirmed):
    An OLE2 / MS-CFB compound file. Each top-level storage (``PROCESSOR``,
    ``PROGRAM FILES``, ``DATA FILES``, ``MEM DATABASE``, ...) contains one
    ``ObjectData`` stream. ``ONLINEIMAGE/<storage>`` holds copies of some
    storages, inferred to be the image from the last online session.
    ``\\x05SummaryInformation`` has the standard OLE properties plus some
    custom ones: 20 = processor name, 25 = number of program files and
    32 = number of data files. The first DWORD of the ``Contents`` stream is
    the file format version (0x71 and 0x80 have been seen).

``ObjectData`` header (confirmed):
    Four little-endian DWORDs: compression mode (0 = stored, 1 = PKWARE DCL
    implode, 2 = zlib), header size (always 16), stored size and decoded size.
    The decoded payload is MFC ``CArchive`` serialization (see
    :mod:`peat.parsing.mfc_archive`), starting with a class definition such
    as ``CProc`` or ``CProgHolder``.

Ladder logic (``PROGRAM FILES``, confirmed on the samples):
    ``CProgHolder`` (number of program files), then one ``CLadFile`` per
    program file (rungs, type, name, file number), then the rungs. Each rung
    is a tree of ``CRung``, ``CBranchLeg`` and ``CBranch`` objects whose
    leaves are ``CIns`` instructions. A ``CIns`` is a WORD count of operand
    strings, the strings, a WORD flag, a WORD opcode, a reserved DWORD, and
    (if the flag is set) a WORD length and a blob of compiled bytes whose
    meaning is unknown. The rung topology is carried by structural opcodes
    (start/end of rung, branch start/end, leg start/end), so the parser scans
    for ``CIns`` records instead of decoding the other objects. Word operands
    are stored as (text, cached value) pairs. See
    :mod:`peat.modules.rockwell.rss_const` for the opcode table and the
    confidence of each mnemonic.

Documentation (``MEM DATABASE``, class ``DBXMemMap``):
    Address entries (confirmed): the address in a zero-padded form such as
    ``N0007:003/05``, a symbol (position inferred, empty in all samples), five
    description lines, and a trailer of unknown meaning (16 or 24 bytes). Rung
    comments (confirmed): a WORD count, then for each comment a DWORD, the
    comment text, a string of unknown use (empty in all samples, maybe a page
    title), and a key ``RUNG<file:06>-<rung:06>``.

Untrusted input:
    Every read is bounds checked. The size of the decoded streams (per stream
    and per file), the number of decoded records, and the work spent scanning
    for records at offsets that turn out to be invalid are all limited, so a
    corrupt or crafted file can't use up memory or take hours to parse. When a
    limit is reached, the parse continues with what was decoded and records
    a warning.

Not decoded (extracted raw only): data table values (``DATA FILES``), I/O and
channel configuration, the legacy ``DATABASE`` stream of old files, and the
VBA macro source code. The processor type code is reported as a number
because the mapping to catalog numbers is unknown. Password fields are never
decoded.

References:

- morluto/rea issue #3494, notes on the RSS format:
  https://github.com/morluto/rea/issues/3494
- MFC TN002, Persistent Object Data Format:
  https://learn.microsoft.com/en-us/cpp/mfc/tn002-persistent-object-data-format
- MS-CFB and MS-OVBA specifications:
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/ and
  https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/
"""

import codecs
import hashlib
import re
import struct
import zlib
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import olefile

from peat import log
from peat.consts import ParseError
from peat.parsing.mfc_archive import MfcFormatError, MfcReader, find_class_defs
from peat.parsing.pkware_dcl import DCLError, explode

from .rss_const import (
    BND,
    BST,
    COMPRESSION_MODES,
    DEFAULT_PROCESSOR_NAME,
    EOR,
    FILE_TYPE_NAMES,
    LADDER_FILE_TYPES,
    LEG_END,
    LEG_START,
    MAX_DECODED_STREAM_SIZE,
    MAX_STREAM_COUNT,
    MAX_TOTAL_DECODED_SIZE,
    RSS_OPCODES,
    RSS_REQUIRED_STORAGES,
    SOR,
)

__all__ = [
    "RssContainer",
    "RssStream",
    "address_type_name",
    "compare_online_image",
    "decode_object_data",
    "find_referenced_data_files",
    "is_default_processor_name",
    "is_default_status_address",
    "is_rslogix500_project",
    "normalize_address",
    "parse_contents",
    "parse_mem_database",
    "parse_processor",
    "parse_program_files",
    "parse_rss",
    "parse_summary_info",
    "parse_vba_project",
    "parse_version",
    "read_rss",
    "render_ladder_text",
    "render_rung",
]

#: Name of the stream that holds the serialized object in each storage
OBJECT_DATA = "ObjectData"

#: Prefix of the storages that hold the image from the last online session
ONLINE_IMAGE = "ONLINEIMAGE"

#: Stream with the text description of the embedded VBA project
VBA_PROJECT_STREAM = "apc/The VBA Project/_VBA_Project/PROJECT"

#: Default (empty) VBA document for a RSLogix 500 project
_DEFAULT_VBA_DOCUMENT = "RSLogix_500_Project"

_HEADER = struct.Struct("<4I")
_LADHDR = struct.Struct("<HH10sHBH")  # rungs, type, name, number, flag, rung count

#: MFC class tag of ``CLadFile`` objects after the first. ``CProgHolder`` is
#: the first class (index 1) and object (index 2), so ``CLadFile`` is index 3.
_LADFILE_TAG = b"\x03\x80"

#: Most operand strings that will be accepted for one instruction
_MAX_OPERANDS = 32
#: Longest operand string that will be accepted
_MAX_OPERAND_LENGTH = 255
#: Largest compiled blob that will be accepted for one instruction
_MAX_BLOB_LENGTH = 4096
#: Largest number of program files (SLC 500 allows file numbers 0 to 255)
_MAX_PROGRAM_FILES = 256
#: Extra output allowed beyond the declared size when decompressing DCL data
_DCL_SLACK = 64 * 1024
#: Most MFC class definitions looked at in a payload (real payloads have a few)
_MAX_CLASS_DEFS = 4096

# The ladder decoder tries to read an instruction at many offsets (when
# learning the CIns tag, and when resyncing after a record that isn't an
# instruction). These limits bound the work for one PROGRAM FILES payload,
# so a corrupt or crafted file can't make the parse take hours. Real project
# files are far below them.

#: Most offsets tried when learning the CIns tag
_MAX_VOTE_ATTEMPTS = 100_000
#: Most failed instruction reads when decoding the rungs
_MAX_RESYNC_ATTEMPTS = 100_000
#: Most bytes read by the attempts above (each), before giving up
_MAX_SCAN_BYTES = 16 * 1024 * 1024
#: Most instructions decoded from one PROGRAM FILES payload. The largest
#: SLC 500 processors have 64K words of memory, so real projects have far
#: fewer instructions than this.
_MAX_INSTRUCTIONS = 250_000

# Candidate MFC object tags (short or big form) followed by an operand count of 1-32
_CINS_CANDIDATE_RE = re.compile(
    rb"(?=(\xff\x7f[\x00-\xff]{3}[\x80-\xff]|[\x00-\xff][\x80-\xff])[\x01-\x20]\x00)", re.S
)

# Address of a documented data table element in the "MEM DATABASE". Specialty
# I/O module files are "M0" and "M1" followed by a file number of 0000, e.g.
# "M10000:008.000" is "M1:8.0"
_DB_ADDRESS_RE = re.compile(r"(M[01]|[A-Z]{1,3})(\d{4}):(\d{3})(?:\.(\d{3}))?(?:/(\d{2}))?")
# Documented program files, e.g. "PFILE:00003" and "U:00003"
_DB_PROGRAM_RE = re.compile(r"(PFILE|U):(\d{5})")
# Any "MEM DATABASE" entry key, which also includes forms such as "M00000:008.000"
_DB_ENTRY_RE = re.compile(r"[A-Z]{1,5}\d{0,5}:\d{3,5}(?:\.\d{3})?(?:/\d{2})?")
# Candidate length byte for an entry key CString in the "MEM DATABASE"
_DB_ENTRY_CANDIDATE_RE = re.compile(rb"[\x03-\x28](?=[A-Z]{1,5}\d{0,5}:\d{3})")
_RUNG_KEY_RE = re.compile(r"RUNG(\d{6})-(\d{6})")
#: Longest rung comment text (or title) that will be accepted, in characters
_MAX_RUNG_COMMENT_LENGTH = 64 * 1024
#: Furthest the rung comment count can be before the first comment key. Only
#: the ID, text and title of the first comment are between them.
_MAX_COMMENT_COUNT_DISTANCE = 2 + 4 + 2 * (7 + 2 * _MAX_RUNG_COMMENT_LENGTH)
#: Most possible offsets of the rung comment count that are fully decoded
_MAX_COMMENT_COUNT_ATTEMPTS = 8
#: Most offsets that look like (but aren't) a database entry, before giving up
_MAX_DB_ENTRY_FAILURES = 200_000
#: Most database entries (documented addresses) that will be decoded
_MAX_DB_ENTRIES = 250_000
_RUNG_KEY_BYTES_RE = re.compile(rb"\x11RUNG\d{6}-\d{6}")

# Data file references in instruction operands, e.g. "N7:2", "#N10:4", "T4:1.ACC", "S:1/13"
_OPERAND_FILE_RE = re.compile(r"(?<![A-Za-z0-9\[])#?([A-Z]{1,3})(\d{1,3})?:\d")
# Data files that can be referenced without a file number
_IMPLIED_FILE_NUMBERS = {"O": 0, "I": 1, "S": 2}

# SummaryInformation property IDs (standard and RSLogix 500 specific), with
# their names and expected types
_SUMMARY_PROPERTIES: dict[int, tuple[str, type]] = {
    2: ("title", str),
    3: ("subject", str),
    4: ("author", str),
    5: ("keywords", str),
    6: ("comments", str),
    8: ("last_saved_by", str),
    9: ("revision_number", str),
    10: ("total_edit_time_seconds", int),
    11: ("last_printed", datetime),
    12: ("create_time", datetime),
    13: ("last_saved_time", datetime),
    18: ("creating_application", str),
    20: ("processor_name", str),
    25: ("num_program_files", int),
    32: ("num_data_files", int),
}
_MAX_PROPERTY_STRING = 1024


@dataclass
class RssStream:
    """A stream read from a RSLogix 500 project file."""

    #: Path of the stream in the compound file, e.g. ``PROGRAM FILES/ObjectData``
    path: str
    #: Raw bytes of the stream (empty if the stream was too large to read)
    raw: bytes
    #: Decoded payload of ``ObjectData`` streams, or :obj:`None` if not decoded
    payload: bytes | None
    #: Inventory information (size, hash, compression, status, ...)
    info: dict[str, Any]


@dataclass
class RssContainer:
    """The streams and metadata read from a RSLogix 500 project file."""

    #: Streams, keyed by path
    streams: dict[str, RssStream] = field(default_factory=dict)
    #: Decoded ``\\x05SummaryInformation`` properties
    summary_info: dict[str, Any] = field(default_factory=dict)
    #: Non-fatal problems found while reading the file
    warnings: list[str] = field(default_factory=list)
    #: Sections that couldn't be read
    errors: list[str] = field(default_factory=list)

    def payload(self, storage: str) -> bytes | None:
        """
        Get the decoded ``ObjectData`` payload of a storage.

        Args:
            storage: Storage path, e.g. ``PROGRAM FILES`` or ``ONLINEIMAGE/PROCESSOR``
        """
        stream = self.streams.get(f"{storage}/{OBJECT_DATA}")
        return stream.payload if stream else None

    @property
    def inventory(self) -> list[dict[str, Any]]:
        """Inventory information for all streams, sorted by path."""
        return [self.streams[path].info for path in sorted(self.streams)]


def is_rslogix500_project(fp: BinaryIO) -> bool:
    """
    Check if a file is a RSLogix 500 project file, using its contents.

    The file must be an OLE compound file that has the ``PROCESSOR`` and
    ``PROGRAM FILES`` storages. This is used as a
    :class:`~peat.file_signature.FileSignature` custom check, which runs
    on every candidate file, so it returns quickly for other files.

    Args:
        fp: Binary file object. It's left open.
    """
    try:
        fp.seek(0)
        if fp.read(len(olefile.MAGIC)) != olefile.MAGIC:
            return False
        fp.seek(0)
        # NOTE: always pass a file object, never bytes. olefile treats
        # data shorter than 1536 bytes as a filename.
        with olefile.OleFileIO(fp) as ole:
            return all(ole.exists(s) for s in RSS_REQUIRED_STORAGES) and ole.exists(
                f"PROCESSOR/{OBJECT_DATA}"
            )
    except Exception:
        return False
    finally:
        try:
            fp.seek(0)
        except Exception:
            pass


def decode_object_data(
    raw: bytes, max_size: int = MAX_DECODED_STREAM_SIZE
) -> tuple[bytes | None, dict[str, Any]]:
    """
    Decode the 16-byte header and the payload of an ``ObjectData`` stream.

    Args:
        raw: Raw bytes of the stream
        max_size: Largest decoded size that will be accepted

    Returns:
        Tuple of the decoded payload (or :obj:`None` if it couldn't be
        decoded) and a :class:`dict` describing the header and the result.
        ``status`` is one of ``ok``, ``size_mismatch``, ``bad_header``,
        ``unknown_mode``, ``decode_error`` or ``too_large``.
    """
    info: dict[str, Any] = {
        "mode": None,
        "compression": None,
        "header_size": None,
        "stored_size": None,
        "decoded_size": None,
        "status": "ok",
        "error": "",
    }

    if len(raw) < _HEADER.size:
        info["status"] = "bad_header"
        info["error"] = f"stream is too short ({len(raw)} bytes) for the header"
        return None, info

    mode, header_size, stored_size, decoded_size = _HEADER.unpack_from(raw)
    info.update(
        {
            "mode": mode,
            "compression": COMPRESSION_MODES.get(mode, "unknown"),
            "header_size": header_size,
            "stored_size": stored_size,
            "decoded_size": decoded_size,
        }
    )

    if header_size != _HEADER.size:
        info["status"] = "bad_header"
        info["error"] = f"unexpected header size {header_size}"
        return None, info

    body = raw[header_size : header_size + stored_size]
    size_problem = ""
    if stored_size != len(raw) - header_size:
        size_problem = f"stored size {stored_size} != {len(raw) - header_size} bytes in stream"

    if mode not in COMPRESSION_MODES:
        info["status"] = "unknown_mode"
        info["error"] = f"unknown compression mode {mode}"
        return None, info

    if decoded_size > max_size or len(body) > max_size:
        info["status"] = "too_large"
        info["error"] = f"decoded size {decoded_size} exceeds the limit of {max_size} bytes"
        return None, info

    try:
        if mode == 0:
            payload = bytes(body)
        elif mode == 1:
            payload = explode(body, max_out=min(max_size, decoded_size + _DCL_SLACK))
        else:
            decompressor = zlib.decompressobj()
            payload = decompressor.decompress(body, max_size)
            if decompressor.unconsumed_tail:
                info["status"] = "too_large"
                info["error"] = f"decompressed data exceeds the limit of {max_size} bytes"
                return None, info
            if not decompressor.eof:
                raise zlib.error("incomplete or truncated zlib stream")
    except (DCLError, zlib.error) as ex:
        info["status"] = "decode_error"
        info["error"] = str(ex)
        return None, info

    if len(payload) != decoded_size:
        size_problem = (
            f"{size_problem}; " if size_problem else ""
        ) + f"decoded {len(payload)} bytes, header says {decoded_size}"

    if size_problem:
        info["status"] = "size_mismatch"
        info["error"] = size_problem

    return payload, info


def _class_names(payload: bytes, limit: int = 64) -> list[str]:
    """Unique MFC class names defined in a payload, in order."""
    names: list[str] = []
    for class_def in find_class_defs(payload, limit=_MAX_CLASS_DEFS):
        if class_def.name not in names:
            names.append(class_def.name)
            if len(names) >= limit:
                break
    return names


def read_rss(
    path: Path,
    max_size: int = MAX_DECODED_STREAM_SIZE,
    max_total_size: int = MAX_TOTAL_DECODED_SIZE,
) -> RssContainer:
    """
    Read and decode every stream in a RSLogix 500 project file.

    Args:
        path: Path of the ``.RSS`` file
        max_size: Largest stream (raw or decoded) that will be processed
        max_total_size: Largest total size of all streams read from the file
            (raw plus decoded). Streams after the limit is reached aren't read,
            and have the status ``too_large``.

    Returns:
        The streams and the SummaryInformation metadata

    Raises:
        ParseError: If the file isn't an OLE compound file, or doesn't have
            the storages of a RSLogix 500 project
    """
    container = RssContainer()

    try:
        with path.open("rb") as fp:
            if fp.read(len(olefile.MAGIC)) != olefile.MAGIC:
                raise ParseError(
                    f"'{path.name}' is not an OLE compound file "
                    f"(RSLogix 500 project files are OLE compound files)"
                )
            fp.seek(0)

            with olefile.OleFileIO(fp) as ole:
                missing = [s for s in RSS_REQUIRED_STORAGES if not ole.exists(s)]
                if missing:
                    raise ParseError(
                        f"'{path.name}' is an OLE file, but is missing the RSLogix 500 "
                        f"storage(s) {missing}"
                    )

                entries = ole.listdir(streams=True, storages=False)
                if len(entries) > MAX_STREAM_COUNT:
                    container.warnings.append(
                        f"file has {len(entries)} streams, only reading the first "
                        f"{MAX_STREAM_COUNT}"
                    )
                    entries = entries[:MAX_STREAM_COUNT]

                total = 0
                for entry in entries:
                    total += _read_stream(ole, entry, container, max_size, max_total_size - total)

                try:
                    container.summary_info = parse_summary_info(ole)
                    container.warnings.extend(container.summary_info.pop("warnings", []))
                except Exception as ex:
                    msg = f"failed to read SummaryInformation: {ex}"
                    log.warning(msg)
                    container.errors.append(msg)
    except ParseError:
        raise
    except Exception as ex:
        raise ParseError(f"failed to read OLE compound file '{path.name}': {ex}") from ex

    return container


def _read_stream(
    ole: olefile.OleFileIO,
    entry: list[str],
    container: RssContainer,
    max_size: int,
    remaining: int,
) -> int:
    """
    Read (and decode) a stream into ``container``.

    Args:
        remaining: How many bytes are left of the total size limit for the file

    Returns:
        Number of bytes that were kept (raw plus decoded)
    """
    path = "/".join(entry)
    size = ole.get_size(entry)
    info: dict[str, Any] = {"path": path, "size": size, "sha256": ""}

    limit = max(0, min(max_size, remaining))
    if size > limit:
        info["status"] = "too_large"
        if limit < max_size:
            info["error"] = "the total size limit for the file's streams has been reached"
        else:
            info["error"] = f"stream size {size} exceeds the limit of {max_size} bytes"
        container.warnings.append(f"stream '{path}' was not read: {info['error']}")
        container.streams[path] = RssStream(path=path, raw=b"", payload=None, info=info)
        return 0

    raw = ole.openstream(entry).read(limit)
    info["sha256"] = hashlib.sha256(raw).hexdigest()
    payload = None

    if entry[-1] == OBJECT_DATA:
        decode_limit = max(0, min(max_size, remaining - len(raw)))
        payload, header_info = decode_object_data(raw, decode_limit)
        if header_info["status"] == "too_large" and decode_limit < max_size:
            header_info["error"] = (
                f"{header_info['error']} (the total size limit for the file's "
                f"streams has been reached)"
            )
        info.update(header_info)
        if payload is not None:
            info["mfc_classes"] = _class_names(payload)

        if entry[0] == "DATABASE" and header_info["status"] not in ("ok", "too_large"):
            # Legacy (format 0x71) database, which uses a different format
            log.info(f"Legacy RSLogix 500 '{path}' stream isn't decoded, extracting it raw")
            info["status"] = "not_decoded"
        elif header_info["status"] != "ok":
            container.warnings.append(f"stream '{path}': {header_info['error']}")

    container.streams[path] = RssStream(path=path, raw=raw, payload=payload, info=info)
    return len(raw) + (len(payload) if payload is not None else 0)


def _decode_text(value: bytes, encoding: str) -> str:
    text = value.split(b"\x00", 1)[0].decode(encoding, errors="replace")
    return text[:_MAX_PROPERTY_STRING]


def _filetime(value: Any) -> datetime | None:
    if not isinstance(value, datetime) or value.year <= 1601:
        return None
    return value.replace(tzinfo=UTC)


def parse_summary_info(ole: olefile.OleFileIO) -> dict[str, Any]:
    """
    Read the ``\\x05SummaryInformation`` properties.

    Standard properties are named (``author``, ``create_time``, ...).
    The RSLogix 500 specific properties 20 (processor name), 25 (number of
    program files) and 32 (number of data files) are also named. All other
    properties, and named properties that don't have the expected type, are
    returned in ``other_properties`` with the ID as the key. Problems are
    listed in ``warnings``.

    Args:
        ole: The open compound file

    Returns:
        The properties, or an empty :class:`dict` if the stream doesn't exist
    """
    stream = "\x05SummaryInformation"
    if not ole.exists(stream):
        return {}

    props = ole.getproperties(stream, convert_time=True, no_conversion=[10])

    encoding = "cp1252"
    codepage = props.get(1)
    if isinstance(codepage, int) and 0 < codepage < 65000:
        try:
            encoding = codecs.lookup(f"cp{codepage}").name
        except LookupError:
            pass

    result: dict[str, Any] = {"codepage": codepage}
    other: dict[str, Any] = {}
    warnings: list[str] = []

    for prop_id, value in sorted(props.items()):
        if prop_id in (0, 1):
            continue
        if isinstance(value, bytes):
            value = _decode_text(value, encoding)
        elif isinstance(value, str):
            value = value[:_MAX_PROPERTY_STRING]
        elif isinstance(value, datetime):
            value = _filetime(value)
        elif not isinstance(value, (int, float, bool)) and value is not None:
            value = repr(value)[:_MAX_PROPERTY_STRING]

        name, expected = _SUMMARY_PROPERTIES.get(prop_id, ("", object))
        if name and (
            value is None
            or (isinstance(value, expected) and not (expected is int and isinstance(value, bool)))
        ):
            result[name] = value
            continue
        if name:
            # Don't trust the file: a property with the wrong type is kept,
            # but not under its name, so it can't break the code using it.
            warnings.append(
                f"SummaryInformation property {prop_id} ({name}) has the unexpected "
                f"type {type(value).__name__}, it's in 'other_properties'"
            )
        other[str(prop_id)] = value.isoformat() if isinstance(value, datetime) else value

    result["other_properties"] = other
    result["warnings"] = warnings
    return result


def parse_contents(raw: bytes) -> int | None:
    """
    Get the file format version from the ``Contents`` stream.

    Returns:
        The version (for example ``0x80``), or :obj:`None` if the stream is too short
    """
    if len(raw) < 4:
        return None
    return struct.unpack_from("<I", raw)[0]


def _is_printable_ascii(data: bytes) -> bool:
    return bool(data) and all(0x20 <= b < 0x7F for b in data)


def _find_comms_path(data: bytes, limit: int = 4096) -> str:
    """
    Find a RSLinx communication path (``WORKSTATION!DRIVER\\node``) CString.
    """
    data = data[:limit]
    for i, length in enumerate(data):
        if length < 3 or i + 1 + length > len(data):
            continue
        candidate = data[i + 1 : i + 1 + length]
        if b"!" in candidate[1:] and _is_printable_ascii(candidate):
            return candidate.decode("ascii")
    return ""


def parse_processor(payload: bytes) -> dict[str, Any]:
    """
    Parse the ``PROCESSOR`` storage (class ``CProc``).

    Confirmed fields: the processor type code (a WORD, written twice; its
    mapping to catalog numbers is unknown), the RSLinx driver settings and
    the processor name. The last communication path, if present, names the
    engineering workstation that last went online with the processor.
    """
    reader = MfcReader(payload)
    result: dict[str, Any] = {"schema": reader.expect_class("CProc")}
    result["processor_type_code"] = reader.u16()
    result["processor_type_code_2"] = reader.u16()

    settings = reader.cstring()
    result["comms_driver"] = settings.split("%", 1)[0]
    result["comms_driver_settings"] = settings
    result["warnings"] = []

    try:
        reader.skip(6)  # Unknown
        result["processor_name"] = reader.cstring(max_length=64).strip()
    except MfcFormatError as ex:
        result["processor_name"] = ""
        result["warnings"].append(f"failed to read the processor name: {ex}")

    comms_path = _find_comms_path(payload[reader.pos :])
    result["last_comms_path"] = comms_path
    workstation, _, route = comms_path.partition("!")
    result["engineering_workstation"] = workstation
    result["last_comms_driver"] = route.split("\\", 1)[0]

    return result


def parse_version(payload: bytes) -> dict[str, Any]:
    """
    Parse the ``Version`` storage (class ``CVersionData``): the version of
    RSLogix 500 that last saved the project.
    """
    reader = MfcReader(payload)
    reader.expect_class("CVersionData")
    return {
        "rslogix_version": reader.cstring(max_length=64),
        "rslogix_version_short": reader.cstring(max_length=64),
        "rslogix_build": reader.cstring(max_length=64),
    }


def _first_u16_of_class(payload: bytes, class_name: str) -> int:
    reader = MfcReader(payload)
    reader.expect_class(class_name)
    return reader.u16()


# ----------------------------------------------------------------------------
# Ladder logic
# ----------------------------------------------------------------------------


class _ScanBudget:
    """Limit on the number of attempts (and bytes read) when scanning for records."""

    def __init__(self, attempts: int, scan_bytes: int = _MAX_SCAN_BYTES) -> None:
        self.attempts = attempts
        self.scan_bytes = scan_bytes

    @property
    def exhausted(self) -> bool:
        return self.attempts <= 0 or self.scan_bytes <= 0

    def spend(self, scanned: int) -> None:
        self.attempts -= 1
        self.scan_bytes -= scanned


def _read_cins(
    data: bytes, pos: int, end: int | None = None, budget: _ScanBudget | None = None
) -> tuple[dict[str, Any], int]:
    """
    Read the body of a ``CIns`` (instruction) object.

    Args:
        data: Payload to read from
        pos: Offset of the body (after the object tag)
        end: Offset the instruction must end before
        budget: Charged with the attempt and the bytes read if the read fails

    Raises:
        MfcFormatError: If the data doesn't look like a valid instruction
    """
    reader = MfcReader(data, pos, end=end)
    try:
        count = reader.u16()
        if count > _MAX_OPERANDS:
            raise MfcFormatError(f"operand count {count} is too large")

        operands = []
        for _ in range(count):
            operand = reader.cstring(max_length=_MAX_OPERAND_LENGTH)
            # Fail fast, since most offsets that are tried aren't instructions
            if not operand.isprintable():
                raise MfcFormatError("operand text isn't printable")
            operands.append(operand)

        flag = reader.u16()
        opcode = reader.u16()
        reserved = reader.u32()
        if flag not in (0, 1) or reserved:
            raise MfcFormatError("invalid instruction flag or reserved field")

        blob = b""
        if flag:
            blob_len = reader.u16()
            if blob_len > _MAX_BLOB_LENGTH:
                raise MfcFormatError(f"compiled blob length {blob_len} is too large")
            blob = reader.read(blob_len)
    except MfcFormatError:
        if budget is not None:
            budget.spend(reader.pos - pos)
        raise

    return {"opcode": opcode, "flag": flag, "operands": operands, "blob": blob}, reader.pos


def _vote_cins_tag(data: bytes, warnings: list[str] | None = None) -> bytes | None:
    """
    Learn the MFC class tag used for ``CIns`` objects.

    The tag depends on the order classes and objects were first written,
    so it isn't hard-coded. Instead, every candidate tag that's followed by
    a valid instruction with at least one operand gets a vote.
    """
    votes: Counter[bytes] = Counter()
    budget = _ScanBudget(_MAX_VOTE_ATTEMPTS)
    for match in _CINS_CANDIDATE_RE.finditer(data):
        if budget.exhausted:
            if warnings is not None:
                warnings.append(
                    f"stopped learning the CIns tag after {_MAX_VOTE_ATTEMPTS} attempts"
                )
            break
        tag = match.group(1)
        if tag == b"\xff\xff":
            continue
        try:
            _, end = _read_cins(data, match.start() + len(tag), budget=budget)
        except MfcFormatError:
            continue
        # Successful reads are charged too, since candidates can overlap
        budget.spend(end - match.start())
        votes[tag] += 1
    if not votes:
        return None
    return votes.most_common(1)[0][0]


def _valid_ladhdr(data: bytes, offset: int, prev_number: int) -> bool:
    """Check if there is a plausible ``CLadFile`` header at ``offset``."""
    if offset < 0 or offset + _LADHDR.size > len(data):
        return False
    rungs, ftype, name, number, _flag, count = _LADHDR.unpack_from(data, offset)
    stripped = name.rstrip(b"\x00")
    return (
        rungs == count
        and ftype < 16
        and prev_number < number < _MAX_PROGRAM_FILES
        and (not stripped or _is_printable_ascii(stripped))
        and b"\x00" not in stripped
    )


def _find_next_ladfile(data: bytes, start: int, prev_number: int) -> int | None:
    """Offset of the next ``CLadFile`` header (after its tag), or :obj:`None`."""
    pos = start
    while True:
        hit = data.find(_LADFILE_TAG, pos)
        if hit < 0:
            return None
        if _valid_ladhdr(data, hit + len(_LADFILE_TAG), prev_number):
            return hit + len(_LADFILE_TAG)
        pos = hit + 1


def _token(raw: dict[str, Any]) -> dict[str, Any]:
    info = RSS_OPCODES.get(raw["opcode"])
    return {
        "opcode": raw["opcode"],
        "opcode_hex": f"{raw['opcode']:02X}",
        "mnemonic": info.mnemonic if info else f"OP_{raw['opcode']:02X}",
        "confidence": info.confidence if info else "unknown",
        "flag": raw["flag"],
        "operands": raw["operands"],
        "compiled_hex": raw["blob"].hex(),
    }


def _render_instruction(token: dict[str, Any]) -> str:
    info = RSS_OPCODES.get(token["opcode"])
    operands = token["operands"]
    if info is None:
        return " ".join([f"OP_{token['opcode']:02X}", *operands])
    if info.paired and len(operands) % 2 == 0:
        operands = operands[0::2]
    return " ".join([info.mnemonic, *operands])


def render_rung(tokens: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """
    Render the instructions of a rung as mnemonic text.

    Branch legs are rendered as ``NXB`` (except the first leg of a branch,
    even if it's empty), and the leg end markers aren't rendered, so the text
    matches how RSLogix 500 displays rungs in ASCII form, for example
    ``SOR BST XIC I:1/0 NXB XIC B3:2/4 BND OTE O:0/2 EOR``. A branch with an
    empty (shorted) first leg is rendered as ``BST NXB XIC I:1/0 BND``.

    Args:
        tokens: Instructions of the rung, as returned in ``rungs[].tokens``
            by :func:`parse_program_files`

    Returns:
        Tuple of the rendered text and any structural problems found
    """
    parts: list[str] = []
    problems: list[str] = []
    # Stack of open branches. Each item is [a leg is open, the branch has
    # started a leg or has an instruction]. The second item decides if a
    # leg start is rendered as NXB, so an empty first leg isn't lost.
    branches: list[list[bool]] = []

    for token in tokens:
        opcode = token["opcode"]
        if opcode == LEG_START:
            if not branches:
                problems.append("branch leg outside of a branch")
                if parts:
                    parts.append("NXB")
                continue
            branch = branches[-1]
            if branch[0]:
                problems.append("branch leg started before the previous leg ended")
            if branch[1]:
                parts.append("NXB")
            branch[0] = branch[1] = True
            continue
        if opcode == LEG_END:
            if not branches or not branches[-1][0]:
                problems.append("branch leg end without a leg start")
            else:
                branches[-1][0] = False
            continue
        if branches:
            branches[-1][1] = True
        if opcode == BST:
            branches.append([False, False])
        elif opcode == BND:
            if not branches:
                problems.append("branch end without a branch start")
            elif branches.pop()[0]:
                problems.append("branch ended while a leg was open")
        parts.append(_render_instruction(token))

    if branches:
        problems.append(f"{len(branches)} branch(es) not closed")
    if not tokens or tokens[0]["opcode"] != SOR:
        problems.append("rung doesn't start with SOR")
    if not tokens or tokens[-1]["opcode"] != EOR:
        problems.append("rung doesn't end with EOR")

    return " ".join(parts), problems


def _finish_rung(tokens: list[dict[str, Any]], number: int, warnings: list[str]) -> dict:
    text, problems = render_rung(tokens)
    for problem in problems:
        warnings.append(f"rung {number}: {problem}")
    return {"number": number, "text": text, "tokens": tokens}


def parse_program_files(payload: bytes) -> dict[str, Any]:
    """
    Parse the ladder logic in the ``PROGRAM FILES`` storage.

    Returns:
        :class:`dict` with ``declared_count`` (from ``CProgHolder``),
        ``program_files`` (a list with ``number``, ``name``, ``type``,
        ``type_name``, ``declared_rungs``, ``rungs`` and ``warnings`` for
        each program file), ``cins_tag`` and ``warnings``.

    Raises:
        MfcFormatError: If the payload doesn't start with a ``CProgHolder``
    """
    reader = MfcReader(payload)
    reader.expect_class("CProgHolder")
    declared_count = reader.u16()
    warnings: list[str] = []

    if declared_count > _MAX_PROGRAM_FILES:
        raise MfcFormatError(f"program file count {declared_count} is too large")

    try:
        reader.expect_class("CLadFile")
        hdr_pos: int | None = reader.pos
    except MfcFormatError:
        found = payload.find(b"\x08\x00CLadFile")
        hdr_pos = found + 10 if found >= 0 else None
        warnings.append("first CLadFile isn't directly after CProgHolder")

    ins_tag = _vote_cins_tag(payload, warnings)
    resync_budget = _ScanBudget(_MAX_RESYNC_ATTEMPTS)
    files: list[dict[str, Any]] = []
    cins_class_def = next(
        (c for c in find_class_defs(payload, limit=_MAX_CLASS_DEFS) if c.name == "CIns"), None
    )
    cins_class = cins_class_def.offset if cins_class_def else -1
    num_files_before_rungs = 0
    seen_cins = False
    prev_number = -1
    num_instructions = 0

    for index in range(declared_count):
        if resync_budget.exhausted or num_instructions >= _MAX_INSTRUCTIONS:
            break
        if hdr_pos is None or hdr_pos + _LADHDR.size > len(payload):
            warnings.append(f"found {index} of {declared_count} program files")
            break

        rungs, ftype, raw_name, number, flag, rung_count = _LADHDR.unpack_from(payload, hdr_pos)
        if index and not _valid_ladhdr(payload, hdr_pos, prev_number):
            warnings.append(f"invalid program file header after file {prev_number}")
            break

        pos = hdr_pos + _LADHDR.size
        next_hdr = _find_next_ladfile(payload, pos, number) if index + 1 < declared_count else None
        boundary = next_hdr - len(_LADFILE_TAG) if next_hdr is not None else len(payload)

        pfile: dict[str, Any] = {
            "number": number,
            "name": raw_name.rstrip(b"\x00").decode("ascii", errors="replace"),
            "type": ftype,
            "type_name": LADDER_FILE_TYPES.get(ftype, f"type_{ftype}"),
            "flag": flag,
            "declared_rungs": rungs,
            "rungs": [],
            "warnings": [],
        }
        if rungs != rung_count:
            pfile["warnings"].append(f"rung counts differ in header ({rungs} != {rung_count})")
        if not seen_cins:
            num_files_before_rungs += 1

        tokens: list[dict[str, Any]] = []
        if rungs and not seen_cins and cins_class_def and pos <= cins_class < boundary:
            # The very first instruction directly follows the CIns class definition
            try:
                raw_tok, pos = _read_cins(payload, cins_class_def.end, boundary)
                tokens.append(_token(raw_tok))
                num_instructions += 1
                seen_cins = True
            except MfcFormatError as ex:
                pfile["warnings"].append(f"failed to read first instruction: {ex}")
                pos = cins_class_def.end

        while (
            len(pfile["rungs"]) < rungs
            and ins_tag
            and not resync_budget.exhausted
            and num_instructions < _MAX_INSTRUCTIONS
        ):
            hit = payload.find(ins_tag, pos, boundary)
            if hit < 0:
                break
            try:
                raw_tok, new_pos = _read_cins(
                    payload, hit + len(ins_tag), boundary, budget=resync_budget
                )
            except MfcFormatError:
                pos = hit + 1  # Resync
                continue
            seen_cins = True
            pos = new_pos
            if raw_tok["opcode"] == SOR and tokens:
                # Missing EOR: keep what was decoded as a separate rung
                pfile["rungs"].append(_finish_rung(tokens, len(pfile["rungs"]), pfile["warnings"]))
                tokens = []
                if len(pfile["rungs"]) >= rungs:
                    break
            tokens.append(_token(raw_tok))
            num_instructions += 1
            if raw_tok["opcode"] == EOR:
                pfile["rungs"].append(_finish_rung(tokens, len(pfile["rungs"]), pfile["warnings"]))
                tokens = []

        if tokens:
            pfile["rungs"].append(_finish_rung(tokens, len(pfile["rungs"]), pfile["warnings"]))
            pfile["warnings"].append("last rung is incomplete")
        if len(pfile["rungs"]) != rungs:
            pfile["warnings"].append(f"declared {rungs} rungs, decoded {len(pfile['rungs'])}")

        files.append(pfile)
        prev_number = number
        hdr_pos = next_hdr

    if resync_budget.exhausted or num_instructions >= _MAX_INSTRUCTIONS:
        reason = (
            "too many invalid instruction records"
            if resync_budget.exhausted
            else f"more than {_MAX_INSTRUCTIONS} instructions"
        )
        warnings.append(
            f"stopped decoding in program file {files[-1]['number'] if files else '?'}: "
            f"{reason} (corrupt or crafted file?)"
        )

    # Cross-check the learned CIns tag against the MFC object numbering:
    # CProgHolder (1, 2), CLadFile (3), the CLadFile objects, CRung (class
    # and object), CBranchLeg (class and object), then the CIns class.
    expected_index = 3 + num_files_before_rungs + 5
    expected_tag = struct.pack("<H", 0x8000 | expected_index)
    if ins_tag and seen_cins and ins_tag != expected_tag:
        warnings.append(
            f"learned CIns tag {ins_tag.hex()} differs from the expected tag {expected_tag.hex()}"
        )
    if not ins_tag and any(f["declared_rungs"] for f in files):
        warnings.append("couldn't find the CIns class tag")

    return {
        "declared_count": declared_count,
        "program_files": files,
        "cins_tag": ins_tag.hex() if ins_tag else "",
        "warnings": warnings,
    }


# ----------------------------------------------------------------------------
# Documentation database
# ----------------------------------------------------------------------------


def normalize_address(raw: str) -> str:
    """
    Convert an address from the zero-padded ``MEM DATABASE`` form to the
    form used in ladder logic.

    Examples:

    .. code-block:: python

        >>> normalize_address("N0007:003/05")
        'N7:3/5'
        >>> normalize_address("T0004:002")
        'T4:2'
        >>> normalize_address("I0001:002.000/03")
        'I:2.0/3'
        >>> normalize_address("S0002:001/13")
        'S:1/13'
        >>> normalize_address("M10000:008.000")
        'M1:8.0'
        >>> normalize_address("not an address")
        'not an address'

    Anything that doesn't match the expected pattern is returned unchanged.
    """
    match = _DB_ADDRESS_RE.fullmatch(raw)
    if not match:
        return raw

    letter, file_num, element, word, bit = match.groups()
    file_num_i = int(file_num)
    if letter in ("I", "O", "M0", "M1") or (letter == "S" and file_num_i == 2):
        # I/O, module files and status are addressed without the file number
        address = f"{letter}:{int(element)}"
    else:
        address = f"{letter}{file_num_i}:{int(element)}"
    if word is not None:
        address += f".{int(word)}"
    if bit is not None:
        address += f"/{int(bit)}"
    return address


def _parse_db_header(reader: MfcReader, result: dict[str, Any]) -> None:
    result["schema"] = reader.expect_class("DBXMemMap")
    # Values seen: 1, 20, 5, 20, 0/5, 5/0 (maybe description width and lines)
    result["header_values"] = [reader.u32() for _ in range(6)]
    result["status_text"] = reader.cstring(max_length=256)
    reader.u32()  # Unknown
    result["declared_entry_count"] = reader.u32()


def _parse_rung_comments(
    payload: bytes, lower_bound: int, result: dict[str, Any]
) -> list[dict[str, Any]]:
    keys = list(_RUNG_KEY_BYTES_RE.finditer(payload, lower_bound))
    if not keys:
        return []
    first_key = keys[0].start()

    def _first_comment_fits(start: int) -> bool:
        """Cheap check if the first comment ends exactly at the first key."""
        try:
            reader = MfcReader(payload, start, end=first_key)
            reader.skip(2 + 4)  # Count and ID
            reader.skip_cstring(_MAX_RUNG_COMMENT_LENGTH)  # Text
            reader.skip_cstring(_MAX_RUNG_COMMENT_LENGTH)  # Title
            return reader.pos == first_key
        except MfcFormatError:
            return False

    def _entries_at(start: int) -> list[dict[str, Any]] | None:
        try:
            reader = MfcReader(payload, start)
            if reader.u16() != len(keys):
                return None
            comments = []
            for _ in keys:
                comment_id = reader.u32()
                text = reader.cstring(max_length=_MAX_RUNG_COMMENT_LENGTH)
                title = reader.cstring(max_length=_MAX_RUNG_COMMENT_LENGTH)
                key = _RUNG_KEY_RE.fullmatch(reader.cstring(max_length=17))
                if not key:
                    return None
                comments.append(
                    {
                        "file": int(key.group(1)),
                        "rung": int(key.group(2)),
                        "text": text,
                        "title": title,
                        "id": comment_id,
                    }
                )
            return comments
        except MfcFormatError:
            return None

    if len(keys) <= 0xFFFF:
        count = struct.pack("<H", len(keys))
        # Search backwards from the first key for the comment count. The
        # search is bounded, so a crafted file can't make it take hours.
        search_start = max(lower_bound, first_key - _MAX_COMMENT_COUNT_DISTANCE)
        end = first_key
        attempts = 0
        while attempts < _MAX_COMMENT_COUNT_ATTEMPTS:
            pos = payload.rfind(count, search_start, end)
            if pos < 0:
                break
            end = pos + 1
            if not _first_comment_fits(pos):
                continue
            attempts += 1
            comments = _entries_at(pos)
            if comments is not None:
                return comments

    result["warnings"].append(
        f"couldn't decode the rung comments, only reporting {len(keys)} comment keys"
    )
    comments = []
    for key in keys:
        match = _RUNG_KEY_RE.fullmatch(key.group(0)[1:].decode("ascii"))
        if match:
            comments.append(
                {
                    "file": int(match.group(1)),
                    "rung": int(match.group(2)),
                    "text": "",
                    "title": "",
                    "id": None,
                }
            )
    return comments


def parse_mem_database(payload: bytes) -> dict[str, Any]:
    """
    Parse the address documentation and rung comments in the
    ``MEM DATABASE`` storage (class ``DBXMemMap``).

    Returns:
        :class:`dict` with ``entries`` (``address``, ``address_raw``,
        ``kind``, ``symbol`` and ``description_lines`` of each documented
        address; ``kind`` is ``data`` for data table and specialty I/O
        module file (``M0``/``M1``) addresses,
        ``program_file`` for program file documentation such as
        ``PFILE:00003`` or ``U:00003``, and ``other`` for anything else),
        ``rung_comments`` (``file``, ``rung``, ``text`` and ``title``),
        ``declared_entry_count`` and ``warnings``.
    """
    result: dict[str, Any] = {
        "schema": None,
        "header_values": [],
        "status_text": "",
        "declared_entry_count": None,
        "entries": [],
        "rung_comments": [],
        "warnings": [],
    }

    reader = MfcReader(payload)
    try:
        _parse_db_header(reader, result)
    except MfcFormatError as ex:
        result["warnings"].append(f"failed to parse the database header: {ex}")
    pos = reader.pos

    entries = result["entries"]
    declared = result["declared_entry_count"]
    last_end = pos
    budget = _ScanBudget(_MAX_DB_ENTRY_FAILURES)
    for match in _DB_ENTRY_CANDIDATE_RE.finditer(payload, pos):
        start = match.start()
        if start < last_end:
            continue
        if declared is not None and len(entries) >= declared:
            break
        if len(entries) >= _MAX_DB_ENTRIES:
            result["warnings"].append(
                f"stopped looking for database entries after {_MAX_DB_ENTRIES} entries"
            )
            break
        if budget.exhausted:
            result["warnings"].append(
                "stopped looking for database entries: too many invalid entries "
                "(corrupt or crafted file?)"
            )
            break
        entry_reader = MfcReader(payload, start)
        try:
            address_raw = entry_reader.cstring(max_length=40)
            if not _DB_ENTRY_RE.fullmatch(address_raw):
                budget.spend(entry_reader.pos - start)
                continue
            symbol = entry_reader.cstring(max_length=255)
            lines = [entry_reader.cstring(max_length=255) for _ in range(5)]
            # NOTE: each entry is followed by a trailer of unknown meaning,
            # usually 24 bytes but 16 bytes for some entries. It isn't skipped
            # here, the next entry is found by its address instead.
        except MfcFormatError:
            budget.spend(entry_reader.pos - start)
            continue
        if _DB_ADDRESS_RE.fullmatch(address_raw):
            kind = "data"
        elif _DB_PROGRAM_RE.fullmatch(address_raw):
            kind = "program_file"
        else:
            kind = "other"
        entries.append(
            {
                "address": normalize_address(address_raw),
                "address_raw": address_raw,
                "kind": kind,
                "symbol": symbol.strip(),
                "description_lines": lines,
            }
        )
        last_end = entry_reader.pos

    if declared is not None and declared != len(entries):
        result["warnings"].append(
            f"database header declares {declared} entries, decoded {len(entries)}"
        )

    result["rung_comments"] = _parse_rung_comments(payload, last_end, result)
    return result


# ----------------------------------------------------------------------------
# Other streams
# ----------------------------------------------------------------------------


def parse_vba_project(raw: bytes) -> dict[str, Any]:
    """
    Parse the text ``PROJECT`` stream of the embedded VBA project.

    A project without macros has only the default
    ``Document=RSLogix_500_Project/&H00000000`` entry. Any ``Module``,
    ``Class`` or ``BaseClass`` entries, or other documents, mean the project
    contains user VBA code, which is notable for forensics. The VBA source
    code itself isn't decompressed.
    """
    text = raw[: 1024 * 1024].decode("cp1252", errors="replace")
    modules: list[dict[str, str]] = []
    project_name = ""

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            break  # The module list is in the first section
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if key in ("Module", "Class", "BaseClass"):
            modules.append({"type": key, "name": value[:256]})
        elif key == "Document":
            name = value.split("/", 1)[0]
            if name != _DEFAULT_VBA_DOCUMENT:
                modules.append({"type": key, "name": name[:256]})
        elif key == "Name":
            project_name = value.strip('"')[:256]

    return {"present": True, "project_name": project_name, "modules": modules}


def compare_online_image(container: RssContainer) -> dict[str, bool | None]:
    """
    Compare the ``ONLINEIMAGE`` copies of storages with the offline storages.

    A difference suggests the project was changed after it was last online
    with the processor (inferred meaning).

    Returns:
        Mapping of storage name to :obj:`True` if the decoded payloads differ,
        :obj:`False` if they're the same, or :obj:`None` if they can't be compared
    """
    result: dict[str, bool | None] = {}
    prefix = f"{ONLINE_IMAGE}/"
    for path in sorted(container.streams):
        if not path.startswith(prefix) or not path.endswith(f"/{OBJECT_DATA}"):
            continue
        storage = path[len(prefix) : -len(OBJECT_DATA) - 1]
        online = container.payload(f"{ONLINE_IMAGE}/{storage}")
        offline = container.payload(storage)
        result[storage] = None if online is None or offline is None else online != offline
    return result


def find_referenced_data_files(
    program_files: list[dict[str, Any]], entries: list[dict[str, Any]]
) -> list[str]:
    """
    Find the data files referenced by instruction operands or documented
    addresses, for example ``["B3", "M1", "N7", "O0", "S2"]``.
    """
    found: set[tuple[str, int]] = set()

    def _add(letter: str, number: str | None) -> None:
        if letter == "M" and number in ("0", "1"):
            letter = f"M{number}"  # Specialty I/O module files, e.g. "M1:8.0"
        if letter in ("M0", "M1"):
            found.add((letter, -1))  # These don't have a file number
        elif letter not in FILE_TYPE_NAMES:
            return
        elif number is None:
            if letter not in _IMPLIED_FILE_NUMBERS:
                return
            found.add((letter, _IMPLIED_FILE_NUMBERS[letter]))
        else:
            found.add((letter, int(number)))

    for pfile in program_files:
        for rung in pfile["rungs"]:
            for token in rung["tokens"]:
                for operand in token["operands"]:
                    for match in _OPERAND_FILE_RE.finditer(operand):
                        _add(match.group(1), match.group(2))

    for entry in entries:
        db_match = _DB_ADDRESS_RE.fullmatch(entry["address_raw"])
        if db_match:
            _add(db_match.group(1), db_match.group(2))

    return [f"{letter}{num}" if num >= 0 else letter for letter, num in sorted(found)]


def _safe(result: dict[str, Any], name: str, func, *args) -> Any:
    """Run a section decoder, recording any failure instead of raising."""
    try:
        return func(*args)
    except Exception as ex:
        msg = f"failed to parse {name}: {ex}"
        log.warning(f"RSLogix 500: {msg}")
        log.opt(exception=True).debug(f"Traceback for failure to parse {name}")
        result["errors"].append(msg)
        return None


def parse_rss(container: RssContainer) -> dict[str, Any]:
    """
    Decode the sections of a RSLogix 500 project.

    Each section is decoded independently. A section that fails is recorded
    in ``errors`` and the other sections are still decoded. Self-checks
    (counts and cross-references between sections) are recorded in
    ``warnings``.

    Args:
        container: Streams read by :func:`read_rss`

    Returns:
        The structured decode, in a deterministic order
    """
    result: dict[str, Any] = {
        "file_format_version": None,
        "summary_info": container.summary_info,
        "processor": {},
        "version": {},
        "io_type_code": None,
        "num_data_files": None,
        "program_files": [],
        "program_files_declared": None,
        "online_image_program_files": [],
        "documentation": [],
        "rung_comments": [],
        "online_image_differs": {},
        "vba": {"present": False, "project_name": "", "modules": []},
        "referenced_data_files": [],
        "warnings": list(container.warnings),
        "errors": list(container.errors),
    }
    warnings: list[str] = result["warnings"]

    if "Contents" in container.streams:
        result["file_format_version"] = parse_contents(container.streams["Contents"].raw)

    payload = container.payload("PROCESSOR")
    if payload is not None:
        processor = _safe(result, "PROCESSOR", parse_processor, payload)
        if processor:
            warnings.extend(f"PROCESSOR: {w}" for w in processor.pop("warnings"))
            result["processor"] = processor
    else:
        result["errors"].append("PROCESSOR stream couldn't be decoded")

    payload = container.payload("Version")
    if payload is not None:
        result["version"] = _safe(result, "Version", parse_version, payload) or {}

    payload = container.payload("IO CONFIGURATION")
    if payload is not None:
        result["io_type_code"] = _safe(
            result, "IO CONFIGURATION", _first_u16_of_class, payload, "CIOInfo"
        )

    payload = container.payload("DATA FILES")
    if payload is not None:
        result["num_data_files"] = _safe(
            result, "DATA FILES", _first_u16_of_class, payload, "CDataHolder"
        )

    payload = container.payload("PROGRAM FILES")
    if payload is not None:
        programs = _safe(result, "PROGRAM FILES", parse_program_files, payload)
        if programs:
            result["program_files"] = programs["program_files"]
            result["program_files_declared"] = programs["declared_count"]
            warnings.extend(f"PROGRAM FILES: {w}" for w in programs["warnings"])
            for pfile in programs["program_files"]:
                warnings.extend(
                    f"PROGRAM FILES: file {pfile['number']}: {w}" for w in pfile["warnings"]
                )
    else:
        result["errors"].append("PROGRAM FILES stream couldn't be decoded")

    payload = container.payload(f"{ONLINE_IMAGE}/PROGRAM FILES")
    if payload is not None:
        programs = _safe(result, "ONLINEIMAGE/PROGRAM FILES", parse_program_files, payload)
        if programs:
            result["online_image_program_files"] = programs["program_files"]

    payload = container.payload("MEM DATABASE")
    if payload is not None:
        database = _safe(result, "MEM DATABASE", parse_mem_database, payload)
        if database:
            result["documentation"] = database["entries"]
            result["rung_comments"] = database["rung_comments"]
            result["database_header"] = {
                "schema": database["schema"],
                "header_values": database["header_values"],
                "status_text": database["status_text"],
                "declared_entry_count": database["declared_entry_count"],
            }
            warnings.extend(f"MEM DATABASE: {w}" for w in database["warnings"])

    if VBA_PROJECT_STREAM in container.streams:
        vba = _safe(
            result, "VBA project", parse_vba_project, container.streams[VBA_PROJECT_STREAM].raw
        )
        if vba:
            result["vba"] = vba
            if vba["modules"]:
                log.warning(
                    f"RSLogix 500 project contains VBA code modules: "
                    f"{[m['name'] for m in vba['modules']]}"
                )
    elif any(path.startswith("apc/") for path in container.streams):
        result["vba"]["present"] = True

    result["online_image_differs"] = (
        _safe(result, "ONLINEIMAGE", compare_online_image, container) or {}
    )
    result["referenced_data_files"] = (
        _safe(
            result,
            "referenced data files",
            find_referenced_data_files,
            result["program_files"],
            result["documentation"],
        )
        or []
    )

    _safe(result, "cross-checks", _cross_check, result)
    return result


def _cross_check(result: dict[str, Any]) -> None:
    """Add warnings for inconsistencies between sections."""
    warnings = result["warnings"]
    summary = result["summary_info"]
    processor = result["processor"]

    declared = summary.get("num_program_files")
    if isinstance(declared, int) and result["program_files_declared"] is not None:
        if declared != result["program_files_declared"]:
            warnings.append(
                f"SummaryInformation has {declared} program files, "
                f"CProgHolder has {result['program_files_declared']}"
            )
    if result["program_files_declared"] is not None and result["program_files"]:
        if len(result["program_files"]) != result["program_files_declared"]:
            warnings.append(
                f"decoded {len(result['program_files'])} of "
                f"{result['program_files_declared']} program files"
            )

    declared = summary.get("num_data_files")
    if isinstance(declared, int) and result["num_data_files"] is not None:
        if declared != result["num_data_files"]:
            warnings.append(
                f"SummaryInformation has {declared} data files, "
                f"CDataHolder has {result['num_data_files']}"
            )

    if processor and result["io_type_code"] is not None:
        if processor["processor_type_code"] != result["io_type_code"]:
            warnings.append(
                f"processor type code {processor['processor_type_code']:#x} != "
                f"I/O configuration type code {result['io_type_code']:#x}"
            )

    summary_name = summary.get("processor_name")
    if processor.get("processor_name") and isinstance(summary_name, str) and summary_name:
        if processor["processor_name"] != summary_name.strip():
            warnings.append(
                f"processor name '{processor['processor_name']}' != "
                f"SummaryInformation processor name '{summary_name}'"
            )

    rungs = {
        (pfile["number"], rung["number"])
        for pfile in result["program_files"]
        for rung in pfile["rungs"]
    }
    if result["program_files"]:
        for comment in result["rung_comments"]:
            if (comment["file"], comment["rung"]) not in rungs:
                warnings.append(
                    f"rung comment for file {comment['file']} rung {comment['rung']} "
                    f"doesn't match a decoded rung"
                )


# ----------------------------------------------------------------------------
# Text output
# ----------------------------------------------------------------------------


def _one_line(text: str, limit: int = 4096) -> str:
    """Collapse a string to one line of printable text, for comment lines."""
    text = " ".join(text.split())
    text = "".join(c if c.isprintable() else "?" for c in text)
    return text[:limit]


def render_ladder_text(
    parsed: dict[str, Any],
    program_files: list[dict[str, Any]] | None = None,
    include_comments: bool | None = None,
) -> str:
    """
    Render the ladder logic of a parsed project as text.

    Lines starting with ``;`` are comments. Each rung is written as its
    rung number followed by the mnemonic text, for example
    ``0000 SOR XIC I:1/0 OTE O:0/0 EOR``.

    Args:
        parsed: Result of :func:`parse_rss`
        program_files: Program files to render, defaults to ``parsed["program_files"]``
        include_comments: If the rung comments should be included. They're
            keyed by the rung numbers of the offline program, so by default
            they're only included when rendering the offline program files.
    """
    if program_files is None:
        program_files = parsed["program_files"]
    if include_comments is None:
        include_comments = program_files is parsed["program_files"]

    name = parsed["processor"].get("processor_name") or parsed["summary_info"].get(
        "processor_name", ""
    )
    if not isinstance(name, str):
        name = ""
    header = f"; RSLogix 500 project {_one_line(name or '(unnamed)')}"
    if parsed["file_format_version"] is not None:
        header += f" | format {parsed['file_format_version']:#x}"
    if parsed["version"].get("rslogix_version"):
        header += f" | saved by RSLogix 500 {_one_line(parsed['version']['rslogix_version'])}"
    lines = [header]
    if not include_comments and parsed["rung_comments"]:
        lines.append("; Rung comments aren't shown, they belong to the offline program")

    comments = (
        {(c["file"], c["rung"]): c for c in parsed["rung_comments"]} if include_comments else {}
    )
    for pfile in program_files:
        lines.append(
            f'; Program file {pfile["number"]} "{_one_line(pfile["name"])}" '
            f"({pfile['type_name']}, {len(pfile['rungs'])} rungs)"
        )
        for rung in pfile["rungs"]:
            comment = comments.get((pfile["number"], rung["number"]))
            if comment and comment["text"]:
                lines.append(
                    f"; Rung {pfile['number']}:{rung['number']} comment: "
                    f"{_one_line(comment['text'])}"
                )
            lines.append(f"{rung['number']:04d} {rung['text']}")

    return "\n".join(lines) + "\n"


def address_type_name(address_raw: str) -> str:
    """Tag type name for a ``MEM DATABASE`` address, e.g. ``"integer"`` for ``N0007:001``."""
    match = _DB_ADDRESS_RE.fullmatch(address_raw)
    return FILE_TYPE_NAMES.get(match.group(1), "") if match else ""


def is_default_status_address(address_raw: str) -> bool:
    """If an address is in the status file (S2), which has factory default descriptions."""
    match = _DB_ADDRESS_RE.fullmatch(address_raw)
    return bool(match and match.group(1) == "S" and int(match.group(2)) == 2)


def is_default_processor_name(name: str) -> bool:
    """If the processor name is empty or the RSLogix 500 default."""
    return not name or name.strip().upper() == DEFAULT_PROCESSOR_NAME
