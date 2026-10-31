"""
Bounds-checked readers for Microsoft Foundation Classes (MFC) ``CArchive`` data.

Many Windows engineering tools written in C++ save their project files using
MFC serialization (``CObject::Serialize`` with a ``CArchive``). This module
provides small, safe building blocks for reading that format from untrusted
input. It does not attempt to model any particular application's classes.

Format references:

- MFC Technical Note 2, "Persistent Object Data Format"
  (https://learn.microsoft.com/en-us/cpp/mfc/tn002-persistent-object-data-format).
  A new class is written as the tag ``0xFFFF``, a schema number (WORD), the
  length of the class name (WORD), and the ASCII class name. Later objects of
  the same class are written as ``0x8000 | class_index``. Large indexes use the
  tag ``0x7FFF`` followed by a DWORD.
- ``CString`` serialization (``AfxReadStringLength``): a BYTE length, or ``0xFF``
  followed by a WORD length, or ``0xFF 0xFFFF`` followed by a DWORD length.
  The prefix ``0xFF 0xFFFE`` marks a UTF-16 (wide) string, followed by a
  length in characters encoded the same way.

Example:

.. code-block:: python

    >>> from peat.parsing.mfc_archive import MfcReader, read_cstring
    >>> read_cstring(b"\\x05hello")
    ('hello', 6)
    >>> reader = MfcReader(b"\\xff\\xff\\x80\\x00\\x05\\x00CProc\\x2a\\x00")
    >>> reader.expect_class("CProc")
    128
    >>> reader.u16()
    42
"""

import re
import struct
from typing import NamedTuple

__all__ = [
    "CLASS_DEF_RE",
    "MAX_CSTRING_LENGTH",
    "NEW_CLASS_TAG",
    "ClassDef",
    "MfcFormatError",
    "MfcReader",
    "find_class_defs",
    "read_cstring",
]

#: Tag that marks the definition of a new class in the archive
NEW_CLASS_TAG = 0xFFFF

#: Upper bound on the length of a single string, to limit memory use on
#: corrupt or malicious input (16 MiB).
MAX_CSTRING_LENGTH = 16 * 1024 * 1024

#: Regular expression that finds candidate new-class definitions.
#: Matches must also be checked with the name length field, see
#: :func:`find_class_defs`.
CLASS_DEF_RE = re.compile(rb"\xff\xff(?P<schema>..)(?P<len>..)(?P<name>[A-Za-z_]\w{1,63})", re.S)

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")


class MfcFormatError(ValueError):
    """Data doesn't match the expected MFC ``CArchive`` structure."""


class ClassDef(NamedTuple):
    """A new-class definition found in an MFC archive."""

    #: Offset of the ``0xFFFF`` tag
    offset: int
    #: Class name, e.g. ``"CProc"``
    name: str
    #: Class schema (version) number
    schema: int
    #: Offset of the first byte after the class name
    end: int


def read_cstring(
    data: bytes,
    pos: int = 0,
    encoding: str = "cp1252",
    max_length: int = MAX_CSTRING_LENGTH,
) -> tuple[str, int]:
    """
    Read a serialized MFC ``CString``.

    Args:
        data: Buffer to read from
        pos: Offset of the length prefix
        encoding: Encoding used for narrow (8-bit) strings
        max_length: Largest length (in characters) that will be accepted

    Returns:
        Tuple of the decoded string and the offset of the first byte after it

    Raises:
        MfcFormatError: If the string is truncated or too long
    """
    reader = MfcReader(data, pos, encoding=encoding)
    value = reader.cstring(max_length=max_length)
    return value, reader.pos


def find_class_defs(data: bytes, limit: int | None = None) -> list[ClassDef]:
    """
    Find all new-class definitions (``0xFFFF`` tags) in an MFC archive.

    Matches where the name length field doesn't equal the length of the
    name are ignored, which filters most false positives.

    Args:
        data: The serialized archive
        limit: Stop after this many class definitions have been found.
            Use this for untrusted data, which can have millions of them.

    Returns:
        Class definitions in the order they appear
    """
    found: list[ClassDef] = []
    for match in CLASS_DEF_RE.finditer(data):
        if limit is not None and len(found) >= limit:
            break
        name = match.group("name")
        (length,) = _U16.unpack(match.group("len"))
        if length < 2 or length > len(name):
            continue
        # The regex is greedy, so trim the name to the declared length
        name = name[:length]
        (schema,) = _U16.unpack(match.group("schema"))
        found.append(
            ClassDef(
                offset=match.start(),
                name=name.decode("ascii"),
                schema=schema,
                end=match.start("name") + length,
            )
        )
    return found


class MfcReader:
    """
    Sequential, bounds-checked reader for MFC ``CArchive`` data.

    Every read checks that enough data remains and raises
    :class:`MfcFormatError` otherwise, so callers can treat any
    malformed input as a recoverable error.
    """

    def __init__(
        self, data: bytes, pos: int = 0, encoding: str = "cp1252", end: int | None = None
    ) -> None:
        """
        Args:
            data: Buffer to read from
            pos: Offset to start reading at
            encoding: Encoding used for narrow (8-bit) strings
            end: Offset reads must not go past, defaults to the end of ``data``
        """
        self.end = len(data) if end is None else max(0, min(end, len(data)))
        if pos < 0 or pos > self.end:
            raise MfcFormatError(f"start offset {pos} is outside of the data")
        self.data = data
        self.pos = pos
        self.encoding = encoding

    @property
    def remaining(self) -> int:
        """Number of bytes left to read."""
        return self.end - self.pos

    def read(self, size: int) -> bytes:
        """Read exactly ``size`` bytes."""
        if size < 0 or size > self.remaining:
            raise MfcFormatError(
                f"read of {size} bytes at offset {self.pos} exceeds the data "
                f"({self.remaining} bytes remaining)"
            )
        chunk = self.data[self.pos : self.pos + size]
        self.pos += size
        return bytes(chunk)

    def skip(self, size: int) -> None:
        """Skip over ``size`` bytes."""
        self.read(size)

    def u8(self) -> int:
        """Read an unsigned 8-bit integer (BYTE)."""
        return self.read(1)[0]

    def u16(self) -> int:
        """Read an unsigned little-endian 16-bit integer (WORD)."""
        return _U16.unpack(self.read(2))[0]

    def u32(self) -> int:
        """Read an unsigned little-endian 32-bit integer (DWORD)."""
        return _U32.unpack(self.read(4))[0]

    def _string_length(self) -> int:
        length = self.u8()
        if length < 0xFF:
            return length
        length = self.u16()
        if length == 0xFFFE:
            return -1  # Marker for a wide string, handled by the caller
        if length < 0xFFFF:
            return length
        return self.u32()

    def _cstring_header(self, max_length: int) -> tuple[int, bool]:
        """Read the length prefix of a ``CString``: the length and if it's wide."""
        wide = False
        length = self._string_length()
        if length == -1:
            wide = True
            length = self._string_length()
            if length == -1:
                raise MfcFormatError(f"invalid CString length prefix at offset {self.pos}")

        if length > max_length:
            raise MfcFormatError(f"CString length {length} exceeds limit of {max_length}")
        return length, wide

    def cstring(self, max_length: int = MAX_CSTRING_LENGTH) -> str:
        """
        Read a serialized ``CString`` (narrow or wide).

        Narrow strings are decoded with the reader's encoding, and
        wide strings are decoded as UTF-16-LE. Undecodable bytes are
        replaced instead of raising an error.
        """
        length, wide = self._cstring_header(max_length)
        if wide:
            return self.read(length * 2).decode("utf-16-le", errors="replace")
        return self.read(length).decode(self.encoding, errors="replace")

    def skip_cstring(self, max_length: int = MAX_CSTRING_LENGTH) -> int:
        """
        Skip over a serialized ``CString`` without decoding it.

        This is cheaper than :meth:`cstring` when checking if data has
        the expected structure.

        Returns:
            Length of the string, in characters
        """
        length, wide = self._cstring_header(max_length)
        size = length * 2 if wide else length
        if size > self.remaining:
            raise MfcFormatError(
                f"CString of {size} bytes at offset {self.pos} exceeds the data "
                f"({self.remaining} bytes remaining)"
            )
        self.pos += size
        return length

    def expect_class(self, name: str) -> int:
        """
        Read a new-class definition and check it has the expected class name.

        Returns:
            The class schema number

        Raises:
            MfcFormatError: If there isn't a class definition for ``name`` at
                the current position
        """
        start = self.pos
        tag = self.u16()
        if tag != NEW_CLASS_TAG:
            raise MfcFormatError(f"expected class definition at offset {start}, got tag {tag:#x}")
        schema = self.u16()
        length = self.u16()
        found = self.read(length)
        if found != name.encode("ascii"):
            raise MfcFormatError(
                f"expected class '{name}' at offset {start}, "
                f"got '{found.decode('ascii', errors='replace')}'"
            )
        return schema
