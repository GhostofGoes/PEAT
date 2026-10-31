"""
Decompress PKWARE Data Compression Library (DCL) "implode" streams.

This is the compression format produced by the PKWARE DCL ``implode()``
function (not the ZIP "implode" method). It is used by some older Windows
applications, for example RSLogix 500 project files saved by older versions
of the software (see :mod:`peat.modules.rockwell.rss_parse`).

This module is a pure-Python port of ``blast.c`` version 1.3 by Mark Adler,
from the ``contrib/blast`` directory of the zlib source distribution
(https://github.com/madler/zlib/tree/develop/contrib/blast).
It is an altered version of the original software: the C code was translated
to Python, the output callback was replaced by an in-memory buffer with a
size limit, and errors are raised as exceptions. The original license and
copyright notice are retained below, as required by the zlib license.

.. code-block:: text

    blast.c
    Copyright (C) 2003, 2012, 2013 Mark Adler
    version 1.3, 24 Aug 2013

    This software is provided 'as-is', without any express or implied
    warranty.  In no event will the author be held liable for any damages
    arising from the use of this software.

    Permission is granted to anyone to use this software for any purpose,
    including commercial applications, and to alter it and redistribute it
    freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
       claim that you wrote the original software. If you use this software
       in a product, an acknowledgment in the product documentation would be
       appreciated but is not required.
    2. Altered source versions must be plainly marked as such, and must not be
       misrepresented as being the original software.
    3. This notice may not be removed or altered from any source distribution.

    Mark Adler    madler@alumni.caltech.edu

Format summary (from ``blast.c``): the first byte is ``0`` if literals are
stored uncoded or ``1`` if they are Huffman coded, the second byte is the
number of extra distance bits (``4``, ``5`` or ``6``, for a 1K, 2K or 4K
dictionary), and the rest is a bit stream of literals and length/distance
pairs. A length of ``519`` marks the end of the stream.

Example:

.. code-block:: python

    >>> from peat.parsing.pkware_dcl import explode
    >>> explode(bytes.fromhex("00048224258f807f"))
    b'AIAIAIAIAIAIA'

Authors

- Mark Adler (original ``blast.c``)
"""

__all__ = ["DCLError", "explode"]

#: Maximum bits in a Huffman code
_MAXBITS = 13

#: Default limit on the size of the decompressed output (64 MiB)
DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024

# Code lengths for the fixed Huffman tables, in the compact run-length form
# used by blast.c: each byte is ((repeat - 1) << 4) | length.
# fmt: off
_LITLEN = bytes(
    [
        11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8,
        9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5,
        7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12,
        8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27,
        44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45,
        44, 173,
    ]
)
# fmt: on
_LENLEN = bytes([2, 35, 36, 53, 38, 23])
_DISTLEN = bytes([2, 20, 53, 230, 247, 151, 248])

# Base lengths and extra bits for length codes 0..15
_BASE = (3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264)
_EXTRA = (0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8)

#: Length value that marks the end of the compressed stream
_END_LENGTH = 519


class DCLError(ValueError):
    """Invalid, truncated, or oversized PKWARE DCL compressed data."""


def _construct(rep: bytes) -> tuple[list[int], list[int]]:
    """
    Build a canonical Huffman decoding table from compact code lengths.

    Returns:
        Tuple of (number of codes of each length, symbols ordered by code)
    """
    lengths = []
    for byte in rep:
        lengths.extend([byte & 15] * ((byte >> 4) + 1))

    count = [0] * (_MAXBITS + 1)
    for length in lengths:
        count[length] += 1

    offs = [0] * (_MAXBITS + 1)
    for length in range(1, _MAXBITS):
        offs[length + 1] = offs[length] + count[length]

    symbol = [0] * len(lengths)
    for sym, length in enumerate(lengths):
        if length:
            symbol[offs[length]] = sym
            offs[length] += 1

    return count, symbol


_LITCODE = _construct(_LITLEN)
_LENCODE = _construct(_LENLEN)
_DISTCODE = _construct(_DISTLEN)


def explode(data: bytes, max_out: int = DEFAULT_MAX_OUTPUT) -> bytes:
    """
    Decompress PKWARE DCL "implode" compressed data.

    Args:
        data: The compressed data
        max_out: Maximum number of decompressed bytes to produce.
            Decompression stops with :class:`DCLError` if this is exceeded,
            which guards against decompression bombs.

    Returns:
        The decompressed data

    Raises:
        DCLError: If the data is invalid or truncated, or the output is too large
    """
    data = bytes(data)
    size = len(data)
    pos = 0
    bitbuf = 0
    bitcnt = 0
    out = bytearray()

    def bits(need: int) -> int:
        """Return ``need`` bits from the input stream (LSB first)."""
        nonlocal pos, bitbuf, bitcnt
        while bitcnt < need:
            if pos >= size:
                raise DCLError("unexpected end of compressed data")
            bitbuf |= data[pos] << bitcnt
            pos += 1
            bitcnt += 8
        val = bitbuf & ((1 << need) - 1)
        bitbuf >>= need
        bitcnt -= need
        return val

    def decode(table: tuple[list[int], list[int]]) -> int:
        """Decode one symbol using a canonical Huffman table (codes are inverted)."""
        count, symbol = table
        code = first = index = 0
        for length in range(1, _MAXBITS + 1):
            code |= bits(1) ^ 1
            cnt = count[length]
            if code < first + cnt:
                return symbol[index + (code - first)]
            index += cnt
            first = (first + cnt) << 1
            code <<= 1
        raise DCLError("invalid Huffman code")

    lit = bits(8)
    if lit > 1:
        raise DCLError(f"invalid literal coding flag {lit}")
    dict_bits = bits(8)
    if not 4 <= dict_bits <= 6:
        raise DCLError(f"invalid dictionary size {dict_bits}")

    while True:
        if bits(1):
            # Length/distance pair
            sym = decode(_LENCODE)
            length = _BASE[sym] + bits(_EXTRA[sym])
            if length == _END_LENGTH:
                return bytes(out)

            shift = 2 if length == 2 else dict_bits
            dist = (decode(_DISTCODE) << shift) + bits(shift) + 1
            if dist > len(out):
                raise DCLError("distance is too far back")

            start = len(out) - dist
            if dist >= length:
                out += out[start : start + length]
            else:
                # Overlapping copy: the last "dist" bytes repeat
                chunk = out[start:]
                reps, rem = divmod(length, dist)
                out += chunk * reps + chunk[:rem]
        else:
            # Literal byte
            out.append(decode(_LITCODE) if lit else bits(8))

        if len(out) > max_out:
            raise DCLError(f"decompressed data exceeds the limit of {max_out} bytes")
