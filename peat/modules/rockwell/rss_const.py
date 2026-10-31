"""
Constants for parsing Rockwell RSLogix 500 project files (``.RSS``).

The format is undocumented. The values here come from reverse engineering
of a small number of real project files, plus the public notes listed in
:mod:`peat.modules.rockwell.rss_parse`. Each instruction opcode has a
confidence level:

- ``high``: confirmed by two independent sources, or proven by the
  semantics of the surrounding logic (for example a rung comment that
  describes what the instruction does).
- ``medium``: inferred from the shape of the operands and the sequence
  of opcodes only. These should be re-checked when new samples are found.

Opcodes that aren't in :data:`RSS_OPCODES` are rendered as ``OP_<hex>``
with all of their operand strings, so unknown instructions are never
given a guessed mnemonic.
"""

from typing import Final, NamedTuple

__all__ = [
    "BND",
    "BST",
    "COMPRESSION_MODES",
    "DEFAULT_PROCESSOR_NAME",
    "EOR",
    "FILE_TYPE_NAMES",
    "LADDER_FILE_TYPES",
    "LEG_END",
    "LEG_START",
    "MAX_DECODED_STREAM_SIZE",
    "MAX_STREAM_COUNT",
    "MAX_TOTAL_DECODED_SIZE",
    "RSS_OPCODES",
    "RSS_REQUIRED_STORAGES",
    "SKIP_DEFAULT_STATUS_DESCRIPTIONS",
    "SOR",
    "STRUCTURAL_OPCODES",
    "OpInfo",
]


class OpInfo(NamedTuple):
    """Information about a ladder logic instruction opcode."""

    #: Instruction mnemonic, e.g. ``"XIC"``
    mnemonic: str

    #: How sure we are about the mnemonic: ``"high"`` or ``"medium"``
    confidence: str

    #: If the operands are serialized as (text, cached display value) pairs.
    #: Only the text of each pair is rendered.
    paired: bool = False


# Structural opcodes that define the topology of a rung
SOR: Final[int] = 0x00  #: Start of rung
EOR: Final[int] = 0x01  #: End of rung
BST: Final[int] = 0x02  #: Branch start
BND: Final[int] = 0x03  #: Branch end
LEG_START: Final[int] = 0x04  #: Start of a branch leg (NXB if not the first leg)
LEG_END: Final[int] = 0x05  #: End of a branch leg

STRUCTURAL_OPCODES: Final[frozenset[int]] = frozenset({SOR, EOR, BST, BND, LEG_START, LEG_END})

#: Known instruction opcodes
RSS_OPCODES: Final[dict[int, OpInfo]] = {
    SOR: OpInfo("SOR", "high"),
    EOR: OpInfo("EOR", "high"),
    BST: OpInfo("BST", "high"),
    BND: OpInfo("BND", "high"),
    LEG_START: OpInfo("NXB", "high"),
    LEG_END: OpInfo("LEG_END", "high"),
    0x09: OpInfo("RET", "medium"),
    0x0C: OpInfo("END", "high"),
    0x11: OpInfo("CTU", "medium"),
    0x13: OpInfo("RES", "high"),
    0x15: OpInfo("JSR", "high"),
    0x1C: OpInfo("MOV", "high", paired=True),
    0x21: OpInfo("FLL", "high"),
    0x22: OpInfo("COP", "high"),
    0x23: OpInfo("AND", "medium", paired=True),
    0x26: OpInfo("MVM", "high", paired=True),
    0x27: OpInfo("ADD", "medium", paired=True),
    0x28: OpInfo("SUB", "high", paired=True),
    0x29: OpInfo("MUL", "medium", paired=True),
    0x2A: OpInfo("DIV", "high", paired=True),
    0x2F: OpInfo("OTE", "high"),
    0x30: OpInfo("OTL", "high"),
    0x31: OpInfo("OTU", "high"),  # codespell:ignore
    0x32: OpInfo("EQU", "high", paired=True),
    0x33: OpInfo("NEQ", "high", paired=True),
    0x34: OpInfo("GRT", "high", paired=True),
    0x35: OpInfo("GEQ", "high", paired=True),
    0x36: OpInfo("LES", "high", paired=True),
    0x37: OpInfo("LEQ", "high", paired=True),
    0x39: OpInfo("XIC", "high"),
    0x3A: OpInfo("XIO", "high"),
    0x3F: OpInfo("LIM", "medium", paired=True),
}

#: Program file types in the ``CLadFile`` header.
#: Types 0 and 2 are the system files (file 0 and file 1), which have no rungs.
LADDER_FILE_TYPES: Final[dict[int, str]] = {
    0: "system",
    1: "ladder",
    2: "system",
}

#: Data table file type letters and their names, used for tag types
FILE_TYPE_NAMES: Final[dict[str, str]] = {
    "O": "output",
    "I": "input",
    "S": "status",
    "B": "binary",
    "T": "timer",
    "C": "counter",
    "R": "control",
    "N": "integer",
    "F": "float",
    "ST": "string",
    "A": "ascii",
    "L": "long",
    "MG": "message",
    "PD": "pid",
    "RI": "routing_information",
    "RIX": "extended_routing_information",
    # Specialty I/O module files, addressed as "M0:<slot>.<word>" (data
    # written to the module) and "M1:<slot>.<word>" (data read from it)
    "M0": "module_output",
    "M1": "module_input",
}

#: Storages that must exist for a OLE file to be treated as an RSLogix 500 project
RSS_REQUIRED_STORAGES: Final[tuple[str, ...]] = ("PROCESSOR", "PROGRAM FILES")

#: Compression modes in the 16-byte header of ``ObjectData`` streams
COMPRESSION_MODES: Final[dict[int, str]] = {
    0: "stored",
    1: "pkware-dcl",
    2: "zlib",
}

#: Largest decompressed (or raw) stream that will be processed (64 MiB).
#: This guards against decompression bombs and corrupt size fields.
MAX_DECODED_STREAM_SIZE: Final[int] = 64 * 1024 * 1024

#: Largest total size of the streams (raw plus decoded) that will be read from
#: one file (256 MiB). Streams after this limit are reported as ``too_large``.
#: This guards against files with many highly compressed streams, or many
#: streams that share the same sectors.
MAX_TOTAL_DECODED_SIZE: Final[int] = 256 * 1024 * 1024

#: Largest number of streams in a file that will be read.
#: Real project files have around 30 to 60 streams.
MAX_STREAM_COUNT: Final[int] = 4096

#: Processor name used by RSLogix 500 when the project hasn't been named
DEFAULT_PROCESSOR_NAME: Final[str] = "UNTITLED"

#: If the factory default descriptions of the status file (S2) should be
#: skipped when creating tags. There are about 150 of these in every project.
#: They are always kept in the ``parsed.json`` output file.
SKIP_DEFAULT_STATUS_DESCRIPTIONS: Final[bool] = True
