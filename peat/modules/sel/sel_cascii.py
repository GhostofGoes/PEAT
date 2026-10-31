"""
Parse SEL Compressed ASCII messages.

Compressed ASCII is the comma-delimited form of SEL ASCII command responses,
meant to be read by programs instead of people. The ``ID`` command and the
"C" commands (``CASCII``, ``CSTATUS``, ``CHISTORY``, ``CSER``, ``CEVENT``,
``CSUMMARY``, ...) answer in this format, and so do some files on relays,
such as ``CSER.TXT`` and ``CHISTORY.TXT``.

The format, as described in the "Compressed ASCII" sections of public SEL
instruction manuals (e.g. the SEL-421 Reference Manual section 5, the
SEL-351S Appendix K, and the SEL-551 Appendix E):

- A message starts with STX (``0x02``) and ends with ETX (``0x03``). Over
  Telnet or serial, the relay echoes the command before the message and sends
  the prompt after it. Files read from a relay may not have the framing.
- Lines end with CR LF (CR alone on some older relays).
- Fields are separated by commas. Strings are in double quotes and numbers
  aren't. An empty field means there's no value. Quotes inside a string
  aren't escaped, so the :mod:`csv` module can't be used.
- The last field of a line is a checksum: four hex digits in quotes, upper or
  lower case. It's the sum of the bytes of the line, from the first byte
  (after the STX, CR, or CR LF) through the comma before the checksum,
  modulo 65536.
- Label lines (all strings) name the values in the lines that follow them.
  The ``CASCII`` (``CAS``) command describes the label and data lines that
  each compressed command returns, so the layouts can be read from the device
  instead of being hard-coded.

Everything in this module is pure (no device or file I/O), so it works on data
from any source: Telnet, serial, files, or a packet capture (after the Telnet
negotiation bytes are removed).

Use :func:`parse_records` to split data into :class:`Record` objects,
:func:`parse_report` to get the rows of a report as :class:`dict` objects
keyed by their labels, :func:`parse_cas` for ``CAS`` output, and
:func:`parse_id_output` for ``ID`` output.
"""

import re
from dataclasses import dataclass, field
from typing import Final, Literal

from peat import log

STX: Final = "\x02"  #: Start of text, the start of a message
ETX: Final = "\x03"  #: End of text, the end of a message
XON: Final = "\x11"  #: Flow control, resume sending
XOFF: Final = "\x13"  #: Flow control, pause sending
CAN: Final = "\x18"  #: Cancel, aborts the output of a command

#: First byte of a binary SEL Fast Meter, Fast Operate, or Fast SER frame,
#: which can be interleaved with ASCII data on the same port. The third byte
#: of a frame is the length of the frame.
FAST_FRAME_START: Final = "\xa5"

#: Second byte (function code) of the binary SEL Fast frames that have a length:
#: Fast Message and Fast SER (``A546``), and the Fast Meter and Fast Operate
#: messages (``A5C0`` to ``A5ED``). Any other ``0xA5`` byte is text, e.g. the
#: second byte of a UTF-8 ``U+00E5`` (a with a ring), or a Latin-1 yen sign.
FAST_FRAME_CODES: Final = frozenset({0x46, *range(0xC0, 0xEE)})

#: Maximum number of physical lines joined into one record, for a quoted
#: field that spans lines (e.g. the settings in ``CEV`` output)
MAX_JOINED_LINES: Final = 500

#: Checksum field at the end of a line, e.g. ``,"0668"``
CHECKSUM_RE: Final = re.compile(r',"([0-9A-Fa-f]{4})"[ \t]*$')

#: Response from a compressed command (e.g. ``CSE`` or ``CHI``) when there isn't any data
NO_DATA_MESSAGE: Final = "No Data Available"

#: First label of label lines that are always label lines, even if they're
#: the first line after another label line. These are the device header
#: (``FID`` or ``RID``) and the first label of event and history rows.
KNOWN_LABEL_STARTS: Final = ("FID", "RID", "#", "REC_NUM", "EVENT_NUM", "REF_NUM", "MONTH")

#: Header (``H``), format header (``h``), or data format (``D``) line in ``CAS`` output
_CAS_BLOCK_RE: Final = re.compile(r"(\d+)([HhD]?)")

#: Line endings, CR LF for most relays, CR for some older relays
_LINE_SPLIT_RE: Final = re.compile(r"\r\n|\r|\n")

_INT_RE: Final = re.compile(r"[+-]?\d+")
_FLOAT_RE: Final = re.compile(r"[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?")

#: Key in ``ID`` output, e.g. ``FID``, ``iedName``, or ``SEL DISPLAY PACKAGE``
_ID_KEY_RE: Final = re.compile(r"[A-Za-z][\w .\-]*")

#: Value in ``ID`` output when the IEC 61850 CID file on the relay is invalid
ID_PARSE_FAILURE: Final = "PARSE FAILURE"

RecordStatus = Literal["valid", "invalid", "missing", "unverified"]

#: The checksum is correct
STATUS_VALID: Final = "valid"
#: The checksum is wrong. The record may be corrupted.
STATUS_INVALID: Final = "invalid"
#: The record doesn't have a checksum (e.g. the echo of a command, or a prompt)
STATUS_MISSING: Final = "missing"
#: The record spans multiple lines and the checksum didn't match. SEL doesn't
#: publicly document how the checksum of these records is calculated,
#: so they aren't treated as invalid.
STATUS_UNVERIFIED: Final = "unverified"


@dataclass
class Field:
    """
    A field in a Compressed ASCII record.
    """

    #: Text of the field, without the quotes
    text: str

    #: If the field was in quotes (a string)
    quoted: bool

    @property
    def value(self) -> str | int | float | None:
        """
        The value of the field: :class:`str` for a quoted field, :obj:`None` for
        an empty unquoted field, :class:`int` or :class:`float` for a number, and
        the text for anything else (e.g. ``$$$$.$$``, an unknown fault location).
        """
        if self.quoted:
            return self.text

        return parse_number(self.text)


@dataclass
class Record:
    """
    A line (record) of Compressed ASCII data.
    """

    #: The record as received, without the line ending. Records that span
    #: multiple lines have the lines joined with CR LF.
    text: str

    #: Fields in the record, without the checksum
    fields: list[Field] = field(default_factory=list)

    #: Checksum in the record, if it has one
    checksum: int | None = None

    #: Checksum calculated from the record, if the record has a checksum
    calculated: int | None = None

    #: If the checksum is correct (``valid``), wrong (``invalid``), not present
    #: (``missing``), or couldn't be verified (``unverified``)
    status: RecordStatus = STATUS_MISSING

    #: Number of physical lines in the record
    lines: int = 1

    @property
    def valid(self) -> bool:
        """If the record has a checksum and it's correct."""
        return self.status == STATUS_VALID

    @property
    def values(self) -> list[str | int | float | None]:
        """Values of the fields (refer to :attr:`Field.value`)."""
        return [f.value for f in self.fields]

    @property
    def labels(self) -> list[str]:
        """Text of the fields, e.g. the labels in a label line."""
        return [f.text for f in self.fields]

    @property
    def all_quoted(self) -> bool:
        """If the record has fields and every field is a string (in quotes)."""
        return bool(self.fields) and all(f.quoted for f in self.fields)


def checksum(body: bytes | str) -> int:
    """
    Calculate the checksum of a Compressed ASCII line.

    Args:
        body: The bytes of the line from the first byte through the comma
            before the checksum field, e.g. ``"No Data Available",``.
            Text is encoded as Latin-1 (so that every character is one byte),
            or UTF-8 if it has characters that aren't in Latin-1.

    Returns:
        The sum of the bytes, modulo 65536 (``0x0668`` for the example above)
    """
    if isinstance(body, str):
        try:
            body = body.encode("latin-1")
        except UnicodeEncodeError:
            body = body.encode("utf-8")

    return sum(body) & 0xFFFF


def format_record(values: list[str | int | float | None]) -> str:
    """
    Create a Compressed ASCII line with a checksum, e.g. for tests or
    emulating a device. Strings are quoted, numbers aren't, and :obj:`None`
    is an empty field.

    .. code-block:: python

       >>> format_record(["CAS", 5])
       '"CAS",5,"01A8"'
    """
    parts = []
    for value in values:
        if value is None:
            parts.append("")
        elif isinstance(value, str):
            parts.append(f'"{value}"')
        else:
            parts.append(str(value))

    body = ",".join(parts) + ","
    return f'{body}"{checksum(body):04X}"'


def parse_number(text: str) -> int | float | str | None:
    """
    Convert the text of an unquoted field to an :class:`int` or :class:`float`.

    Returns:
        :obj:`None` if the text is empty, the number, or the text if it's not
        a number (e.g. ``$$$$$$$``, which relays use for unknown values)
    """
    text = text.strip()

    if not text:
        return None
    if _INT_RE.fullmatch(text):
        return int(text)
    if _FLOAT_RE.fullmatch(text):
        return float(text)

    return text


def _to_text(data: bytes | bytearray | str) -> str:
    # Latin-1 maps every byte to the character with the same value,
    # so checksums calculated from the text match the bytes.
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode("latin-1")
    return data


def _fast_frame_length(text: str, start: int) -> int:
    """
    Length of the binary SEL Fast frame at ``start``, or ``0`` if there isn't one.

    A frame is ``0xA5``, a function code in :data:`FAST_FRAME_CODES`, and
    the length of the frame (all of it), and it must be complete. Fast Message
    frames (``A546``) end with a CRC and their routing address (bytes 3 to 7)
    is always zero. The other frames end with a checksum, the sum of the other
    bytes (modulo 256).
    """
    if start + 3 >= len(text) or ord(text[start + 1]) not in FAST_FRAME_CODES:
        return 0

    length = ord(text[start + 2])
    if length < 4 or start + length > len(text):
        return 0

    frame = text[start : start + length]

    if ord(frame[1]) == 0x46:
        # The header is 11 bytes and the CRC is 2 bytes
        return length if length >= 13 and frame[3:8] == "\x00" * 5 else 0

    if (sum(ord(char) for char in frame[:-1]) & 0xFF) == ord(frame[-1]):
        return length

    return 0


def _strip_fast_frames(text: str) -> str:
    """
    Remove binary SEL Fast frames (``0xA5 <type> <length> ...``), which can be
    interleaved with ASCII data on the same port (refer to :func:`_fast_frame_length`).
    Other ``0xA5`` characters are kept.
    """
    if FAST_FRAME_START not in text:
        return text

    out = []
    i = 0
    while i < len(text):
        if text[i] == FAST_FRAME_START:
            length = _fast_frame_length(text, i)
            if length:
                i += length
                continue
        out.append(text[i])
        i += 1

    return "".join(out)


def extract_messages(data: bytes | str) -> list[str]:
    """
    Get the messages in data received from a SEL device.

    A message is the text between a STX (``0x02``) and the next ETX (``0x03``).
    The command echo before a message and the prompt after it are removed.
    If there's no STX (e.g. a file downloaded from a relay with FTP), all of the
    data up to the first ETX (if any) is one message.

    Flow control characters (XON, XOFF), CAN, NUL characters (Telnet sends
    CR NUL for a bare CR), and binary SEL Fast frames are removed.

    Args:
        data: Data received from a device. :class:`bytes` are decoded
            as Latin-1, so that checksums can be verified.

    Returns:
        The messages, without the STX and ETX. Messages that are empty or
        only whitespace are skipped.
    """
    text = _strip_fast_frames(_to_text(data))

    for char in (XON, XOFF, CAN, "\x00"):
        text = text.replace(char, "")

    if STX not in text:
        parts = [text.split(ETX, 1)[0]]
    else:
        parts = [part.split(ETX, 1)[0] for part in text.split(STX)[1:]]

    return [part for part in parts if part.strip()]


def _closing_quote(text: str, start: int) -> int:
    """
    Find the quote that ends a quoted field starting at ``start`` (after the
    opening quote). Quotes inside fields aren't escaped, so the field ends at
    the first quote that's followed by a comma (spaces are allowed before
    the comma) or the end of the text.

    Returns:
        Position of the quote, or ``-1`` if the field isn't terminated
    """
    pos = text.find('"', start)
    while pos != -1:
        after = pos + 1
        while after < len(text) and text[after] in " \t":
            after += 1
        if after == len(text) or text[after] == ",":
            return pos
        pos = text.find('"', pos + 1)

    return -1


def _tokenize(text: str) -> tuple[list[Field], bool]:
    """
    Split text into fields.

    Returns:
        The fields, and :obj:`False` if the last quoted field isn't terminated
    """
    fields = []
    pos = 0

    while True:
        start = pos
        while start < len(text) and text[start] in " \t":
            start += 1

        if start < len(text) and text[start] == '"':
            end = _closing_quote(text, start + 1)
            if end == -1:
                fields.append(Field(text[start + 1 :], quoted=True))
                return fields, False

            fields.append(Field(text[start + 1 : end], quoted=True))
            comma = text.find(",", end + 1)
            if comma == -1:
                return fields, True
            pos = comma + 1
        else:
            comma = text.find(",", pos)
            if comma == -1:
                fields.append(Field(text[pos:].strip(), quoted=False))
                return fields, True
            fields.append(Field(text[pos:comma].strip(), quoted=False))
            pos = comma + 1


def tokenize(text: str) -> list[Field]:
    """
    Split the text of a record (without the checksum) into fields.

    A quoted field ends at the first quote that's followed by a comma or the
    end of the text, since quotes inside strings aren't escaped. Unquoted
    fields end at the next comma.

    .. code-block:: python

       >>> [f.value for f in tokenize('"Ok",,,"Ok",24.8')]
       ['Ok', None, None, 'Ok', 24.8]
    """
    if not text:
        return []

    return _tokenize(text)[0]


def _make_record(text: str) -> Record:
    """
    Create a record from a single line, and verify its checksum.
    """
    stripped = text.strip(" \t")
    match = CHECKSUM_RE.search(stripped)

    if not match:
        return Record(text=stripped, fields=tokenize(stripped))

    body = stripped[: match.start() + 1]  # Through the comma before the checksum
    expected = int(match.group(1), 16)
    calculated = checksum(body)

    # Lines from relays don't have leading whitespace, but just in case
    # it's part of the line, check the checksum with it.
    if calculated != expected and text[:1] in (" ", "\t"):
        unstripped = text.rstrip(" \t")
        unstripped_body = unstripped[: CHECKSUM_RE.search(unstripped).start() + 1]
        if checksum(unstripped_body) == expected:
            calculated = expected

    return Record(
        text=stripped,
        fields=tokenize(body[:-1]),
        checksum=expected,
        calculated=calculated,
        status=STATUS_VALID if calculated == expected else STATUS_INVALID,
    )


def _make_joined_record(lines: list[str]) -> Record:
    """
    Create a record from a quoted field that spans multiple lines,
    e.g. the settings in ``CEV`` output.

    The relay may or may not include the line endings in the checksum
    (it's not documented), so a few variations are tried. If none of them
    match, the record is ``unverified`` instead of ``invalid``.
    """
    text = "\r\n".join(lines).rstrip(" \t")
    match = CHECKSUM_RE.search(lines[-1].rstrip(" \t"))

    if not match:  # The record wasn't terminated (e.g. the data was truncated)
        return Record(text=text, fields=tokenize(text), lines=len(lines))

    expected = int(match.group(1), 16)
    last = lines[-1].rstrip(" \t")
    body_lines = [*lines[:-1], last[: match.start() + 1]]
    body = "\r\n".join(body_lines)

    status = STATUS_UNVERIFIED
    calculated = checksum(body)
    for separator in ("\r\n", "\n", "\r", ""):
        candidate = checksum(separator.join(body_lines))
        if candidate == expected:
            status = STATUS_VALID
            calculated = candidate
            break

    # A single string that spans lines, e.g. "Group 1\r\n...\r\n",
    # may have quotes in it, so it's kept as one field.
    inner = body[:-1].strip(" \t")
    if len(inner) >= 2 and inner[0] == '"' and inner[-1] == '"':
        fields = [Field(inner[1:-1], quoted=True)]
    else:
        fields = tokenize(inner)

    return Record(
        text=text,
        fields=fields,
        checksum=expected,
        calculated=calculated,
        status=status,
        lines=len(lines),
    )


def split_records(message: str, max_join: int = MAX_JOINED_LINES) -> list[Record]:
    """
    Split a message into records and verify their checksums.

    Blank lines are skipped. A line that doesn't end with a checksum and has an
    unterminated quoted field is joined with the following lines, up to the
    line with a checksum (and at most ``max_join`` lines). If the checksum of
    the joined record isn't correct but the line with the checksum is a record
    with a correct checksum by itself, then the first line was truncated
    (e.g. by noise on a serial port), so it's a record by itself (without a
    checksum) and the following lines are split as usual. Records with a wrong
    checksum are kept (their status is ``invalid``) and a warning is logged.

    Args:
        message: A message, from :func:`extract_messages`
        max_join: Maximum number of lines to join into one record

    Returns:
        The records in the message
    """
    records = []
    lines = _LINE_SPLIT_RE.split(message)
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip(" \t")
        index += 1

        if not stripped:
            continue

        if CHECKSUM_RE.search(stripped) or _tokenize(stripped)[1]:
            records.append(_make_record(line))
            continue

        # Unterminated quoted field: join the lines up to the next checksum
        pending = [stripped]
        end = index
        has_checksum = False
        while end < len(lines) and len(pending) < max_join:
            pending.append(lines[end])
            end += 1
            if CHECKSUM_RE.search(lines[end - 1].rstrip(" \t")):
                has_checksum = True
                break

        joined = _make_joined_record(pending)

        # Only the last line has a checksum, since the join ends there
        if has_checksum and not joined.valid and _make_record(pending[-1]).valid:
            log.warning(
                f"Compressed ASCII record has an unterminated string "
                f"and no checksum: {stripped[:80]!r}"
            )
            records.append(_make_record(stripped))
            continue  # Split the following lines as usual

        if not has_checksum and len(pending) >= max_join:
            log.warning(
                f"Compressed ASCII record is longer than {max_join} lines, "
                f"splitting it (first line: {pending[0][:80]!r})"
            )

        records.append(joined)
        index = end

    for record in records:
        if record.status == STATUS_INVALID:
            log.warning(
                f"Invalid Compressed ASCII checksum (expected {record.checksum:04X}, "
                f"calculated {record.calculated:04X}): {record.text[:120]!r}"
            )

    return records


def parse_records(data: bytes | str) -> list[Record]:
    """
    Get the records in data received from a device or read from a file.

    This combines :func:`extract_messages` and :func:`split_records`.
    """
    records = []
    for message in extract_messages(data):
        records.extend(split_records(message))

    return records


def _as_records(data: bytes | str | list[Record]) -> list[Record]:
    if isinstance(data, list):
        return data
    return parse_records(data)


def is_compressed_ascii(data: bytes | str | list[Record]) -> bool:
    """
    If data is Compressed ASCII, meaning at least one record has a correct checksum.
    """
    return any(record.valid for record in _as_records(data))


def is_no_data(data: bytes | str | list[Record]) -> bool:
    """
    If the response is ``"No Data Available"``, which compressed
    commands (e.g. ``CSE``) return when there's no data.
    """
    return any(
        len(record.fields) == 1
        and record.fields[0].text.strip().lower() == NO_DATA_MESSAGE.lower()
        for record in _as_records(data)
    )


def parse_cas(data: bytes | str | list[Record]) -> dict[str, dict]:
    """
    Parse the output of the ``CAS`` (``CASCII``) command, which describes
    the Compressed ASCII commands on the device.

    The format is ``"CAS",<number of commands>``, then for each command a line
    with the command and the minimum access level to run it (``"CHI",1``),
    followed by pairs of label (``"12H","REC_NUM",...``) and data format
    (``"20D","I",...``) lines. The number in a ``H`` line is the number of
    labels, and the number in a ``D`` line is the maximum number of data lines
    for those labels. Data types are ``I`` (integer), ``F`` (float), and
    ``<n>S`` (string with at most ``n`` characters). A format line without the
    ``D`` (e.g. ``"1952"``, a typo in a SEL manual) is treated as a ``D`` line.
    A ``h`` (lowercase) line is a header with format fields, which isn't
    described in public manuals, and is recorded with ``format_fields``.

    For example, the ``CHI`` command of a SEL-551 is
    ``{"access_level": 1, "blocks": [{"labels": ["REC_NUM", "MONTH", ...],
    "types": ["I", "I", ...], "max_rows": 20}]}``.

    Args:
        data: Output of the ``CAS`` command, or records from :func:`parse_records`

    Returns:
        The commands, keyed by the command (e.g. ``CEV L``). Each has
        the ``access_level`` and the ``blocks`` of labels and data types.
    """
    commands = {}  # type: dict[str, dict]
    current = None  # type: dict | None
    declared = None

    for record in _as_records(data):
        if not record.fields or record.status == STATUS_MISSING:
            continue

        values = record.values
        first = record.fields[0].text.strip()

        if first.upper() == "CAS" and declared is None and len(values) >= 2:
            declared = values[1]
            continue

        block_match = _CAS_BLOCK_RE.fullmatch(first)

        if block_match and current is not None:
            count = int(block_match.group(1))
            kind = block_match.group(2)
            items = [str(v) if v is not None else "" for v in values[1:]]

            if kind in ("H", "h"):
                block = {"labels": items, "types": [], "max_rows": None}
                if kind == "h":
                    block["format_fields"] = True
                if count != len(items):
                    log.debug(f"CAS: {count} labels expected for {first!r}, got {len(items)}")
                current["blocks"].append(block)
            else:  # "D" (or a bare number)
                blocks = current["blocks"]
                if not blocks or blocks[-1]["types"]:
                    blocks.append({"labels": [], "types": [], "max_rows": None})
                blocks[-1]["types"] = items
                blocks[-1]["max_rows"] = count
            continue

        if record.fields[0].quoted and len(values) >= 2:
            current = commands.setdefault(first, {"access_level": values[1], "blocks": []})
        else:
            log.debug(f"CAS: skipping unexpected record {record.text!r}")

    if isinstance(declared, int) and declared != len(commands):
        log.debug(f"CAS: {declared} commands declared, {len(commands)} parsed")

    return commands


def _is_known_label_line(record: Record) -> bool:
    first = record.fields[0].text.strip().upper()
    return first in KNOWN_LABEL_STARTS


def _zip_row(labels: list[str], values: list) -> dict:
    """
    Map values to their labels. A row can be shorter than the labels (the
    missing labels aren't in the row) or longer (the values without a label
    are in ``_extra``).
    """
    row = dict(zip(labels, values, strict=False))

    if len(values) > len(labels):
        row["_extra"] = values[len(labels) :]

    return row


def _new_block(labels: list[str], label_record: Record | None) -> dict:
    return {"labels": labels, "label_record": label_record, "rows": [], "records": []}


def parse_report(data: bytes | str | list[Record], layout: list[dict] | None = None) -> list[dict]:
    """
    Parse the label and data lines of a Compressed ASCII report
    (e.g. ``CSE`` or ``CHI`` output, or ``CSER.TXT``).

    Without a layout, label lines are found like this: a record where every
    field is a string is a label line, unless it's the first record after a
    label line (then it's data, e.g. the ``"FID=SEL-..."`` line after the
    ``"FID"`` label line). Records that start with a common first label
    (:data:`KNOWN_LABEL_STARTS`) are always label lines.

    With a layout (the ``blocks`` of a command from :func:`parse_cas`), records
    that match the labels of a block are label lines, and up to ``max_rows``
    records after them are data. Records that don't fit the layout are parsed
    without it.

    Args:
        data: The report, or records from :func:`parse_records`
        layout: Blocks for the command, from :func:`parse_cas`

    Returns:
        The blocks of the report, in order. Each has the ``labels``, the
        ``label_record``, the ``rows`` (:class:`dict` objects keyed by the
        labels, with values that don't have a label in ``_extra``), and the
        ``records`` of the rows (to check the checksums).
    """
    records = [r for r in _as_records(data) if r.fields]
    expected = [
        [label.strip().upper() for label in block["labels"]]
        for block in (layout or [])
        if block.get("labels")
    ]
    max_rows = [block.get("max_rows") for block in (layout or []) if block.get("labels")]

    blocks = []  # type: list[dict]
    current = None  # type: dict | None
    after_label = False
    rows_left = None  # type: int | None
    next_layout = 0

    for record in records:
        # Label line from the layout (CAS)
        upper = [label.strip().upper() for label in record.labels]
        if record.all_quoted and upper in expected[next_layout:]:
            index = expected.index(upper, next_layout)
            next_layout = index + 1
            rows_left = max_rows[index]
            current = _new_block(record.labels, record)
            blocks.append(current)
            after_label = True
            continue

        if current is not None and rows_left is not None and rows_left > 0:
            is_label = False  # Data line for the labels in the layout
        else:
            # No layout, or more rows than the layout allows
            rows_left = None
            is_label = record.all_quoted and (
                current is None or not after_label or _is_known_label_line(record)
            )

        if is_label:
            current = _new_block(record.labels, record)
            blocks.append(current)
            after_label = True
            rows_left = None
            continue

        if current is None:
            current = _new_block([], None)
            blocks.append(current)

        current["rows"].append(_zip_row(current["labels"], record.values))
        current["records"].append(record)
        after_label = False
        if rows_left is not None:
            rows_left -= 1

    return blocks


def parse_id_output(data: bytes | str) -> dict[str, str | list[str]]:
    """
    Parse the output of the ``ID`` command.

    Each line is a Compressed ASCII record with a ``KEY=VALUE`` string,
    e.g. ``"FID=SEL-351S-5-R512-V0-Z104104-D20120830","095B"``. Common keys
    are ``FID``, ``BFID``, ``CID`` (firmware checksum), ``DEVID``, ``DEVCODE``,
    ``PARTNO``, ``SERIALNO``, ``CONFIG``, ``SPECIAL``, and on relays with
    IEC 61850, ``iedName``, ``type``, ``configVersion``, and ``LIB61850ID``.

    - The key and value are split at the first ``=`` and whitespace is removed
      from both. 700-series relays print a space before the ``=``
      (``"iedName =TEMPLATE"``), and values can contain ``=``.
    - Keys without a value (``"iedName="``, no CID file loaded) are skipped.
    - A ``PARSE FAILURE`` value (some relays print this if the CID file is
      invalid) isn't a real value, so it's skipped, and the keys are listed in
      ``iec61850_parse_failure``.
    - Checksums are verified, and a warning is logged for a wrong checksum.
      The value is still used.
    - If a key is in the output more than once, the first value is used.
    - The command echo and the prompt are ignored, and the framing (STX/ETX)
      is optional.

    Args:
        data: Output of the ``ID`` command, as received from the device

    Returns:
        The values, keyed by the keys in the output (e.g. ``FID``)
    """
    info = {}  # type: dict[str, str | list[str]]
    parse_failures = []  # type: list[str]

    for record in parse_records(data):
        if len(record.fields) != 1 or "=" not in record.fields[0].text:
            continue

        key, _, value = record.fields[0].text.partition("=")
        key = key.strip()
        value = value.strip()

        if not _ID_KEY_RE.fullmatch(key):  # e.g. the "=>" prompt
            continue

        if record.status == STATUS_INVALID:
            log.warning(f"Using '{key}' from 'id' output despite its invalid checksum")

        if not value:
            continue

        if value.upper() == ID_PARSE_FAILURE:
            parse_failures.append(key)
            continue

        if key in info:
            if info[key] != value:
                log.debug(f"Ignoring second value for '{key}' in 'id' output: {value!r}")
            continue

        info[key] = value

    if parse_failures:
        log.warning(
            f"The relay reported '{ID_PARSE_FAILURE}' for {', '.join(parse_failures)} "
            f"in the 'id' output, its IEC 61850 CID file may be invalid"
        )
        info["iec61850_parse_failure"] = parse_failures

    return info


__all__ = [
    "CAN",
    "ETX",
    "STX",
    "XOFF",
    "XON",
    "Field",
    "Record",
    "checksum",
    "extract_messages",
    "format_record",
    "is_compressed_ascii",
    "is_no_data",
    "parse_cas",
    "parse_id_output",
    "parse_number",
    "parse_records",
    "parse_report",
    "split_records",
    "tokenize",
]
