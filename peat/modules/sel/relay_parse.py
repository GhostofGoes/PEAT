import copy
import csv
import re
import zlib
from datetime import datetime, timedelta
from pathlib import PurePath, PurePosixPath
from typing import Any, Final, Literal

import olefile
from dateutil.parser import parse as date_parse
from dateutil.parser import parserinfo
from pathvalidate import is_valid_filepath

from peat import (
    IO,
    DeviceData,
    Event,
    Interface,
    ParseError,
    Register,
    Service,
    consts,
    datastore,
    log,
    state,
    utils,
)
from peat import config as peat_config
from peat.data.data_utils import merge_models
from peat.data.models import Firmware
from peat.data.validators import validate_hash
from peat.protocols import clean_ipv4, split_ipv4_cidr

from . import sel_cascii
from .sel_consts import ANSI_CODES, LOGIC_KEYS
from .sel_files import SOURCE_DERIVED, write_and_record_file

ConfigSectionType = list[str] | dict[str, str]
ConfigsType = dict[str, ConfigSectionType]


#: Individual settings files, e.g. ``SET_1.TXT`` on a relay or ``set_p1.txt`` in an RDB.
#: This also matches ``SET_ALL.TXT``, callers that care must check for it.
SETTINGS_FILENAME_RE: Final = re.compile(r"^SET_[A-Z0-9]+\.TXT$", re.IGNORECASE)

#: Section header line in a settings file, e.g. ``[INFO]`` or ``[P5]``
SECTION_HEADER_RE: Final = re.compile(r"^\s*\[([^\]]*)\]\s*$")

#: Characters that appear in settings files but aren't part of the settings.
#: QuickSet terminates each line in an RDB stream with a file separator (0x1C),
#: some files end with a substitution character (0x1A), and some older RDBs
#: (e.g. ``300G_000.rdb``) have NUL bytes that break the CSV parser.
SETTINGS_JUNK_CHARS: Final = ("\x1c", "\x1a", "\x00")


#: Event files, e.g. ``SER.TXT``, ``CSER.TXT``, ``HISTORY.TXT``, or ``CHISTORY.TXT``.
#: A prefix is allowed (``192.0.2.1_SER.TXT``), but not one that's part of a word (``USER.TXT``).
EVENT_FILENAME_RE: Final = re.compile(r"(?:^|[^A-Z])C?(?:SER|HISTORY)\.TXT$", re.IGNORECASE)


def is_event_filename(filename: str) -> bool:
    """
    If a filename is for a SER, CSER, HISTORY, or CHISTORY event file.
    """
    return bool(EVENT_FILENAME_RE.search(filename))


def clean_settings_text(data: bytes | str) -> str:
    """
    Decode settings file data and remove characters that aren't part of the settings.
    """
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            # QuickSet runs on Windows, files may have Windows-1252 characters
            data = data.decode("latin-1")

    data = data.removeprefix("\ufeff")  # UTF-8 Byte Order Mark (BOM)

    for char in SETTINGS_JUNK_CHARS:
        data = data.replace(char, "")

    return data


def _format_dnpb_lines(lines: list[str]) -> list[str]:
    """
    Convert the DNP Binary map (``[DNPB]``) from a single space-separated
    value into one ``BI_<n>`` line per point.

    Example: ``DNPB,"52A 52B IN101"`` => ``BI_1,"52A"``, ``BI_2,"52B"``, etc.
    """
    formatted = []
    idx = 1

    for line in extract_csv_lines(lines):
        if len(line) > 1 and line[0].upper() == "DNPB":
            for address in line[1].split():
                formatted.append(f'BI_{idx},"{address}"')
                idx += 1
        else:
            formatted.append(",".join(f'"{chunk}"' for chunk in line))

    return formatted


def _format_dnpb(data: str) -> str:
    """
    Convert the ``[DNPB]`` section in the text of a settings file with
    :func:`_format_dnpb_lines`, leaving the other sections as-is.
    """
    output = []

    for section, lines in split_raw_sections(data):
        if section.upper() == "DNPB":
            lines = _format_dnpb_lines(lines)
        output.extend([f"[{section}]", *lines])

    return "\r\n".join(output) + "\r\n"


def split_raw_sections(text: str) -> list[tuple[str, list[str]]]:
    """
    Split the text of a settings file into sections, preserving their order
    and the original lines. Lines before the first section header are dropped.

    Returns:
        List of tuples of section name and the raw lines in that section
    """
    sections = []  # type: list[tuple[str, list[str]]]

    for line in text.splitlines():
        if not line.strip():
            continue

        header = SECTION_HEADER_RE.match(line)
        if header:
            sections.append((header.group(1).strip(), []))
        elif sections:
            sections[-1][1].append(line.rstrip())
        else:
            log.debug("Skipping settings line before the first section header")

    return sections


def _natural_sort_key(name: str) -> list[int | str]:
    # "SET_2.TXT" sorts before "SET_10.TXT"
    return [int(c) if c.isdigit() else c for c in re.split(r"(\d+)", name.upper())]


def combine_settings_files(
    files: dict[str, bytes | str], save_info: list[str] | None = None
) -> str:
    """
    Combine ``CFG.TXT`` and individual settings files (``SET_*.TXT``) into
    a single string in the same format as ``SET_ALL.TXT``.

    This is used for relays that don't have a ``SET_ALL.TXT``, directories
    of settings files, and the settings in QuickSet RDB files.

    Every settings file begins with a copy of the ``[INFO]`` section. Only
    the first ``[INFO]`` is kept, with ``CFG.TXT`` taking priority since it
    also has the ``[CLASSES]`` section listing the settings classes.

    Args:
        files: settings file data keyed by filename. The filenames are case-insensitive.
            Files that aren't ``CFG.TXT`` or ``SET_*.TXT`` are ignored, as is ``SET_ALL.TXT``.
        save_info: Lines about when and how settings were saved, e.g. from the
            ``Version`` stream in a RDB file ("Saved on 2/16/2023 at 10:14:22 PM").
            These are added to the ``[CLASSES]`` section.

    Returns:
        The combined settings, or an empty string if there were no settings
    """
    by_name = {name.upper(): data for name, data in files.items()}

    ordered_names = []
    if "CFG.TXT" in by_name:
        ordered_names.append("CFG.TXT")

    # Order the settings files the same as the classes in CFG.TXT, like in
    # SET_ALL.TXT ("SET_P1.TXT" is the settings for class "P1").
    class_order = []  # type: list[str]
    if "CFG.TXT" in by_name:
        for section, lines in split_raw_sections(clean_settings_text(by_name["CFG.TXT"])):
            if section.upper() == "CLASSES":
                class_order.extend(
                    f"SET_{line[0].upper()}.TXT" for line in extract_csv_lines(lines) if line
                )

    def _order(name: str) -> tuple[int, list[int | str]]:
        position = class_order.index(name) if name in class_order else len(class_order)
        return position, _natural_sort_key(name)

    ordered_names.extend(
        sorted(
            (
                name
                for name in by_name
                if SETTINGS_FILENAME_RE.match(name) and name != "SET_ALL.TXT"
            ),
            key=_order,
        )
    )

    info_lines = None  # type: list[str] | None
    classes_lines = []  # type: list[str]
    other_sections = []  # type: list[tuple[str, list[str]]]

    for name in ordered_names:
        text = clean_settings_text(by_name[name])

        for section, lines in split_raw_sections(text):
            if section.upper() == "DNPB":
                lines = _format_dnpb_lines(lines)

            if section.upper() == "INFO":
                if info_lines is None:
                    info_lines = lines
            elif section.upper() == "CLASSES":
                classes_lines.extend(lines)
            else:
                other_sections.append((section, lines))

    if not other_sections and not info_lines:
        return ""

    if save_info:
        for msg in save_info:
            escaped = msg.strip().replace('"', '""')
            classes_lines.append(f'"{escaped}"')

    output = []
    if info_lines is not None:
        output.extend(["[INFO]", *info_lines])
    if classes_lines:
        output.extend(["[CLASSES]", *classes_lines])
    for section, lines in other_sections:
        output.extend([f"[{section}]", *lines])

    return "\r\n".join(output) + "\r\n"


def read_rdb_streams(rdb_data: bytes) -> dict[str, dict[str, bytes]]:
    """
    Read the streams from a SEL QuickSet database (``*.rdb`` file) and
    group them by the relay they're for.

    RDB files are OLE2 Compound File Binary (CFB) files, with a storage
    for each relay in the database:

    .. code-block:: text

       Relays/
           <relay name>/
               Misc/
                   Cfg.txt       (same as CFG.TXT on a relay)
                   Device.txt    (name of the relay in QuickSet)
                   Version       (QuickSet version and when the settings were saved)
                   GL1.gle, ...  (logic diagrams, binary)
               set_1.txt, set_p1.txt, SET_G1.TXT, ...

    Args:
        rdb_data: Binary data from an ``.rdb`` project file

    Returns:
        Stream data keyed by the relay name, then by the path of the stream
        relative to the relay's storage (e.g. ``"Misc/Cfg.txt"``). Streams that
        aren't in a relay's storage are keyed by an empty relay name (``""``).
    """
    relays = {}  # type: dict[str, dict[str, bytes]]

    with olefile.OleFileIO(rdb_data) as rdb_ole:
        for stream_list in rdb_ole.listdir(streams=True, storages=False):
            data = rdb_ole.openstream(stream_list).read()

            if len(stream_list) >= 3 and stream_list[0].lower() == "relays":
                relay_name = stream_list[1]
                stream_path = "/".join(stream_list[2:])
            else:
                relay_name = ""
                stream_path = "/".join(stream_list)

            relays.setdefault(relay_name, {})[stream_path] = data

    return relays


def rdb_relay_to_set_all(streams: dict[str, bytes]) -> str:
    """
    Convert the streams for a single relay in a RDB file into a string
    in the same format as ``SET_ALL.TXT``.

    Args:
        streams: Streams for a relay, from :func:`read_rdb_streams`

    Returns:
        The relay's settings in the ``SET_ALL.TXT`` format, or an
        empty string if there are no settings.
    """
    files = {}  # type: dict[str, bytes]
    save_info = []  # type: list[str]

    for stream_path, data in streams.items():
        name = PurePosixPath(stream_path).name

        if name.lower() == "cfg.txt":
            files["CFG.TXT"] = data
        elif name.lower() == "version":
            # "Saved on 2/16/2023 at 10:14:22 PM"
            save_info.extend(
                line.strip() for line in clean_settings_text(data).splitlines() if line.strip()
            )
        elif SETTINGS_FILENAME_RE.match(name):
            files[name] = data

    return combine_settings_files(files, save_info)


def _concat_rdb_streams(rdb_data: bytes) -> str:
    """
    Concatenate every stream in a RDB file. This is a fallback for
    RDB files that don't have the usual ``Relays/<name>/`` layout.
    """
    output = ""
    rdb_ole = olefile.OleFileIO(rdb_data)
    streams = rdb_ole.listdir(streams=True, storages=False)  # type: list[list[str]]

    for stream_list in streams:
        stream_path = "/".join(stream_list)
        data = clean_settings_text(rdb_ole.openstream(stream_path).read())

        if not data.endswith("\r\n"):
            data += "\r\n"

        if "[DNPB]" in data:
            data = _format_dnpb(data)

        output += data

    rdb_ole.close()

    # Remove UI info stored by some configs
    start_index = output.find("[INFO]")
    if start_index > 0:
        output = output[start_index:]

    return output


def parse_rdb_relays(rdb_data: bytes) -> dict[str, str]:
    """
    Extract the settings for every relay in a SEL QuickSet database (``*.rdb`` file).

    Args:
        rdb_data: Binary data from an ``.rdb`` project file

    Returns:
        Settings for each relay in the ``SET_ALL.TXT`` format, keyed by
        the name of the relay in the RDB file. If the file doesn't have
        the usual layout, then all of the streams are combined and returned
        with an empty string as the relay name.
    """
    relays = {}  # type: dict[str, str]

    for relay_name, streams in read_rdb_streams(rdb_data).items():
        if not relay_name:
            continue

        set_all = rdb_relay_to_set_all(streams)
        if set_all:
            relays[relay_name] = set_all
        else:
            log.warning(f"No settings found for relay '{relay_name}' in RDB file")

    if not relays:
        log.debug("No relays found in RDB 'Relays' storage, combining all streams")
        relays[""] = _concat_rdb_streams(rdb_data)

    return relays


def has_settings_sections(text: str) -> bool:
    """
    If text has settings sections, e.g. ``[1]`` or ``[P5]``, and not just
    the sections with information about the settings (``[INFO]``,
    ``[CLASSES]``, and ``[STORAGE]``).
    """
    return bool(set(extract_sections(text)) - {"INFO", "CLASSES", "STORAGE"})


def parse_rdb(rdb_data: bytes) -> str:
    """
    Extract usable configuration from a SEL QuickSet database (``*.rdb`` file).

    Parse the binary data contained in a rdb project file and convert it
    to a string that is the same format used in SET_ALL.TXT. If there
    are multiple relays in the file, the settings for the first relay are
    returned. Use :func:`parse_rdb_relays` to get the settings for all relays.

    Args:
        rdb_data: Binary data from an ``.rdb`` project file

    Returns:
        Device configuration information parsed from the file, in the SET_ALL.TXT format
    """
    relays = parse_rdb_relays(rdb_data)

    if len(relays) > 1:
        log.warning(
            f"{len(relays)} relays in RDB file, only returning settings for "
            f"the first relay ('{next(iter(relays))}')"
        )

    return next(iter(relays.values()))


def extract_sections(raw_text: str) -> dict[str, list[str]]:
    """
    Convert raw text of a config file into a dict with the text lines
    for each section.

    Lines before the first section header are skipped. If a section
    appears more than once, the last one wins (this happens with the
    ``[INFO]`` section when individual settings files are concatenated).
    """
    raw_sections = {}

    for section, lines in split_raw_sections(raw_text):
        cleaned_lines = []

        for line in lines:
            line = line.strip()

            if line.endswith(","):
                line += '""'  # Handle trailing commas in some configs
            elif line.endswith(',"'):
                line += '"'

            cleaned_lines.append(line)

        raw_sections[section] = cleaned_lines

    return raw_sections


def parse_ini_style(lines: list[str]) -> dict[str, str]:
    """
    INI-style syntax with key-value pairs.
    """
    result = {}

    for line in lines:
        if not line:
            log.warning(f"Failed parsing of INI-style line: {line}")
            continue

        key, _, value = line.strip().partition("=")
        result[key] = value

    return result


def extract_csv_lines(lines: list[str]) -> list[list[str]]:
    reader = csv.reader(lines)

    # Example line: ['N1', 'Notes', '\\SETTINGS\\SET_N1.TXT', '4d9a3b89']
    # This list comprehension does several things:
    #   Creates a list from the CSV.reader (which is a generator)
    #   Removes empty values from the line
    #   Removes extraneous whitespace from values
    parsed_lines = [[chunk.strip() for chunk in line] for line in reader if line]  # type: list[list[str]]

    return parsed_lines


def parse_csv_style(raw_lines: list[str], section_name: str) -> ConfigSectionType:
    """
    Parse lines of sections with CSV-style syntax. It's an odd and
    inconsistent format, but Python's CSV parser is apparently able
    to handle it with ablomb, so we use that instead of trying to
    write some crazy regex ourselves. A good example of weird formatting
    is from the SEL-451, look at the SET_ALL files in tests/ and examples/.
    """

    # Examples of lines:
    #   "URETRY1",3,2~10,U,,"Unsolicited Message Max Retry Attempts (2-10)"
    #   "AUTO_1","",,S,"",""
    #   RID,"Relay 1 RID","","","","Relay Identifier(30chars)"
    #   E50P,"N","","","","      Phase"
    #   RST9,"0","","","",""

    parsed_lines = extract_csv_lines(raw_lines)

    # ["\\SWCFG.ZIP"]
    if "STORAGE" in section_name:
        return [line[0].replace("\\", "/").strip() for line in parsed_lines]

    results = {}

    for line in parsed_lines:
        if "CLASSES" in section_name:
            # NOTE: For certain rdb files the header is missing,
            # which corrupts the parsing of the [CLASSES] section.
            # This appears to be happening in a number of the rdb files.
            if len(line) == 1:
                if "Saved " in line[0]:
                    if not results.get("SAVE_INFO"):
                        results["SAVE_INFO"] = []

                    results["SAVE_INFO"].append(line[0])
                else:
                    # NOTE: do NOT log the line itself, it could lead to decode
                    # errors when passed to logging if it's really nasty.
                    log.debug("Skipping malformed CLASSES line")

                continue

            results[line[0]] = {
                "class": line[0].strip(),
                "name": line[1].strip(),
            }

            # "\SETTINGS\SET_A1.TXT"
            # "SET_1.TXT"
            if len(line) > 2:
                f_path = line[2].replace("\\", "/").strip()
                results[line[0]]["file"] = f_path

            # "0x ef43c8e"
            # "0xd727d356"
            # "a9dd3ac2"
            # "30C0490A"
            if len(line) > 3:
                hex_thingy = line[3].replace("0x", "").strip().lower()
                results[line[0]]["hex_id"] = hex_thingy
        else:
            # Always have value and description, even if it's not present for
            # a particular section. This makes it easier to read from the dict.
            results[line[0]] = {
                "value": "",
                "description": "",
            }

            if len(line) > 1:  # sections L1-L6 only have a value
                results[line[0]]["value"] = line[1].strip()
            if len(line) > 2:
                results[line[0]]["description"] = line[-1].strip()

    return results


def parse_sections(raw_sections: dict[str, list[str]]) -> dict[str, ConfigSectionType]:
    # Instead of doing it line by line,
    # Grab the entire config at once, extract whole sections
    # at a time, then feed the contents of each section in Python's CSV
    # parser.
    #
    # This will work around the inconsistencies between how
    # relay configs are formatted, e.g. some devices don't use quotes
    # for all values.

    # [INFO] and [FRONTPANEL] sections are exceptions, those are INI-style key-value pairs
    #
    # [FRONTPANEL]

    configs = {}

    for section, lines in raw_sections.items():
        if not lines:
            continue

        # key-value pairs
        if "," not in lines[0] and len(lines[0].split("=")) == 2:
            configs[section] = parse_ini_style(lines)

        # CSV-thingy
        else:
            configs[section] = parse_csv_style(lines, section)

    return configs


#: Echo of a ``SHOW`` command in a terminal capture, e.g. ``=>>SHO P 5``
SHOW_COMMAND_RE: Final = re.compile(
    r"^[ \t]*(?:[=>]*>[ \t]*)?SHOW?(?P<args>(?:[ \t]+[A-Z0-9]+)*)[ \t]*$", re.IGNORECASE
)

#: A setting in ``SHOW`` command output. Newer relays use ``:=``
#: (``RID      := FEEDER 1``), older relays use ``=`` (``RID     =FEEDER 1``).
SHOW_SETTING_RE: Final = re.compile(r"(?<![^\s])(?P<key>[A-Z0-9_]+)\s*:?=(?!=)")

#: Headings in ``SHOW`` command output that name a settings class.
#: Used when the command that produced the output wasn't captured.
SHOW_HEADINGS: Final = (
    (re.compile(r"^Group\s+(\d+)$", re.IGNORECASE), r"\1"),
    (re.compile(r"^(?:SELogic|Logic)(?:\s+group)?\s+(\d+)$", re.IGNORECASE), r"L\1"),
    (re.compile(r"^Port\s+([0-9F]+)$", re.IGNORECASE), r"P\1"),
    (re.compile(r"^Global(?:\s+Settings)?$", re.IGNORECASE), "G"),
    (re.compile(r"^Front[\s-]+Panel(?:\s+Settings)?$", re.IGNORECASE), "F"),
    (re.compile(r"^Report(?:\s+Settings)?$", re.IGNORECASE), "R"),
)

#: Settings in ``SHOW`` output that belong in the ``[INFO]`` section
SHOW_INFO_KEYS: Final = ("RELAYTYPE", "FID", "BFID", "PARTNO", "CID", "DEVID", "SERIALNO")


def _show_command_section(args: str) -> str | None:
    """
    Settings class from the arguments of a ``SHOW`` command, e.g.
    ``"P 5"`` => ``"P5"``, ``"1"`` => ``"1"``, ``"L 2"`` => ``"L2"``.

    Returns None if the class can't be determined from the arguments,
    e.g. ``SHO`` without arguments shows the active group.
    """
    tokens = args.upper().split()
    if not tokens:
        return None

    # "SHO 1", "SHO L 2", "SHO P F", "SHO D1"
    section = "".join(tokens[:2]) if len(tokens[0]) == 1 and not tokens[0].isdigit() else tokens[0]

    # Settings classes, e.g. "1", "G", "L1", "PF", "D1", "DNPB".
    # Other arguments are settings, e.g. "SHO TR" shows just the TR setting.
    if not re.fullmatch(r"\d+|[A-Z]\d*|PF|DNP[A-Z]?", section):
        return None

    # "SHO L" and "SHO P" show the active group or the current port
    if section in ("L", "P"):
        return None

    return section


def looks_like_show_output(text: str) -> bool:
    """
    If text looks like the output of the ``SHOW`` (``SHO``) settings command,
    instead of a settings file like ``SET_ALL.TXT``.
    """
    if any(SECTION_HEADER_RE.match(line) for line in text.splitlines()):
        return False

    # Lines like "FID=..." are in other output too, e.g. SER.TXT
    return any(
        match.group(1) not in SHOW_INFO_KEYS
        for match in re.finditer(r"(?m)^[ \t]*([A-Z0-9_]+)[ \t]*:?=", text)
    )


def parse_show_output(text: str) -> dict[str, ConfigSectionType]:
    """
    Parse settings from the output of the ``SHOW`` (``SHO``) command, e.g.
    from a capture of a Telnet or serial terminal session or a report
    saved from the QuickSet terminal.

    Settings are put into the same structure as :func:`parse_config_data`,
    with sections named after the settings class (``"1"`` for Group 1,
    ``"P5"`` for Port 5, ``"L1"`` for Logic 1, etc.). The settings class
    is determined from the echo of the command (e.g. ``=>>SHO P 5``),
    or from headings in the output (e.g. ``Port 5``) if the command
    wasn't captured. Settings that can't be associated with a class are
    put into a section named ``"SHOW"``.

    Example of output from newer relays:

    .. code-block:: text

       =>>SHO 1
       Group 1

       Relay Configuration
       RID      := SEL-751
       CTR      := 120               CTRN     := 120
       TR       := 51P1T OR 50P1T OR 51G1T OR
                   50G1T

    Example of output from older relays:

    .. code-block:: text

       =>SHO L 1
       SELogic group 1

       TR      =M1P + Z1G + M2PT + 51GT

    Args:
        text: Output of one or more ``SHOW`` commands

    Returns:
        :class:`dict` representation of the settings
    """
    configs = {"INFO": {}}  # type: dict[str, Any]
    section = "SHOW"
    section_from_command = False
    last_key = ""

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            last_key = ""  # Continuations never follow a blank line
            continue

        # Commands are short, don't run the regex on long lines
        command = SHOW_COMMAND_RE.match(line) if len(line) < 80 else None
        if command:
            from_args = _show_command_section(command.group("args") or "")
            section = from_args or "SHOW"
            section_from_command = bool(from_args)
            last_key = ""
            continue

        stripped = line.strip()

        # Prompt with no command, e.g. "=>" or "=>>"
        if re.fullmatch(r"[=>]+", stripped):
            last_key = ""
            continue

        matches = list(SHOW_SETTING_RE.finditer(line))

        if not matches:
            # Equations that are too long for one line are continued
            # on the next line, which is indented.
            if last_key and raw_line[:1].isspace():
                current = configs[section][last_key]
                current["value"] = f"{current['value']} {stripped}".strip()
                continue

            last_key = ""
            if not section_from_command:
                for heading_re, replacement in SHOW_HEADINGS:
                    if heading_re.match(stripped):
                        section = heading_re.sub(replacement, stripped).upper()
                        break
            continue

        for idx, match in enumerate(matches):
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(line)
            key = match.group("key")
            value = line[match.end() : end].strip()

            # String values are quoted in the output of some relays
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]

            if key in SHOW_INFO_KEYS:
                configs["INFO"][key] = value
                last_key = ""
                continue

            configs.setdefault(section, {})[key] = {"value": value, "description": ""}
            last_key = key

        # A continuation can only follow a line with a single setting
        if len(matches) > 1:
            last_key = ""

    return configs


def parse_config_data(config_text: bytes | str) -> dict[str, ConfigSectionType]:
    """
    Convert config file sections into a Python :class:`dict` structure.

    SEL config files structure is like a combination of INI and CSV file formats.
    Sections are in INI style, while variables may be in key=value structure or in
    a comma-separated CSV structure.

    Every config file starts with a ``[INFO]`` section, so this section ends up duplicated
    in every config file.

    SET_ALL.TXT contains all of the data from all of the config files.

    Example 1:

    .. code-block::

       [L3]
       TR,"OC+51PT+51GT+81D1T+LB3+50P1*SH0","","","",""
       TRCOMM,"0","","","",""
       TRSOTF,"0","","","",""

    Example 2:

    .. code-block::

       [INFO]
       RELAYTYPE=0351
       FID=SEL-351-5-R510-V0-Z103103-D20110429
       BFID=SLBT-3CF1-R102-V0-Z100100-D20091207
       PARTNO=035152B3A11XX1

    Args:
        config_file_data: complete contents of a config file, including all sections

    Returns:
        :class:`dict` representation of the config file values.
        Top level keys in the dict are config sections, e.g. ``"INFO"`` or ``"P1"``.
        Nested keys are individual values in those sections, e.g. ``"RELAYTYPE"`` OR ``"TRCOMM"``
    """
    if isinstance(config_text, bytes):
        config_text = clean_settings_text(config_text)

    if not config_text:
        return {}

    try:
        if looks_like_show_output(config_text):
            log.debug("Settings look like SHOW command output, parsing as SHOW output")
            return parse_show_output(config_text)

        extracted_sections = extract_sections(config_text)
        parsed_configs = parse_sections(extracted_sections)
        return parsed_configs
    except Exception:
        log.exception("Failed to parse SEL config data")
        return {}


def parse_cfg_txt(cfg_txt: bytes | str, dev: DeviceData) -> ConfigsType:
    """
    Parse contents of CFG.TXT, including the [INFO] and [CLASSES] sections.

    Args:
        cfg_txt: Data from a CFG.TXT config
        dev: :class:`~peat.data.models.DeviceData` instance to add data to

    Returns:
        Raw configs extracted from CFG.TXT
    """
    configs = parse_config_data(cfg_txt)

    if not configs:
        raise ParseError("No config sections extracted from CFG.TXT")

    if peat_config.DEBUG:
        dev.write_file(configs, "raw-cfg-configs.json")

    # Process the [INFO] and [CLASSES] sections
    process_info_classes(configs, dev)

    log.debug(f"Completed parsing CFG.TXT ({len(configs)} sections parsed)")

    return configs


def parse_set_all(
    set_all_data: bytes | str, dev: DeviceData | None = None
) -> tuple[dict[str, dict], DeviceData]:
    """
    Parse the data contained in SET_ALL.TXT.

    Args:
        set_all_data: Data from a SET_ALL config pulled from an relay
            or extracted from a RDB project file
        dev: :class:`~peat.data.models.DeviceData` instance to add data to

    Returns:
        Tuple with the device configuration information parsed from the file
        and the DeviceData object generated from the file data (or passed as
        argument to this function)
    """
    # Parse raw data from SET_ALL.TXT into a nested dict
    # NOTE: the 451 truncates config variable names longer than 7 characters
    configs = parse_config_data(set_all_data)

    if not configs:
        raise ParseError("No config sections extracted from SET_ALL")

    if not dev:
        dev = create_dev_from_configs(configs)

    if peat_config.DEBUG:
        dev.write_file(configs, "raw-setall-configs.json")

    # Process the [INFO] and [CLASSES] sections
    process_info_classes(configs, dev)

    # Date format of the relay (DATE_F), used to parse the dates of events
    date_format = extract_date_format(configs)
    if date_format:
        dev.extra["date_format"] = date_format

    # Extract network info
    process_network_configuration(configs, dev)

    # Update interface/network info
    dev.populate_fields()

    # Extract Modbus registers
    parse_and_process_modbus(configs, dev)

    # Extract DNP3 registers
    parse_and_process_dnp3(configs, dev)

    parsed_ids = parse_ids(configs)
    dev.extra.update(parsed_ids)

    device_info = {
        "protection_schemes": parse_protection_schemes(configs, dev.description.model),
        **parsed_ids,
    }

    for section, keys in LOGIC_KEYS.items():
        device_info[section.lower()] = parse_logic_section(configs, keys, section)

    log.trace(
        f"{len(configs)} SET_ALL config sections parsed: {', '.join(x for x in configs.keys())}"
    )
    log.debug(f"Completed parsing of SET_ALL ({len(configs)} sections parsed)")

    return device_info, dev


def process_info_classes(configs: ConfigsType, dev: DeviceData) -> None:
    """
    Process the [INFO] and [CLASSES] sections into the PEAT data model.
    """
    # Extract firmware info
    # NOTE: The INFO section should always be present in settings files,
    # but it's not in SHOW command output or a file that was cut off.
    if isinstance(configs.get("INFO"), dict):
        process_info_into_dev(configs["INFO"], dev)
    else:
        log.warning(f"No [INFO] section in settings for {dev.get_id()}")

    # Parse [CLASSES] section and put into related.files
    if configs.get("CLASSES"):
        if configs["CLASSES"].get("SAVE_INFO"):
            save_info = configs["CLASSES"]["SAVE_INFO"]  # type: list
            dev.extra["SAVE_INFO_FROM_CLASSES"] = copy.copy(save_info)

            # Extract logic save timestamp if it's listed
            # "Saved on 2/16/2023 at 10:14:22 PM"
            for msg in save_info:
                if not msg.startswith("Saved on"):
                    continue

                save_ts = utils.parse_date(msg.partition("Saved on ")[2])

                if save_ts and not dev.logic.created:
                    dev.logic.created = save_ts

                if save_ts and not dev.logic.last_updated:
                    dev.logic.last_updated = save_ts

        # Create Path objects from the file keys
        # This will parse the file path as well, if it's specified
        # "SET_1.TXT"
        # "\\SETTINGS\\SET_1.TXT"
        file_objs = [
            PurePosixPath(c["file"].replace("\\", "/"))
            for c in configs["CLASSES"].values()
            if isinstance(c, dict) and c.get("file")
        ]
        file_names = [f.name for f in file_objs]

        if file_names:
            dev.extra["files_from_classes"] = file_names
            dev.related.files.update(file_names)

    if configs.get("STORAGE"):
        # Add any filenames from [STORAGE] section, if they're files
        # Lines in this section can be random data too.
        for line in configs["STORAGE"]:
            # "/SWCFG.ZIP" (paths are absolute, which aren't valid on all platforms)
            if (
                " " not in line
                and "." in line
                and len(line) > 3
                and is_valid_filepath(line, platform="posix")
            ):
                file_obj = PurePosixPath(line)
                dev.related.files.add(file_obj.name)


def create_dev_from_configs(configs: ConfigsType) -> DeviceData:
    """
    Generate a :class:`~peat.data.models.DeviceData` object using the best
    available identification for a device (IP, name, etc.).
    """
    # NOTE: iteration happens 3 times here because we have to
    # scan for the settings key, e.g. "IPADDR", all the way before
    # checking for the next key (e.g. "RID" and "TID")

    # IP address
    for settings in configs.values():
        if isinstance(settings, dict) and "IPADDR" in settings:
            ip_addr = parse_ipaddr(settings).ip
            if ip_addr:
                return datastore.get(ip_addr, "ip")

    # RID+TID generally in sections [1] through [6] or section [G1]
    for settings in configs.values():
        for id_key in ["RID", "TID"]:
            if id_key in settings:
                name = _getv(settings[id_key])
                if name:
                    return datastore.get(name, "name")

    # Fallback to SID (Station ID) if we can't find another identifier
    for settings in configs.values():
        if "SID" in settings:
            name = _getv(settings["SID"])
            if name:
                return datastore.get(name, "name")

    rand_id = consts.gen_random_dev_id()
    log.warning(
        f"Failed to find a suitable device ID while parsing "
        f"config, using an auto-generated ID instead\n"
        f"ID: {rand_id}"
    )

    # TODO: find a better fallback if we can't find a IP or ID
    return datastore.get(rand_id, "id")


def process_info_into_dev(info: dict, dev: DeviceData) -> None:
    """
    Put data from the info dict into the PEAT device data model.
    """
    # Make copy to mutate, so we can pop keys that
    # shouldn't go into dev.extra
    info = copy.deepcopy(info)

    if info.get("FID"):
        process_fid(info.pop("FID"), dev)

    if info.get("BFID"):
        process_fid(info.pop("BFID"), dev)

    if info.get("PARTNO"):
        dev.part_number = info.pop("PARTNO")

    # This comes from parsing status output and exit info
    if info.get("serial_number"):
        dev.serial_number = info.pop("serial_number")
    # This comes from the "id" command
    elif info.get("SERIALNO"):
        dev.serial_number = info.pop("SERIALNO")

    # "0351", "SEL-710", "SEL-487E-3" ("487E", the same as in the FID)
    relaytype = info.pop("RELAYTYPE", None)
    if relaytype and not dev.description.model:
        model = relaytype.strip().upper().removeprefix("SEL-").split("-")[0]
        dev.description.model = model.lstrip("0")

    # Add any remaining info that hasn't been processed
    # to dev.extra (hence the .pop() calls above).
    dev.extra.update(info)

    if not dev.name:
        name = info.get("device_name")
        ident = info.get("device_identifier")

        if not ident:
            ident = info.get("DEVID")

        if name and ident:
            dev.name = f"{name} - {ident}"
        elif name:
            dev.name = name
        elif ident:
            dev.name = ident


def process_fid(id_string: str, dev: DeviceData) -> None:
    """
    Get data from the FID string and put it into the PEAT device data model.
    """
    fid_info = parse_fid(id_string)

    if not fid_info:
        return

    if "model" in fid_info:  # FID (Firmware ID)
        dev.description.model = fid_info.pop("model")
        dev.description.product = fid_info.pop("product")
        fw_obj = dev.firmware
    else:  # BFID (Boot Firmware ID)
        fw_obj = dev.boot_firmware

    if "settings_version" in fid_info:
        settings_version = fid_info.pop("settings_version")
        fw_obj.extra["settings_version"] = settings_version

    for key, value in fid_info.items():
        if hasattr(fw_obj, key):
            setattr(fw_obj, key, value)


def process_firmware_checksum(
    checksum: str, dev: DeviceData, firmware: Firmware | None = None
) -> None:
    """
    Put a firmware checksum into the device data model, e.g. the
    ``Firmware Checksum`` of a RTAC or the checksum in the ``VER``
    output of a relay.

    The checksum is stored in ``firmware.checksum``. Some checksums are
    hashes (e.g. a MD5 hash), and others definitely aren't (e.g. ``B0AB``).
    If it's a valid hash, it's added to ``dev.related.hash``, and a 32
    character hash is also used as the MD5 hash of the firmware (if unset).

    Args:
        checksum: The checksum
        dev: The device
        firmware: Firmware the checksum is for (default: ``dev.firmware``)
    """
    if firmware is None:
        firmware = dev.firmware

    firmware.checksum = checksum

    try:
        checksum_hash = validate_hash(checksum)
    except ValueError:
        return

    dev.related.hash.add(checksum_hash)
    if not firmware.hash.md5 and len(checksum) == 32:
        firmware.hash.md5 = checksum_hash


def parse_ipaddr(settings: dict) -> Interface:
    """
    Parse ``IPADDR`` section out of a port config (e.g., ``P5``).

    IP/ethernet interfaces. Usually port 5 (P5), though it could
    potentially be other interfaces.
    """
    iface = Interface(type="ethernet")

    # NOTE: examples of values for "settings" are in test_parse_ipaddr
    if "SUBNETM" in settings:
        # 351: subnet mask is a separate value
        iface.ip = clean_ipv4(_getv(settings["IPADDR"]))
        iface.subnet_mask = clean_ipv4(_getv(settings["SUBNETM"]))
    else:
        # Subnet mask is part of the address in CIDR "slash"
        # notation on the SEL-451 and possibly other models.
        ip_addr = _getv(settings["IPADDR"])
        if "/" in ip_addr:
            ip_addr, iface.subnet_mask = split_ipv4_cidr(ip_addr)
        iface.ip = clean_ipv4(ip_addr)

    if "DEFRTR" in settings:
        gw = _getv(settings["DEFRTR"])
        if gw:
            iface.gateway = clean_ipv4(gw)

    return iface


def process_port_settings(
    port_id: Literal["1", "2", "3", "4", "5", "F"],
    settings: dict[str, dict | str],
    dev: DeviceData,
) -> None:
    """
    Process parsed port settings into the device data model.
    """
    log.trace(f"Processing port settings for port {port_id} from {dev.get_id()}")

    iface = Interface(
        name=f"Port {port_id}",
    )

    if "EPORT" in settings:
        iface.enabled = value_is_enabled(_getv(settings["EPORT"]))

    if "IPADDR" in settings:
        # Ethernet interfaces
        merge_models(iface, parse_ipaddr(settings))
    else:
        # Serial interfaces
        # Generally, these are are port 1-3 and port F
        if settings.get("PROTO"):
            app_proto = _getv(settings["PROTO"]).replace("DNP", "DNP3").lower()
            iface.application = app_proto
        elif "PROTO" not in settings and port_id == "F":
            iface.application = "sel"

        if settings.get("SPEED"):
            speed = _getv(settings["SPEED"])

            # Possible value for SPEED may be "SYNC" on some models,
            # according to SEL documentation
            if _to_int(speed) is not None:
                iface.baudrate = _to_int(speed)

            iface.type = "serial"

        if "BITS" in settings:
            iface.data_bits = _to_int(_getv(settings["BITS"]))
        elif "DATABIT" in settings:  # 411L, 487E, some 451's
            iface.data_bits = _to_int(_getv(settings["DATABIT"]))

        if "PARITY" in settings:
            parity = _getv(settings["PARITY"]).upper()

            if parity == "O":
                parity = "odd"
            elif parity == "E":
                parity = "even"
            elif parity == "N":
                parity = "none"
            else:
                log.warning(f"Unknown parity value: {parity} (device: {dev.get_id()})")
                parity = ""

            iface.parity = parity

        if "STOP" in settings:  # 2411, 2015+ firmwares (possibly earlier)
            iface.stop_bits = _to_int(_getv(settings["STOP"]))
        elif "STOPBIT" in settings:
            # 451, 411L, and others
            iface.stop_bits = _to_int(_getv(settings["STOPBIT"]))

        if "RTSCTS" in settings and value_is_enabled(_getv(settings["RTSCTS"])):
            iface.flow_control = "rts/cts"
        elif settings.get("SPEED"):
            iface.flow_control = "none"

        # Port timeout in minutes, can be "OFF" on some models
        if "T_OUT" in settings and _to_float(_getv(settings["T_OUT"])) is not None:
            iface.extra["inactivity_timeout"] = _to_float(_getv(settings["T_OUT"]))

        if "MAXACC" in settings:
            iface.extra["max_privilege_level"] = _getv(settings["MAXACC"])

        # 311L: "PROTO" on P1 can be "TELNET".
        # Per the SEL documentation (311L-1-7_IM_20191107):
        # "To enable Telnet-to-relay communications on PORT 5 and
        #  PORT6, the PORT 1 PROTO setting must be set to TELNET.
        #  Setting PROTO = TELNET disables PORT 1 for EIA-485 communications."
        # NOTE: PROTO field may not be present for PF on newer firmwares
        if settings.get("PROTO"):
            if _getv(settings["PROTO"]) == "TELNET":
                iface.enabled = False

        for key in ["TPORT", "TIDLE"]:
            if key in settings:
                iface.extra[key] = _getv(settings[key])

    # Service configurations
    # TODO: break this out into a function
    # TODO: utility functions for setting processing (alternate keys, type casts)

    services = []

    if settings.get("FTPUSER") or settings.get("FTPSERV"):
        ftp_svc = Service(protocol="ftp", transport="tcp", port=21)

        if settings.get("FTPSERV"):
            ftp_svc.enabled = value_is_enabled(_getv(settings["FTPSERV"]))
        elif settings.get("EFTPSERV"):
            ftp_svc.enabled = value_is_enabled(_getv(settings["EFTPSERV"]))

        if settings.get("FTPIDLE"):
            ftp_svc.extra["idle_timeout"] = _to_float(_getv(settings["FTPIDLE"]))

        if settings.get("FTPUSER"):
            ftp_svc.extra["user"] = _getv(settings["FTPUSER"])
            dev.related.user.add(_getv(settings["FTPUSER"]))

        if settings.get("FTPANMS"):
            anon_login_enabled = value_is_enabled(_getv(settings["FTPANMS"]))
            ftp_svc.extra["anonymous_login_enabled"] = anon_login_enabled

        if settings.get("FTPAUSR"):
            ftp_svc.extra["anonymous_access_level"] = _getv(settings["FTPAUSR"])

        services.append(ftp_svc)

    for svc_name in [
        "HTTP",
        "TELNET",
        "GSE",
        "MMSFS",
        "DNP",
        "MODBUS",
        "SNTP",
        "61850",
        "PMIP",
    ]:
        # "EHTTP", "ETELNET", etc.
        if settings.get(f"E{svc_name}"):
            protocol = svc_name.lower()

            if svc_name in ["GSE", "61850"]:
                protocol = "iec61850"
            elif svc_name == "DNP":
                protocol = "dnp3"
            elif svc_name == "PMIP":
                protocol = "c37.118"

            enable_value = str(_getv(settings[f"E{svc_name}"])).strip().upper()

            # ESNTP is the SNTP mode: OFF, UNICAST, MANYCAST, or BROADCAST
            # EDNP is the number of DNP sessions (0-6) on some relays
            if svc_name in ["SNTP", "DNP"]:
                svc_enabled = enable_value not in ["", "OFF", "N", "NO", "0"]
            else:
                svc_enabled = value_is_enabled(enable_value)

            svc = Service(
                protocol=protocol,
                enabled=svc_enabled,
            )

            if protocol == "http":
                svc.transport = "tcp"

                if settings.get("HTTPPOR"):
                    svc.port = _to_int(_getv(settings["HTTPPOR"]))
                elif settings.get("HTTPPORT"):
                    svc.port = _to_int(_getv(settings["HTTPPORT"]))

                if settings.get("HIDLE"):
                    svc.extra = {"idle_timeout": _to_float(_getv(settings["HIDLE"]))}
                elif settings.get("HTTPIDLE"):
                    svc.extra = {"idle_timeout": _to_float(_getv(settings["HTTPIDLE"]))}

            elif protocol == "telnet":
                svc.transport = "tcp"

                if settings.get("TPORT"):
                    svc.port = _to_int(_getv(settings["TPORT"]))
                # 311L: "Telnet Port for Card Access"
                elif settings.get("TPORTC"):
                    svc.port = _to_int(_getv(settings["TPORTC"]))

                if settings.get("TIDLE"):
                    svc.extra["idle_timeout"] = _to_float(_getv(settings["TIDLE"]))

            elif protocol == "sntp":
                svc.transport = "udp"

                if settings.get("SNTPPORT"):
                    svc.port = _to_int(_getv(settings["SNTPPORT"]))
                elif settings.get("SNTPPOR"):
                    svc.port = _to_int(_getv(settings["SNTPPOR"]))

                if settings.get("SNTPPSIP"):
                    svc.extra["sntp_primary_ip"] = clean_ipv4(_getv(settings["SNTPPSIP"]))
                    dev.related.ip.add(svc.extra["sntp_primary_ip"])
                elif settings.get("SNTPPIP"):
                    svc.extra["sntp_primary_ip"] = clean_ipv4(_getv(settings["SNTPPIP"]))
                    dev.related.ip.add(svc.extra["sntp_primary_ip"])

                if settings.get("SNTPBSIP"):
                    svc.extra["sntp_backup_ip"] = clean_ipv4(_getv(settings["SNTPBSIP"]))
                    dev.related.ip.add(svc.extra["sntp_backup_ip"])
                elif settings.get("SNTPBIP"):
                    svc.extra["sntp_backup_ip"] = clean_ipv4(_getv(settings["SNTPBIP"]))
                    dev.related.ip.add(svc.extra["sntp_backup_ip"])

                if settings.get("SNTPRATE"):
                    svc.extra["sntp_rate"] = _to_int(_getv(settings["SNTPRATE"]))
                elif settings.get("SNTPRAT"):
                    svc.extra["sntp_rate"] = _to_int(_getv(settings["SNTPRAT"]))
                if settings.get("SNTPTO"):
                    svc.extra["sntp_timeout"] = _to_float(_getv(settings["SNTPTO"]))

            elif protocol == "dnp3":
                if settings.get("DNPNUM"):
                    svc.port = _to_int(_getv(settings["DNPNUM"]))
                elif settings.get("DNPPNUM"):
                    svc.port = _to_int(_getv(settings["DNPPNUM"]))
                if settings.get("DNPADR"):
                    svc.protocol_id = _getv(settings["DNPADR"])
                if settings.get("DNPID"):
                    # "DNP ID for Object 0, Var 246 (20 characters)"
                    svc.extra["dnp3_id"] = _getv(settings["DNPID"])
                if settings.get("DNPMAP"):
                    svc.extra["session_map"] = _getv(settings["DNPMAP"])

                dnp3_stations = []

                for idx in range(1, 7):
                    st = {}

                    if settings.get(f"DNPIP{idx}"):
                        # "IP Address (zzz.yyy.xxx.www)"
                        st["ip"] = clean_ipv4(_getv(settings[f"DNPIP{idx}"]))
                        dev.related.ip.add(st["ip"])

                    if settings.get(f"DNPTR{idx}"):
                        # "Transport Protocol (UDP,TCP)"
                        st["transport"] = _getv(settings[f"DNPTR{idx}"]).lower()

                    if settings.get(f"DNPUDP{idx}"):
                        # "UDP Response Port (REQ, 1025-65534)"
                        # "REQ" means respond to the port the request came from
                        udp_port = _getv(settings[f"DNPUDP{idx}"])
                        if _to_int(udp_port) is not None:
                            st["port"] = _to_int(udp_port)
                            dev.related.ports.add(st["port"])
                        else:
                            st["port"] = udp_port

                    if settings.get(f"REPADR{idx}"):
                        # "DNP Address to Report to (0-65519)"
                        st["report_address"] = _getv(settings[f"REPADR{idx}"])

                    if settings.get(f"DNPMAP{idx}"):
                        # "DNP Session Map (1-5)"
                        st["session_map"] = _getv(settings[f"DNPMAP{idx}"])

                    if settings.get(f"DNPINA{idx}"):
                        # "Seconds to Send Data Link Heartbeat (0-7200)"
                        st["heartbeat_timeout"] = _to_int(_getv(settings[f"DNPINA{idx}"]))

                    if settings.get(f"DNPCL{idx}"):
                        # "Enable Control Operations (Y,N)"
                        cne = value_is_enabled(_getv(settings[f"DNPCL{idx}"]))
                        st["control_operations_enabled"] = cne

                    if settings.get(f"DNPID{idx}"):
                        st["dnp3_id"] = _getv(settings[f"DNPID{idx}"])

                    if st:
                        st["station_num"] = idx
                        dnp3_stations.append(st)

                if dnp3_stations:
                    svc.extra["dnp3_stations"] = dnp3_stations

            elif protocol == "modbus":
                if iface.type == "ethernet":
                    svc.transport = "tcp"
                    svc.port = 502

                endpoints = []

                for idx in range(1, 4):
                    endp = {}

                    if settings.get(f"MODIP{idx}"):
                        endp["ip"] = clean_ipv4(_getv(settings[f"MODIP{idx}"]))
                        dev.related.ip.add(endp["ip"])

                    if settings.get(f"MTIMEO{idx}"):
                        endp["timeout"] = _to_float(_getv(settings[f"MTIMEO{idx}"]))

                    if endp:
                        endp["endpoint_num"] = idx
                        endpoints.append(endp)

                if endpoints:
                    svc.extra["modbus_endpoints"] = endpoints

            elif protocol == "c37.118":
                # TODO: improve processing of PMU fields, want to add a
                #   separate local service for each PMU that's configured,
                #   based on it's configuration (TCP,UDP_S,UDP_T,UDP_U)
                #   Refer to "Ethernet Operation" section in SEL documentation
                # C37.118 is TCP (port 4712) or UDP (port 4713)
                # Reference: https://wiki.wireshark.org/IEEE%20C37.118
                endpoints = []

                for idx in range(1, 2):
                    endp = {}
                    if settings.get(f"PMOTS{idx}"):
                        # TODO: resolve to actual transport method
                        #   Possible values: (OFF,TCP,UDP_S,UDP_T,UDP_U)
                        endp["transport_scheme"] = str(_getv(settings[f"PMOTS{idx}"]))
                        endp["enabled"] = bool(endp["transport_scheme"].lower() != "off")

                    if settings.get(f"PMOIPA{idx}"):
                        endp["ip"] = clean_ipv4(_getv(settings[f"PMOIPA{idx}"]))
                        dev.related.ip.add(endp["ip"])

                    if _to_int(_getv(settings.get(f"PMOTCP{idx}", ""))) is not None:
                        endp["tcp_local_port"] = _to_int(_getv(settings[f"PMOTCP{idx}"]))
                        dev.related.ports.add(endp["tcp_local_port"])

                    if _to_int(_getv(settings.get(f"PMOUDP{idx}", ""))) is not None:
                        endp["udp_remote_port"] = _to_int(_getv(settings[f"PMOUDP{idx}"]))
                        dev.related.ports.add(endp["udp_remote_port"])

                    if endp:
                        endp["endpoint_num"] = idx
                        endpoints.append(endp)

                if endpoints:
                    svc.extra["c37_endpoints"] = endpoints

            services.append(svc)

    # Store interface in the data model, followed by the services
    dev.store("interface", iface)

    for service in services:
        if service.port:
            dev.related.ports.add(service.port)

        if service.protocol:
            dev.related.protocols.add(service.protocol)

        dev.store("service", service, interface_lookup={"name": iface.name})


def process_network_configuration(configs: dict[str, dict], dev: DeviceData) -> None:
    """
    Process relay network information into the data model.
    """
    for section, settings in configs.items():
        # NOTE: 311L doesn't have "EPORT"
        if "EPORT" not in settings and "PROTO" not in settings and "IPADDR" not in settings:
            continue

        port_id = "".join(section[1:]).upper()  # 5 for P5, F for PF
        process_port_settings(port_id, settings, dev)


def parse_ids(configs: dict[str, dict]) -> dict[str, str | dict[str, str]]:
    """
    Extract and parse various relay IDs from a set of configs.

    These include:

    - RID (Relay ID)
    - SID (Station ID)
    - TID (Terminal ID)

    Args:
        configs: parsed SET_ALL as a dict

    Returns:
        Parsed relay IDs, including cleaned values, raw values,
        and the relay IDs for each settings group (e.g. the ID for group 1).

        .. code-block:: python
           :caption: Example of returned data from parse_ids

           {
               "relay_id_by_group": {"1": "GENERATOR", "2": "GENERATOR"},
               "station_id_by_group": {},
               "terminal_id_by_group": {"1": "TERMINAL", "2": "TERMINAL"},
               "relay_id": "generator",
               "station_id": "",
               "terminal_id": "terminal",
               "raw_rid": "GENERATOR",
               "raw_sid": "",
               "raw_tid": "TERMINAL",
           }
    """

    ids = {
        "relay_id_by_group": {},
        "station_id_by_group": {},
        "terminal_id_by_group": {},
        "relay_id": "",
        "station_id": "",
        "terminal_id": "",
        "raw_rid": "",
        "raw_sid": "",
        "raw_tid": "",
    }

    table = {
        "RID": "relay_id",
        "SID": "station_id",
        "TID": "terminal_id",
    }

    for config, settings in configs.items():
        for ident, desc in table.items():
            if ident not in settings:
                continue

            id_val = _getv(settings[ident])

            # "relay_id_by_group"
            ids[f"{desc}_by_group"][config] = id_val

            if config in ["1", "G1"]:
                # "raw_rid"
                ids[f"raw_{ident.lower()}"] = id_val
                # "relay_id"
                ids[desc] = clean_id(id_val)

    return ids


# TODO: consolidate Modbus+DNP3 register parsing logic into single function
def parse_and_process_modbus(configs: dict[str, dict], dev: DeviceData) -> None:
    """
    Put Modbus registers into the data model as
    :class:`~peat.data.models.Register` objects.

    Args:
        configs: parsed SET_ALL as a dict
        dev: device object to add the data to
    """

    # TODO: unit test

    for config, settings in configs.items():
        # M, M1, M2, etc.
        if not re.match(r"^M\d?$", config, re.ASCII) or not isinstance(settings, dict):
            continue

        # TODO: [M1] is "monitoring and metering" on SEL-487E
        if dev.description.model == "487E" and config != "M":
            continue

        log.debug(f"Parsing and processing Modbus data from section {config}")

        # MOD_031,"MWH3I"
        for regaddr, field in settings.items():
            if not regaddr.startswith("MOD"):
                log.warning(f"Unknown modbus register: {regaddr}")
                continue

            # "MOD_031" => "031"
            addr = regaddr[4:]

            # Strip leading zeros
            if len(addr) == addr.count("0"):  # just zeroes
                addr = "0"
            else:
                addr = addr.lstrip("0")

            reg = Register(
                address=addr,
                description=field["description"],
                group=config,
                name=regaddr,
                protocol="modbus",
            )

            # If no value, or value is marked as "NA", then still create
            # a register, but mark it as disabled.
            if not field["value"] or field["value"] == "NA":
                reg.enabled = False
            else:
                io = IO(
                    name=field["value"],
                )
                dev.store("io", io, lookup="name")

                reg.enabled = True
                reg.io = io.name

            dev.store("registers", reg)


def parse_and_process_dnp3(configs: dict[str, dict], dev: DeviceData) -> None:
    """
    Put DNP3 registers and inferred IO-points into the data model as
    :class:`~peat.data.models.Register` and
    :class:`~peat.data.models.IO` objects.

    Args:
        configs: parsed SET_ALL as a dict
        dev: device object to add the data to
    """

    # TODO: unit tests for all formats, [D1], [DNPB], [DNPA]
    #   Example files as well.
    # TODO: unit test with Modbus and DNP3 points.

    td_table = {
        "BI": ("binary", "input"),
        "BO": ("binary", "output"),
        "AI": ("analog", "input"),
        "AO": ("analog", "output"),
    }

    for config, settings in configs.items():
        # D, DNPA, DNPB, D1, D2, D3, etc.
        if not re.match(r"^(D\d*|DNP.*)$", config, re.ASCII) or not isinstance(settings, dict):
            continue

        log.debug(f"Parsing and processing DNP3 data from section {config}")

        for regaddr, field in settings.items():
            # DNPA and DNPB are from 311L and 387, and possibly others.
            #
            # 387:
            #   DNPAI "DNP Analog Input Map Settings"
            #   DNPAO "DNP Analog Output Map Settings"
            #   DNPBI "DNP Binary Input Map Settings"
            #   DNPBO "DNP Binary Output Map Settings"
            #
            # [DNPA]
            # DNPA,""
            # [DNPB]
            # BI_1,""
            #
            # "DNPA" == "DNPA"
            if regaddr == config:
                if not field["value"] or field["value"] in ["NA", "0"]:
                    continue

                if not dev.extra.get(f"{config}_analog_inputs"):
                    dev.extra[f"{config}_analog_inputs"] = {}

                vals = field["value"].split(" ")

                for idx, val in enumerate(vals):
                    # TODO: create Register and IO objects for DNPA/DNPB
                    dev.extra[f"{config}_analog_inputs"][str(idx)] = val

                continue

            # if does not start with BI, BO, AI, AO,
            # then parse as a variable, e.g.
            # MINDIST or MAXDIST
            if len(regaddr) < 3 or regaddr[:2] not in td_table:
                if not field["value"] or field["value"] == "NA" or not regaddr:
                    continue

                io = IO(
                    name=regaddr,
                )
                dev.store("io", io, lookup="name")

                continue

            # "BI_00" => "00"
            addr = regaddr[3:]

            # "BI_00" => "binary", "input"
            reg_type, direction = td_table[regaddr[:2]]

            # Strip leading zeros
            if len(addr) == addr.count("0"):  # just zeroes
                addr = "0"
            else:
                addr = addr.lstrip("0")

            reg = Register(
                address=addr,
                description=field["description"],
                # Associate register with a DNP3 group, e.g D1, D3
                group=config,
                measurement_type=reg_type,
                name=regaddr,
                protocol="dnp3",
                # TODO: determine register read/write settings for SEL
                # read_write="",
            )

            # If no value, or value is marked as "NA", then still create
            # a register, but mark it as disabled.
            if not field["value"] or field["value"] == "NA":
                reg.enabled = False
            else:
                io = IO(
                    direction=direction,
                    name=field["value"],
                    type=reg_type,
                )
                dev.store("io", io, lookup="name")

                reg.enabled = True
                reg.io = io.name

            dev.store("registers", reg)


def parse_protection_schemes(
    configs: dict[str, dict], device_type: str = ""
) -> dict[str, str | list]:
    protection_schemes = {}  # type: dict[str, Union[str, list]]

    for section, settings in configs.items():
        if "487e" in device_type.lower() and isinstance(settings, dict):
            proto = []
            for setting, fields in settings.items():
                if "PROTSEL" in setting.upper() and fields["value"]:
                    proto.append(fields["value"])
            if proto:
                protection_schemes[section] = proto
        elif re.match(r"^S?\d$", section):
            for setting, fields in settings.items():
                # TODO: set flag if scheme is enabled based on global
                #       flag configuring if setting is enabled.
                if re.match(r"^E\d", setting) and re.match(r"Y|YES|ON|[1-9]", fields["value"]):
                    if setting[1:] in ANSI_CODES:
                        code = setting[1:]
                        protection_schemes[code] = ANSI_CODES[code]
                elif re.match(r"^\d", setting):
                    voltage_elements = (
                        r"^(27TN.59N|27TN|27AUX|27X|27.50|27P|27S|"
                        r"36|59NU|59N|59B|59P|59X|59Q|87V|91)"
                    )
                    try:
                        if (
                            re.match(voltage_elements, setting)
                            and fields["value"] not in ("N", "0.00", "OFF")
                            and settings["EVOLT"]["value"] == "Y"
                        ):
                            code = re.match(voltage_elements, setting).group(1)
                            if code in ANSI_CODES:
                                scheme = ANSI_CODES[code]
                            else:
                                scheme = "UNKNOWN"
                            protection_schemes[code] = scheme
                    except Exception:
                        pass

    return protection_schemes


def parse_logic_section(
    configs: dict[str, dict], logic_keys: list[str], logic_type: str
) -> dict[str, dict[str, str]]:
    logic = {}

    for section, settings in configs.items():
        logic[section] = {}

        for logic_key in logic_keys:
            if logic_key not in settings:
                continue

            value = _getv(settings[logic_key])

            # NOTE: close logic used to compare value != 0, which
            # was never valid (at least for a while) since the values
            # are always strings after getting parsed out of the config.
            if logic_type == "TRIP_LOGIC" or value != "0":
                logic[section][logic_key] = value

        if not logic[section]:  # Delete groups that have no logic
            logic.pop(section)

    return logic


def parse_fid(id_string: str) -> dict[str, str]:
    """
    Parse the ``FID`` and ``BFID`` strings into a :class:`dict` with
    the relay model and firmware information.

    - Model: "SEL-351"
    - Variant (??): "5" (some devices may not have this portion)
    - Release: "R510" (major release, generally new or changed features)
    - Point release: "V0" (minor release, usually fixes or minor changes)
    - Settings version: "Z103103" (indicates what version of SEL ACCSELERATOR software to use)
    - Firmware release date: "D20110429" (2011-04-29, or April 29, 2011)

    Args:
        id_string: Firmware ID string to parse, e.g. FID or BFID

    Returns:
        Information extracted from the firmware ID

            - ``id`` (the full FID/BFID string)
            - ``version`` ("V0")
            - ``revision`` ("R322")
            - ``settings_version`` ("Z025013")
            - ``release_date`` (datetime object)
            - (FID-only) ``model`` ("451")
            - (FID-only) ``product`` ("SEL-451-5")
    """
    if not id_string:
        log.warning(f"parse_fid got an empty FID (Raw value: '{id_string}')")
        return {}

    id_string = id_string.replace("\r", "").replace("\n", "")
    sfid = [x.strip() for x in id_string.split("-") if x]

    if len(sfid) == 3:
        return {"id": id_string, "revision": sfid[2]}

    if len(sfid) < 5:
        log.error(f"Failed to parse firmware ID '{id_string}': length less than 5")
        return {}

    # Parse backwards to handle variable parts (SLBT-3CF1 vs BOOTLDR)
    release_date = sfid.pop().strip("D")  # D20120321
    # Masked dates in QuickSet templates, e.g. "Dxxxxxxxx" or "DXXXXXXXX"
    if re.fullmatch(r"[xX]+", release_date):
        release_datetime = None
    else:
        release_datetime = utils.parse_date(release_date)
    # Older firmware doesn't have the settings version ("SEL-551-R101-Vr-D960321")
    settings_version = sfid.pop() if sfid[-1][:1] in ("Z", "z") else ""  # Z100100
    version = sfid.pop()  # V0
    revision = sfid.pop()  # R200

    info = {
        "id": id_string,
        "version": version,
        "revision": revision,
        "settings_version": settings_version,
        "release_date": release_datetime,
    }
    if not settings_version:
        del info["settings_version"]

    if sfid[0] == "SEL":
        info["model"] = sfid[1]  # "351"
        info["product"] = "-".join(sfid)  # "SEL-351-5"

    return info


def parse_status_output(lines: list[str], date_format: str = "") -> dict:
    """
    Parse status command output.

    This data can be retrieved via Telnet or Serial with the ``sta`` command
    or scraped from the HTTP web interface device status page.

    The data extracted will vary by device model.
    This can then be processed by ``process_info_into_dev()``.

    Data that may be extracted:

    - ``device_name``: Device name (``"STATION A"``)
    - ``device_identifier``: Device identifier (``"Relay 1"``)
    - ``device_time``: Current date and time on the device
        (:class:`~datetime.datetime` instance)
    - ``FID``: FID string
    - ``CID``: CID string (``"F029"``)
    - (TODO) Temperature
    - (TODO) Self-test results for components (RAM, ROM, FPGA, etc.)
    - (TODO) Voltages and currents

    Args:
        lines: Extracted status info lines
        date_format: Date format of the device (``DATE_F`` setting),
            ``MDY`` (the default), ``YMD``, or ``DMY``

    Returns:
        Data extracted from the command output
    """
    # TODO: this function needs a lot of work. Should refactor to work
    #   as a regex on the raw response text instead of line parsing, since
    #   the output of 'sta' varies significantly between devices/versions.
    #   Also, operate on raw text, don't rely on lines being preprocessed

    if not lines:
        log.warning("No data passed to parse_status_output")
        return {}

    info = {}

    if len(lines) == 1:
        info["FID"] = lines[0].split("=")[1].strip()
        return info

    id_time = re.search(
        r"(?P<dev_id>[\w\-. ]+)\s+"
        r"Date: (?P<date>\d+/\d+/\d{2,4})\s+"
        r"Time: (?P<time>\d+:\d+:[\d.]+)",
        lines[0],
        re.ASCII,
    )

    if id_time:
        # "THERMOMETER", "FEEDER 1", "SEL-700G", "Relay 1"
        info["device_identifier"] = id_time["dev_id"].strip()
        info["device_time"] = parse_sel_datetime(id_time["date"], id_time["time"], date_format)
    else:
        log.debug(f"Failed to match 'sta' output for line {repr(lines[0])}")

    if "Time Source" in lines[1]:
        # "GENERATOR RELAY                          Time Source: Internal"
        name_ts = re.search(
            r"(?P<dev_name>[\w\-. ]+)\s+Time Source: (?P<time_source>\w+)",
            lines[1],
            re.ASCII,
        )

        if name_ts:
            info["device_name"] = name_ts["dev_name"].strip()
            info["time_source"] = name_ts["time_source"].strip()
    else:
        # "STATION A", or on 400-series relays,
        # "Station A                  Serial Number: 2001001234"
        name, _, serial = lines[1].partition("Serial Number:")
        info["device_name"] = name.strip()
        if serial.strip():
            info["serial_number"] = serial.strip()

    # Finish early if there are only two lines
    if len(lines) <= 2:
        return info

    try:
        if "FID" in lines[2] and "CID" in lines[2]:
            fid_cid = [x.strip() for x in re.split(r"\s{2,}", lines[2]) if x]
            info["FID"] = fid_cid[0].split("=")[1].strip()
            info["CID"] = fid_cid[1].split("=")[1].strip()

        elif "serial num" in lines[2].lower():
            serial_fid = [x.strip() for x in re.split(r"\s{2,}", lines[2]) if x]
            info["serial_number"] = serial_fid[0].split("=")[1].strip()
            info["FID"] = serial_fid[1].split("=")[1].strip()

            cid_partnum = [x.strip() for x in re.split(r"\s{2,}", lines[3]) if x]
            info["CID"] = cid_partnum[0].split("=")[1].strip()
            info["part_number"] = cid_partnum[1].split("=")[1].strip()

        elif "serial no" in lines[2].lower():
            sn_line = f"{lines[2]} {lines[3]}"
            result = re.match(
                (
                    r".+erial.+\s+=\s+(?P<serial_number>\w+)\s+"
                    r"FID\s+=\s+(?P<FID>[\w\-]+)\s+"
                    r"CID\s+=\s+(?P<CID>\w+)\s*"
                ),
                sn_line,
                re.ASCII,
            )
            info.update(result.groupdict())

        elif lines[2].startswith("FID="):
            info["FID"] = lines[2].split("=")[1].strip()

    except Exception:
        log.exception("Failed to parse FID from status lines")
        log.error(f"Bad lines: {lines}")

    # TODO: parse voltages and currents
    # TODO: parse self-test statuses
    # TODO: parse temperature

    return info


#: Text in an event report that means there aren't any events. Most relays print
#: ``No data available`` (``"No Data Available"`` for compressed commands),
#: and the SEL-351S prints ``History Buffer Empty``.
EMPTY_EVENT_MARKERS: Final = ("no data available", "history buffer empty")

#: Values of the ``DATE_F`` (date format) global setting
DATE_FORMATS: Final = ("MDY", "YMD", "DMY")

_DATE_PATTERN: Final = r"\d{1,4}[/-]\d{1,2}(?:[/-]\d{1,4})?"
_TIME_PATTERN: Final = r"\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?"

#: Header line of a SER or history report, e.g. ``#  DATE  TIME  ELEMENT  STATE``.
#: The SEL-551 SER report uses ``Row`` instead of ``#``, and some history
#: files have a column before the date (``#  REF  DATE  TIME ...``).
EVENT_HEADER_RE: Final = re.compile(
    r"^(?:#|row)\s+(?:\S+\s+)?date\s+time\b", re.ASCII | re.IGNORECASE
)

#: Key in ``DeviceData._cache`` for the relay's time in the header of the last
#: SER report that was parsed, which is the reference time for the uptime
SER_DEVICE_TIME_KEY: Final = "sel_ser_device_time"

#: Row in a SER report, e.g. ``213  01/15/2021  17:09:45.504    Relay Powered Up``.
#: The element and state (``rest``) are split on two or more spaces, since
#: both can have single spaces (``GROUND O/C 1 LINE 1   51S1 PICKED UP``).
SER_ROW_RE: Final = re.compile(
    rf"^(?P<num>\d+)\s+(?P<date>{_DATE_PATTERN})\s+(?P<time>{_TIME_PATTERN})"
    r"(?:\s+(?P<rest>.*?))?\s*$",
    re.ASCII,
)

#: States that may be separated from the element by a single space in SER rows
_SER_STATES: Final = ("asserted", "deasserted", "enabled", "disabled")

_NUMBER_OR_UNKNOWN: Final = r"-?\d+(?:\.\d+)?|\$[$.]*"

#: Columns in the header of a history report (``HIS`` command or ``HISTORY.TXT``),
#: with the name of the value and its regex. The names vary by relay family:
#: ``CURR`` (351S, 421, 551) or ``CURRENT`` (751A, 700G), ``FREQ`` (351S, 751A)
#: or ``FREQX`` (700G). ``$`` characters are an unknown value (e.g. ``$$$$$$$``
#: for the fault location when the fault locator didn't run).
HISTORY_COLUMNS: Final = {
    "#": ("num", r"\d+"),
    "ROW": ("num", r"\d+"),
    "REF": ("ref", r"\d+"),
    "REF_NUM": ("ref", r"\d+"),
    "DATE": ("date", _DATE_PATTERN),
    "TIME": ("time", _TIME_PATTERN),
    "EVENT": ("event", r"\S.*?"),
    "LOCAT": ("locat", _NUMBER_OR_UNKNOWN),
    "LOCATION": ("locat", _NUMBER_OR_UNKNOWN),
    "CURR": ("current", _NUMBER_OR_UNKNOWN),
    "CURRENT": ("current", _NUMBER_OR_UNKNOWN),
    "FREQ": ("frequency", _NUMBER_OR_UNKNOWN),
    "FREQX": ("frequency", _NUMBER_OR_UNKNOWN),
    "FREQUENCY": ("frequency", _NUMBER_OR_UNKNOWN),
    "GRP": ("group", r"\d+"),
    "GROUP": ("group", r"\d+"),
    "SHOT": ("shot", r"\d+"),
    "TARGETS": ("targets", r".*?"),
}

#: Layout of ``HISTORY.TXT`` that PEAT parsed before it read the header
#: (record number, reference number, date, time, event, current, frequency, targets)
_LEGACY_HISTORY_ROW_RE: Final = re.compile(
    rf"^(?P<num>\d+)\s+(?P<ref>\d+)\s+(?P<date>{_DATE_PATTERN})\s+(?P<time>{_TIME_PATTERN})\s+"
    r"(?P<event>\S.*?)\s+(?P<current>[\d.]+)\s+(?P<frequency>[\d.]+)(?:\s+(?P<targets>.*?))?\s*$",
    re.ASCII,
)

#: History events that are trips, e.g. ``TRIP``, ``Diff 87 Trip``, or ``AG T``
#: (fault type and ``T`` for a trip, on the 351S and 421)
TRIP_EVENT_RE: Final = re.compile(r"\btrip\b|^[ABCG]{1,4} T$", re.IGNORECASE)

#: Element of a SER record for a relay power-up or restart: ``Relay newly powered up``
#: (351S), ``Relay Powered Up`` (700 series), ``Power-up`` (400 series, with the
#: settings group as the state), and ``Diagnostic Restart`` (400 series).
#: This must match the whole element (after :func:`_normalize_name`), so that
#: the alias of a Relay Word bit (e.g. ``UPS POWER UP``) isn't a power-up.
POWER_UP_RE: Final = re.compile(
    r"^(?:relay (?:newly )?powered up|power[- ]?up|diagnostic restart)\.?$", re.IGNORECASE
)

#: Element of a SER record that's logged for a power-up OR a settings change
#: (SEL-551, SEL-710 and SEL-749M), so it doesn't mean the relay restarted
AMBIGUOUS_POWER_UP_RE: Final = re.compile(
    r"^relay (?:newly )?powered up or settings changed\.?$", re.IGNORECASE
)


#: Event file names (refer to :data:`EVENT_FILENAME_RE`), with the
#: Compressed ASCII prefix (``C``) and the kind of events
_EVENT_FILE_KIND_RE: Final = re.compile(
    r"(?:^|[^A-Z])(?P<compressed>C?)(?P<kind>SER|HISTORY)\.TXT$", re.IGNORECASE
)

#: Commands (and words in the names of web pages) for each kind of events,
#: and if they're Compressed ASCII
_EVENT_DATASET_WORDS: Final = {
    "ser": ("ser", False),
    "sequential": ("ser", False),
    "cse": ("ser", True),
    "cser": ("ser", True),
    "his": ("history", False),
    "history": ("history", False),
    "historical": ("history", False),
    "chi": ("history", True),
    "chis": ("history", True),
    "chistory": ("history", True),
}


def event_dataset_kind(dataset: str) -> tuple[str, bool]:
    """
    The kind of events in a dataset, and if they're Compressed ASCII.

    File names are classified by their suffix (``SER.TXT``, ``CSER.TXT``,
    ``HISTORY.TXT``, or ``CHISTORY.TXT``), so a prefix
    (``Whistler_SER.TXT``) doesn't matter. Commands must match exactly
    (``ser``, ``cse``, ``his``, ``chi``), and other names (e.g. web pages)
    are classified by their words.

    Args:
        dataset: Name of the file, command, or web page the events are from,
            e.g. ``SER.TXT``, ``CSER.TXT``, ``HIS``, or
            ``Sequential Event Recorder ('ser')``

    Returns:
        ``ser`` (Sequential Events Recorder) or ``history`` (or an empty string
        if the dataset isn't known), and :obj:`True` if it's Compressed ASCII
        (``CSER.TXT``, ``CHISTORY.TXT``, or the ``CSE`` and ``CHI`` commands)
    """
    name = dataset.strip()

    # A file name is classified by its suffix, so a prefix (e.g. a device
    # or site name, like "Whistler_SER.TXT") doesn't change the kind
    file_match = _EVENT_FILE_KIND_RE.search(name)
    if file_match:
        kind = "ser" if file_match["kind"].upper() == "SER" else "history"
        return kind, bool(file_match["compressed"])

    lower = name.lower()
    if lower in _EVENT_DATASET_WORDS:  # Command, e.g. "ser" or "CHI"
        return _EVENT_DATASET_WORDS[lower]

    # Any other file (e.g. "SET_1.TXT") isn't an event file
    if re.search(r"\.[a-z0-9]{1,4}$", lower):
        return "", False

    # Other names, e.g. web pages ("Historical Events ('his')"),
    # are classified by their first word that's known
    for word in re.findall(r"[a-z]+", lower):
        if word in _EVENT_DATASET_WORDS:
            return _EVENT_DATASET_WORDS[word]

    return "", False


def extract_date_format(configs: ConfigsType) -> str:
    """
    Get the date format of the relay from the ``DATE_F`` global setting.

    Returns:
        ``MDY``, ``YMD``, or ``DMY``, or an empty string if it's not in the settings
    """
    for section in configs.values():
        if isinstance(section, dict) and "DATE_F" in section:
            value = str(_getv(section["DATE_F"])).strip().strip('"').upper()
            if value in DATE_FORMATS:
                return value

    return ""


def get_date_format(dev: DeviceData) -> str:
    """
    The date format of the device (``DATE_F``), if it was parsed from its settings.
    """
    value = str(dev.extra.get("date_format", "")).upper()
    return value if value in DATE_FORMATS else ""


def infer_date_format(dates: list[str]) -> str:
    """
    Infer the date format from dates in event reports, for when the ``DATE_F``
    setting isn't known. A date with the year first is ``YMD``, a first part
    larger than 12 is ``DMY``, and a second part larger than 12 is ``MDY``.

    Returns:
        The date format, or an empty string if it can't be determined
        (e.g. ``01/02/2021``)
    """
    for date in dates:
        parts = re.split(r"[/-]", str(date).strip())
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            continue

        if len(parts[0]) == 4:
            return "YMD"

        first, second = int(parts[0]), int(parts[1])
        if first > 12 >= second:
            return "DMY"
        if second > 12 >= first:
            return "MDY"

    return ""


def parse_sel_datetime(date: str, time: str, date_format: str = "") -> datetime:
    """
    Parse a date and time from a SEL device, e.g. ``01/15/2021`` and ``17:09:45.504``.

    The result is timezone-unaware, since relays report their local time.

    Args:
        date: The date, in the format of the device (``DATE_F`` setting)
        time: The time
        date_format: ``MDY`` (the default), ``YMD``, or ``DMY``

    Raises:
        ValueError: if the date or time is invalid
    """
    order = date_format.upper() if date_format else ""

    return date_parse(f"{date} {time}".strip(), dayfirst=order == "DMY", yearfirst=order == "YMD")


def _clean_event_text(data: bytes | str) -> str:
    """
    Decode event data and remove NUL characters. Bytes are decoded as UTF-8,
    or Latin-1 if they aren't valid UTF-8, so non-ASCII bytes don't fail.
    """
    if isinstance(data, (bytes, bytearray)):
        return clean_settings_text(bytes(data))

    return data.replace("\x00", "")


def event_data_present(data: bytes | str) -> bool:
    """
    If event data (SER, CSER, HISTORY, CHISTORY) has events.

    Data has events if it has at least one row (a line that starts with a
    number) and doesn't have any of the :data:`EMPTY_EVENT_MARKERS`
    (e.g. ``No data available``). Every line is checked, since the marker
    is after the status information and header in some reports.
    """
    text = _clean_event_text(data).replace(sel_cascii.STX, "").replace(sel_cascii.ETX, "")
    lines = [line.strip() for line in text.lower().splitlines() if line.strip()]

    for line in lines:
        if not line[:1].isdigit() and any(marker in line for marker in EMPTY_EVENT_MARKERS):
            return False

    return any(line[:1].isdigit() for line in lines)


def _parse_front_matter(lines: list[str], date_format: str = "") -> dict:
    """
    Parse the status information before the events in a report,
    e.g. the relay ID, station ID, current time, and FID.
    """
    front = []
    for line in lines:
        lowered = line.lower()
        if EVENT_HEADER_RE.match(line) or any(m in lowered for m in EMPTY_EVENT_MARKERS):
            break
        front.append(line)

    # A single line is only parsed if it's a FID (e.g. not a "=>" prompt)
    if not front or (len(front) == 1 and not re.match(r"\s*FID\s*=", front[0], re.I)):
        return {}

    try:
        return parse_status_output(front, date_format=date_format)
    except Exception as ex:
        log.debug(f"Failed to parse the status information in event data: {ex}")
        return {}


def parse_and_process_events(
    data: bytes | str, dataset: str, dev: DeviceData
) -> tuple[list[dict], dict]:
    """
    Parse events from SER (``SER.TXT``, ``ser`` command or web page),
    CSER (``CSER.TXT``), history (``HISTORY.TXT``, ``his`` command or web page),
    or CHISTORY (``CHISTORY.TXT``) data, and add them to the device.

    The kind of events is determined from ``dataset``
    (refer to :func:`event_dataset_kind`). SER or history data that
    is Compressed ASCII is parsed as CSER or CHISTORY.

    Args:
        data: The data
        dataset: Name of the file, command, or page the data is from
        dev: Device to add the events and status information to

    Returns:
        The events (from :func:`parse_ser`, :func:`parse_cser`,
        :func:`parse_history`, or :func:`parse_chistory`) and the status
        information (e.g. ``device_time``)
    """
    log.info(f"Parsing events in {dataset} from {dev.get_id()}")

    # TODO: error state should be better propagated to callers,
    # e.g. the caller should be able to differentiate between
    # no events returned because there are no events vs.
    # no events returned because a parsing error occurred.

    kind, compressed = event_dataset_kind(dataset)
    if not kind:
        log.error(f"Invalid SER/HISTORY filename: {dataset}")
        state.error = True
        return [], {}

    text = _clean_event_text(data)
    raw_lines = split_lines(text)

    if not raw_lines:
        return [], {}

    if not compressed and sel_cascii.is_compressed_ascii(text):
        log.debug(f"{dataset} is Compressed ASCII")
        compressed = True

    date_format = get_date_format(dev)

    if not event_data_present(text):
        log.debug(f"No event data present for {dataset}")
        info = {} if compressed else _parse_front_matter(raw_lines, date_format)
        if info:
            process_info_into_dev(info, dev)
        return [], info

    info = {}

    try:
        if kind == "ser" and compressed:
            events, info = parse_cser(text)
        elif kind == "ser":
            events, info = parse_ser(raw_lines, date_format=date_format)
        elif compressed:
            events, info = parse_chistory(text)
        else:
            events, info = parse_history(raw_lines, date_format=date_format)
    except Exception:
        log.exception(f"Failed to parse events in {dataset} from {dev.get_id()}")
        state.error = True
        return [], info

    if compressed:
        # Don't add the empty keys of parse_cser and parse_chistory to the device
        info = {key: value for key, value in info.items() if value not in (None, "")}

    if info:
        try:
            process_info_into_dev(info, dev)
        except Exception as ex:
            # Don't lose the events if the status information is bad
            log.warning(f"Failed to process the status information in {dataset}: {ex}")

        # The relay's time when the SER was read, from the same clock as the events
        if kind == "ser" and isinstance(info.get("device_time"), datetime):
            dev._cache[SER_DEVICE_TIME_KEY] = info["device_time"]

    if not events:
        log.warning(f"No events in {dataset} from {dev.get_id()}")
        return [], info

    process_events(events, dev, dataset=dataset)

    log.info(f"Extracted {len(events)} events from {dataset} from {dev.get_id()}")

    return events, info


def _find_header(lines: list[str]) -> int | None:
    return next((idx for idx, line in enumerate(lines) if EVENT_HEADER_RE.match(line)), None)


def _split_ser_element_state(rest: str) -> tuple[str, str]:
    """
    Split the element and state in a SER row, which are separated by two or more
    spaces. If there's only a single space before a common state
    (e.g. ``SALARM Deasserted``), then that's used.
    """
    parts = [part for part in re.split(r"\s{2,}|\t", rest.strip()) if part]

    if not parts:
        return "", ""

    if len(parts) == 1:
        element, _, last_word = parts[0].rpartition(" ")
        if element and last_word.lower() in _SER_STATES:
            return element, last_word
        return parts[0], ""

    return parts[0], " ".join(parts[1:])


def parse_ser(raw_lines: list[str], date_format: str = "") -> tuple[list[dict], dict]:
    """
    Parse output of ``SER.TXT``, the ``ser`` command, or the ``ser`` web page.

    Examples of SER data:

    - SER.TXT pulled via FTP or Telnet
    - Output from 'ser' command (via Telnet or serial)
    - "ser" page in the web interface

    Examples of rows:

    .. code-block:: text

       1024 12/09/2020  18:08:43.048    SALARM                       Deasserted
       213  01/15/2021  17:09:45.504    Relay Powered Up
       6      03/15/2001   00:00:00.004   Power-up              Group 1
       4      03/15/2001   00:30:00.021   GROUND O/C 1 LINE 1   51S1 PICKED UP

    Rows that can't be parsed (e.g. ``Invalid Data``, for a record that was
    corrupted by a power loss) are skipped.

    Args:
        raw_lines: Lines of the SER data
        date_format: Date format of the relay (``DATE_F`` setting), used for
            the current time in the status information. If not set, it's
            inferred from the dates of the events.

    Returns:
        Events and status info. Events will be empty if there are no events.
        Status info will be empty if no front matter was present.
    """
    lines = split_lines("\n".join(raw_lines))
    header_index = _find_header(lines)

    if header_index is None:
        rows = lines
        front = []
    else:
        rows = lines[header_index + 1 :]
        front = lines[:header_index]

    events = []
    skipped = []

    for line in rows:
        if not line[:1].isdigit():
            continue

        match = SER_ROW_RE.match(line)
        if not match:
            skipped.append(line)
            continue

        element, ser_state = _split_ser_element_state(match["rest"] or "")
        if not element:
            skipped.append(line)
            continue

        events.append(
            {
                "sequence": int(match["num"]),
                "date": match["date"],
                "time": match["time"],
                "original": line,
                "element": element,
                "state": ser_state,
            }
        )

    if skipped:
        log.debug(f"Skipped {len(skipped)} SER lines that aren't events: {skipped[:10]}")

    if header_index is None and not events:
        log.warning("No events found in SER output, attempting to parse status info")
        return [], _parse_front_matter(lines, date_format)

    if not date_format:
        date_format = infer_date_format([e["date"] for e in events])

    status_info = {}

    # Process the status information front matter
    if front and "SEL-2032" not in front[0]:
        status_info = _parse_front_matter(front, date_format)

    return events, status_info


def _history_row_regex(header: str) -> re.Pattern | None:
    """
    Build a regex for the rows of a history report from its header,
    e.g. ``#  DATE  TIME  EVENT  LOCAT  CURR  FREQ  GRP  SHOT  TARGETS``.
    """
    tokens = header.split()
    names = [token.upper() for token in tokens]

    if not {"DATE", "TIME", "EVENT"} <= set(names):
        return None

    parts = []
    used = set()
    trailing = ""

    for index, name in enumerate(names):
        group, pattern = HISTORY_COLUMNS.get(name, (f"col{index}", r"\S+"))
        if group in used:
            group = f"col{index}"
        used.add(group)

        if index == len(names) - 1 and group == "targets":
            # Targets are optional, and can have spaces ("INST SOTF 50 51 81")
            trailing = rf"(?:\s+(?P<targets>{pattern}))?"
        else:
            parts.append(rf"(?P<{group}>{pattern})")

    return re.compile(r"^" + r"\s+".join(parts) + trailing + r"\s*$", re.ASCII)


def _history_row_event(values: dict, line: str) -> dict | None:
    """
    Create an event from the values of a history row (from the regex built by
    :func:`_history_row_regex`), or :obj:`None` if it doesn't have the
    values of an event (sequence number, date, time, and event).
    """
    sequence = values.get("ref") or values.get("num")
    if not sequence or not values.get("date") or not values.get("time"):
        return None

    event_name = (values.get("event") or "").strip()
    if not event_name:
        return None

    event = {
        "sequence": int(sequence),
        "date": values["date"],
        "time": values["time"],
        "original": line,
        "event": event_name,  # "Trip"
        "current": _to_float(values.get("current")),  # 1.00
        "frequency": _to_float(values.get("frequency")),  # 60.0
        "targets": (values.get("targets") or "").strip(),  # "11000000"
    }

    if values.get("ref") and values.get("num"):
        event["record_number"] = int(values["num"])
    if values.get("locat") is not None and _to_float(values["locat"]) is not None:
        event["locat"] = _to_float(values["locat"])
    for key in ("group", "shot"):
        if values.get(key) is not None:
            event[key] = int(values[key])

    return event


def parse_history(raw_lines: list[str], date_format: str = "") -> tuple[list[dict], dict]:
    """
    Parse output of ``HISTORY.TXT``, the ``his`` command, or the ``his`` web page.

    The columns are read from the header line, since they vary by relay family:

    .. code-block:: text

       #  DATE TIME EVENT LOCAT CURR FREQ GRP SHOT TARGETS     (351S)
       #  DATE TIME EVENT LOCAT CURR GRP TARGETS               (421)
       #  DATE TIME EVENT CURRENT FREQ TARGETS                 (751A)
       #  DATE TIME EVENT CURRENT FREQX TARGETS                (700G)
       #  DATE TIME EVENT SHOT CURR TARGETS                    (551)

    Events can have spaces (``AG T``, ``Phase 51 Trip``), as can targets.
    Unknown values (``$$$$$$$``) are :obj:`None`. Rows that can't be parsed
    (e.g. ``Invalid History Data``) are skipped.

    Args:
        raw_lines: Lines of the history data
        date_format: Date format of the relay (``DATE_F`` setting), used for
            the current time in the status information. If not set, it's
            inferred from the dates of the events.

    Returns:
        Events and status info. Events will be empty if there are no events.
        Status info will be empty if no front matter was present.
    """
    lines = split_lines("\n".join(raw_lines))
    header_index = _find_header(lines)

    if header_index is None:
        log.warning("No events found in HISTORY output, attempting to parse status info")
        return [], _parse_front_matter(lines, date_format)

    row_regex = _history_row_regex(lines[header_index])

    events = []
    skipped = []

    for line in lines[header_index + 1 :]:
        if not line[:1].isdigit():
            continue

        match = (row_regex.match(line) if row_regex else None) or _LEGACY_HISTORY_ROW_RE.match(
            line
        )
        if not match:
            skipped.append(line)
            continue

        try:
            event = _history_row_event(match.groupdict(), line)
        except (KeyError, TypeError, ValueError) as ex:
            log.debug(f"Failed to parse history row {line!r}: {ex}")
            event = None

        if event is None:
            skipped.append(line)
            continue

        events.append(event)

    if skipped:
        log.info(f"Skipped {len(skipped)} history lines that couldn't be parsed: {skipped[:10]}")

    if not date_format:
        date_format = infer_date_format([e["date"] for e in events])

    status_info = {}

    # Process the status information front matter
    if header_index != 0:
        status_info = _parse_front_matter(lines[:header_index], date_format)

    return events, status_info


def _upper_keys(row: dict) -> dict:
    return {str(key).strip().upper(): value for key, value in row.items() if key != "_extra"}


def _first_value(row: dict, *keys: str) -> Any:
    for key in keys:
        if row.get(key) not in (None, ""):
            return row[key]
    return None


def _parse_cascii_events(lines: list[str] | str) -> tuple[list[dict], dict]:
    """
    Parse a Compressed ASCII report (e.g. ``CSER.TXT``) into its blocks
    (refer to :func:`~peat.modules.sel.sel_cascii.parse_report`), and get
    the device information from the header (``"FID","SERIAL NO","CID"``
    on the 700 series, ``"RID","SID","FID"`` on the 400 series).
    The device information always has ``serial_number``, ``FID``, and ``CID``
    (empty strings if they aren't in the header).
    """
    text = lines if isinstance(lines, str) else "\r\n".join(lines)
    blocks = sel_cascii.parse_report(sel_cascii.parse_records(text))

    device_info = {}
    for block in blocks:
        labels = [label.strip().upper() for label in block["labels"]]
        if not block["rows"] or not labels or labels[0] not in ("FID", "RID"):
            continue

        row = _upper_keys(block["rows"][0])
        fid = _first_value(row, "FID")
        if fid:
            device_info["FID"] = str(fid).split("=")[-1].strip()

        for key, info_key in (
            ("SERIAL NO", "serial_number"),
            ("SERIALNO", "serial_number"),
            ("CID", "CID"),
            ("RID", "device_identifier"),
            ("SID", "device_name"),
        ):
            value = _first_value(row, key)
            if value not in (None, "") and info_key not in device_info:
                device_info[info_key] = str(value).strip()
        break

    # parse_cser and parse_chistory have always returned these keys
    # (empty if they aren't in the header), and HEAT uses these functions
    for key in ("serial_number", "FID", "CID"):
        device_info.setdefault(key, "")

    return blocks, device_info


def _cascii_row_timestamp(row: dict) -> tuple[str, str, datetime | None]:
    """
    The date and time of a Compressed ASCII row, from the ``DATE`` and ``TIME``
    labels (700 series), or the ``MONTH``, ``DAY``, ``YEAR``, ``HOUR``, ``MIN``,
    ``SEC``, and ``MSEC`` labels (most other relays).

    Returns:
        The date and time (as strings, ``MM/DD/YYYY`` and ``HH:MM:SS.mmm``
        for the separate labels), and the datetime, if the date
        is in separate labels (so it doesn't depend on ``DATE_F``)
    """
    if row.get("DATE") not in (None, "") and row.get("TIME") not in (None, ""):
        return str(row["DATE"]).strip(), str(row["TIME"]).strip(), None

    try:
        year = int(row["YEAR"])
        if year < 100:
            # The same century as a 2-digit year in a text report
            # (refer to parse_sel_datetime), so the events can be merged
            year = parserinfo().convertyear(year)
        msec = int(row.get("MSEC") or 0)
        usec = int(row.get("USEC") or 0)
        created = datetime(
            year,
            int(row["MONTH"]),
            int(row["DAY"]),
            int(row["HOUR"]),
            int(row["MIN"]),
            int(row["SEC"]),
            msec * 1000 + usec,
        )
    except (KeyError, TypeError, ValueError):
        return "", "", None

    return (
        created.strftime("%m/%d/%Y"),
        f"{created:%H:%M:%S}.{msec:03d}",
        created,
    )


def parse_cser(lines: list[str] | str) -> tuple[list[dict], dict]:
    """
    Extract and parse events and device info from ``CSER.TXT``
    (or the output of the ``CSE`` command).

    The rows are mapped by their labels, so both known layouts work:
    ``"REC_NUM","DATE","TIME","ELEMENT","STATE"`` (700 series) and
    ``"#","MONTH","DAY","YEAR","HOUR","MIN","SEC","MSEC","ELEMENT","STATE"``
    (400 series). Rows can be shorter than the labels (e.g. ``Relay Powered Up``
    has no state). Checksums are verified, and events from rows with a wrong
    checksum have ``checksum_valid`` set to :obj:`False`.

    Args:
        lines: Lines of the data, or the data

    Returns:
        Events and device info (``FID``, ``CID``, ``serial_number``, and for the
        400 series, the relay and station ID). ``FID``, ``CID``, and
        ``serial_number`` are empty strings if they aren't in the data.
    """
    blocks, device_info = _parse_cascii_events(lines)
    events = []

    for block in blocks:
        if "ELEMENT" not in [label.strip().upper() for label in block["labels"]]:
            continue

        for raw_row, record in zip(block["rows"], block["records"], strict=False):
            row = _upper_keys(raw_row)
            sequence = _first_value(row, "#", "REC_NUM")
            date, time, created = _cascii_row_timestamp(row)
            element = str(row.get("ELEMENT") or "").strip()

            if not isinstance(sequence, int) or not date or not element:
                log.debug(f"Skipping CSER row that isn't an event: {record.text!r}")
                continue

            event = {
                "sequence": sequence,
                "date": date,
                "time": time,
                "original": record.text,
                "element": element,
                "state": str(row.get("STATE") or "").strip(),
            }
            if created:
                event["created"] = created
            if record.status == sel_cascii.STATUS_INVALID:
                event["checksum_valid"] = False

            events.append(event)

    return events, device_info


def parse_chistory(lines: list[str] | str) -> tuple[list[dict], dict]:
    """
    Extract and parse events and device info from ``CHISTORY.TXT``
    (or the output of the ``CHI`` command).

    The rows are mapped by their labels, which vary by relay family, e.g.
    ``REC_NUM,REF_NUM,MONTH,...,EVENT,CURRENT,FREQX,TARGETS`` (700 series),
    ``REC_NUM,REF_NUM,MONTH,...,EVENT,LOCATION,CURR,FREQ,GROUP,SHOT,TARGETS``
    (351S), or ``EVENT_NUM,MONTH,...,MSEC,USEC,EVENT,LOCATION,...`` (421).

    Args:
        lines: Lines of the data, or the data

    Returns:
        Events and device info (just the FID generally with CHISTORY,
        refer to :func:`parse_cser`).
    """
    blocks, device_info = _parse_cascii_events(lines)
    events = []

    for block in blocks:
        if "EVENT" not in [label.strip().upper() for label in block["labels"]]:
            continue

        for raw_row, record in zip(block["rows"], block["records"], strict=False):
            row = _upper_keys(raw_row)

            # NOTE: for CHISTORY, "REC_NUM" is just it's order in the file
            # The actual sequence number is REF_NUM (REF, not REC, easy to miss)
            sequence = _first_value(row, "REF_NUM", "EVENT_NUM", "REC_NUM", "#")
            date, time, created = _cascii_row_timestamp(row)
            event_name = str(row.get("EVENT") or "").strip()

            if not isinstance(sequence, int) or not date or not event_name:
                log.debug(f"Skipping CHISTORY row that isn't an event: {record.text!r}")
                continue

            event = {
                "sequence": sequence,
                "date": date,
                "time": time,
                "original": record.text,
                "event": event_name,  # "Trip"
                "current": _to_float(_first_value(row, "CURR", "CURRENT")),  # 1.00
                "frequency": _to_float(_first_value(row, "FREQ", "FREQX", "FREQUENCY")),
                "targets": str(row.get("TARGETS") or "").strip(),  # "11000000"
            }
            if created:
                event["created"] = created

            locat = _to_float(_first_value(row, "LOCATION", "LOCAT"))
            if locat is not None:
                event["locat"] = locat
            for key, labels in (("group", ("GROUP", "GRP")), ("shot", ("SHOT",))):
                value = _to_int(_first_value(row, *labels))
                if value is not None:
                    event[key] = value

            if record.status == sel_cascii.STATUS_INVALID:
                event["checksum_valid"] = False

            events.append(event)

    return events, device_info


def _normalize_name(value: Any) -> str:
    # CSER may use underscores where SER has spaces ("GROUND_O/C_1_LINE_1")
    return re.sub(r"[\s_]+", " ", str(value or "")).strip().lower()


def _event_identity(event: Event) -> tuple:
    """
    What makes an event unique: the kind of events (``ser`` or ``history``),
    when it happened, and the element and state (SER) or event (history).
    The same event from different sources (e.g. ``SER.TXT`` and the ``ser``
    command) has the same identity. The sequence number isn't used, since
    it changes as new events are added (``1`` is the newest event).
    """
    if event.created is None:
        return (event.dataset, event.sequence, event.original)

    if event.dataset == "ser":
        name = (
            _normalize_name(event.extra.get("element")),
            _normalize_name(event.extra.get("state")),
        )
    elif event.dataset == "history":
        name = (_normalize_name(event.extra.get("event")),)
    else:
        name = (event.message.lower(),)

    return (event.dataset, event.created, *name)


def _create_event(
    raw_event: dict, dev: DeviceData, kind: str, dataset: str, date_format: str
) -> Event | None:
    """
    Create an :class:`~peat.data.models.Event` from an event parsed by
    :func:`parse_ser`, :func:`parse_cser`, :func:`parse_history`, or
    :func:`parse_chistory`.
    """
    event_category = {"host"}  # type: set[str]
    event_type = set()  # type: set[str]
    extra = {"source_datasets": [dataset]}

    created = raw_event.get("created")
    if created is None:
        if not raw_event.get("date") or not raw_event.get("time"):
            return None
        # date: "09/13/2022" (Month/Day/Year by default, refer to DATE_F)
        # time: "16:09:12.264"
        created = parse_sel_datetime(raw_event["date"], raw_event["time"], date_format)

    # SER/CSER
    if raw_event.get("element"):
        # Examples of element values:
        # 'Relay', 'Power-up', 'Settings changed', '51G', 'OUT101', 'Group change'
        element = str(raw_event["element"]).strip()
        event_element = element.lower()
        # Examples of event state:
        # 'Enabled', 'Group 1', 'Class P 5', 'Asserted', 'Deasserted'
        ser_state = str(raw_event.get("state") or "").strip()

        extra["element"] = element
        if ser_state:
            extra["state"] = ser_state

        # Power-up is checked first, since it can be combined with
        # a settings change ("Relay newly powered up or settings changed")
        power_up = ser_power_up_kind(element, ser_state)
        if power_up == "ambiguous":
            event_category.add("configuration")
            event_type.update({"start", "change"})
        elif power_up == "power_up":
            event_type.add("start")
        elif "change" in event_element:
            event_category.add("configuration")
            event_type.add("change")
        elif "archive cleared" in event_element:
            # "SER archive cleared"
            event_category.update({"database", "file"})
            event_type.update({"change", "deletion"})

        action = event_element.replace(" ", "-")  # type: str

        event_state = ser_state.lower()
        if "assert" in event_state:
            event_type.add("change")
            action = f"{event_state}-{event_element}"

        message = f"{element} {ser_state}" if ser_state else element

    # HISTORY/CHISTORY
    elif raw_event.get("event"):
        event_name = str(raw_event["event"]).strip()
        action = event_name.lower()
        event_type.add("info")
        extra["event"] = event_name

        for key in ("current", "frequency", "targets", "locat", "group", "shot"):
            if raw_event.get(key) not in (None, ""):
                extra[key] = raw_event[key]

        if TRIP_EVENT_RE.search(event_name):
            event_type.add("change")
            details = ", ".join(
                f"{label}: {raw_event[key]}"
                for label, key in (
                    ("Targets", "targets"),
                    ("Current", "current"),
                    ("Frequency", "frequency"),
                )
                if raw_event.get(key) not in (None, "")
            )
            message = f"{event_name} ({details})" if details else event_name
        else:
            message = event_name

    else:
        return None

    if raw_event.get("checksum_valid") is False:
        extra["checksum_valid"] = False

    return Event(
        action=action,
        category=event_category,
        created=created,
        dataset=kind,
        kind={"event"},
        message=message,
        module=dev._module.__name__ if dev._module else "SELRelay",
        original=raw_event.get("original", ""),
        provider=dev.get_id(),
        # NOTE: "1" is the newest event in the SER and history
        sequence=_to_int(raw_event.get("sequence")),
        type=event_type,
        extra=extra,
    )


def process_events(raw_events: list[dict], dev: DeviceData, dataset: str) -> None:
    """
    Process events into the data model.

    The event's ``dataset`` is the kind of events, ``ser`` (SER and CSER) or
    ``history`` (HISTORY and CHISTORY), and the dataset the event was parsed
    from (e.g. ``SER.TXT``) is in ``extra.source_datasets``. An event that's
    the same as an event that was already processed (the same kind of event,
    time, element and state, or event; e.g. from ``SER.TXT`` and the ``ser``
    command) is merged with it, so SER and history events are never merged.

    Dates are parsed using the relay's date format (the ``DATE_F`` setting)
    if it's known, otherwise it's inferred from the dates (refer to
    :func:`infer_date_format`), and the default is month/day/year.

    Events that can't be processed (e.g. an invalid date) are skipped
    and a warning is logged.

    Args:
        raw_events: list of events extracted from an event file
            (SER, CSER, HISTORY, CHISTORY)
        dev: device object to add events to
        dataset: Dataset of the events, e.g. ``ser``, ``CSER.TXT``, ``HISTORY.TXT``
    """
    kind = event_dataset_kind(dataset)[0] or dataset
    date_format = get_date_format(dev) or infer_date_format(
        [e.get("date", "") for e in raw_events if isinstance(e, dict) and not e.get("created")]
    )

    existing = {_event_identity(e): e for e in dev.event if e.dataset == kind}
    skipped = 0

    for raw_event in raw_events:
        try:
            event = _create_event(raw_event, dev, kind, dataset, date_format)
        except Exception as ex:
            log.warning(f"Skipping invalid event in {dataset} from {dev.get_id()}: {ex}")
            log.debug(f"Raw event: {raw_event}")
            skipped += 1
            continue

        if event is None:
            log.warning(f"Skipping invalid event in {dataset} from {dev.get_id()}: {raw_event}")
            skipped += 1
            continue

        identity = _event_identity(event)
        match = existing.get(identity)

        if match is None:
            dev.store("event", event, append=True)
            existing[identity] = event
            continue

        sources = match.extra.setdefault("source_datasets", [])
        if dataset not in sources:
            sources.append(dataset)
        merge_models(match, event)
        match.annotate(dev)

    if skipped:
        log.warning(f"Skipped {skipped} invalid events in {dataset} from {dev.get_id()}")


def _naive(value: datetime) -> datetime:
    # The relay's clock is local time. A UTC offset (e.g. from the "date"
    # command on the 451) is dropped, so it can be compared to event times.
    return value.replace(tzinfo=None) if value.tzinfo else value


def ser_power_up_kind(element: Any, state: Any = "") -> str:
    """
    If a SER record is a power-up or restart of the relay.

    The whole element must be a power-up record (refer to :data:`POWER_UP_RE`
    and :data:`AMBIGUOUS_POWER_UP_RE`), and a record whose state is the state
    of a Relay Word bit (e.g. ``Asserted``) isn't a power-up, since that's
    a SER trigger element (or its alias), not a record logged by the relay.

    Returns:
        ``power_up`` if it's a power-up or restart, ``ambiguous`` if it's
        a power-up or a settings change (SEL-551, 710, 749M), otherwise
        an empty string
    """
    name = _normalize_name(element)

    if not name or _normalize_name(state) in _SER_STATES:
        return ""
    if AMBIGUOUS_POWER_UP_RE.match(name):
        return "ambiguous"
    if POWER_UP_RE.match(name):
        return "power_up"

    return ""


def _power_up_kind(event: Event) -> str:
    """
    :func:`ser_power_up_kind` of a SER event (from :func:`process_events`).
    """
    return ser_power_up_kind(event.extra.get("element"), event.extra.get("state"))


def compute_uptime(
    events: list[Event], device_now: datetime | None
) -> tuple[timedelta | None, dict]:
    """
    Calculate how long a relay has been running from its SER events.

    The relay logs a SER record when it powers up or restarts (refer to
    :data:`POWER_UP_RE`). The uptime is the time between the newest
    power-up record and the relay's current time. Both are in the relay's
    local time, so the timezone doesn't matter. The newest record is chosen
    by its time, not the sequence number.

    The uptime can't be calculated if:

    - The newest power-up record (or the only one) is ambiguous (refer to
      :data:`AMBIGUOUS_POWER_UP_RE`). The relay has been running since at
      least that record, so it's the lower bound.
    - There's no power-up record, e.g. the SER is a ring buffer that has
      more recent records, or it was cleared. The relay has been running since
      at least the oldest record, so it's the lower bound. This assumes that
      the relay logs power-ups to the SER (all documented SEL relays do).
    - The result is negative (e.g. the relay's clock was reset), in which
      case nothing is calculated.

    Records corrupted by a power loss (``Invalid Data``) don't have a time,
    so they're ignored.

    Args:
        events: SER events (``dataset`` is ``ser``)
        device_now: The relay's current time (local time on the relay).
            If :obj:`None`, then only the time of the last boot is returned.

    Returns:
        The uptime (or :obj:`None`) and information about it:

        - ``last_boot``: Time of the newest power-up record (relay local time),
          if it's not ambiguous
        - ``source``: ``ser_power_up`` (uptime), ``ser_ambiguous_power_up``,
          or ``ser_oldest_record`` (lower bound)
        - ``lower_bound``: Minimum uptime (:class:`~datetime.timedelta`),
          if the uptime can't be calculated
    """
    info = {}
    dated = [e for e in events if e.created is not None]

    if not dated:
        return None, info

    power_ups = [e for e in dated if _power_up_kind(e) == "power_up"]
    ambiguous = [e for e in dated if _power_up_kind(e) == "ambiguous"]

    newest_boot = max(power_ups, key=lambda e: _naive(e.created)) if power_ups else None
    newest_ambiguous = max(ambiguous, key=lambda e: _naive(e.created)) if ambiguous else None

    boot_is_newest = newest_boot is not None and (
        newest_ambiguous is None or _naive(newest_ambiguous.created) < _naive(newest_boot.created)
    )

    if boot_is_newest:
        info["last_boot"] = _naive(newest_boot.created)

    if device_now is None:
        return None, info

    now = _naive(device_now)

    if boot_is_newest:
        uptime = now - info["last_boot"]
        if uptime < timedelta(0):
            log.warning(
                f"The relay's time ({now}) is before its last power-up ({info['last_boot']}), "
                f"the relay's clock may have been changed. Uptime won't be calculated."
            )
            return None, info

        info["source"] = "ser_power_up"
        return uptime, info

    if newest_ambiguous is not None:
        anchor = _naive(newest_ambiguous.created)
        source = "ser_ambiguous_power_up"
    else:
        anchor = min(_naive(e.created) for e in dated)
        source = "ser_oldest_record"

    lower_bound = now - anchor
    if lower_bound < timedelta(0):
        log.warning(
            f"The relay's time ({now}) is before its SER records ({anchor}), "
            f"the relay's clock may have been changed. Uptime won't be calculated."
        )
        return None, info

    info["source"] = source
    info["lower_bound"] = lower_bound

    return None, info


def apply_uptime(dev: DeviceData, device_now: datetime | None = None) -> timedelta | None:
    """
    Set the device's uptime from its SER events (refer to :func:`compute_uptime`).

    If the uptime is calculated, ``dev.uptime`` and ``dev.start_time``
    (``now - uptime``, in UTC) are set if they aren't already set. Otherwise,
    the lower bound is saved in ``dev.extra["uptime_lower_bound"]``.
    How it was determined is saved in ``dev.extra["uptime_source"]``, and the
    time of the last power-up (relay local time) in
    ``dev.extra["last_boot_device_time"]``.

    Args:
        dev: The device, with SER events (from :func:`process_events`)
        device_now: The relay's current time (local time on the relay), e.g.
            from the SER report header, the ``date`` and ``time`` commands,
            or the information when logging out. This must be from the
            same pull as the SER, so leave it unset when parsing files
            (only ``last_boot_device_time`` is saved).

    Returns:
        The uptime, or :obj:`None` if it couldn't be calculated
    """
    ser_events = [e for e in dev.event if e.dataset == "ser"]
    if not ser_events:
        return None

    if device_now is not None and not isinstance(device_now, datetime):
        device_now = utils.parse_date(str(device_now))

    uptime, info = compute_uptime(ser_events, device_now)

    if info.get("last_boot"):
        dev.extra["last_boot_device_time"] = info["last_boot"]

    if uptime is not None:
        dev.extra.pop("uptime_lower_bound", None)
        if not dev.uptime:
            dev.uptime = uptime
            dev.extra["uptime_source"] = info["source"]
            log.info(f"Uptime of {dev.get_id()} from its SER: {uptime}")
        if not dev.start_time:
            dev.start_time = utils.utc_now() - uptime
    elif info.get("lower_bound") is not None and not dev.uptime:
        dev.extra["uptime_lower_bound"] = info["lower_bound"]
        dev.extra["uptime_source"] = info["source"]
        log.info(
            f"{dev.get_id()} has been running for at least {info['lower_bound']} "
            f"(the uptime can't be calculated from its SER: {info['source']})"
        )

    return uptime


def extract_cid_content(data: bytes) -> str:
    if not data:
        return ""

    decompressed = zlib.decompress(data)

    # NOTE utf-8-sig is required to remove the
    # Byte Order Mark (BOM) that gets prepended in some cases.
    decoded = decompressed.decode("utf-8-sig")

    return decoded


def process_cid_file(data: bytes, filepath: PurePath, dev: DeviceData) -> str:
    """
    .CID files are zlib-compressed data (zlib-header 0x7801 - No Compression/low).
    The only known CID file currently is ``SET_61850.CID``, which contains XML data.

    This function decompresses the zlib data and saves the decoded text to a new file,
    which is hashed and recorded in ``dev.files``.
    """
    log.info(f"Extracting data from CID file '{filepath.name}'")

    if not data:
        log.warning(f"Empty data for CID file {filepath.name}")
        return ""

    try:
        extracted = extract_cid_content(data)

        ext = "txt"
        if "<?xml version" in extracted:
            ext = "xml"

        write_and_record_file(
            dev=dev,
            data=extracted,
            filename=f"{filepath.stem}_decompressed.{ext}",
            source=SOURCE_DERIVED,
            peat_module="SELRelay",
            description=f"Decompressed contents of {filepath.name}",
            extra={"derived_from": [filepath.name]},
        )

        if not extracted:
            log.warning(f"No data extracted from CID file {filepath.name}")

        return extracted
    except Exception as ex:
        log.error(f"Failed to extract CID file {filepath.name}: {ex}")
        return ""


def _getv(val: dict | Any) -> Any:
    """
    Helper function to handle if a value is either
    in a dict or the value itself.
    """
    if isinstance(val, dict) and "value" in val:
        return val["value"]
    return val


def _to_int(val: Any) -> int | None:
    """
    Convert a setting value to an integer, or None if it's not a number (e.g. "OFF").
    """
    try:
        return int(str(val).strip())
    except ValueError:
        return None


def _to_float(val: Any) -> float | None:
    """
    Convert a setting value to a float, or None if it's not a number (e.g. "OFF").
    """
    try:
        return float(str(val).strip())
    except ValueError:
        return None


def is_enabled(conf: dict) -> bool:
    return value_is_enabled(conf.get("value", ""))


def value_is_enabled(value: str) -> bool:
    return bool(value.upper() in ("Y", "YES", "ON", "1"))


def clean_id(id_str: str) -> str:
    cleaned = utils.clean_replace(id_str, "_", " ,!:")
    return re.sub("_{2,}", "_", cleaned).strip("_")


def split_lines(val: bytes | str) -> list[str]:
    """
    Split text into stripped lines, without blank lines and STX (``0x02``)
    and ETX (``0x03``) characters. Bytes are decoded as UTF-8, or Latin-1 if
    they aren't valid UTF-8 (refer to :func:`clean_settings_text`).
    """
    if isinstance(val, (bytes, bytearray)):
        val = clean_settings_text(bytes(val))
    val = val.replace(sel_cascii.STX, "").replace(sel_cascii.ETX, "")
    return [x.strip() for x in val.strip().splitlines() if x.strip()]
