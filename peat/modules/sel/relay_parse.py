import copy
import csv
import re
from datetime import datetime, timedelta
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, Literal

import olefile
from dateutil.parser import parse as date_parse
from pathvalidate import is_valid_filepath

from peat import (
    IO,
    Description,
    DeviceData,
    Event,
    File,
    Indicator,
    Interface,
    NetworkStatistics,
    NetworkTraffic,
    ParseError,
    Redundancy,
    Register,
    Relationship,
    RelationshipEndpoint,
    Service,
    ServiceSecurity,
    TimeSource,
    consts,
    datastore,
    log,
    state,
    utils,
)
from peat import config as peat_config
from peat.data.data_utils import merge_models
from peat.parsing import scl
from peat.protocols import clean_ipv4, split_ipv4_cidr

from .sel_consts import ANSI_CODES, LOGIC_KEYS

ConfigSectionType = list[str] | dict[str, str]
ConfigsType = dict[str, ConfigSectionType]


def parse_rdb(rdb_data: bytes) -> str:
    """
    Extract usable configuration from a SEL QuickSet database (``*.rdb`` file).

    Parse the binary data contained in a rdb project file and convert it
    to a string that is the same format used in SET_ALL.TXT.

    Args:
        rdb_data: Binary data from an ``.rdb`` project file

    Returns:
        Device configuration information parsed from the file, in the SET_ALL.TXT format
    """
    output = ""
    rdb_ole = olefile.OleFileIO(rdb_data)
    streams = rdb_ole.listdir(streams=True, storages=False)  # type: list[list[str]]

    for stream_list in streams:
        stream_path = "/".join(stream_list)
        data = rdb_ole.openstream(stream_path).read().decode("ascii", "replace")

        # Remove the file separator character
        data = data.replace("\x1c", "")

        # Remove the substitution character
        data = data.replace("\x1a", "")

        # Remove NUL characters that break CSV parser
        # An example of a file where these appear is 300G_000.rdb
        data = data.replace("\x00", "")

        if not data.endswith("\r\n"):
            data += "\r\n"

        # Format the DNP Binary map
        if "[DNPB]" in data:
            start = data.find('"')  # Find the start of the DNP Binary Memory Map
            dnpb_sub = data[start + 1 : -3]
            dnp_addresses = dnpb_sub.split(" ")
            data = "[DNPB]\r\n"
            idx = 1
            for address in dnp_addresses:
                data += f'BI_{idx},"{address}"\r\n'
                idx += 1
        output += data

    # Remove UI info stored by some configs
    start_index = output.find("INFO")
    output = output[start_index - 1 :]

    return output


def extract_sections(raw_text: str) -> dict[str, list[str]]:
    """
    Convert raw text of a config file into a dict with the text lines
    for each section.
    """
    cleaned_lines = [line.strip() for line in raw_text.splitlines() if line]

    raw_sections = {}
    current_section = ""  # Section name, e.g. "INFO", "P1", etc.

    for line in cleaned_lines:
        if re.match(r"^\[.*]$", line):
            # Set what the current section is and initialize it's dict
            current_section = line.strip("[]")
            raw_sections[current_section] = []
        else:
            if line.endswith(","):
                line += '""'  # Handle trailing commas in some configs
            elif line.endswith(',"'):
                line += '"'

            raw_sections[current_section].append(line)

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
        config_text = config_text.decode("ascii")

    if not config_text:
        return {}

    try:
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

    # Extract network info
    process_network_configuration(configs, dev)

    # Update interface/network info
    dev.populate_fields()

    # Extract Modbus registers
    parse_and_process_modbus(configs, dev)

    # Extract DNP3 registers
    parse_and_process_dnp3(configs, dev)

    # Front-panel target LED and pushbutton definitions ([F] class)
    if isinstance(configs.get("F"), dict):
        process_front_panel_settings(configs["F"], dev)

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


# Front-panel settings (SET F / "SHO F"). Setting names are not verified across
# relay models, so only these patterns are mapped; other settings are left alone.
_FP_PATTERNS = (
    (re.compile(r"^(T\d+|PB\d+)_?LED$", re.IGNORECASE), "equation"),
    (re.compile(r"^(T\d+|PB\d+)_?LEDL$", re.IGNORECASE), "latched"),
    (re.compile(r"^(T\d+|PB\d+)_?LEDC$", re.IGNORECASE), "color"),
)

# Letters of SEL LED color settings (e.g. "T01LEDC := RO")
_SEL_LED_COLORS = {"R": "red", "G": "green", "A": "amber", "O": "off"}


def sel_led_colors(code: str) -> tuple[str, str] | None:
    """
    Decode a SEL LED color setting (``T01LEDC``): the first letter is the color
    of the asserted LED, the optional second letter the color of the deasserted
    LED (``R`` red, ``G`` green, ``A`` amber, ``O`` off).

    ``"RO"`` -> ``("red", "off")``, ``"AG"`` -> ``("amber", "green")``,
    ``"G"`` -> ``("green", "")``.

    Returns:
        The asserted and deasserted colors, or :data:`None` if `code` isn't
        a known color code
    """
    code = str(code).strip().upper()
    if not 1 <= len(code) <= 2 or any(c not in _SEL_LED_COLORS for c in code):
        return None
    return _SEL_LED_COLORS[code[0]], _SEL_LED_COLORS[code[1]] if len(code) == 2 else ""


def front_panel_indicators(settings: dict) -> tuple[list[Indicator], dict]:
    """
    Map front-panel settings (``SET F``, ``SHO F``) to target LED and pushbutton
    definitions (configured, no live state).

    - ``T01_LED``/``PB1_LED`` (SELogic equation) -> ``Indicator.equation``
    - ``T01LEDL`` (latch, ``Y``/``N``) -> ``Indicator.latched``
    - ``T01LEDC`` (color, see :func:`sel_led_colors`) -> ``Indicator.color``
      (asserted color, empty if the LED is off when asserted) and
      ``Indicator.extra["deasserted_color"]``; an unknown code is kept in
      ``Indicator.extra["color_code"]``
    - a ``comment`` of the setting (``SHO F`` web page) -> ``Indicator.label``

    Targets (``T*``) are ``type="led"``, ``category="target"``; pushbuttons
    (``PB*``) are ``type="pushbutton"``, ``category="pushbutton"``.

    Args:
        settings: Setting name -> value (:class:`str`, or :class:`dict` with
            ``value`` and optionally ``comment``)

    Returns:
        The indicators and the settings that were not mapped
    """
    definitions = {}  # type: dict[str, dict[str, str]]
    remaining = {}

    for key, raw in settings.items():
        value = str(_getv(raw) if raw is not None else "").strip()
        comment = str(raw.get("comment", "")).strip() if isinstance(raw, dict) else ""

        for regex, field in _FP_PATTERNS:
            match = regex.match(str(key).strip())
            if match:
                definition = definitions.setdefault(match.group(1).upper(), {})
                definition[field] = value
                if comment and not definition.get("label"):
                    definition["label"] = comment
                break
        else:
            remaining[key] = raw

    indicators = []
    for stem, definition in definitions.items():
        is_pushbutton = stem.startswith("PB")
        indicator = Indicator(
            type="pushbutton" if is_pushbutton else "led",
            category="pushbutton" if is_pushbutton else "target",
            name=stem,
            label=definition.get("label", ""),
            equation=definition.get("equation", ""),
        )
        if definition.get("color"):
            colors = sel_led_colors(definition["color"])
            if colors is None:
                indicator.extra["color_code"] = definition["color"]
            else:
                if colors[0] != "off":
                    indicator.color = colors[0]
                if colors[1]:
                    indicator.extra["deasserted_color"] = colors[1]
        if definition.get("latched"):
            indicator.latched = value_is_enabled(definition["latched"])
        indicators.append(indicator)

    return indicators, remaining


def process_front_panel_settings(settings: dict, dev: DeviceData) -> dict:
    """
    Store the target LED and pushbutton definitions of the front-panel settings
    (see :func:`front_panel_indicators`) in ``dev.indicators``.

    Returns:
        The settings that were not mapped to indicators
    """
    indicators, remaining = front_panel_indicators(settings)
    for indicator in indicators:
        dev.store("indicators", indicator)
    return remaining


def _module_name(dev: DeviceData, default: str = "SELRelay") -> str:
    return dev._module.__name__ if dev._module else default


def device_file_path(raw_path: str) -> PurePosixPath:
    """
    Normalize a file path on a relay to an absolute POSIX path:
    ``"\\SETTINGS\\SET_1.TXT"`` -> ``/SETTINGS/SET_1.TXT``,
    ``"SETTINGS SET_1.TXT"`` -> ``/SETTINGS/SET_1.TXT``, ``"CFG.TXT"`` -> ``/CFG.TXT``.
    """
    path = str(raw_path).strip().replace("\\", "/")
    if " " in path and "/" not in path:
        path = "/".join(path.split())  # Telnet style: "<dir> <file>"
    if not path.startswith("/"):
        path = f"/{path}"
    return PurePosixPath(path)


def sel_file_categories(path: PurePath | str) -> set[str]:
    """
    :attr:`~peat.data.models.File.category` of a file on a SEL relay.

    - ``SET_*.TXT`` -> ``settings``, ``configuration``
    - ``CFG.TXT``, ``CFG.XML`` -> ``configuration``
    - ``SER.TXT``, ``CSER.TXT``, ``HISTORY.TXT``, ``CHISTORY.TXT`` -> ``log``
    - files in ``EVENTS/`` -> ``event_record``
    - ``*.CID`` -> ``configuration``, ``iec61850``
    """
    path = PurePosixPath(str(path).replace("\\", "/"))
    name = path.name.upper()
    parents = {p.upper() for p in path.parent.parts}

    if name.endswith(".CID"):
        return {"configuration", "iec61850"}
    if name.startswith("SET_") and name.endswith(".TXT"):
        return {"settings", "configuration"}
    if name in ("CFG.TXT", "CFG.XML"):
        return {"configuration"}
    if name in ("SER.TXT", "CSER.TXT", "HISTORY.TXT", "CHISTORY.TXT"):
        return {"log"}
    if "EVENTS" in parents:
        return {"event_record"}
    return set()


def process_info_classes(configs: ConfigsType, dev: DeviceData) -> None:
    """
    Process the [INFO] and [CLASSES] sections into the PEAT data model.
    """
    # Extract firmware info
    # NOTE: The INFO section should ALWAYS be present
    process_info_into_dev(configs["INFO"], dev)

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

        # Settings files of each settings class, e.g.
        # "SET_1.TXT" or "\\SETTINGS\\SET_1.TXT"
        for settings_class in configs["CLASSES"].values():
            if not isinstance(settings_class, dict) or not settings_class.get("file"):
                continue

            file_obj = File(
                path=device_file_path(settings_class["file"]),
                type="file",
                description=settings_class.get("name", ""),
                peat_module=_module_name(dev),
            )
            file_obj.category = sel_file_categories(file_obj.path)
            if settings_class.get("class"):
                file_obj.extra["settings_class"] = settings_class["class"]
            if settings_class.get("hex_id"):
                file_obj.extra["hex_id"] = settings_class["hex_id"]

            dev.store("files", file_obj, lookup="path")
            dev.related.files.add(file_obj.path.name)

    if configs.get("STORAGE"):
        # Add any filenames from [STORAGE] section, if they're files
        # Lines in this section can be random data too.
        for line in configs["STORAGE"]:
            if " " not in line and "." in line and len(line) > 3 and is_valid_filepath(line):
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
        if "IPADDR" in settings:
            ip_addr = parse_ipaddr(settings).ip
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


def process_info_into_dev(info: dict, dev: DeviceData, observed: datetime | None = None) -> None:
    """
    Put data from the info dict into the PEAT device data model.

    Args:
        info: Data from the ``id``/``sta`` commands, the status page, the ``exit``
            output or the front matter of event files
        dev: Device to update
        observed: When the data was read from the device (live reads). If set,
            ``device_time`` becomes ``dev.clock.time`` with ``dev.clock.observed``.
            If :obj:`None` (e.g. a parsed file), ``device_time`` is only used if
            the clock time is unset, and no offset is computed.
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

    relaytype = info.pop("RELAYTYPE", None)
    if relaytype and not dev.description.model:
        dev.description.model = relaytype.strip("0")

    # Device clock (status output, "exit" output, "date"/"time" commands)
    device_time = info.pop("device_time", None)
    if device_time:
        apply_device_time(dev, device_time, observed)

    time_source = info.pop("time_source", None)
    if time_source:
        dev.clock.source = normalize_time_source(time_source)
        dev.clock.extra["time_source_raw"] = str(time_source).strip()

    # IEC 61850 identity ("id" command)
    ied_name = str(info.pop("iedName", "") or "").strip()
    if ied_name:
        dev.iec61850.ied_name = ied_name
    config_version = str(info.pop("configVersion", "") or "").strip()
    if config_version:
        dev.iec61850.config_version = config_version
    lib61850_id = str(info.pop("LIB61850ID", "") or "").strip()
    if lib61850_id:
        dev.iec61850.extra["lib61850_id"] = lib61850_id

    # Self-tests and "Relay Enabled"/"Relay Disabled" (status output)
    self_tests = info.pop("self_tests", None) or []
    relay_enabled = info.pop("relay_enabled", None)
    if self_tests or relay_enabled is not None:
        apply_self_tests(dev, self_tests, relay_enabled, observed)

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


def normalize_time_source(raw: str) -> str:
    """
    Normalize a SEL time source name to a :attr:`~peat.data.models.Clock.source` value.

    - ``IRIG``, ``IRIG-B``, ``HIRIG`` (high-accuracy IRIG) -> ``irig_b``
    - ``PTP`` -> ``ptp``, ``SNTP`` -> ``sntp``, ``Internal`` -> ``internal``
    - anything else is lowercased (spaces and dashes become underscores)
    """
    value = str(raw).strip().lower()
    if value.replace("-", "").replace("_", "").replace(" ", "") in ("irig", "irigb", "hirig"):
        return "irig_b"
    return re.sub(r"[\s\-]+", "_", value)


def _format_utc_offset(value: datetime) -> str:
    """UTC offset of an aware datetime as ``+HH:MM``."""
    offset = value.utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    hours, mins = divmod(abs(minutes), 60)
    return f"{sign}{hours:02d}:{mins:02d}"


def apply_device_time(
    dev: DeviceData, device_time: datetime | str, observed: datetime | None = None
) -> None:
    """
    Set ``dev.clock.time`` from a time read from the device.

    The time stays naive (device-local) unless the device reported its UTC offset
    (SEL-451 ``date``/``time``), in which case ``dev.clock.utc_offset`` is set too.

    Args:
        dev: Device to update
        device_time: Device time (a string is parsed)
        observed: PEAT's (aware) time when the device time was read. If
            :obj:`None`, the clock is only set if it's empty and no offset is computed.
    """
    if isinstance(device_time, str):
        device_time = utils.parse_date(device_time)
    if not isinstance(device_time, datetime):
        return

    if observed is not None:
        dev.clock.time = device_time
        dev.clock.observed = observed
        dev.clock.offset = None  # recomputed by Clock.annotate()
    elif dev.clock.time is None:
        dev.clock.time = device_time
    else:
        return

    if device_time.tzinfo is not None and device_time.utcoffset() is not None:
        dev.clock.utc_offset = _format_utc_offset(device_time)


_SELF_TEST_HEALTH = {
    "OK": "normal",
    "PASS": "normal",
    "PASSED": "normal",
    "FAIL": "failure",
    "FAILED": "failure",
    "FAILURE": "failure",
    "F": "failure",
    "WARN": "maintenance_required",
    "WARNING": "maintenance_required",
    "W": "maintenance_required",
}

_NUMBER_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
_RELAY_ENABLED_RE = re.compile(r"^\s*relay\s+(enabled|disabled)\b", re.IGNORECASE)


def _is_value_token(token: str) -> bool:
    return bool(_NUMBER_RE.match(token)) or token.upper() in _SELF_TEST_HEALTH


def parse_self_tests(lines: list[str]) -> dict:
    """
    Parse the self-test results and the enabled state from the output of the
    SEL ASCII ``STA`` command (or the ``sta`` web page).

    Self-tests follow a ``SELF TESTS`` line, as rows of column names followed by
    a row of values, optionally with a row label (``OS``, ``PS``). Values are
    numbers (offsets, voltages, temperature) or ``OK``/``W``/``WARN``/``F``/``FAIL``.
    ``Failures``/``Warnings`` lists (one failed item per line, ``No Failures``)
    are also handled.

    .. code-block:: text

       SELF TESTS (W=Warn, F=Fail)

                IA     IB     IC     IN
       OS       2      2      1      1

                TEMP   RAM   ROM   A/D   CR_RAM
                24.0   OK    OK    FAIL  OK

       Relay Enabled

    Returns:
        :class:`dict` with ``self_tests`` (list of ``{name, value, health}``,
        ``health`` is a NE 107 value or ``""`` for plain measurements) and
        ``relay_enabled`` (``True``/``False``, or :obj:`None` if not reported)
    """
    results = {"self_tests": [], "relay_enabled": None}
    if not lines:
        return results

    cleaned = [str(x).replace("\x02", "").replace("\x03", "").strip() for x in lines]

    for line in cleaned:
        match = _RELAY_ENABLED_RE.match(line)
        if match:
            results["relay_enabled"] = match.group(1).lower() == "enabled"

    start = next(
        (i + 1 for i, line in enumerate(cleaned) if re.match(r"^self[\s-]?tests?\b", line, re.I)),
        None,
    )
    if start is None:
        return results

    rows = [line for line in cleaned[start:] if not _RELAY_ENABLED_RE.match(line)]
    seen = set()

    def _add(name: str, value: str, health: str) -> None:
        if name and name not in seen:
            seen.add(name)
            results["self_tests"].append({"name": name, "value": value, "health": health})

    list_mode = ""  # "failure" or "maintenance_required" inside a Failures/Warnings list
    idx = 0
    while idx < len(rows):
        line = rows[idx]
        lower = line.lower()

        if lower in ("failures", "warnings"):
            list_mode = "failure" if lower == "failures" else "maintenance_required"
            idx += 1
            continue
        if not line or "=" in line:
            list_mode = ""
            idx += 1
            continue
        if list_mode:
            if not lower.startswith("no "):
                _add(line, "FAIL" if list_mode == "failure" else "WARN", list_mode)
            idx += 1
            continue

        header = line.split()
        nxt = rows[idx + 1].split() if idx + 1 < len(rows) else []
        if header and nxt and not any(_is_value_token(t) for t in header):
            label = ""
            values = nxt
            if len(nxt) == len(header) + 1 and not _is_value_token(nxt[0]):
                label, values = nxt[0], nxt[1:]
            if len(values) == len(header) and all(_is_value_token(v) for v in values):
                for column, value in zip(header, values, strict=True):
                    name = f"{label}_{column}" if label else column
                    _add(name, value, _SELF_TEST_HEALTH.get(value.upper(), ""))
                idx += 2
                continue
        idx += 1

    return results


def apply_self_tests(
    dev: DeviceData,
    self_tests: list[dict],
    relay_enabled: bool | None,
    timestamp: datetime | None = None,
) -> None:
    """
    Store self-test results from :func:`parse_self_tests` as
    :class:`~peat.data.models.Indicator` (``type="status_flag"``,
    ``category="self_test"``) and derive ``dev.health`` (NE 107):
    ``failure`` if any self-test failed, ``check_function`` if the relay is
    disabled, ``maintenance_required`` if a self-test warns, else ``normal``.
    """
    if timestamp is None:
        timestamp = utils.utc_now()

    for test in self_tests:
        dev.store(
            "indicators",
            Indicator(
                type="status_flag",
                category="self_test",
                name=test["name"],
                value=str(test.get("value", "")),
                health=test.get("health", ""),
                timestamp=timestamp,
            ),
        )

    if relay_enabled is not None:
        raw = "Relay Enabled" if relay_enabled else "Relay Disabled"
        dev.status = raw
        dev.store(
            "indicators",
            Indicator(
                type="status_flag",
                category="run",
                name="relay_enabled",
                state="on" if relay_enabled else "off",
                value=raw,
                health="normal" if relay_enabled else "check_function",
                timestamp=timestamp,
            ),
        )

    healths = {t.get("health", "") for t in self_tests}
    if "failure" in healths:
        dev.health = "failure"
    elif relay_enabled is False:
        dev.health = "check_function"
    elif "maintenance_required" in healths:
        dev.health = "maintenance_required"
    elif relay_enabled or "normal" in healths:
        dev.health = "normal"


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


# --------------------------------------------------------------------------- #
# ETH command / "eth" web page
# --------------------------------------------------------------------------- #
_ETH_COUNTER_NAMES = (
    "packets_sent",
    "packets_received",
    "bytes_sent",
    "bytes_received",
    "errors_sent",
    "errors_received",
)

# Model field path ("ingress.packets") of each ETH counter, for "overflowed"
_ETH_COUNTER_PATHS = {
    "packets_sent": "egress.packets",
    "packets_received": "ingress.packets",
    "bytes_sent": "egress.bytes",
    "bytes_received": "ingress.bytes",
    "errors_sent": "egress.errors",
    "errors_received": "ingress.errors",
}


def _safe_ipv4(value: str) -> str:
    """:func:`~peat.protocols.clean_ipv4`, returning ``""`` for invalid values."""
    try:
        return clean_ipv4(value.strip())
    except (ValueError, AttributeError):
        return ""


def _eth_value(name: str, text: str) -> str:
    """Value of a ``NAME: value`` line of the ETH output (``""`` if absent)."""
    match = re.search(
        rf"^\s*{name}\s*[:=]\s*(?:PORT\s+)?(\S+)", text, re.ASCII | re.IGNORECASE | re.MULTILINE
    )
    return match.group(1).strip() if match else ""


def _eth_speed(raw: str) -> int | None:
    """``"100M"`` -> ``100``, ``"1G"`` -> ``1000``, ``"---"`` -> :obj:`None` (Mbps)."""
    match = re.fullmatch(r"(\d+)\s*([MG])?(?:BPS)?", raw.strip().upper())
    if not match:
        return None
    value = int(match.group(1))
    return value * 1000 if match.group(2) == "G" else value


def parse_eth_output(text: str) -> dict:
    """
    Parse the output of the SEL ASCII ``ETH`` command (Ethernet port status and
    counters), which is also shown by the ``eth`` page of the relay web interface.

    .. code-block:: text

       MAC: 00-30-A7-00-00-01
       IP ADDRESS: 192.0.2.10/24
       DEFAULT GATEWAY: 192.0.2.1

       NETMODE: FAILOVER
       PRIMARY PORT: PORT 5A
       ACTIVE PORT: PORT 5A

                 LINK    SPEED   DUPLEX  MEDIA
       PORT 5A   UP      100M    FULL    TX
       PORT 5B   DOWN    ---     ---     FX

            PACKETS                 BYTES               ERRORS
          SENT     RCVD         SENT       RCVD      SENT    RCVD
       $$$$$$$  $$$$$$$   1463657022 1664082074         0       0

    A counter that exceeds its display width is shown as ``$`` characters by the
    relay (cleared with ``ETH C``). Such counters are returned as :obj:`None` and
    listed in ``statistics["overflowed"]``.

    Args:
        text: Raw text of the command output or web page

    Returns:
        :class:`dict` with the keys ``macs`` (list, the ``MAC``/``MAC 1`` value
        first), ``ip``, ``subnet_mask``, ``gateway``, ``network_mode``,
        ``primary_port``, ``active_port``, ``ports`` (``{port: {link, speed,
        duplex, media}}``) and ``statistics`` (counters + ``overflowed``).
        Empty values are omitted.
    """
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    text = text.replace("\r", "")
    result = {}

    # "MAC: 00-30-A7-..." or "MAC 1: ...", "MAC 2: ..." (SEL-451)
    macs = []
    for _, raw_mac in re.findall(
        r"^\s*MAC(\s*\d+)?\s*:\s*(\S+)", text, re.ASCII | re.IGNORECASE | re.MULTILINE
    ):
        mac = raw_mac.replace("-", ":").upper()
        if mac not in macs:
            macs.append(mac)
    if macs:
        result["macs"] = macs

    raw_ip = _eth_value("IP ADDRESS", text)
    if raw_ip and "/" in raw_ip:
        try:
            ip, mask = split_ipv4_cidr(raw_ip)
            result["ip"] = _safe_ipv4(ip)
            result["subnet_mask"] = mask
        except ValueError:
            log.warning(f"Invalid IP ADDRESS in ETH output: {raw_ip}")
    elif raw_ip:
        result["ip"] = _safe_ipv4(raw_ip)
    if not result.get("subnet_mask") and _eth_value("SUBNET MASK", text):
        result["subnet_mask"] = _safe_ipv4(_eth_value("SUBNET MASK", text))
    for key in ("ip", "subnet_mask"):
        if key in result and not result[key]:
            del result[key]

    for key, name in (
        ("gateway", "DEFAULT GATEWAY"),
        ("network_mode", "NETMODE"),
        ("primary_port", "PRIMARY PORT"),
        ("active_port", "ACTIVE PORT"),
    ):
        value = _eth_value(name, text)
        if value and value != "---":
            result[key] = _safe_ipv4(value) if key == "gateway" else value.upper()
            if not result[key]:
                del result[key]

    ports = {}
    for name, link, speed, duplex, media in re.findall(
        r"^\s*PORT\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$",
        text,
        re.ASCII | re.IGNORECASE | re.MULTILINE,
    ):
        if name.upper() in ("LINK", "STATUS") or name.endswith(":"):
            continue
        duplex = duplex.lower().replace("---", "")
        ports[name.upper()] = {
            "link": link.lower(),
            "speed": _eth_speed(speed),
            "duplex": duplex if duplex in ("half", "full", "auto") else "",
            "media": media.replace("---", ""),
        }
    if ports:
        result["ports"] = ports

    counters = re.search(
        r"^\s*(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)\s+(\d+|\$+)\s*$",
        text,
        re.ASCII | re.MULTILINE,
    )
    if counters:
        stats = {"overflowed": []}
        for name, raw in zip(_ETH_COUNTER_NAMES, counters.groups(), strict=True):
            if "$" in raw:
                stats[name] = None
                stats["overflowed"].append(name)
            else:
                stats[name] = int(raw)
        result["statistics"] = stats

    return result


def _ethernet_interface_name(dev: DeviceData, ip: str, ports: list[str]) -> str:
    """
    Name of the relay's Ethernet IP interface: the existing interface with this IP
    (created by :func:`process_port_settings`), else ``Port <n>`` from the
    physical port names (``5A``/``5B`` -> ``Port 5``), else ``Port 5``.
    """
    if ip:
        for iface in dev.interface:
            if iface.ip == ip and iface.name:
                return iface.name
    prefixes = {m.group() for m in (re.match(r"\d+", p) for p in ports) if m}
    if len(prefixes) == 1:
        return f"Port {prefixes.pop()}"
    for iface in dev.interface:
        if iface.type == "ethernet" and iface.ip and iface.name:
            return iface.name
    return "Port 5"


def apply_eth_output(eth: dict, dev: DeviceData, timestamp: datetime | None = None) -> None:
    """
    Put the data from :func:`parse_eth_output` into the data model.

    - counters -> :attr:`~peat.data.models.Interface.statistics` of the Ethernet IP
      interface (overflowed counters are :obj:`None`, listed in
      ``statistics.extra["overflowed"]``)
    - ``MAC``/``MAC 1`` -> IP interface ``mac``
    - physical ports (``5A``, ``5B``, ...) -> one physical
      :class:`~peat.data.models.Interface` each
    - ``NETMODE`` -> IP interface ``redundancy`` (``members`` = the ports);
      ``FAILOVER``: the active port is ``state="active"``, the others ``standby``;
      ``PRP``: every port is ``state="active"``

    Args:
        eth: Parsed ETH data
        dev: Device to update
        timestamp: When the counters were read (default: now)
    """
    if not eth:
        return
    if timestamp is None:
        timestamp = utils.utc_now()

    ports = list(eth.get("ports", {}))
    ip = eth.get("ip") or ""
    name = _ethernet_interface_name(dev, ip or dev.ip, ports)
    iface = Interface(name=name, type="ethernet")
    if ip:
        iface.ip = ip
    if eth.get("subnet_mask"):
        iface.subnet_mask = eth["subnet_mask"]
    if eth.get("gateway") and eth["gateway"] != "0.0.0.0":
        iface.gateway = eth["gateway"]

    macs = eth.get("macs", [])
    if macs:
        iface.mac = macs[0]
        if len(macs) > 1:
            iface.extra["mac_addresses"] = macs
        dev.related.mac.update(macs)

    stats = eth.get("statistics")
    if stats:
        iface.statistics = NetworkStatistics(
            timestamp=timestamp,
            ingress=NetworkTraffic(
                packets=stats.get("packets_received"),
                bytes=stats.get("bytes_received"),
                errors=stats.get("errors_received"),
            ),
            egress=NetworkTraffic(
                packets=stats.get("packets_sent"),
                bytes=stats.get("bytes_sent"),
                errors=stats.get("errors_sent"),
            ),
        )
        if stats.get("overflowed"):
            iface.statistics.extra["overflowed"] = sorted(
                _ETH_COUNTER_PATHS[c] for c in stats["overflowed"]
            )

    mode = eth.get("network_mode", "").upper()
    if mode:
        iface.redundancy = Redundancy(
            protocol="prp" if mode == "PRP" else "failover" if mode == "FAILOVER" else "",
            mode=mode.lower(),
            members=ports,
        )
        if eth.get("primary_port"):
            iface.redundancy.extra["primary_port"] = eth["primary_port"]

    dev.store("interface", iface, lookup="name")

    active = eth.get("active_port", "")
    for port, info in eth.get("ports", {}).items():
        port_iface = Interface(
            name=port,
            type="ethernet",
            physical=True,
            connected=info.get("link") == "up",
            speed=info.get("speed"),
            duplex=info.get("duplex", ""),
        )
        if info.get("media"):
            port_iface.description = Description(description=info["media"])
        if mode == "FAILOVER" and active:
            port_iface.redundancy = Redundancy(
                protocol="failover", state="active" if port == active else "standby"
            )
        elif mode == "PRP":
            # NOTE: SEL names the PRP ports "xA"/"xB", but the LAN A/B assignment
            # is not confirmed by documentation available to PEAT, so "lan" is
            # left empty.
            port_iface.redundancy = Redundancy(protocol="prp", state="active")
        dev.store("interface", port_iface, lookup="name")


def normalize_serial_protocol(proto: str) -> str:
    """
    Normalize a serial port ``PROTO`` setting to a canonical protocol name.

    - ``MB*`` (``MBA``, ``MBB``, ``MB8A``, ``MB8B``, ``MBT``, ...) -> ``mirrored_bits``
    - ``DNP`` -> ``dnp3``
    - ``MOD`` -> ``modbus_rtu``
    - ``SEL`` -> ``sel``
    - anything else is lowercased (e.g. ``LMD`` -> ``lmd``)
    """
    raw = proto.strip().upper()
    if raw.startswith("MB"):
        return "mirrored_bits"
    if raw in ("DNP", "DNP3"):
        return "dnp3"
    if raw in ("MOD", "MODBUS"):
        return "modbus_rtu"
    return raw.lower()


def _int_setting(settings: dict, *keys: str) -> int | None:
    """First of ``keys`` present in ``settings`` with an integer value."""
    for key in keys:
        value = str(_getv(settings.get(key, ""))).strip()
        if value.isdigit():
            return int(value)
    return None


def _str_setting(settings: dict, *keys: str) -> str:
    """First non-empty value of ``keys`` in ``settings``."""
    for key in keys:
        value = str(_getv(settings.get(key, ""))).strip()
        if value:
            return value
    return ""


def _float_setting(settings: dict, *keys: str) -> float | None:
    for key in keys:
        value = str(_getv(settings.get(key, ""))).strip()
        if value:
            try:
                return float(value)
            except ValueError:
                log.debug(f"Non-numeric value for setting {key}: {value}")
    return None


def _add_time_source(dev: DeviceData, source: TimeSource) -> None:
    """Add (or merge) a :class:`~peat.data.models.TimeSource` in ``dev.clock.sources``."""
    source.annotate(dev)
    for existing in dev.clock.sources:
        if (existing.protocol, existing.address, existing.port) == (
            source.protocol,
            source.address,
            source.port,
        ):
            merge_models(existing, source)
            return
    dev.clock.sources.append(source)


def _dnp3_relationships(
    settings: dict,
    svc: Service,
    iface: Interface,
    dev: DeviceData,
    sessions: int | None = None,
) -> list[Relationship]:
    """
    DNP3 master sessions (``DNPIP{n}``, ``DNPTR{n}``, ``REPADR{n}``, ...) ->
    one ``communicates_with`` relationship per configured master.

    ``sessions`` is the number of enabled DNP3 sessions when ``EDNP`` is a
    session count (SEL-751/351 class relays, ``0-5``/``0-6``): sessions above
    the count are configured but disabled.

    Several sessions with one master IP address are one edge
    (:meth:`~peat.data.models.Relationship.key`): they are combined into one
    relationship (enabled if any session is) with the settings of each session in
    ``extra["sessions"]`` (incl. ``remote_protocol_address``, ``transport`` and
    ``enabled``).
    """
    relationships = []

    for idx in range(1, 7):
        # "IP Address (zzz.yyy.xxx.www)"
        ip = _safe_ipv4(_str_setting(settings, f"DNPIP{idx}"))
        if not ip or ip == "0.0.0.0":
            continue

        extra = {"station_num": idx}

        # "UDP Response Port (REQ, 1025-65534)"
        udp_port = _str_setting(settings, f"DNPUDP{idx}")
        if udp_port.isdigit():
            extra["udp_response_port"] = int(udp_port)
            dev.related.ports.add(int(udp_port))
        elif udp_port:
            extra["udp_response_port"] = udp_port

        # "DNP Session Map (1-5)"
        if _str_setting(settings, f"DNPMAP{idx}"):
            extra["session_map"] = _str_setting(settings, f"DNPMAP{idx}")

        # "Seconds to Send Data Link Heartbeat (0-7200)"
        heartbeat = _int_setting(settings, f"DNPINA{idx}")
        if heartbeat is not None:
            extra["heartbeat_timeout"] = heartbeat

        # "Enable Control Operations (Y,N)"
        if _str_setting(settings, f"DNPCL{idx}"):
            extra["control_operations_enabled"] = value_is_enabled(
                _str_setting(settings, f"DNPCL{idx}")
            )

        if _str_setting(settings, f"DNPID{idx}"):
            extra["dnp3_id"] = _str_setting(settings, f"DNPID{idx}")

        relationships.append(
            Relationship(
                type="communicates_with",
                protocol="dnp3",
                # "Transport Protocol (UDP,TCP)"
                transport=_str_setting(settings, f"DNPTR{idx}").lower(),
                direction="ingress",
                local=RelationshipEndpoint(
                    interface=iface.name,
                    port=svc.port,
                    role="outstation",
                    protocol_address=svc.protocol_id,
                ),
                remote=RelationshipEndpoint(
                    ip=ip,
                    role="master",
                    # "DNP Address to Report to (0-65519)"
                    protocol_address=_str_setting(settings, f"REPADR{idx}"),
                ),
                enabled=(
                    idx <= sessions
                    if sessions is not None
                    else (svc.enabled if svc.enabled is not None else True)
                ),
                evidence={"config"},
                extra=extra,
            )
        )

    by_master = {}  # type: dict[str, list[Relationship]]
    for rel in relationships:
        by_master.setdefault(rel.remote.ip, []).append(rel)

    combined = []
    for rels in by_master.values():
        rel = rels[0]
        if len(rels) > 1:
            rel.extra = {
                "sessions": [
                    {
                        **r.extra,
                        "remote_protocol_address": r.remote.protocol_address,
                        "transport": r.transport,
                        "enabled": r.enabled,
                    }
                    for r in rels
                ]
            }
            rel.enabled = any(r.enabled for r in rels)
            if len({r.remote.protocol_address for r in rels}) > 1:
                rel.remote.protocol_address = ""
            if len({r.transport for r in rels}) > 1:
                rel.transport = ""
        combined.append(rel)

    return combined


def _modbus_relationships(settings: dict, svc: Service, iface: Interface) -> list[Relationship]:
    """Allowed Modbus TCP clients (``MODIP1``-``MODIP3``) -> relationships."""
    relationships = []

    for idx in range(1, 4):
        ip = _safe_ipv4(_str_setting(settings, f"MODIP{idx}"))
        if not ip or ip == "0.0.0.0":
            continue

        extra = {"allow_list": True, "endpoint_num": idx}
        timeout = _float_setting(settings, f"MTIMEO{idx}")
        if timeout is not None:
            extra["timeout"] = timeout

        relationships.append(
            Relationship(
                type="communicates_with",
                protocol="modbus_tcp",
                transport="tcp",
                direction="ingress",
                local=RelationshipEndpoint(interface=iface.name, port=svc.port, role="server"),
                remote=RelationshipEndpoint(ip=ip, role="client"),
                enabled=svc.enabled,
                evidence={"config"},
                extra=extra,
            )
        )

    return relationships


def _c37_118_relationships(
    settings: dict, svc: Service, iface: Interface, dev: DeviceData
) -> list[Relationship]:
    """
    IEEE C37.118 synchrophasor outputs (``PMOTS{n}``, ``PMOIPA{n}``, ...) -> relationships.

    Transport schemes: ``TCP`` (the PDC connects to the relay), ``UDP_S`` (data
    and commands over UDP), ``UDP_T``/``UDP_U`` (UDP data plus a PDC-initiated TCP
    command channel). Reference: "Ethernet Operation" in SEL documentation.
    """
    relationships = []

    for idx in range(1, 2):
        scheme = _str_setting(settings, f"PMOTS{idx}").upper()
        ip = _safe_ipv4(_str_setting(settings, f"PMOIPA{idx}"))
        if not ip:
            continue

        tcp_port = _int_setting(settings, f"PMOTCP{idx}")
        udp_port = _int_setting(settings, f"PMOUDP{idx}")
        extra = {"transport_scheme": scheme, "endpoint_num": idx}

        rel = Relationship(
            type="communicates_with",
            protocol="c37_118",
            local=RelationshipEndpoint(interface=iface.name, role="pmu"),
            remote=RelationshipEndpoint(ip=ip, role="pdc"),
            enabled=bool(scheme and scheme != "OFF") and svc.enabled is not False,
            evidence={"config"},
            extra=extra,
        )

        if scheme == "TCP":
            rel.transport = "tcp"
            rel.direction = "ingress"
            rel.local.port = tcp_port
        elif scheme.startswith("UDP"):
            rel.transport = "udp"
            rel.direction = "egress"
            rel.remote.port = udp_port
            if tcp_port is not None:
                extra["tcp_local_port"] = tcp_port
        else:
            if tcp_port is not None:
                extra["tcp_local_port"] = tcp_port
            if udp_port is not None:
                extra["udp_remote_port"] = udp_port

        for port in (tcp_port, udp_port):
            if port:
                dev.related.ports.add(port)

        relationships.append(rel)

    return relationships


def apply_mac_output(macs: dict[str, str], dev: DeviceData) -> None:
    """
    Put the output of the ``MAC`` command (:meth:`SELAscii.show_mac`) into the
    data model: ``ip_mac`` -> ``mac`` of the Ethernet IP interface; ``goose_mac``
    (the relay's unicast GOOSE source MAC) -> ``dev.iec61850.extra["goose_source_mac"]``.
    Both are added to ``related.mac``.
    """
    ip_mac = macs.get("ip_mac", "")
    goose_mac = macs.get("goose_mac", "")

    if ip_mac:
        name = ""
        for iface in dev.interface:
            if iface.type == "ethernet" and iface.ip and (not dev.ip or iface.ip == dev.ip):
                name = iface.name
                break
        iface = Interface(type="ethernet", name=name, mac=ip_mac)
        if not name and dev.ip:
            iface.ip = dev.ip
        dev.store("interface", iface, lookup="name" if name else None)
        dev.related.mac.add(ip_mac)

    if goose_mac:
        dev.iec61850.extra["goose_source_mac"] = goose_mac
        # Unicast source MAC of the relay's GOOSE frames (pcap/Zeek key on it)
        dev.related.mac.add(goose_mac)


def process_port_settings(
    port_id: Literal["1", "2", "3", "4", "5", "F"],
    settings: dict[str, dict | str],
    dev: DeviceData,
) -> None:
    """
    Process parsed port settings into the device data model.

    - Ethernet ports (``IPADDR``) -> :class:`~peat.data.models.Interface` with the
      IP settings; serial ports -> serial interface (``application`` = normalized
      ``PROTO``; ``type`` is ``serial``, ``rs_232`` for the front port ``F``, or
      from ``COMMINF``)
    - ``E<service>`` settings -> :class:`~peat.data.models.Service` (``mms``,
      ``goose``, ``dnp3``, ``modbus_tcp``, ``sntp``, ``c37_118``, ...), with
      ``configured_port`` set wherever the port comes from a setting
    - DNP3 masters, allowed Modbus TCP clients and C37.118 PDCs ->
      :class:`~peat.data.models.Relationship` (``evidence={"config"}``)
    - SNTP servers -> ``dev.clock.sources``
    - MIRRORED BITS serial ports -> ``physical_link`` relationships
    """
    log.trace(f"Processing port settings for port {port_id} from {dev.get_id()}")

    iface = Interface(
        name=f"Port {port_id}",
    )
    relationships = []  # type: list[Relationship]

    if "EPORT" in settings:
        iface.enabled = value_is_enabled(_getv(settings["EPORT"]))

    if "IPADDR" in settings:
        # Ethernet interfaces
        merge_models(iface, parse_ipaddr(settings))
    else:
        # Serial interfaces
        # Generally, these are are port 1-3 and port F
        if settings.get("PROTO"):
            iface.application = normalize_serial_protocol(_getv(settings["PROTO"]))
        elif "PROTO" not in settings and port_id == "F":
            iface.application = "sel"

        if settings.get("SPEED"):
            speed = _getv(settings["SPEED"])

            # Possible value for SPEED may be "SYNC" on some models,
            # according to SEL documentation
            if speed.upper() != "SYNC":
                iface.baudrate = int(speed)

            iface.type = "serial"

        # The electrical standard is only known for the front port (always
        # EIA-232) or from an explicit communications interface setting.
        comm_inf = _str_setting(settings, "COMMINF")
        if "232" in comm_inf:
            iface.type = "rs_232"
        elif "485" in comm_inf:
            iface.type = "rs_485"
        elif "422" in comm_inf:
            iface.type = "rs_422"
        elif port_id == "F":
            iface.type = "rs_232"

        if "BITS" in settings:
            iface.data_bits = int(_getv(settings["BITS"]))
        elif "DATABIT" in settings:  # 411L, 487E, some 451's
            iface.data_bits = int(_getv(settings["DATABIT"]))

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
            iface.stop_bits = int(_getv(settings["STOP"]))
        elif "STOPBIT" in settings:
            # 451, 411L, and others
            iface.stop_bits = int(_getv(settings["STOPBIT"]))

        if "RTSCTS" in settings and value_is_enabled(_getv(settings["RTSCTS"])):
            iface.flow_control = "rts/cts"
        elif settings.get("SPEED"):
            iface.flow_control = "none"

        if "T_OUT" in settings:
            iface.extra["inactivity_timeout"] = float(_getv(settings["T_OUT"]))

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

        # MIRRORED BITS: relay-to-relay protection link on this serial port
        if iface.application == "mirrored_bits":
            mb_extra = {}
            for key, name in (("TXID", "tx_id"), ("RXID", "rx_id")):
                if _str_setting(settings, key):
                    mb_extra[name] = _str_setting(settings, key)
            relationships.append(
                Relationship(
                    type="physical_link",
                    protocol="mirrored_bits",
                    local=RelationshipEndpoint(
                        interface=iface.name, serial_port=iface.name, role="peer"
                    ),
                    remote=RelationshipEndpoint(role="peer"),
                    enabled=iface.enabled,
                    evidence={"config"},
                    extra=mb_extra,
                )
            )

    # Service configurations
    services = []

    if settings.get("FTPUSER") or settings.get("FTPSERV"):
        ftp_svc = Service(protocol="ftp", transport="tcp", port=21)

        if settings.get("FTPSERV"):
            ftp_svc.enabled = value_is_enabled(_getv(settings["FTPSERV"]))
        elif settings.get("EFTPSERV"):
            ftp_svc.enabled = value_is_enabled(_getv(settings["EFTPSERV"]))

        if settings.get("FTPIDLE"):
            ftp_svc.extra["idle_timeout"] = float(_getv(settings["FTPIDLE"]))

        if settings.get("FTPUSER"):
            ftp_svc.extra["user"] = _getv(settings["FTPUSER"])
            dev.related.user.add(_getv(settings["FTPUSER"]))

        if settings.get("FTPANMS"):
            anon_login_enabled = value_is_enabled(_getv(settings["FTPANMS"]))
            ftp_svc.security = ServiceSecurity(anonymous_access=anon_login_enabled)
            if anon_login_enabled:
                ftp_svc.security.authentication_required = False

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
        if not settings.get(f"E{svc_name}"):
            continue

        raw_enable = str(_getv(settings[f"E{svc_name}"])).strip()
        protocol = {
            "GSE": "goose",  # IEC 61850 GOOSE (EGSE)
            "61850": "mms",  # IEC 61850 MMS server (E61850)
            "DNP": "dnp3",
            "PMIP": "c37_118",
        }.get(svc_name, svc_name.lower())

        svc = Service(protocol=protocol, enabled=value_is_enabled(raw_enable))

        if protocol == "mms":
            svc.transport = "tcp"
            svc.port = 102

        elif protocol == "http":
            svc.transport = "tcp"

            svc.port = _int_setting(settings, "HTTPPOR", "HTTPPORT")
            svc.configured_port = svc.port

            if settings.get("HIDLE"):
                svc.extra = {"idle_timeout": float(_getv(settings["HIDLE"]))}
            elif settings.get("HTTPIDLE"):
                svc.extra = {"idle_timeout": float(_getv(settings["HTTPIDLE"]))}

        elif protocol == "telnet":
            svc.transport = "tcp"

            # 311L: "TPORTC" is the "Telnet Port for Card Access"
            svc.port = _int_setting(settings, "TPORT", "TPORTC")
            svc.configured_port = svc.port

            if settings.get("TIDLE"):
                svc.extra["idle_timeout"] = float(_getv(settings["TIDLE"]))

        elif protocol == "sntp":
            svc.transport = "udp"

            # ESNTP is OFF, UNICAST, MANYCAST or BROADCAST
            sntp_mode = raw_enable.lower()
            svc.enabled = sntp_mode not in ("off", "n", "no", "0", "")

            svc.port = _int_setting(settings, "SNTPPORT", "SNTPPOR")
            svc.configured_port = svc.port

            ts_extra = {}
            if sntp_mode in ("unicast", "manycast", "broadcast"):
                ts_extra["mode"] = sntp_mode
            poll_rate = _int_setting(settings, "SNTPRATE", "SNTPRAT")
            if poll_rate is not None:
                ts_extra["poll_rate"] = poll_rate
            timeout = _float_setting(settings, "SNTPTO")
            if timeout is not None:
                ts_extra["timeout"] = timeout

            sources = []
            for priority, keys in ((1, ("SNTPPSIP", "SNTPPIP")), (2, ("SNTPBSIP", "SNTPBIP"))):
                address = _safe_ipv4(_str_setting(settings, *keys))
                if address and address != "0.0.0.0":
                    sources.append(
                        TimeSource(
                            protocol="sntp",
                            address=address,
                            priority=priority,
                            enabled=svc.enabled,
                            extra=dict(ts_extra),
                        )
                    )
                    dev.related.ip.add(address)

            for source in sources:
                _add_time_source(dev, source)

            # Broadcast mode has no server addresses: keep the settings
            if not sources and ts_extra:
                dev.clock.extra.update({f"sntp_{k}": v for k, v in ts_extra.items()})

        elif protocol == "dnp3":
            svc.port = _int_setting(settings, "DNPNUM", "DNPPNUM")
            svc.configured_port = svc.port
            if settings.get("DNPADR"):
                svc.protocol_id = _getv(settings["DNPADR"])
            if settings.get("DNPID"):
                # "DNP ID for Object 0, Var 246 (20 characters)"
                svc.extra["dnp3_id"] = _getv(settings["DNPID"])
            if settings.get("DNPMAP"):
                svc.extra["session_map"] = _getv(settings["DNPMAP"])

            # "Enable DNP Sessions (0-5)": EDNP is a session count on some relays
            sessions = None
            if raw_enable.isdigit():
                sessions = int(raw_enable)
                svc.enabled = sessions > 0
                svc.extra["sessions"] = sessions

            relationships.extend(_dnp3_relationships(settings, svc, iface, dev, sessions))

        elif protocol == "modbus":
            if iface.type == "ethernet":
                svc.protocol = "modbus_tcp"
                svc.transport = "tcp"
                svc.port = 502
                relationships.extend(_modbus_relationships(settings, svc, iface))

        elif protocol == "c37_118":
            # C37.118 is TCP (port 4712) or UDP (port 4713)
            # Reference: https://wiki.wireshark.org/IEEE%20C37.118
            relationships.extend(_c37_118_relationships(settings, svc, iface, dev))

        services.append(svc)

    # Store interface in the data model, followed by the services
    dev.store("interface", iface)

    for service in services:
        if service.port:
            dev.related.ports.add(service.port)

        if service.protocol:
            dev.related.protocols.add(service.protocol)

        dev.store("service", service, interface_lookup={"name": iface.name})

    for rel in relationships:
        dev.store("relationships", rel)


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

            id_val = settings[ident]["value"]

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
        if not config[0] == "M" or not re.match(r"^M\d?$", config, re.ASCII):
            continue

        # TODO: [M1] is "monitoring and metering" on SEL-487E
        if dev.description.model == "487E" and config[1].isdigit():
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
        # DNPA, DNPB, D1, D2, D3, etc.
        if not config[0] == "D" or (not config[1].isdigit() and not config.startswith("DNP")):
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

            value = settings[logic_key]["value"]

            # NOTE: close logic used to compare value != 0, which
            # was never valid (at least for a while) since the values
            # are always strings after getting parsed out of the config.
            if logic_type == "TRIP_LOGIC" or value != "0":
                logic[section][logic_key] = value

        if not logic[section]:  # Delete groups that have no logic
            logic.pop(section)

    return logic


def extract_fid(data: bytes | str) -> str:
    return extract_string(data, r"FID\s?=\s?(SEL[\w\-]+)\s")


def extract_bfid(data: bytes | str) -> str:
    return extract_string(data, r"BFID\s?=\s?([\w\-]+)\s")


def extract_cid(data: bytes | str) -> str:
    return extract_string(data, r"CID\s?=\s?(\w+)\s")


def extract_part_number(data: bytes | str) -> str:
    return extract_string(data, r"part\s?(?:number|num):?\s+(\w+)\s", flags=re.IGNORECASE)


def extract_serial_number(data: bytes | str) -> str:
    return extract_string(data, r"serial\s?(?:number|num):?\s+(\w+)\s", flags=re.IGNORECASE)


def extract_selboot_checksum(data: bytes | str) -> str:
    return extract_string(
        data, r"selboot:?\s.*checksum:?\s+(\d+)\s", flags=re.IGNORECASE | re.DOTALL
    )


def extract_string(data: bytes | str, regex: str, flags=None) -> str:
    """
    Extract a string from arbitrary data.
    """
    if isinstance(data, bytes):
        data = data.decode("ascii")

    re_flags = re.ASCII
    if flags:
        re_flags |= flags

    result = re.search(regex, data, re_flags)

    if result is not None:
        return result.groups()[0]

    return ""


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
    if "XXXXX" in release_date:
        release_datetime = None
    else:
        release_datetime = utils.parse_date(release_date)
    settings_version = sfid.pop()  # Z100100
    version = sfid.pop()  # V0
    revision = sfid.pop()  # R200

    info = {
        "id": id_string,
        "version": version,
        "revision": revision,
        "settings_version": settings_version,
        "release_date": release_datetime,
    }

    if sfid[0] == "SEL":
        info["model"] = sfid[1]  # "351"
        info["product"] = "-".join(sfid)  # "SEL-351-5"

    return info


def parse_status_output(lines: list[str]) -> dict:
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
    - ``time_source``: Time source (``"Internal"``, ``"IRIG-B"``, ...)
    - ``self_tests``: Self-test results (see :func:`parse_self_tests`),
      including temperature and power supply voltages where reported
    - ``relay_enabled``: ``True`` for "Relay Enabled", ``False`` for "Relay Disabled"

    Args:
        lines: Extracted status info lines

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
        info["device_time"] = date_parse(f"{id_time['date']} {id_time['time']}")
    else:
        log.debug(f"Failed to match 'sta' output for line {repr(lines[0])}")

    if "Time Source" in lines[1]:
        # "GENERATOR RELAY                          Time Source: Internal"
        name_ts = re.search(
            r"(?P<dev_name>[\w\-. ]+)\s+Time Source: (?P<time_source>[\w\-]+)",
            lines[1],
            re.ASCII,
        )

        if name_ts:
            info["device_name"] = name_ts["dev_name"].strip()
            info["time_source"] = name_ts["time_source"].strip()
    else:
        # "STATION A"
        info["device_name"] = lines[1].strip()

    # Self-tests and "Relay Enabled"/"Relay Disabled"
    self_test_info = parse_self_tests(lines)
    if self_test_info["self_tests"]:
        info["self_tests"] = self_test_info["self_tests"]
    if self_test_info["relay_enabled"] is not None:
        info["relay_enabled"] = self_test_info["relay_enabled"]

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

    return info


def parse_ver_output(data: str) -> dict[str, str]:
    data = data.strip()

    results = {
        "FID": extract_fid(data),
        "BFID": extract_bfid(data),
        "CID": extract_cid(data),
        "part_number": extract_part_number(data),
        "serial_number": extract_serial_number(data),
    }

    # ldata = data.lower()
    # # 311L
    # if ldata.startswith("partnumber") or ldata.startswith("part number"):
    #     flash_size = extract_string

    # # 451 and 351S?
    # else:
    #     pass

    if not any(results.values()):
        log.warning("Failed to parse any data from 'ver' output")
        return {}

    return results


def event_data_present(data: bytes | str) -> bool:
    if isinstance(data, bytes):
        data = data.decode("ascii")

    data = data.lower().strip()

    if not data or "data available" in data or "history buffer empty" in data:
        return False
    else:
        return True


def parse_and_process_events(
    data: bytes | str, dataset: str, dev: DeviceData, observed: datetime | None = None
) -> tuple[list[dict], dict]:
    """
    Parse SER/CSER/HISTORY/CHISTORY data and store the events in ``dev``.

    Args:
        data: Raw data
        dataset: Name of the source (file name or command), selects the parser
        dev: Device to update
        observed: When the data was read live from the device (for the status
            front matter, see :func:`process_info_into_dev`)
    """
    log.info(f"Parsing events in {dataset} from {dev.get_id()}")

    if isinstance(data, bytes):
        data = data.decode("ascii")

    # TODO: error state should be better propagated to callers,
    # e.g. the caller should be able to differentiate between
    # no events returned because there are no events vs.
    # no events returned because a parsing error occurred.

    raw_lines = split_lines(data)  # type: list[str]

    if not raw_lines:
        return [], {}

    if not event_data_present(raw_lines[0]):
        log.debug(f"No event data present for {dataset}")
        return [], {}

    info = {}

    try:
        if "cser" in dataset.lower():
            events, info = parse_cser(raw_lines)
        elif "ser" in dataset.lower():
            events, info = parse_ser(raw_lines)
        elif "chistory" in dataset.lower():
            events, info = parse_chistory(raw_lines)
        elif "history" in dataset.lower() or dataset.lower() == "his":
            events, info = parse_history(raw_lines)
        else:
            log.error(f"Invalid SER/HISTORY filename: {dataset}")
            state.error = True
            return [], info
    except Exception:
        log.exception(f"Failed to parse events in {dataset} from {dev.get_id()}")
        state.error = True
        return [], info

    if info:
        process_info_into_dev(info, dev, observed)

    if not events:
        log.warning(f"No events in {dataset} from {dev.get_id()}")
        return [], info

    process_events(events, dev, dataset=dataset)

    log.info(f"Extracted {len(events)} events from {dataset} from {dev.get_id()}")

    return events, info


def parse_ser(raw_lines: list[str]) -> tuple[list[dict], dict]:
    """
    Parse output of ``SER.TXT``, the ``ser`` command, or the ``ser`` web page.

    Examples of SER data:

    - SER.TXT pulled via FTP or Telnet
    - Output from 'ser' command (via Telnet or serial)
    - "ser" page in the web interface

    Returns:
        Events and status info. Events will be empty if there are no events.
        Status info will be empty if no front matter was present.
    """

    try:
        # Find the header line for the actual events
        header_index = next(
            idx for idx, line in enumerate(raw_lines) if "#" in line and "date" in line.lower()
        )
    except StopIteration:
        log.warning("No events found in SER output, attempting to parse status info")
        return [], parse_status_output(raw_lines)

    status_info = {}

    # Process the status information front matter
    if header_index != 0 and "SEL-2032" not in raw_lines[0]:
        status_info = parse_status_output(raw_lines[:header_index])

    # Filter to just the lines with the events
    event_lines = raw_lines[header_index + 1 :]
    events = []

    for line in event_lines:
        if line and line[0].isdigit():
            # line spacing may be 1 character or two, but event values
            # can also have single spaces, e.g. "Relay Powered Up".
            # To handle this, we use a regex...
            #
            # 1024 12/09/2020  18:08:43.048    SALARM                       Deasserted
            # 213  01/15/2021  17:09:45.504    Relay Powered Up
            # 214  01/13/2021  10:17:40.740    SALARM                       Deasserted
            result = re.match(
                (
                    r"(?P<seq>\d+)\s+"
                    r"(?P<date>\S+)\s+"
                    r"(?P<time>\S+)\s+"
                    r"(?P<element>(?:\w| \w)+)\s*"
                    r"(?P<state>(?:\w| \w)+)?"
                ),
                line,
                re.ASCII | re.IGNORECASE,
            )

            if not result:
                log.warning(
                    f"Failed to parse SER events due to unexpected format.\nRaw line: '{line}'"
                )
                return [], status_info

            values = result.groupdict()

            event = {
                "sequence": int(values["seq"]),
                "date": values["date"],
                "time": values["time"],
                "original": line,
                "element": values["element"],
                "state": "" if not values.get("state") else values["state"],
            }

            events.append(event)

    return events, status_info


# TODO: combine duplicate logic between parse_history(), parse_ser_events(),
#   and sel_http.SELHTTP.get_historical_events()
def parse_history(raw_lines: list[str]) -> tuple[list[dict], dict]:
    """
    Parse output of ``HISTORY.TXT``.

    Returns:
        Events and status info. Events will be empty if there are no events.
        Status info will be empty if no front matter was present.
    """
    # Find the header line for the actual events
    try:
        header_index = next(
            idx for idx, line in enumerate(raw_lines) if "#" in line and "date" in line.lower()
        )
    except StopIteration:
        log.warning("No events found in HISTORY output, attempting to parse status info")
        return [], parse_status_output(raw_lines)

    status_info = {}

    # Process the status information front matter
    if header_index != 0:
        status_info = parse_status_output(raw_lines[:header_index])

    # Filter to just the lines with the events
    event_lines = raw_lines[header_index + 1 :]
    events = []

    # TODO: parse 351 history format
    # "#     DATE      TIME     EVENT   LOCAT  CURR  FREQ GRP SHOT TARGETS"

    for line in event_lines:
        if line and line[0].isdigit():
            result = re.match(
                (
                    r"(?P<num>\d+)\s+"
                    r"(?P<ref>\S+)\s+"
                    r"(?P<date>\S+)\s+"
                    r"(?P<time>\S+)\s+"
                    r"(?P<event>(?:\w| \w)+)\s+"
                    r"(?P<current>[\d\.]+)\s+"
                    r"(?P<freqx>[\d\.]+)\s+"
                    r"(?P<targets>[\w\d\.]+)\s*"
                ),
                line,
                re.ASCII | re.IGNORECASE,
            )

            if not result:
                log.warning(
                    f"Failed to parse HISTORY events due to unexpected format.\nRaw line: {line}"
                )
                return [], status_info

            values = result.groupdict()

            event = {
                "sequence": int(values["ref"]),
                "date": values["date"],
                "time": values["time"],
                "original": line,
                "event": values["event"],  # "Trip"
                "current": float(values["current"]),  # 1.00
                "frequency": float(values["freqx"]),  # 60.0
                "targets": values["targets"],  # "11000000"
            }

            events.append(event)

    return events, status_info


def extract_csv_dicts(lines: list[str]) -> tuple[dict[str, str], list[dict[str, str]]]:
    header = next(iter(csv.DictReader(lines[:2])))
    device_info = {
        "serial_number": header.get("SERIAL NO", ""),
        "FID": header.get("FID", "").split("=")[-1],
        "CID": header.get("CID", ""),
    }

    rows = list(csv.DictReader(lines[2:]))

    return device_info, rows


def parse_cser(lines: list[str]) -> tuple[list[dict], dict]:
    """
    Extract and parse events and device info from ``CSER.TXT``.

    Returns:
        Events and device info (FID, CID, and serial number).
    """
    device_info, rows = extract_csv_dicts(lines)

    events = []
    last_key = list(rows[0].keys())[-1]  # "0A31"

    for row, line in zip(rows, lines[3:], strict=False):
        event = {
            "sequence": int(row["REC_NUM"]),
            "date": row["DATE"],
            "time": row["TIME"],
            "original": line,
            "element": row["ELEMENT"],
        }

        # Handle special lines, like "Relay Powered Up"
        if not row[last_key]:
            row[last_key] = row["STATE"]
            row["STATE"] = ""
        event["state"] = row["STATE"]

        events.append(event)

    return events, device_info


def parse_chistory(lines: list[str]) -> tuple[list[dict], dict]:
    """
    Extract and parse events and device info from ``CHISTORY.TXT``.

    Returns:
        Events and device info (just the FID generally with CHISTORY).
    """
    device_info, rows = extract_csv_dicts(lines)

    events = []

    for row, line in zip(rows, lines[3:], strict=False):
        date = f"{row['MONTH']}/{row['DAY']}/{row['YEAR']}"
        time = f"{row['HOUR']}:{row['MIN']}:{row['SEC']}.{row['MSEC']}"

        event = {
            # NOTE: for CHISTORY, "REC_NUM" is just it's order in the file
            # The actual sequence number is REF_NUM (REF, not REC, easy to miss)
            "sequence": int(row["REF_NUM"]),
            "date": date,
            "time": time,
            "original": line,
            "event": row["EVENT"],  # "Trip"
            "current": float(row["CURRENT"]),  # 1.00
            "frequency": float(row["FREQX"]),  # 60.0
            "targets": row["TARGETS"],  # "11000000"
        }

        events.append(event)

    return events, device_info


def ansi_meaning(element: str) -> str:
    """
    Meaning of a relay element name from its ANSI/IEEE C37.2 device function
    number, e.g. ``"51G"`` -> ``"AC Time Overcurrent Relay"``.

    Returns:
        The meaning, or ``""`` if the element doesn't start with a known code
    """
    element = element.strip().upper()
    match = re.match(r"^(\d+)([A-Z]*)", element)
    if not match:
        return ""
    for candidate in (element, f"{match.group(1)}{match.group(2)}", match.group(1)):
        if candidate in ANSI_CODES:
            return ANSI_CODES[candidate]
    return ""


def history_event_details(event_value: str, targets: Any = "") -> tuple[str, str, set[str]]:
    """
    ``action``, ``reason`` and ``kind`` of an event from the relay history
    (``HIS`` command, ``HISTORY.TXT``, ``CHISTORY.TXT``, ``his`` web page).

    A trip (``EVENT`` contains ``trip``) is ``action="trip"`` with ``kind={"alert"}``;
    the reason is the ``EVENT`` column (fault type) and the asserted targets, e.g.
    ``"AG T; targets 11000000"``.
    """
    event_value = str(event_value).strip()
    targets = str(targets).strip() if targets not in (None, "") else ""
    reason = event_value
    if targets:
        reason = f"{event_value}; targets {targets}" if event_value else f"targets {targets}"
    if "trip" in event_value.lower():
        return "trip", reason, {"alert"}
    return event_value.lower(), reason, {"event"}


def process_events(raw_events: list[dict], dev: DeviceData, dataset: str) -> None:
    """
    Process events into the data model.

    ``event.reason`` is set for history rows (fault type and targets), settings
    and group changes (the new state, e.g. ``Class P 5``) and asserted/deasserted
    protection elements with a known ANSI device number (e.g.
    ``51G AC Time Overcurrent Relay``).

    Args:
        raw_events: list of events extracted from an event file
            (SER, CSER, HISTORY, CHISTORY)
        dev: device object to add events to
        dataset: Dataset of the events, e.g. ``ser``, ``CSER.TXT``, ``HISTORY.TXT``
    """
    for raw_event in raw_events:
        event_category = {"host"}  # type: set[str]
        event_type = set()  # type: set[str]
        event_kind = {"event"}  # type: set[str]
        reason = ""
        extra = {}

        # SER/CSER
        if raw_event.get("element"):
            # Examples of element values:
            # 'Relay', 'Power-up', 'Settings changed', '51G', 'OUT101', 'Group change'
            event_element = raw_event["element"].lower()  # type: str

            if "change" in event_element:
                event_category.add("configuration")
                event_type.add("change")
                # "Settings changed" / "Class P 5", "Group change" / "Group 2"
                if raw_event.get("state"):
                    reason = raw_event["state"].strip()
            elif "power" in event_element and "up" in event_element:
                event_type.add("start")
            elif "archive cleared" in event_element:
                # "SER archive cleared"
                event_category.update({"database", "file"})
                event_type.update({"change", "deletion"})

            action = event_element.replace(" ", "-")  # type: str

            # Examples of event state:
            # 'Enabled', 'Group 1', 'Class P 5', 'Asserted', 'Deasserted'
            event_state = raw_event["state"].lower()
            if "assert" in event_state:
                event_type.add("change")
                action = f"{event_state}-{event_element}"
                meaning = ansi_meaning(raw_event["element"])
                if meaning:
                    reason = f"{raw_event['element'].strip()} {meaning}"

            if raw_event["element"] and raw_event["state"]:
                message = f"{raw_event['element']} {raw_event['state']}"
            else:
                message = raw_event["element"]

        # HISTORY/CHISTORY
        elif raw_event.get("event"):
            action, reason, event_kind = history_event_details(
                raw_event["event"], raw_event.get("targets", "")
            )

            if action == "trip":
                event_type.add("change")
                message = (
                    f"{raw_event['event']} {raw_event['targets']} "
                    f"(Current: {raw_event['current']} - "
                    f"Frequency: {raw_event['frequency']})"
                )
            else:
                message = raw_event["event"]

            extra["current"] = raw_event["current"]
            extra["frequency"] = raw_event["frequency"]
            extra["targets"] = raw_event["targets"]

        else:
            log.error("Invalid events")
            return

        event = Event(
            action=action,
            category=event_category,
            # date: "09/13/2022" (Month/Day/Year)
            # time: "16:09:12.264"
            created=date_parse(f"{raw_event['date']} {raw_event['time']}"),
            dataset=dataset,
            kind=event_kind,
            message=message,
            original=raw_event["original"],
            provider=dev.get_id(),
            reason=reason,
            # TODO: should sequence be reverse order for SER/CSER?
            # Since "1" in the log is actually the newest event, not the oldest?
            sequence=int(raw_event["sequence"]),
            type=event_type,
            extra=extra,
        )

        if not dev._module:
            event.module = "SELRelay"
        else:
            event.module = dev._module.__name__

        # If a event exists with the same sequence number, update it.
        # Otherwise, it's a new event and don't bother comparing values.
        dev.store("event", event, lookup="sequence")


def extract_cid_content(data: bytes) -> str:
    """
    Decompress a SEL ``.CID`` file (zlib). Data that is not zlib-compressed
    (a plain-XML CID exported by other tools) is decoded as-is.

    Raises:
        ParseError: the decompressed data is larger than
            :data:`peat.parsing.scl.MAX_DECOMPRESSED_SIZE` (zlib bomb)
    """
    if not data:
        return ""

    # Bounded decompression (same limit as the SCL parser)
    decompressed = scl.decode_scl_bytes(data)

    # NOTE utf-8-sig is required to remove the
    # Byte Order Mark (BOM) that gets prepended in some cases.
    decoded = decompressed.decode("utf-8-sig")

    return decoded


def process_cid_file(
    data: bytes, filepath: PurePath, dev: DeviceData, local_path: Path | None = None
) -> str:
    """
    .CID files are zlib-compressed data (zlib header ``0x78``, usually ``0x7801``).
    The only known CID file currently is ``SET_61850.CID``, which contains the
    IEC 61850 SCL (XML) of the relay.

    This function decompresses the zlib data, saves the decoded text to a new file,
    adds the CID file to ``dev.files`` and parses the SCL into ``dev.iec61850``
    (with :func:`peat.parsing.scl.apply_iec61850`: MMS/GOOSE/SV services,
    publications/subscriptions/reports and their relationships). A failure to
    parse the SCL never loses the decompressed file or the rest of the pull.

    Args:
        data: Raw (zlib-compressed) content of the CID file
        filepath: Path of the CID file on the relay (pull), or of the input file
        dev: Device the CID file belongs to
        local_path: The CID file on the system running PEAT, if it is a
            ``peat parse`` input instead of a file pulled from the relay. Its
            ``files`` record then has ``path`` = ``local_path``, like other
            parse input files (baseline comparisons skip such records).
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

        dev.write_file(extracted, f"{filepath.stem}_decompressed.{ext}")

        if not extracted:
            log.warning(f"No data extracted from CID file {filepath.name}")
    except Exception as ex:
        log.error(f"Failed to extract CID file {filepath.name}: {ex}")
        return ""

    cid_path = PurePosixPath(PurePath(filepath).as_posix())
    if local_path is not None:
        # "peat parse" input: process_file() sets path to the resolved local path
        dev.store(
            "files",
            File(
                local_path=Path(local_path),
                type="file",
                size=len(data),
                peat_module=_module_name(dev),
                category={"configuration", "iec61850"},
            ),
        )
    else:
        dev.store(
            "files",
            File(
                path=cid_path,
                type="file",
                size=len(data),
                peat_module=_module_name(dev),
                category={"configuration", "iec61850"},
            ),
            lookup="path",
        )

    # IEC 61850 SCL (DESIGN 7.4.1): after the decompressed file was written,
    # in its own try so a bad SCL never loses the file or the rest of the pull
    if extracted:
        try:
            root = scl.load_scl(extracted.encode("utf-8"))
            ied = scl.parse_scl(root, file_type=scl.file_type_from_name(filepath) or "CID")
            ied.scl_file = cid_path.as_posix()
            scl.apply_iec61850(dev, ied, populate_interfaces=False)
        except Exception as ex:  # never lose the CID file or the rest of the pull
            log.warning(f"Failed to parse SCL in '{filepath.name}': {ex}")

    return extracted


def _getv(val: dict | Any) -> Any:
    """
    Helper function to handle if a value is either
    in a dict or the value itself.
    """
    if isinstance(val, dict) and "value" in val:
        return val["value"]
    return val


def is_enabled(conf: dict) -> bool:
    return value_is_enabled(conf.get("value", ""))


def value_is_enabled(value: str) -> bool:
    return bool(value.upper() in ("Y", "YES", "ON", "1"))


def clean_id(id_str: str) -> str:
    cleaned = utils.clean_replace(id_str, "_", " ,!:")
    return re.sub("_{2,}", "_", cleaned).strip("_")


def split_lines(val: bytes | str) -> list[str]:
    if isinstance(val, bytes):
        val = val.decode("ascii")
    return [x.strip() for x in val.strip().splitlines() if x]
