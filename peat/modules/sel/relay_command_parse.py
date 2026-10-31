"""
Parsers for the output of SEL relay ASCII commands: ``VER``, ``ETH``, ``MAC``,
``SHO`` (settings, grouped by heading), and ``MET`` (metering).

The output of a command is the same whether it comes from the relay's web
interface (the ``<pre>`` section of a page, read by
:class:`~peat.modules.sel.sel_http.SELHTTP`) or from a Telnet or serial
session (:class:`~peat.modules.sel.sel_ascii.SELAscii`), so these functions
accept both (e.g. with the command echo, prompts, and CRLF line endings of a
Telnet session). :class:`~peat.modules.sel.sel_http.SELHTTP` uses them, and
the Telnet and serial code doesn't yet. The ``parse_*`` functions are pure
(no device or network access), and the ``process_*`` functions put the
parsed data into the device data model.

Other command outputs are parsed by :mod:`peat.modules.sel.relay_parse`
(``STA``, ``SER``, ``HIS``, ``SHO`` as settings classes) and
:mod:`peat.modules.sel.sel_cascii` (``ID`` and Compressed ASCII).
"""

import re
from typing import Final

import humanfriendly

from peat import DeviceData, log
from peat.protocols import clean_mac, split_ipv4_cidr

from .relay_parse import (
    SHOW_COMMAND_RE,
    SHOW_SETTING_RE,
    _to_float,
    parse_sel_datetime,
    parse_show_output,
    process_firmware_checksum,
    process_info_into_dev,
)

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def parse_simple_line(param_name: str, page_data: str) -> str:
    """
    First word of the value of a ``NAME=value``, ``NAME: value``, or
    ``NAME := value`` line, e.g. ``"SEL-451-5-R320..."`` for ``"FID"``.

    The name is case-sensitive and must be at the start of a line
    (indentation is allowed). This includes the first line of the text.

    Returns:
        The value, or an empty string if there isn't a line with the name
    """
    match = re.search(
        rf"^[ \t]*{re.escape(param_name)}[ \t]*(?::=|[=:])[ \t]*(\S+)",
        page_data,
        re.MULTILINE,
    )

    if not match:
        log.debug(f"parse_simple_line: no line with '{param_name}'")
        return ""

    return match.group(1)


def normalize_keys(obj: dict) -> dict:
    """
    Convert dictionary keys to lowercase underscore-separated,
    e.g. ``"Front Panel Settings"`` => ``"front_panel_settings"``.
    """
    return {key.strip().lower().replace(" ", "_"): value for key, value in obj.items()}


def parse_comments(obj: dict) -> dict:
    """
    Split value strings with comments into the value and the comment,
    e.g. ``"TRIP # trip coil"`` => ``{"value": "TRIP", "comment": "trip coil"}``.
    """
    results = {}

    for name, value in obj.items():
        val, _, comment = str(value).partition("#")
        results[name] = {"value": val.strip(), "comment": comment.strip()}

    return results


def _is_prompt_or_echo(line: str) -> bool:
    """
    If a line is a prompt (``=>``, ``=>>``) or the echo of a command
    (``=>>VER``), which are in Telnet and serial captures.
    """
    stripped = line.strip()
    return bool(re.fullmatch(r"[=>#]*>[=>]*(?:\s*[A-Za-z0-9 ]*)?", stripped))


# ---------------------------------------------------------------------------
# VER (version and hardware information)
# ---------------------------------------------------------------------------

#: A line in ``VER`` output with a value, e.g. ``Serial Number: 1234`` or ``FID=SEL-451-...``
_VER_FIELD_RE: Final = re.compile(r"^(?P<key>[^:=]+?)\s*(?::=|[:=])\s*(?P<value>.*)$")

#: Keys in the result of :func:`parse_ver_output` that are put into ``dev.extra`` as-is
VER_EXTRA_KEYS: Final = (
    "mainboard",
    "front_panel",
    "analog_inputs",
    "interface_boards",
    "e4_configuration",
    "extended_relay_features",
    "relay_features",
    "analog_input_voltage",
    "analog_input_current",
    "main_board_io",
    "additional_io",
    "hardware_warnings",
)

#: Lists in ``VER`` output: (normalized heading, result key)
_VER_LISTS: Final = (
    ("extended relay features", "extended_relay_features"),
    ("relay features", "relay_features"),
)

#: Tables of "name: value" lines in ``VER`` output: (normalized heading prefix, result key)
_VER_TABLES: Final = (
    ("mainboard", "mainboard"),
    ("analog inputs", "analog_inputs"),
    ("interface boards", "interface_boards"),
)

#: Single values in ``VER`` output: (normalized name prefix, result key)
_VER_VALUES: Final = (
    ("front panel", "front_panel"),
    ("e4 configuration", "e4_configuration"),
    ("analog input voltage", "analog_input_voltage"),
    ("analog input current", "analog_input_current"),
    ("main board i/o", "main_board_io"),
    ("additional i/o", "additional_io"),
)


#: Note the relay adds to a line in ``VER`` output if the hardware doesn't match the part number
_HARDWARE_WARNING_RE: Final = re.compile(r"\s*\bWarning\b\s*-", re.IGNORECASE)


def _normalize_ver_key(key: str) -> str:
    return " ".join(key.lower().split())


def _ver_blocks(text: str) -> list[tuple[str, str | None, list[str]]]:
    """
    Split ``VER`` output into entries of ``(name, value, lines)``.

    - ``Name: value`` lines are ``(name, value, [])``
    - Headings (``Mainboard:``) are ``(name, None, lines)``, with the stripped
      lines that are indented below them (any amount of indentation)
    - Other lines (e.g. ``SELboot checksum 58FF OK``) are ``(line, None, [])``
    """
    lines = [
        line.rstrip()
        for line in text.replace("\r\n", "\n").split("\n")
        if line.strip() and not _is_prompt_or_echo(line)
    ]
    if not lines:
        return []

    base_indent = min(len(line) - len(line.lstrip()) for line in lines)
    entries: list[tuple[str, str | None, list[str]]] = []
    heading: list[str] | None = None

    for line in lines:
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent > base_indent and heading is not None:
            heading.append(stripped)
            continue

        match = _VER_FIELD_RE.match(stripped)
        if match and match["value"].strip():
            entries.append((match["key"].strip(), match["value"].strip(), []))
            heading = None
        elif match:
            heading = []
            entries.append((match["key"].strip(), None, heading))
        else:
            entries.append((stripped, None, []))
            heading = None

    return entries


def _table_lines(lines: list[str]) -> dict[str, str]:
    table = {}
    for line in lines:
        match = _VER_FIELD_RE.match(line)
        if match and match["value"].strip():
            table.setdefault(match["key"].strip(), match["value"].strip())
    return table


def parse_ver_output(data: str) -> dict:
    """
    Parse the output of the ``VER`` command (relay configuration and
    firmware version), from the web interface or a Telnet/serial session.

    The layout varies by model, e.g. on 400-series relays the boot loader
    (``SELboot``) and hardware information are in indented tables, while
    the SEL-351S lists its features under ``Relay Features:``. Sections are
    found by their names and indentation (two spaces on the 311L and 351S,
    four spaces on the 400-series), not their order.

    Args:
        data: Output of the ``VER`` command

    Returns:
        The values that were found, out of:

        - ``FID``, ``BFID``, ``CID``, ``part_number``, ``serial_number``
        - ``checksum``: checksum in the ``SELboot`` section
        - ``mainboard``, ``analog_inputs``, ``interface_boards``: :class:`dict` tables
        - ``extended_relay_features``, ``relay_features``: :class:`list` of features
        - ``front_panel``, ``e4_configuration``, ``analog_input_voltage``,
          ``analog_input_current``, ``main_board_io``, ``additional_io``
        - ``hardware_warnings``: lines that say the hardware doesn't match
          the part number

        An empty :class:`dict` is returned if nothing was found.
    """
    entries = _ver_blocks(data)

    # All "name: value" pairs, including the ones in tables (e.g. "BFID" under
    # "SELboot:"). Values that aren't in a table are used first.
    values: dict[str, str] = {}
    for name, value, _ in entries:
        if value is not None:
            values.setdefault(_normalize_ver_key(name), value)
    for _, _, lines in entries:
        for key, val in _table_lines(lines).items():
            values.setdefault(_normalize_ver_key(key), val)

    results = {}

    for key, names in [
        ("FID", ("fid",)),
        ("BFID", ("bfid",)),
        ("CID", ("cid",)),
        ("part_number", ("part number", "partnumber", "part num")),
        ("serial_number", ("serial number", "serial no", "serial num")),
    ]:
        for name in names:
            if values.get(name):
                results[key] = values[name].split()[0]
                break

    # "SELboot checksum 58FF OK" (351S) or "Checksum: D507" under "SELboot:" (400-series)
    checksum = re.search(r"checksum\b\s*[:=]?\s*([0-9A-Fa-f]+)\b", data, re.IGNORECASE)
    if checksum:
        results["checksum"] = checksum.group(1)

    for name, value, lines in entries:
        norm = _normalize_ver_key(name)

        if value is None and lines:
            for heading, key in _VER_LISTS:
                if norm == heading and key not in results:
                    results[key] = list(lines)
                    break
            else:
                for heading, key in _VER_TABLES:
                    if norm.startswith(heading) and key not in results:
                        table = _table_lines(lines)
                        if table:
                            results[key] = table
                        break

        elif value is not None:
            for prefix, key in _VER_VALUES:
                if norm.startswith(prefix) and key not in results:
                    # A mismatch is noted on the line, e.g. "installed  Warning - ..."
                    results[key] = _HARDWARE_WARNING_RE.split(value)[0].strip()
                    break

    warnings = [
        line.strip()
        for line in data.splitlines()
        if "does not match" in line.lower() and line.strip()
    ]
    if warnings:
        results["hardware_warnings"] = warnings

    if not results:
        log.warning("Failed to parse any data from 'ver' output")

    return results


def process_ver_info(info: dict, dev: DeviceData) -> None:
    """
    Put data parsed from ``VER`` output by :func:`parse_ver_output`
    into the device data model.

    The checksum in ``VER`` output is the checksum of the boot loader
    (``SELboot``). It's put in ``dev.boot_firmware.checksum``, and in
    ``dev.firmware.checksum`` as PEAT has done before.
    """
    fids = {key: info[key] for key in ("FID", "BFID") if info.get(key)}
    if fids:
        process_info_into_dev(fids, dev)

    if info.get("checksum"):
        process_firmware_checksum(info["checksum"], dev)
        dev.boot_firmware.checksum = info["checksum"]

    if info.get("serial_number"):
        dev.serial_number = info["serial_number"]

    if info.get("part_number"):
        dev.part_number = info["part_number"]

    if info.get("CID"):
        dev.extra["CID"] = info["CID"]

    for key in VER_EXTRA_KEYS:
        if info.get(key):
            dev.extra[key] = info[key]

    ram_size = info.get("mainboard", {}).get("RAM Size")
    if ram_size and not dev.hardware.memory_total:
        try:
            dev.hardware.memory_total = humanfriendly.parse_size(ram_size, binary=True)
            if not dev.hardware.memory_type:
                dev.hardware.memory_type = "ram"
        except Exception as ex:
            log.error(f"Failed to parse RAM size '{ram_size}': {ex}")


# ---------------------------------------------------------------------------
# ETH (Ethernet port status) and MAC
# ---------------------------------------------------------------------------

#: A MAC address with "-" or ":" separators
MAC_ADDRESS_PATTERN: Final = r"[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}"

#: A line with a MAC address. The formats are:
#:
#: - ``MAC: 00-30-A7-00-00-01`` (``ETH``, most relays)
#: - ``MAC 1: 00-30-A7-00-00-01`` (``ETH``, some 400-series relays)
#: - ``Port 1 MAC Address: 00-30-A7-00-00-01`` (``MAC``, e.g. SEL-351S and SEL-751A)
#: - ``(IP) MAC ... 00-30-A7-00-00-01`` and ``(GOOSE) MAC ...`` (``MAC``, seen on a SEL-351S)
MAC_LINE_RE: Final = re.compile(
    r"^[ \t]*(?:"
    r"(?P<port>Port\s+\w+)\s+MAC\s+Address"
    r"|[^\n(]*?\((?P<paren>[^)]+)\)\s*MAC(?:\s+Address)?"
    r"|MAC(?:\s+Address)?(?:[ \t]+(?P<num>\d+))?"
    rf")[^\n\S]*[:=]?\s*(?P<mac>{MAC_ADDRESS_PATTERN})\b",
    re.IGNORECASE | re.MULTILINE,
)

#: A row in the port table of ``ETH`` output, e.g. ``PORT 5A  Up  100M  Full  TX``
_ETH_PORT_ROW_RE: Final = re.compile(
    r"^PORT\s+(?P<name>\S+)\s+(?P<link>\S+)\s+(?P<speed>\S+)\s+(?P<duplex>\S+)\s+(?P<media>\S+)"
)

#: A row of counters in ``ETH`` output. Counters that are too large are
#: printed as ``$$$$$$$``.
_ETH_STATS_RE: Final = re.compile(r"(?:(?:\d+|\$+)\s+){5}(?:\d+|\$+)")

_ETH_STATS_KEYS: Final = (
    "packets_sent",
    "packets_received",
    "bytes_sent",
    "bytes_received",
    "errors_sent",
    "errors_received",
)

#: A heading for a group of values in ``ETH`` output, e.g. ``IP Port:`` or ``GOOSE Port:``
_ETH_SECTION_RE: Final = re.compile(r"(?P<name>[A-Za-z0-9 ]*Port):")


def _mac_label(match: re.Match) -> str:
    if match["port"]:
        return " ".join(match["port"].split())
    if match["paren"]:
        return match["paren"].strip()
    if match["num"]:
        return f"MAC {match['num']}"
    return "MAC"


def parse_mac_output(text: str) -> dict[str, str]:
    """
    Parse MAC addresses from the output of the ``MAC`` command.

    Two formats are supported: ``Port 1 MAC Address: 00-30-A7-00-00-00``
    (documented for the SEL-351S and SEL-751A), and the ``(IP) MAC`` and
    ``(GOOSE) MAC`` lines that PEAT has seen on a SEL-351S. ``MAC:`` and
    ``MAC 1:`` lines (as in ``ETH`` output) are also read. The regex,
    :data:`MAC_LINE_RE`, is also used by :func:`parse_eth_output`.

    The web interface has no ``MAC`` page, so this is for the ``MAC`` command
    over Telnet or serial. :meth:`~peat.modules.sel.sel_ascii.SELAscii.show_mac`
    doesn't use it yet.

    Returns:
        MAC addresses (uppercase, colon-separated) keyed by their label,
        e.g. ``{"Port 1": "00:30:A7:00:00:00"}`` or ``{"IP": ..., "GOOSE": ...}``.
        If a label repeats, a number is added (``"MAC"``, ``"MAC (2)"``).
    """
    results = {}

    for match in MAC_LINE_RE.finditer(text):
        label = _mac_label(match)
        if label in results:
            label = f"{label} ({sum(1 for k in results if k.startswith(label)) + 1})"
        results[label] = clean_mac(match["mac"])

    return results


def _eth_counters(line: str) -> dict[str, int]:
    return {
        key: -1 if "$" in value else int(value)
        for key, value in zip(_ETH_STATS_KEYS, line.split(), strict=True)
    }


def parse_eth_output(text: str) -> dict:
    """
    Parse the output of the ``ETH`` command (Ethernet port status), from the
    web interface or a Telnet/serial session.

    The layout varies by model and settings (e.g. ``NETMODE``), but the lines
    are the same: ``NETMODE:``, ``PRIMARY PORT:``, ``ACTIVE PORT:``, a table
    of ports (``PORT 5A  Up  100M  Full  TX``), ``MAC:`` (or ``MAC 1:``),
    ``IP ADDRESS:`` (with the subnet mask in CIDR notation on some relays),
    ``SUBNET MASK:``, ``DEFAULT GATEWAY:``, and rows of packet, byte, and error
    counters. Some relays (e.g. the SEL-351S with IEC 61850) group the MAC
    address and counters under ``IP Port:`` and ``GOOSE Port:``.

    Counters that are too large for the relay to print are shown as
    ``$$$$$$$``, and are returned as ``-1``. They can be reset on the relay
    with ``ETH C`` (PEAT never does this).

    Returns:
        A :class:`dict` with:

        - ``mac_addresses``: MAC addresses (lowercase, colon-separated), in order
        - ``ipv4_address``, ``ipv4_subnet_mask``, ``gateway``
        - ``network_mode`` (``NETMODE``), ``primary_port``, ``active_port``
        - ``port_information``: ``link``, ``speed``, ``duplex``, and ``media``
          for each port (unknown values, ``--``, are empty strings)
        - ``statistics``: the first row of counters
        - ``port_sections``: (only if the output has them) the MAC address
          and counters for each group, e.g. ``"IP Port"`` and ``"GOOSE Port"``
    """
    results = {
        "mac_addresses": [],
        "ipv4_address": "",
        "ipv4_subnet_mask": "",
        "gateway": "",
        "network_mode": "",
        "primary_port": "",
        "active_port": "",
        "port_information": {},
        "statistics": {},
    }
    sections: dict[str, dict] = {}
    section = ""

    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue

        heading = _ETH_SECTION_RE.fullmatch(line)
        if heading:
            section = heading["name"].strip()
            sections.setdefault(section, {})
            continue

        mac = MAC_LINE_RE.match(line)
        if mac:
            address = mac["mac"].lower().replace("-", ":")
            if address not in results["mac_addresses"]:
                results["mac_addresses"].append(address)
            if section:
                sections[section].setdefault("mac_address", address)
            continue

        port = _ETH_PORT_ROW_RE.match(line)
        if port:
            results["port_information"][port["name"]] = {
                "link": port["link"].lower(),
                "speed": "" if set(port["speed"]) == {"-"} else port["speed"],
                "duplex": "" if set(port["duplex"]) == {"-"} else port["duplex"],
                "media": port["media"],
            }
            continue

        if _ETH_STATS_RE.fullmatch(line):
            counters = _eth_counters(line)
            if not results["statistics"]:
                results["statistics"] = counters
            if section:
                sections[section].setdefault("statistics", counters)
            continue

        key, sep, value = line.partition(":")
        if not sep or not value.strip():
            continue
        key = " ".join(key.upper().split())
        value = value.strip()
        first = value.split()[0]

        if key == "IP ADDRESS" and not results["ipv4_address"]:
            if "/" in first:
                try:
                    results["ipv4_address"], mask = split_ipv4_cidr(first)
                except ValueError as ex:  # e.g. AddressValueError
                    # Keep the value, so the rest of the output is still parsed
                    log.debug(f"Invalid IP address with prefix in 'eth' output {first!r}: {ex}")
                    results["ipv4_address"] = first
                else:
                    results["ipv4_subnet_mask"] = results["ipv4_subnet_mask"] or mask
            else:
                results["ipv4_address"] = first
        elif key == "SUBNET MASK" and not results["ipv4_subnet_mask"]:
            results["ipv4_subnet_mask"] = first
        elif key in ("DEFAULT GATEWAY", "DEFAULT ROUTER") and not results["gateway"]:
            results["gateway"] = first
        elif key == "NETMODE" and not results["network_mode"]:
            results["network_mode"] = first
        elif key == "PRIMARY PORT" and not results["primary_port"]:
            results["primary_port"] = " ".join(value.split())
        elif key == "ACTIVE PORT" and not results["active_port"]:
            results["active_port"] = " ".join(value.split())

    if sections:
        results["port_sections"] = sections

    if not results["statistics"]:
        log.debug("No network statistics in 'eth' output")

    return results


def process_eth_info(info: dict, dev: DeviceData) -> None:
    """
    Put data parsed from ``ETH`` output by :func:`parse_eth_output`
    into the device data model.

    The data is stored in ``dev.extra["communications"]``, and the MAC
    addresses are added to ``dev.related.mac``.
    """
    dev.extra["communications"] = info

    for mac in info.get("mac_addresses", []):
        dev.related.mac.add(clean_mac(mac))


# ---------------------------------------------------------------------------
# SHO (settings grouped by heading)
# ---------------------------------------------------------------------------


def parse_show_groups(text: str) -> dict[str, dict[str, str]]:
    """
    Parse ``SHO`` output into settings grouped by the headings above them.

    400-series relays group settings under headings, separated by blank
    lines, e.g.:

    .. code-block:: text

       Protocol Card Settings

       IPADDR   := "192.0.2.30/24"
       DEFRTR   := "192.0.2.1"

       FTP Settings

       FTPSERV  := Y        FTPIDLE  := 5

    The settings are parsed by :func:`~peat.modules.sel.relay_parse.parse_show_output`,
    so both ``:=`` and ``=`` (older relays), several settings on a line,
    quoted values, and equations continued on the next line work. Settings
    before the first heading are put under an empty heading (``""``).
    Prompts and command echoes (``=>>SHO P 5``) are ignored.

    Use :func:`~peat.modules.sel.relay_parse.parse_show_output` to get the
    settings by settings class instead (e.g. ``"P5"``).

    Returns:
        Setting values keyed by setting name, keyed by heading
        (e.g. ``{"FTP Settings": {"FTPSERV": "Y", "FTPIDLE": "5"}}``).
        Headings without settings aren't included.
    """
    blocks: dict[str, list[str]] = {}
    heading = ""
    in_setting = False  # If the previous line was a setting (or its continuation)

    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.rstrip()

        if not line.strip():
            in_setting = False
            continue

        if (len(line) < 80 and SHOW_COMMAND_RE.match(line)) or re.fullmatch(
            r"[=>]+", line.strip()
        ):
            in_setting = False
            continue

        if SHOW_SETTING_RE.search(line):
            blocks.setdefault(heading, []).append(line)
            in_setting = True
        elif in_setting and line[:1].isspace():
            blocks[heading].append(line)  # Continuation of an equation
        else:
            heading = line.strip()
            in_setting = False

    groups = {}
    for name, lines in blocks.items():
        parsed = parse_show_output("\n".join(lines))
        values = {}
        for section, settings in parsed.items():
            for key, value in settings.items():
                values[key] = value if section == "INFO" else value["value"]
        if values:
            groups.setdefault(name, {}).update(values)

    return groups


def merge_show_groups(groups: dict[str, dict[str, str]]) -> dict[str, str]:
    """
    Merge the groups from :func:`parse_show_groups` into a single
    :class:`dict` of setting values.
    """
    return {key: value for group in groups.values() for key, value in group.items()}


# ---------------------------------------------------------------------------
# MET (metering)
# ---------------------------------------------------------------------------


def parse_meter_values(text: str, prefix: str) -> dict[str, float]:
    """
    Parse ``NAME = value`` metering values with a name prefix, e.g. the
    automation math variables in the output of ``MET AMV``
    (``AMV001 =  12.500``) or the protection math variables of ``MET PMV``.

    Values that aren't numbers (e.g. ``$$$$$$``) are skipped.

    Args:
        text: Output of the metering command
        prefix: Prefix of the value names, e.g. ``"AMV"`` or ``"PMV"``

    Returns:
        The values, keyed by name (e.g. ``{"AMV001": 12.5}``)
    """
    values = {}

    for match in re.finditer(
        rf"(?<![A-Za-z0-9_])({re.escape(prefix)}\d+)\s*:?=\s*(\S+)", text, re.IGNORECASE
    ):
        number = _to_float(match.group(2))
        if number is None:
            log.debug(f"Skipping meter value {match.group(1)} = {match.group(2)!r}")
            continue
        values[match.group(1)] = number

    return values


#: Rows in energy metering output
_ENERGY_ROWS: Final = ("IN", "OUT", "TOTAL")


def parse_meter_energy(text: str, date_format: str = "") -> dict:
    """
    Parse the output of the energy metering command (``MET E``).

    The output is a table, with a row for energy in, out, and on some
    relays the total, and a column for each quantity, e.g. on a SEL-351S:

    .. code-block:: text

                MWhA    MWhB     MWhC    MWh3P   MVARhA ...
       IN       0.10    0.20     0.30     0.60     0.01 ...
       OUT     12.50   12.75    13.00    38.25     1.10 ...
       LAST RESET 03/01/21 00:00:00.000

    The column labels are the last labels in the line above the first row,
    so a label for the rows (e.g. ``Energy (MWh)``) is ignored.

    Args:
        text: Output of the command
        date_format: Date format of the relay (``DATE_F``), used for the
            time of the last reset

    Returns:
        ``{"<column>": {"in": float, "out": float, "total": float}}``, with
        ``last_energy_reset`` (ISO 8601 string) if it's in the output.
        Values that aren't numbers are :obj:`None`.
    """
    results: dict = {}

    reset = re.search(
        r"LAST\s+(?:ENERGY\s+)?RESET:?\s+(\d+/\d+/\d+)\s+(\d+:\d+:\d+(?:\.\d+)?)",
        text,
        re.IGNORECASE,
    )
    if reset:
        try:
            results["last_energy_reset"] = parse_sel_datetime(
                reset.group(1), reset.group(2), date_format
            ).isoformat()
        except Exception as ex:
            log.debug(f"Failed to parse last energy reset time: {ex}")

    header = ""
    rows: dict[str, list[str]] = {}

    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line or (reset and line.upper().startswith("LAST")):
            continue

        tokens = line.split()
        first = tokens[0].upper()
        if first in _ENERGY_ROWS and len(tokens) > 1:
            if first.lower() not in rows:
                rows[first.lower()] = tokens[1:]
        elif not rows:
            header = line  # The last line before the first row

    if not rows:
        log.debug("No energy values in 'met e' output")
        return results

    width = max(len(values) for values in rows.values())
    # Labels are separated by 2+ spaces, so they can have a space ("Phase A")
    labels = re.split(r"\s{2,}", header)
    if len(labels) < width:
        labels = header.split()
    columns = labels[-width:] if len(labels) >= width else []
    if not columns:
        log.debug(f"Failed to find the energy column labels (header: {header})")
        return results

    for index, column in enumerate(columns):
        results[column] = {
            row: _to_float(values[index]) if index < len(values) else None
            for row, values in rows.items()
        }

    return results


__all__ = [
    "MAC_LINE_RE",
    "VER_EXTRA_KEYS",
    "merge_show_groups",
    "normalize_keys",
    "parse_comments",
    "parse_eth_output",
    "parse_mac_output",
    "parse_meter_energy",
    "parse_meter_values",
    "parse_show_groups",
    "parse_simple_line",
    "parse_ver_output",
    "process_eth_info",
    "process_ver_info",
]
