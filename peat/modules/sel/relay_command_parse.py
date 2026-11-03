"""
Parsers for the output of SEL relay ASCII commands: ``VER``, ``ETH``, ``MAC``,
``SHO`` (settings, grouped by heading), ``MET`` (metering), ``TIM Q`` (time
source and quality), ``GOO`` (GOOSE status), ``HELP``, ``STA`` and ``STA A``
(self-test details), ``STA S`` (SELOGIC usage), and the names returned by
the ``SNS``, ``DNA X``, ``BNA``, and ``CST`` Compressed ASCII commands.

The output of a command is the same whether it comes from the relay's web
interface (the ``<pre>`` section of a page, read by
:class:`~peat.modules.sel.sel_http.SELHTTP`) or from a Telnet or serial
session (:class:`~peat.modules.sel.sel_ascii.SELAscii`), so these functions
accept both (e.g. with the command echo, prompts, and CRLF line endings of a
Telnet session). :class:`~peat.modules.sel.sel_http.SELHTTP` and
:meth:`~peat.modules.sel.sel_relay.SELRelay.pull_more_commands` use them. The
``parse_*`` functions are pure (no device or network access), and the
``process_*`` functions put the parsed data into the device data model.

Other command outputs are parsed by :mod:`peat.modules.sel.relay_parse`
(``STA``, ``SER``, ``HIS``, ``SHO`` as settings classes) and
:mod:`peat.modules.sel.sel_cascii` (``ID`` and Compressed ASCII).
"""

import re
from typing import Final

import humanfriendly

from peat import DeviceData, log
from peat.protocols import clean_mac, split_ipv4_cidr

from . import sel_cascii
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
    over Telnet or serial (:meth:`~peat.modules.sel.sel_ascii.SELAscii.show_mac`).

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


# ---------------------------------------------------------------------------
# TIM Q / TIME Q (time source and clock quality)
# ---------------------------------------------------------------------------

#: Labels in ``TIM Q`` output (SEL-351S IM 20171023 p.10.85, SEL-421 IM 20130627
#: Figure 4.67), and the key and type of their value
_TIME_QUALITY_LABELS: Final = {
    "utc": ("utc_time", "text"),
    "utc offset": ("utc_offset_hours", "number"),
    "time source": ("time_source", "text"),
    "last update source": ("last_update_source", "text"),
    "active irig port": ("active_irig_port", "text"),
    "last update time": ("last_update_time", "text"),
    "irig time quality": ("irig_time_quality_ms", "number"),
    "irig time mark period": ("irig_time_mark_period_ms", "number"),
    "internal clock period": ("internal_clock_period_ns", "number"),
}

_TIME_QUALITY_LINE_RE: Final = re.compile(
    r"^[ \t]*(?P<label>[A-Za-z][A-Za-z ]*?)[ \t]*:[ \t]*(?P<value>\S.*?)\s*$"
)

_NUMBER_RE: Final = re.compile(r"[-+]?\d+(?:\.\d+)?")


def parse_time_quality(text: str, date_format: str = "") -> dict:
    """
    Parse the output of the ``TIM Q`` command (``TIME Q`` on 400 series relays):
    the time source of the relay, where the time was last set from, and how
    accurate the clock is.

    The time sources are ``HIRIG`` (high-accuracy IRIG-B) or ``OTHER``, and the
    last update source is e.g. ``HIRIG``, ``IRIG``, ``SNTP``, ``DNP``,
    ``ASCII TIME``, ``FRONT PANEL DATE``, or ``NONV CLK`` (the battery-backed
    clock, e.g. after a loss of power).

    Args:
        text: Output of the command
        date_format: Date format of the relay (``DATE_F``), for the last update time

    Returns:
        The values that were found: ``utc_time``, ``utc_offset_hours``,
        ``time_source``, ``last_update_source``, ``active_irig_port``,
        ``last_update_time`` (as printed, e.g. ``07:13:01   08/07/11``),
        ``last_update`` (a :class:`~datetime.datetime`, if it could be parsed),
        ``irig_time_quality_ms``, ``irig_time_mark_period_ms``, and
        ``internal_clock_period_ns``
    """
    results: dict = {}

    for line in text.replace("\r\n", "\n").split("\n"):
        match = _TIME_QUALITY_LINE_RE.match(line)
        if not match:
            continue
        label = " ".join(match["label"].lower().split())
        if label not in _TIME_QUALITY_LABELS:
            continue
        key, kind = _TIME_QUALITY_LABELS[label]
        if key in results:
            continue

        value = match["value"].strip()
        if kind == "number":
            number = _NUMBER_RE.search(value)
            if number:
                results[key] = float(number.group(0))
        else:
            results[key] = " ".join(value.split()) if key != "last_update_time" else value

    last = results.get("last_update_time", "")
    parts = last.split()
    if len(parts) == 2:
        # The 351S prints the time first: "07:13:01   08/07/11"
        time_part, date_part = parts if ":" in parts[0] else parts[::-1]
        try:
            results["last_update"] = parse_sel_datetime(date_part, time_part, date_format)
        except Exception as ex:
            log.debug(f"Failed to parse the last update time {last!r}: {ex}")

    if not results:
        log.debug("Failed to parse any data from 'tim q' output")

    return results


def process_time_quality(info: dict, dev: DeviceData) -> None:
    """
    Put data parsed from ``TIM Q`` output by :func:`parse_time_quality`
    into ``dev.extra["time_quality"]``. The time source is also put in
    ``dev.extra["time_source"]``, if it isn't set yet.
    """
    if not info:
        return

    values = dict(info)
    if values.get("last_update") is not None:
        values["last_update"] = values["last_update"].isoformat()
    dev.extra["time_quality"] = values

    if values.get("time_source") and not dev.extra.get("time_source"):
        dev.extra["time_source"] = values["time_source"]


# ---------------------------------------------------------------------------
# GOO / GOOSE (IEC 61850 GOOSE status)
# ---------------------------------------------------------------------------

#: A GOOSE control block reference, e.g. ``SEL_751A_1CFG/LLN0$GO$GooseDSet13``
_GOOSE_CB_RE: Final = re.compile(r"^(?P<ref>[^\s/]+/[^\s$]+\$GO\$\S+)$")

_GOOSE_SECTION_RE: Final = re.compile(r"^GOOSE\s+(?P<kind>Transmit|Receive)\s+Status", re.I)

_GOOSE_DATA_SET_RE: Final = re.compile(r"^Data\s+Set\s*:\s*(?P<ref>\S+)", re.I)

_GOOSE_ROW_RE: Final = re.compile(rf"^(?P<mac>{MAC_ADDRESS_PATTERN})(?P<rest>.*)$")

#: Logical device instance (``ldInst``) in the control block references of SEL devices
SEL_GOOSE_LD_INST: Final = "CFG"

#: Columns of the GOOSE status rows that are numbers, and their key
_GOOSE_NUMBER_COLUMNS: Final = {
    "appid": "app_id",
    "stnum": "state_number",
    "sqnum": "sequence_number",
    "ttl": "ttl_ms",
}


def _goose_row(rest: str, columns: list[str]) -> dict:
    """
    The values after the multicast address in a GOOSE status row, e.g.
    ``4:1      2          20376      50`` (Ptag:Vlan, StNum, SqNum, TTL, and
    the code, if there's a problem). The SEL-351S also has an ``AppID`` column.
    """
    tokens = rest.split()
    row: dict = {}

    if tokens and ":" in tokens[0]:
        ptag, _, vlan = tokens.pop(0).partition(":")
        row["priority"] = int(ptag) if ptag.isdigit() else None
        row["vlan"] = int(vlan) if vlan.isdigit() else None

    numbers = [c for c in columns if c in _GOOSE_NUMBER_COLUMNS] or ["stnum", "sqnum", "ttl"]
    for column in numbers:
        if not tokens or not tokens[0].isdigit():
            break
        value = tokens.pop(0)
        key = _GOOSE_NUMBER_COLUMNS[column]
        # StNum and SqNum are kept as printed (the SEL-751A manual describes them
        # as hexadecimal, and its example values look decimal)
        row[key] = int(value) if key in ("app_id", "ttl_ms") else value

    # A warning or error, e.g. "TTL EXPIRED" (the relay abbreviates them)
    row["code"] = " ".join(tokens)
    return row


def parse_goose_output(text: str) -> dict:
    """
    Parse the output of the ``GOO`` (``GOOSE``) command: the IEC 61850 GOOSE
    messages the relay publishes (transmit) and subscribes to (receive), as
    shown in the SEL-751A IM 20130329 (Figure 7.19) and SEL-351S IM 20171023
    (Figure 10.9). The receive list names the GOOSE publishers this relay
    listens to, which are usually other IEDs in the substation.

    Each control block is a reference (``<IED name><ldInst>/LLN0$GO$<name>``),
    followed by the multicast MAC address, ``Ptag:Vlan``, (on some relays)
    ``AppID``, ``StNum``, ``SqNum``, ``TTL`` (in milliseconds), and a code if
    there's a problem, and then the data set (``Data Set: ...``).

    Returns:
        ``{"transmit": [...], "receive": [...]}`` with a :class:`dict` for each
        control block: ``control_block``, ``logical_device`` (before the ``/``),
        ``ied_name`` (the logical device without SEL's ``ldInst``, ``CFG``, or an
        empty string if it doesn't end with ``CFG``), ``multicast_address``,
        ``priority``, ``vlan``, ``app_id``, ``state_number``, ``sequence_number``,
        ``ttl_ms``, ``code``, and ``data_set``. Values that aren't in the output
        are :obj:`None` or empty strings.
    """
    results: dict[str, list[dict]] = {"transmit": [], "receive": []}
    section = ""
    columns: list[str] = []
    current: dict | None = None

    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line or set(line) <= {"-"}:
            continue

        heading = _GOOSE_SECTION_RE.match(line)
        if heading:
            section = heading["kind"].lower()
            current = None
            continue

        if "multicastaddr" in line.lower():
            columns = [c.lower() for c in line.split()]
            continue

        if not section:
            continue

        cb_match = _GOOSE_CB_RE.match(line)
        if cb_match:
            ref = cb_match["ref"]
            logical_device = ref.split("/", 1)[0]
            ied_name = ""
            if logical_device.upper().endswith(SEL_GOOSE_LD_INST) and len(logical_device) > 3:
                ied_name = logical_device[: -len(SEL_GOOSE_LD_INST)]
            current = {
                "control_block": ref,
                "logical_device": logical_device,
                "ied_name": ied_name,
                "multicast_address": "",
                "priority": None,
                "vlan": None,
                "app_id": None,
                "state_number": "",
                "sequence_number": "",
                "ttl_ms": None,
                "code": "",
                "data_set": "",
            }
            results[section].append(current)
            continue

        if current is None:
            continue

        row = _GOOSE_ROW_RE.match(line)
        if row:
            current["multicast_address"] = clean_mac(row["mac"])
            current.update(_goose_row(row["rest"], columns))
            continue

        data_set = _GOOSE_DATA_SET_RE.match(line)
        if data_set:
            current["data_set"] = data_set["ref"]

    return results


def goose_peer_names(info: dict) -> list[str]:
    """
    Names of the IEDs in the GOOSE status (from :func:`parse_goose_output`):
    the IED name (or the logical device, if the IED name isn't known) of each
    control block, in order, without duplicates.
    """
    names = []
    for kind in ("transmit", "receive"):
        for cb in info.get(kind, []):
            name = cb.get("ied_name") or cb.get("logical_device")
            if name and name not in names:
                names.append(name)
    return names


def process_goose_info(info: dict, dev: DeviceData) -> None:
    """
    Put data parsed from ``GOO`` output by :func:`parse_goose_output` into the
    device data model: ``dev.extra["goose"]``, and the names of the IEDs
    (this relay's, and the publishers it subscribes to) in ``dev.related.hosts``.
    The multicast addresses aren't added to ``dev.related.mac``, since they
    aren't the addresses of a device.
    """
    if not info or not (info.get("transmit") or info.get("receive")):
        return

    dev.extra["goose"] = info
    for name in goose_peer_names(info):
        dev.related.hosts.add(name)


# ---------------------------------------------------------------------------
# HELP (commands available at the present access level)
# ---------------------------------------------------------------------------

#: A command in ``HELP`` output, e.g. ``ACC``, ``2AC``, ``L_D``, or ``Baud``
_HELP_COMMAND_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_]{1,9}")

#: Commands that are on all SEL relays, to check that ``HELP`` output is a list of commands
KNOWN_COMMAND_KEYS: Final = frozenset(
    {
        "2AC",
        "ACC",
        "BRE",
        "CAL",
        "DAT",
        "EVE",
        "FIL",
        "GRO",
        "HIS",
        "ID",
        "MET",
        "PAS",
        "QUI",
        "SER",
        "SET",
        "SHO",
        "STA",
        "SUM",
        "TAR",
        "TIM",
    }
)


def parse_help_output(text: str) -> list[str]:
    """
    Parse the list of commands from the output of the ``HELP`` command, which
    lists the commands available at the present access level, one per line with
    a short description (e.g. ``ACC   Go to Access Level 1`` or
    ``Baud  - Set the baud rate``). Lines with several command names (a table
    of names) are read too.

    SEL doesn't print the layout of relay ``HELP`` output in the public manuals,
    so a word may be read as a command that isn't one (e.g. a word in the header).

    Returns:
        The command names (uppercase), in order, without duplicates
    """
    names: list[str] = []

    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.replace(sel_cascii.STX, "").replace(sel_cascii.ETX, "").strip()
        if not line or _is_prompt_or_echo(line):
            continue

        tokens = line.split()
        first = tokens[0].rstrip(":,")

        if len(tokens) > 1 and all(
            _HELP_COMMAND_RE.fullmatch(t) and t.isupper() for t in tokens if t != "-"
        ):
            candidates = [t for t in tokens if t != "-"]  # A table of command names
        elif _HELP_COMMAND_RE.fullmatch(first) and (
            first.upper() == first or (len(tokens) > 1 and tokens[1] == "-")
        ):
            candidates = [first]
        else:
            continue

        for name in candidates:
            if name.upper() not in names and name.upper() != "HELP":
                names.append(name.upper())

    return names


def help_lists_commands(names: list[str]) -> bool:
    """
    If the command names from :func:`parse_help_output` look like a list of the
    relay's commands (at least 5 commands that all SEL relays have), so they can
    be used to decide which commands to run.
    """
    return len({name[:3] for name in names} & KNOWN_COMMAND_KEYS) >= 5


# ---------------------------------------------------------------------------
# STA and STA A (self-test details), STA S (SELOGIC usage)
# ---------------------------------------------------------------------------

#: A value in a self-test table: a number, a status, or ``$$$`` (too large)
_STATUS_VALUE_RE: Final = re.compile(
    r"[-+]?\d+(?:\.\d+)?|OK|FAIL|WARN|W|F|NA|N/A|--+|\$+(?:\.\$+)?", re.IGNORECASE
)

#: A name in a self-test table, e.g. ``RAM``, ``3.3V_REG``, ``A/D``, ``+0.9V``, ``CH10``
_STATUS_NAME_RE: Final = re.compile(r"[A-Za-z0-9_+./-]*[A-Za-z][A-Za-z0-9_+./-]*")

#: Headings of the lists in 400 series ``STA`` output, and their key
_STATUS_LISTS: Final = {
    "failures": "failures",
    "warnings": "warnings",
    "selogic relay programming environment errors": "selogic_errors",
}

#: Lines in the lists that mean the list is empty
_STATUS_NONE_RE: Final = re.compile(r"^No (?:Failures|Warnings|Errors)$", re.IGNORECASE)


def _status_value(token: str) -> str | float:
    number = _to_float(token) if _NUMBER_RE.fullmatch(token) else None
    return number if number is not None else token.upper()


def _is_status_names(tokens: list[str]) -> bool:
    return len(tokens) >= 2 and all(
        _STATUS_NAME_RE.fullmatch(t) and not _STATUS_VALUE_RE.fullmatch(t) for t in tokens
    )


def _status_values(tokens: list[str], width: int) -> tuple[str, list[str]] | None:
    """
    The label (e.g. ``OS`` for the offsets on the 351S, or an empty string) and
    the values of a row in a self-test table, or :obj:`None` if it isn't a row
    of values for a table with ``width`` names.
    """
    label = ""
    if tokens and not _STATUS_VALUE_RE.fullmatch(tokens[0]):
        label, tokens = tokens[0], tokens[1:]
    if not tokens or len(tokens) > width or not all(_STATUS_VALUE_RE.fullmatch(t) for t in tokens):
        return None
    if label and not _STATUS_NAME_RE.fullmatch(label):
        return None
    return label, tokens


def parse_status_details(text: str) -> dict:
    """
    Parse the self-test details from the output of the ``STA`` command, or
    ``STA A`` on 400 series relays (all of the status report).

    The layout varies by family, so the tables are found by their shape: a line
    of names followed by lines of values (``OK``, ``FAIL``, ``WARN``, or numbers),
    with an optional label at the start of a value line (``OS`` and ``OSH``
    for the offsets of the SEL-351S). Examples are in the SEL-351S IM 20171023
    (``STA`` command), SEL-751A IM 20130329 (Figure 1.3), and SEL-421 IM
    20130627 (Figure 6.32, ``STA A``).

    Returns:
        ``self_tests`` (values keyed by name, e.g. ``{"RAM": "OK", "OS_IA": -1.0}``),
        ``failures``, ``warnings``, and ``selogic_errors`` (400 series lists, if
        they're in the output), ``temperature_c``, ``time_sync_source``, and
        ``relay_enabled`` (:obj:`True` for ``Relay Enabled``, :obj:`False` for
        ``Relay Disabled``). Only the values that were found are included.
    """
    results: dict = {}
    tests: dict[str, str | float] = {}
    lines = [
        line.replace(sel_cascii.STX, "").replace(sel_cascii.ETX, "").rstrip()
        for line in text.replace("\r\n", "\n").split("\n")
    ]
    names: list[str] = []
    list_key = ""

    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            list_key = ""
            continue
        lowered = " ".join(stripped.lower().split())

        if lowered in ("relay enabled", "relay disabled"):
            results["relay_enabled"] = lowered == "relay enabled"
            list_key = ""
            continue

        if lowered in _STATUS_LISTS:
            list_key = _STATUS_LISTS[lowered]
            results.setdefault(list_key, [])
            continue

        if list_key:
            # The entries of a list are indented below its heading
            if line[:1].isspace():
                if not _STATUS_NONE_RE.match(stripped):
                    results[list_key].append(stripped)
                continue
            list_key = ""

        temperature = re.match(r"^([-+]?\d+(?:\.\d+)?)\s+degrees\s+C", stripped, re.IGNORECASE)
        if temperature:
            results["temperature_c"] = float(temperature.group(1))
            continue

        sync = re.match(r"^Active .*Time Synchronization Source:\s*(\S.*)$", stripped, re.I)
        if sync:
            results["time_sync_source"] = sync.group(1).strip()
            continue

        tokens = stripped.split()
        next_tokens = lines[index + 1].split() if index + 1 < len(lines) else []
        if _is_status_names(tokens) and _status_values(next_tokens, len(tokens)):
            names = tokens
            continue

        row = _status_values(tokens, len(names)) if names else None
        if row is None:
            names = []
            continue

        label, values = row
        for name, value in zip(names, values, strict=False):
            key = f"{label}_{name}" if label else name
            if key not in tests:
                tests[key] = _status_value(value)

    if tests:
        results["self_tests"] = tests
        if "temperature_c" not in results and isinstance(tests.get("TEMP"), float):
            results["temperature_c"] = tests["TEMP"]

    return results


def process_status_details(info: dict, dev: DeviceData) -> None:
    """
    Put data parsed by :func:`parse_status_details` into the device data model:
    ``dev.extra["self_tests"]`` (merged with the values that are already there),
    ``dev.extra["status_failures"]``, ``dev.extra["status_warnings"]``,
    ``dev.extra["selogic_errors"]``, ``dev.extra["temperature_c"]``,
    ``dev.extra["time_sync_source"]``, and ``dev.status`` (``enabled`` or
    ``disabled``, if it isn't set yet).
    """
    if info.get("self_tests"):
        dev.extra.setdefault("self_tests", {}).update(info["self_tests"])

    for key, extra_key in (
        ("failures", "status_failures"),
        ("warnings", "status_warnings"),
        ("selogic_errors", "selogic_errors"),
        ("temperature_c", "temperature_c"),
        ("time_sync_source", "time_sync_source"),
    ):
        if key in info:
            dev.extra[extra_key] = info[key]

    if "relay_enabled" in info and not dev.status:
        dev.status = "enabled" if info["relay_enabled"] else "disabled"


def parse_selogic_usage(text: str) -> dict:
    """
    Parse the output of the ``STA S`` command on 700 series relays: how much of
    the SELOGIC capacity and execution time is used (SEL-751A IM 20130329,
    Figure 7.22). On 400 series relays, ``STA S`` shows SELOGIC errors instead,
    which isn't parsed by this.

    Returns:
        ``part_number``, ``usage_percent`` (e.g. ``{"Global": 81, "FP": 69}``),
        and ``groups`` (e.g. ``{"1": {"Execution": 90, "Group": 81, "Logic": 89}}``),
        if they're in the output
    """
    results: dict = {}
    groups: list[str] = []
    usage: dict[str, float] = {}
    per_group: dict[str, dict[str, float]] = {}

    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if not line:
            continue

        part = re.match(r"^Part\s+Number[\s:=]+(\S+)$", line, re.IGNORECASE)
        if part:
            results["part_number"] = part.group(1)
            continue

        if re.fullmatch(r"(?:GROUP\s+\d+\s*)+", line, re.IGNORECASE):
            groups = re.findall(r"GROUP\s+(\d+)", line, re.IGNORECASE)
            continue

        row = re.match(r"^(?P<name>[A-Za-z][\w ]*?)\s*\(%\)\s+(?P<values>[\d.\s]+)$", line)
        if not row:
            continue
        values = [float(v) for v in row["values"].split()]
        if groups and len(values) == len(groups):
            for group, value in zip(groups, values, strict=True):
                per_group.setdefault(group, {})[row["name"]] = value
        elif len(values) == 1:
            usage[row["name"]] = values[0]

    if usage:
        results["usage_percent"] = usage
    if per_group:
        results["groups"] = per_group

    return results


# ---------------------------------------------------------------------------
# Compressed ASCII names (SNS, DNA X, BNA) and status (CST)
# ---------------------------------------------------------------------------


def parse_cascii_names(text: str) -> list[str]:
    """
    Parse the names in the output of the ``SNS`` (names of the elements in the
    SER trigger settings), ``DNA X`` (names of the Relay Word bits in the Fast
    Meter message), or ``BNA`` (names of the status bits in the Fast Meter
    message) Compressed ASCII commands (SEL-351S IM 20171023, Appendix J).

    The names are in order (the first is the most significant bit), and unused
    bits are ``*``. Records with a wrong checksum are skipped.

    Returns:
        The names, or an empty list if there are none (e.g. "No Data Available")
    """
    names: list[str] = []

    for record in sel_cascii.parse_records(text):
        if record.status == sel_cascii.STATUS_INVALID:
            log.warning(f"Skipping a record with a wrong checksum: {record.text!r}")
            continue
        if record.status == sel_cascii.STATUS_MISSING or not record.all_quoted:
            continue
        if sel_cascii.is_no_data([record]):
            continue
        names.extend(f.text.strip() for f in record.fields)

    return names


def parse_cst_output(text: str) -> dict:
    """
    Parse the output of the ``CST`` (``CSTATUS``) Compressed ASCII command: the
    relay's status, as label lines followed by a line of values (e.g. ``"FID"``,
    then ``"MONTH","DAY",...``, then the self-test results, ``"IA_OS",...,"RAM",...``).

    Returns:
        The values of the first row after each label line, keyed by the label
    """
    values: dict = {}

    for block in sel_cascii.parse_report(text):
        if not block["labels"] or not block["rows"]:
            continue
        for label, value in block["rows"][0].items():
            if label != "_extra" and label not in values:
                values[label.strip()] = value

    return values


__all__ = [
    "KNOWN_COMMAND_KEYS",
    "MAC_LINE_RE",
    "SEL_GOOSE_LD_INST",
    "VER_EXTRA_KEYS",
    "goose_peer_names",
    "help_lists_commands",
    "merge_show_groups",
    "normalize_keys",
    "parse_cascii_names",
    "parse_comments",
    "parse_cst_output",
    "parse_eth_output",
    "parse_goose_output",
    "parse_help_output",
    "parse_mac_output",
    "parse_meter_energy",
    "parse_meter_values",
    "parse_selogic_usage",
    "parse_show_groups",
    "parse_simple_line",
    "parse_status_details",
    "parse_time_quality",
    "parse_ver_output",
    "process_eth_info",
    "process_goose_info",
    "process_status_details",
    "process_time_quality",
    "process_ver_info",
]
