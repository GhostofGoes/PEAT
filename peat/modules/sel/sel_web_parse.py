"""
Parsers for the web pages of SEL devices: the login and ``<pre>`` pages of
relays, the pages of SEL RTACs (``*.sel`` and ``soe.csv``), and the pages
of the SEL-3620 Ethernet Security Gateway.

The pages are fetched by :class:`~peat.modules.sel.sel_http.SELHTTP`. The
``parse_*`` functions here are pure (no device or network access), so they
can be tested with saved pages, and the ``process_*`` functions put the
parsed data into the device data model.

Relay pages contain the output of an ASCII command (e.g. ``ver``) in their
``<pre>`` section. That text is parsed by functions that also work for the
output of the command over Telnet or serial, in
:mod:`~peat.modules.sel.relay_command_parse` and
:mod:`~peat.modules.sel.relay_parse`.
"""

import csv
import io
import re
from typing import Final, NamedTuple
from urllib.parse import urlsplit, urlunsplit

import humanfriendly
from bs4 import BeautifulSoup

from peat import DeviceData, Event, consts, log, utils
from peat.data.models import User
from peat.data.validators import validate_hash

from .relay_parse import _to_int, process_fid, process_firmware_checksum

# ---------------------------------------------------------------------------
# Generic HTML helpers
# ---------------------------------------------------------------------------


def gen_soup(content: str | bytes) -> BeautifulSoup:
    """
    BeautifulSoup instance for a page. Pass the raw bytes when possible,
    BeautifulSoup determines the encoding.
    """
    return BeautifulSoup(content, features=consts.BS4_PARSER)


def clean_text(data: str) -> str:
    """
    Attempt to remove whitespace and new line characters.
    """
    return data.replace("\\\\n", "").replace("\\n", "").lstrip().rstrip()


def read_html(content: str | bytes) -> dict[str, str | list[str]]:
    """
    Read the first table in a page into a :class:`dict`, keyed by the text
    of the first cell of each row.

    - Rows with two cells have a :class:`str` value (the second cell)
    - Rows with more cells have a :class:`list` value (the other cells)
    - Rows with less than two cells (e.g. ``<th>`` headers) are skipped
    - If the value cell is empty and has an ``<input>``, the value is the
      ``value`` attribute of the input, or ``"true"``/``"false"`` for a checkbox
    - Rows with an empty first cell are named ``Unknown_<n>``
    """
    soup = gen_soup(content)

    table = soup.find("table")
    if not table:
        return {}

    unknown_i = 0
    data = {}

    # Find rows in html table objects
    for row in table.find_all("tr"):
        if not row:
            continue

        # Find columns in each row
        col = row.find_all("td")
        if len(col) < 2:
            continue

        # Row Label
        # '<td class="firstColumn">Host Name:</td>' => "Host Name"
        name = clean_text(col[0].get_text())

        # handle case where empty string as key
        if not name:
            name = f"Unknown_{unknown_i}"
            unknown_i += 1

        if len(col) == 2:
            data[name] = clean_text(col[1].get_text())

            # Some cells have a <input/> tag as their value, instead of the text
            # These fields are designed to take user input, and provide the current
            # value in the "value" attribute.
            if not data[name] and col[1].contents:
                input_tag = col[1].find("input")

                # We don't care about other tag types for now,
                # they may be things like links to other pages.
                if not input_tag:
                    continue

                # Current value
                if input_tag.attrs.get("value"):
                    data[name] = clean_text(input_tag.attrs["value"])

                # Checkbox fields
                elif input_tag.attrs.get("type", "") == "checkbox":
                    # boolean, if attr named "checked", then true, else false
                    if "checked" in input_tag.attrs:
                        data[name] = "true"
                    else:
                        data[name] = "false"
        else:
            # Iterate over columns
            data[name] = []
            for pos in col[1:]:
                data[name].append(clean_text(pos.get_text()))

    return data


def parse_html_table(content: str | bytes | None) -> dict[str, str | list[str]]:
    """
    Read the first table in a page with :func:`read_html`, with ``:``
    removed from the labels (``"Host Name:"`` => ``"Host Name"``).
    """
    if not content:
        return {}

    return {k.replace(":", " ").strip(): v for k, v in read_html(content).items()}


def extract_pre_sections(content: str | bytes) -> list[str]:
    """
    Text of each ``<pre>`` section in a page, with CRLF line endings replaced
    with LF. Text in tags inside the section (e.g. links) is included.
    """
    return [pre.get_text().replace("\r\n", "\n") for pre in gen_soup(content).find_all("pre")]


def extract_pre_text(content: str | bytes) -> str:
    """
    Text of the ``<pre>`` section of a relay page, which is the output of the
    command that the page ran on the relay. If there are multiple sections
    (e.g. the SEL-351 ``sho1`` page has the group and logic settings), they're
    joined with a blank line.

    Raises:
        ValueError: if the page doesn't have a ``<pre>`` section
    """
    sections = extract_pre_sections(content)
    if not sections:
        raise ValueError("no 'pre' section in page")

    return "\n\n".join(sections)


def extract_login_token(content: str | bytes, hidden_only: bool = True) -> str | None:
    """
    Token in the login page that must be sent with the credentials: the value
    of the first hidden ``<input>`` element (``rando`` on relays,
    ``temp_auth_token`` on RTACs, ``SELSESSID`` on the SEL-3620).

    Args:
        content: The login page
        hidden_only: If :obj:`False`, use the first ``<input>`` element if
            there isn't a hidden one (relays)

    Returns:
        The value of the element (empty string if it doesn't have one), or
        :obj:`None` if the page doesn't have an ``<input>`` element
    """
    soup = gen_soup(content)

    element = soup.find("input", type="hidden")
    if not element and not hidden_only:
        element = soup.find("input")

    if not element:
        return None

    value = element.get("value")
    return "" if value is None else str(value)


#: End of the path of the page a relay returns after a login:
#: ``login.html`` (SEL-351S), ``login_query.html`` (SEL-451), ``login`` (SEL-351)
RELAY_LOGIN_PAGES: Final = ("login_query.html", "login.html", "login")


def derive_relay_session_url(
    response_url: str, content: str | bytes = b"", base_url: str = ""
) -> str:
    """
    URL of the web session on a relay, from the response to the login
    request, e.g. ``http://192.0.2.1:80/protected/N1a2b3c4d/``. Pages are
    read by adding the command to it (``.../protected/N1a2b3c4d/ver.html``).

    - SEL-351S: the response is ``.../protected/N<session>/login.html``
    - SEL-451: the response is ``.../N<session>/login_query.html``,
      and ``protected/`` is added
    - SEL-351: the response is ``.../login``, and the session is in the
      first link in the page (``/N<session>/ver.html``)

    Args:
        response_url: URL of the response to the login request (after redirects)
        content: Body of the response
        base_url: URL of the device. If set, the response URL must be
            for the same host.

    Returns:
        The session URL, or an empty string if the login failed
        (``error=invalid`` in the URL) or the session can't be determined
        (no session link, a link to another host, or a redirect to another host)
    """
    if "error=invalid" in response_url:
        return ""

    parts = urlsplit(response_url)
    if base_url and (parts.hostname or "").lower() != (urlsplit(base_url).hostname or "").lower():
        log.warning(f"Relay login redirected to a different host ({parts.hostname})")
        return ""

    path = parts.path or "/"
    for page in RELAY_LOGIN_PAGES:
        if path.endswith(page):
            path = path[: -len(page)]
            break
    if not path.endswith("/"):
        path += "/"

    # The SEL-351 doesn't include the session in the response URL
    if "/N" not in path:
        link = gen_soup(content).find("a") if content else None
        href = str(link.get("href", "")) if link else ""
        href_parts = urlsplit(href)

        # Only accept a path on the relay, not a URL for another host
        if not href or href_parts.scheme or href_parts.netloc:
            log.debug(f"No session link in relay login response (link: {href!r})")
            return ""

        session = href_parts.path.replace("ver.html", "").lstrip("/")
        path = f"{path}{session}"
        if not path.endswith("/"):
            path += "/"

        if "/N" not in path:
            log.debug(f"Unexpected session link in relay login response: {href!r}")
            return ""

    # 451 (351S includes "protected" in the response url)
    if "protected/" not in path:
        path = path.replace("/N", "/protected/N", 1)

    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


# ---------------------------------------------------------------------------
# RTAC dashboard (device_info.sel, diagnostics.sel, post_summary.sel)
# ---------------------------------------------------------------------------


def parse_rtac_device_info(content: str | bytes | None) -> dict[str, str | list[str]]:
    """
    Parse the RTAC device information page (``device_info.sel``), e.g.
    ``Host Name``, ``Firmware Version``, ``Serial Number``.

    The ``Default Home Page`` setting is left out.
    """
    info = parse_html_table(content)
    info.pop("Default Home Page", None)  # Not useful, even in "extra"
    return info


def process_rtac_device_info(info: dict, dev: DeviceData) -> None:
    """
    Put the RTAC device information from :func:`parse_rtac_device_info`
    into the device data model.
    """
    if info.get("Host Name"):
        if not dev.name:
            dev.name = info["Host Name"]
        if not dev.hostname:
            dev.hostname = info["Host Name"]
        dev.id = info["Host Name"]

    # This sets:
    # - dev.description.model
    # - dev.description.product
    # - dev.firmware (multiple fields, including version)
    if info.get("Firmware Version"):
        process_fid(info["Firmware Version"], dev)

    # NOTE: this was added in RTAC firmware release R152
    # on 2023-11-09: https://selinc.com/api/download/138911/
    if info.get("Firmware Hash"):
        try:
            upper = info["Firmware Hash"].upper()
            if "SHA256" in upper:
                dev.firmware.hash.sha256 = upper.split(":")[-1].strip()
        except Exception as ex:
            log.warning(f"Failed to parse firmware hash '{info['Firmware Hash']}': {ex}")

    if info.get("BIOS Version") and not dev.boot_firmware.version:
        dev.boot_firmware.version = info["BIOS Version"]

    # This may or may not be an actual hash, and in some
    # cases it's definitely not, e.g. "B0AB".
    if info.get("Firmware Checksum"):
        process_firmware_checksum(info["Firmware Checksum"], dev)

    if info.get("Project ID"):
        proj_id = info["Project ID"]
        dev.logic.id = proj_id

        # This may or may not be an actual hash
        try:
            proj_id_hash = validate_hash(proj_id)
            dev.related.hash.add(proj_id_hash)
            if not dev.logic.hash.md5 and len(proj_id_hash) == 32:
                dev.logic.hash.md5 = proj_id_hash
        except ValueError:
            pass

    if info.get("Serial Number"):
        dev.serial_number = info["Serial Number"]
    if info.get("Part Number"):
        dev.part_number = info["Part Number"]

    if info.get("Device Name"):
        dev.name = info["Device Name"]

    if info.get("Device Location"):
        dev.geo.name = info["Device Location"]

    if info.get("Device Description") and not dev.description.description:
        dev.description.description = info["Device Description"]


#: Sizes in the RTAC diagnostics page, and their keys in the parsed data
RTAC_DIAGNOSTICS_SIZES: Final = {
    "Memory Usage (RAM)": "memory_usage_ram",
    "Memory Available (RAM)": "memory_available_ram",
    "Storage Usage": "storage_usage",
    "Storage Available": "storage_available",
}


def _diag_percent(value: str | list[str]) -> float:
    """``"35%"`` (or ``["<bar>", "35%"]``) => ``0.35``"""
    cells = value if isinstance(value, list) else [value]
    cell = next((c for c in cells if "%" in c), cells[-1])
    return float(cell.replace("%", "").strip()) / 100.0


def _diag_number(value: str | list[str]) -> float:
    cell = value[-1] if isinstance(value, list) else value
    match = re.search(r"-?\d+(?:\.\d+)?", cell)
    if not match:
        raise ValueError(f"not a number: {cell!r}")
    return float(match.group(0))


def _diag_size(value: str | list[str]) -> int:
    """
    Size in bytes, e.g. ``"524288 KB"`` => ``536870912``. Units are binary
    (1 KB = 1024 bytes). A number without a unit is returned as-is.
    """
    cell = (value[-1] if isinstance(value, list) else value).strip()
    if re.fullmatch(r"\d+", cell):
        return int(cell)
    return int(humanfriendly.parse_size(cell, binary=True))


def parse_rtac_diagnostics(content: str | bytes | None) -> dict:
    """
    Parse the RTAC diagnostics page (``diagnostics.sel`` or ``diag_report.sel``).

    Some values are converted:

    - ``main_task_usage`` and ``automation_task_usage``: fractions (``0.35`` for 35%)
    - ``power_source_voltage``: :class:`float`
    - ``memory_usage_ram``, ``memory_available_ram``, ``storage_usage``,
      ``storage_available``: bytes (the page shows KB)
    - ``number_of_users_logged_in``: :class:`int`

    Values that can't be converted are kept as-is under their label.
    The other values are as shown on the page, keyed by their label.
    """
    diag = parse_html_table(content)

    conversions = [
        ("Main Task Usage", "main_task_usage", _diag_percent),
        ("Automation Task Usage", "automation_task_usage", _diag_percent),
        ("Power Source Voltage", "power_source_voltage", _diag_number),
        *[(label, key, _diag_size) for label, key in RTAC_DIAGNOSTICS_SIZES.items()],
        (
            "Number of Users Logged In",
            "number_of_users_logged_in",
            lambda v: int(_diag_number(v)),
        ),
    ]

    for label, key, convert in conversions:
        if label not in diag:
            continue
        try:
            diag[key] = convert(diag[label])
            del diag[label]
        except Exception as ex:
            log.warning(
                f"Failed to parse RTAC diagnostics value '{label}' ({diag[label]!r}): {ex}"
            )

    return diag


def process_rtac_diagnostics(diag: dict, dev: DeviceData) -> dict:
    """
    Put the RTAC diagnostics from :func:`parse_rtac_diagnostics` into the
    device data model.

    Returns:
        The values that aren't in the data model (the memory and storage
        sizes, project name, and project modification time are removed)
    """
    diag = dict(diag)

    for key, attr in [
        ("memory_usage_ram", "memory_usage"),
        ("memory_available_ram", "memory_available"),
        ("storage_usage", "storage_usage"),
        ("storage_available", "storage_available"),
    ]:
        if diag.get(key):
            setattr(dev.hardware, attr, int(diag.pop(key)))

    if diag.get("Current Project"):
        dev.logic.name = str(diag.pop("Current Project")).strip()

    if diag.get("Modified Time of Project"):
        try:
            raw_ts = str(diag["Modified Time of Project"]).strip()
            dev.logic.last_updated = utils.parse_date(raw_ts)
            del diag["Modified Time of Project"]  # del here in case parsing fails
        except Exception as ex:
            log.warning(f"Failed to parse project modification timestamp: {ex}")

    return diag


def parse_rtac_post_summary(content: str | bytes | None) -> dict:
    """
    Parse the RTAC power-on self test (POST) summary page (``post_summary.sel``).
    """
    return parse_html_table(content)


def process_rtac_post_summary(summary: dict, dev: DeviceData) -> None:
    """
    Put the RTAC POST summary from :func:`parse_rtac_post_summary` into the
    device data model.
    """
    if "DDR2 SDRAM OK" in summary and not dev.hardware.memory_type:
        dev.hardware.memory_type = "ddr2_sdram"


# ---------------------------------------------------------------------------
# RTAC files (file_repository.sel)
# ---------------------------------------------------------------------------


def parse_rtac_files(content: str | bytes | None) -> dict[str, dict]:
    """
    Parse the list of files in the RTAC file repository (``file_repository.sel``).

    Returns:
        ``{"<name>": {"name": str, "size": int, "timestamp": datetime}}``.
        ``size`` and ``timestamp`` are left out if they can't be parsed.
    """
    files = {}

    for filename, values in parse_html_table(content).items():
        if not filename:
            continue

        file_data = {"name": str(filename)}

        if isinstance(values, list) and len(values) >= 2:
            size = _to_int(values[1])
            if size is not None:
                file_data["size"] = size
            else:
                log.warning(f"Invalid size for web file '{filename}': {values[1]!r}")

            try:
                timestamp = utils.parse_date(values[0])
                if timestamp:
                    file_data["timestamp"] = timestamp
            except Exception as ex:
                log.warning(f"Failed to parse web file timestamp for '{values[0]}': {ex}")
        else:
            log.warning(f"Unexpected values for web file '{filename}': {values!r}")

        files[filename] = file_data

    return files


def process_rtac_files(files: dict[str, dict], dev: DeviceData) -> None:
    """
    Put the RTAC file list from :func:`parse_rtac_files` into the device data model.
    """
    for filename in files:
        dev.related.files.add(str(filename))

    dev.extra["web_files"] = files


# ---------------------------------------------------------------------------
# User accounts (RTAC user_table.sel and SEL-3620 Users.sel)
# ---------------------------------------------------------------------------

#: Dates of a user account: created, last login, and password changed
_ACCOUNT_DATES_RE: Final = re.compile(
    r"(?P<created>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*"
    r"(?P<last_login>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*"
    r"(?P<password_changed>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
    re.ASCII,
)


def parse_web_accounts(content: str | bytes | None) -> tuple[dict[str, dict], list[str]]:
    """
    Parse the table of user accounts on a RTAC (``user_table.sel``) or a
    SEL-3620 (``Users.sel``), which have the same layout: the user name,
    the status, and the dates the account was created, last logged in, and
    had its password changed.

    Returns:
        The accounts, and the names of all users in the table (including
        users without any values). Each account has the ``status``, and the
        ``created``, ``last_login``, and ``password_changed`` dates if all
        three are there.
    """
    raw_accounts = parse_html_table(content)
    accounts = {}

    for username, values in raw_accounts.items():
        if not values:
            log.debug(f"No values for web user '{username}'")
            continue

        if isinstance(values, str):  # Row with just the user name and status
            accounts[username] = {"status": values}
            continue

        accounts[username] = {"status": values[0]}

        if len(values) >= 2:
            match = _ACCOUNT_DATES_RE.match(values[1])
            if match:
                accounts[username].update(match.groupdict())

    return accounts, list(raw_accounts)


def process_web_accounts(accounts: dict[str, dict], usernames: list[str], dev: DeviceData) -> None:
    """
    Put user accounts from :func:`parse_web_accounts` into the device data model.
    """
    # Add all users to related, even if they don't have any values
    for username in usernames:
        dev.related.user.add(username)

    for username, values in accounts.items():
        dev.store("users", User(name=username, extra=values), lookup="name")

    dev.extra["web_accounts"] = accounts


# ---------------------------------------------------------------------------
# RTAC Sequence of Events log (soe.csv)
# ---------------------------------------------------------------------------


class SoeRecord(NamedTuple):
    """A row of the RTAC Sequence of Events (SOE) log (``soe.csv``)."""

    #: Line number of the row in the file (the header is line 0)
    line: int

    #: Values, keyed by the column labels in the header
    fields: dict[str, str]

    #: The row as it is in the file
    original: str


def parse_soe_csv(text: str) -> list[SoeRecord]:
    """
    Parse the RTAC Sequence of Events log (``soe.csv``).

    The file is read with the :mod:`csv` module, so quoted values with commas,
    quotes, or line breaks work. Rows with less values than there are columns
    (e.g. a truncated download), or without a ``message``, are skipped.

    Columns that PEAT uses: ``creation_timestamp``, ``t_value`` (when the event
    occurred), ``category``, ``priority``, ``tag_name``, ``message``, ``host_name``,
    ``device_name``, ``device_guid``, ``comment``, and ``ack_operator_username``.
    """
    text = text.lstrip("\ufeff")  # Byte order mark (BOM)

    # The lines are split the same way for the csv reader and for the original
    # text of the rows (only on "\n"). str.splitlines() also splits on other
    # characters, e.g. "\r" or "\x0c" in a quoted message, which would put the
    # original text of the following rows on the wrong lines.
    raw_lines = io.StringIO(text).readlines()
    lines = [line.removesuffix("\n").removesuffix("\r") for line in raw_lines]
    reader = csv.reader(raw_lines)

    try:
        header = next(reader, None)
    except csv.Error as ex:
        log.warning(f"Failed to read the header of the SOE log: {ex}")
        return []
    if not header:
        return []

    labels = [label.strip() for label in header]
    if "message" not in labels:
        log.warning(f"No 'message' column in the SOE log (columns: {labels})")
        return []

    records = []
    previous = reader.line_num

    while True:
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error as ex:
            # e.g. a field larger than the csv module allows. The rest
            # of the file can't be read reliably, so stop here.
            log.warning(f"Failed to read the SOE log after line {previous}: {ex}")
            break

        start, previous = previous, reader.line_num
        if not any(cell.strip() for cell in row):
            continue

        original = "\n".join(lines[start : reader.line_num])
        if len(row) < len(labels):
            log.warning(
                f"Skipping SOE line {start} with {len(row)} columns "
                f"(expected {len(labels)}): {original!r}"
            )
            continue

        records.append(SoeRecord(start, dict(zip(labels, row, strict=False)), original))

    return records


def _soe_flag(value: str) -> str | bool:
    if value.lower() == "f":
        return False
    if value.lower() == "t":
        return True
    return value


def classify_soe_event(fields: dict[str, str]) -> dict:
    """
    Classify a RTAC Sequence of Events (SOE) record by its message, e.g. as
    a login, a failed login, a settings change, or a power up.

    Args:
        fields: Values of a record from :func:`parse_soe_csv`

    Returns:
        ``action``, ``category``, ``kind``, ``outcome``, ``type``, ``created``,
        and ``extra`` for the :class:`~peat.data.models.Event`, ``related``
        (users, IP addresses, and hosts in the record), and the
        ``project_name`` and ``firmware`` in the message (or :obj:`None`)
    """
    raw_msg = fields.get("message", "").strip()
    msg = raw_msg.lower()

    if fields.get("tag_name"):
        action = fields["tag_name"].split(".")[-1].lower().replace("_", "-")
    else:
        action = utils.clean_replace(msg, "-", " ,:")
        action = action.strip("-").replace("--", "-")

    category = {"host"}
    kind = {"event"}
    # TODO: set outcome to alarm state in some cases?
    outcome = ""  # "success", "failure", "unknown", ""
    event_type = {"info"}
    extra = {}
    related = {"user": set(), "ip": set(), "hosts": set()}
    project_name = None
    firmware = None

    if "user_changed_settings" in msg:
        category.update({"configuration", "host"})
        event_type.update({"change", "access", "user"})

        match = re.match(
            # "Time System modified settings"
            r"^(?P<username>.*) (changed|modified) settings$",
            # NOTE: want to make sure the username is case-sensitive
            raw_msg,
            flags=re.IGNORECASE,
        )

        if match:
            extra["user"] = match["username"].strip()
            related["user"].add(extra["user"])
        else:
            log.warning(
                f"user_changed_settings: Failed to match username regex for message '{raw_msg}'"
            )
            kind.add("pipeline_error")
    elif "password_changed" in msg:
        category.update({"configuration", "host"})
        event_type.update({"change", "access", "user", "connection"})
        match = re.match(
            # "admin changed password for admin"
            r"^(?P<username>.*) changed password for (?P<target>.*)$",
            # NOTE: want to make sure the username is case-sensitive
            raw_msg,
            flags=re.IGNORECASE,
        )

        if match:
            extra["acting_user"] = match["username"].strip()
            extra["target_user"] = match["target"].strip()
            related["user"].update({extra["acting_user"], extra["target_user"]})
        else:
            log.warning(
                f"password_changed: Failed to match username regex for message '{raw_msg}'"
            )
            kind.add("pipeline_error")
    elif "change" in msg:
        category.update({"configuration", "host"})
        event_type.add("change")
    elif "power" in msg and "up" in msg:
        event_type.add("start")
    elif "archive cleared" in msg:
        category.add("database")
        event_type.update({"change", "deletion"})
    elif "factory reset" in msg:
        category.update({"configuration", "host"})
        event_type.add("change")
    elif (
        "attempt failed" in msg
        or "login attempt from" in msg
        or "unauthorized" in msg
        or "unsuccessful_log_on_attempt" in msg
    ):
        category.update({"authentication", "network", "session"})
        event_type.update({"access", "connection", "denied", "user"})
        outcome = "failure"
        if "login attempt" in msg:
            action = "login-attempt"
            match = re.match(
                # "admin login attempt failed"
                # "Unknown login attempt from 192.168.1.1 failed"
                r"^(?P<username>.*) login attempt (from (?P<host>[:\.\w]+) )?failed.*",
                # NOTE: want to make sure the username is case-sensitive
                raw_msg,
                flags=re.IGNORECASE,
            )

            if match:
                extra["user"] = match["username"].strip()
                related["user"].add(extra["user"])

                host = match.groupdict().get("host")
                if host and utils.is_ip(host) and not (":" in host and host.count(".") == 3):
                    related["ip"].add(host)
                elif host:
                    related["hosts"].add(host)
            else:
                log.warning(
                    f"login_attempt: Failed to match username regex for message '{raw_msg}'"
                )
                kind.add("pipeline_error")
    # NOTE: msg is lowercase, so "log_on" (this was "log_On", which never matched)
    elif "logged o" in msg or "login" in msg or "log_on" in msg:
        category.update({"authentication", "network", "session"})
        event_type.update({"access", "allowed", "connection", "user"})
        outcome = "success"

        # "<User> logged off device via Web"
        # "<User> logged on device via ODBC"
        match = re.match(
            r"^(?P<username>.*) logged (?P<direction>off|on) device via (?P<service>.*)$",
            # NOTE: want to make sure the username is case-sensitive
            raw_msg,
        )

        if match:
            extra["logon_user"] = match["username"].strip()
            related["user"].add(extra["logon_user"])
            extra["logon_service"] = match["service"].strip().lower()
            if extra["logon_service"] in ["odbc", "web"]:
                category.add("database")
            action = f"user-logged-{match['direction']}-via-{extra['logon_service']}"
        else:
            log.warning(f"logged_on: Failed to match username regex for message '{raw_msg}'")
            kind.add("pipeline_error")
    elif "application_status" in msg:
        # "The rtacsnmpmgr application has been restarted"
        # TODO: extract application name and put in metadata
        category.update({"process", "host"})
        outcome = "unknown"
        event_type.add("change")
        if "restarted" in msg:
            action = "application-restarted"
    elif "firmware: " in msg or "project: " in msg or "power_up_description" in msg:
        kind.add("state")
        action = "rtac-started"
        # The original message is used, since the project name and
        # firmware ID are case-sensitive (e.g. "SEL-3530-R148-...")
        project = re.search(r"project:\s*(.+)$", raw_msg, re.IGNORECASE)
        if project:
            project_name = project.group(1).strip()
            extra["project_name"] = project_name
        fw = re.search(r"firmware:\s*([^,]+)", raw_msg, re.IGNORECASE)
        if fw:
            firmware = fw.group(1).strip()
            extra["firmware"] = firmware

    # TODO: change time parsing if 't_dst_enabled' is 't' instead of 'f'?
    #   In other words, if daylight savings time is enabled on device
    # t_value: when event actually occurred
    # this value can sometimes be 'f' for some reason
    created = None
    t_value = fields.get("t_value", "").strip()
    if t_value and len(t_value) > 1:
        created = utils.parse_date(t_value)

    # TODO: add a 3rd timestamp to Event data model for this thing
    #   creation_timestamp: when log was last generated
    #       on RTAC (recovered/rebuilt?)
    ct = fields.get("creation_timestamp", "").strip()
    if ct and len(ct) > 1:
        ingest_ts = utils.parse_date(ct)
        if ingest_ts:
            extra["creation_timestamp"] = ingest_ts

    for key in [
        "category",
        "priority",
        "tag_name",
        "host_name",
        "device_name",
        "device_guid",
        "comment",
        "ack_operator_username",
    ]:
        val = fields.get(key, "").strip()
        if val:
            extra[key] = _soe_flag(val)

    for key in ["device_name", "host_name"]:
        if key in extra:
            related["hosts"].add(str(extra[key]))

    return {
        "action": action,
        "category": category,
        "kind": kind,
        "outcome": outcome,
        "type": event_type,
        "created": created,
        "extra": extra,
        "related": related,
        "project_name": project_name,
        "firmware": firmware,
    }


def _newest_soe_info(infos: list[dict]) -> dict | None:
    """
    The classified SOE record that occurred last (``created``). Records
    without a time are older than records with one, and if the times are
    the same (or unknown), the record that is later in the file is used.
    """

    def _key(item: tuple[int, dict]) -> tuple[float, int]:
        index, info = item
        try:
            created = info["created"].timestamp() if info["created"] else float("-inf")
        except (OverflowError, OSError, ValueError):
            created = float("-inf")
        return created, index

    if not infos:
        return None
    return max(enumerate(infos), key=_key)[1]


def process_soe_events(records: list[SoeRecord], dev: DeviceData) -> None:
    """
    Put the RTAC Sequence of Events (SOE) records from :func:`parse_soe_csv`
    into the device data model, as :class:`~peat.data.models.Event` objects
    with the dataset ``web_syslog``.

    The log is a history, e.g. it has the firmware from before an upgrade.
    So the firmware and project in the RTAC start messages are only used
    for the device if it doesn't have them yet (e.g. from
    ``device_info.sel``), and only from the newest message. The values
    of each message are in the ``extra`` of its event.
    """
    module = "SELRTAC" if not dev._module else dev._module.__name__
    with_firmware = []
    with_project = []

    for record in records:
        info = classify_soe_event(record.fields)

        dev.related.user.update(info["related"]["user"])
        dev.related.ip.update(info["related"]["ip"])
        dev.related.hosts.update(info["related"]["hosts"])

        if info["firmware"]:
            with_firmware.append(info)
        if info["project_name"]:
            with_project.append(info)

        event = Event(
            action=info["action"],
            category=info["category"],
            created=info["created"],
            dataset="web_syslog",
            kind=info["kind"],
            message=record.fields["message"].strip(),
            extra=info["extra"],
            module=module,
            original=record.original,
            outcome=info["outcome"],
            provider=dev.name if dev.name else dev.get_id(),
            sequence=record.line,
            type=info["type"],
        )

        dev.store("event", event)

    newest = _newest_soe_info(with_project)
    if newest and not dev.logic.name:
        dev.logic.name = newest["project_name"]

    newest = _newest_soe_info(with_firmware)
    if newest and not dev.firmware.id and not dev.firmware.version:
        process_fid(newest["firmware"], dev)


# ---------------------------------------------------------------------------
# SEL-3620 pages
# ---------------------------------------------------------------------------


def parse_gateway_index(content: str | bytes | None) -> dict:
    """
    Parse the SEL-3620 dashboard (``index.sel``).

    The firmware version is under ``FID String`` in the cell with the
    ``Version Information``, and is returned as ``Firmware Version``.
    ``Version Information`` is the text of that cell (empty if there isn't one).
    """
    info = parse_html_table(content)
    version_info = {"Version Information": ""}

    for key in info:
        if key.startswith("Version Information"):
            lines = key.split("\n")
            for i, line in enumerate(lines[:-1]):
                if "FID String" in line:
                    version_info["Firmware Version"] = lines[i + 1].strip()
                    break
            version_info["Version Information"] = key
            break

    info.update(version_info)
    return info


def parse_gateway_syslog(content: str | bytes | None) -> list[dict[str, str]]:
    """
    Parse the SEL-3620 system log report (``SysLogReport.sel``).

    The rows of the ``syslogReport`` table are newest first, and are returned
    oldest first. Each row is a :class:`dict` of the cells keyed by their CSS
    class (``recvTime``, ``tag``, ``severity``, ``facility``, ``msg``), and
    the ``id`` of the row (``id_000102`` => ``"000102"``). The first row
    (sorting controls) and the ``actions`` cells are skipped.
    """
    if not content:
        return []

    table = gen_soup(content).find("table", id="syslogReport")
    if not table:
        log.warning("No 'syslogReport' table in the system log page")
        return []

    logs = []
    # skip first row, it has UI elements for sorting, etc.
    for row in reversed(table.find_all("tr")[1:]):
        entry = {}
        for col in row.find_all("td"):
            classes = col.get("class") or []
            if classes and classes[0] != "actions":
                entry[classes[0]] = col.get_text()

        if row.get("id"):
            entry["id"] = str(row["id"]).split("_")[-1]  # id='id_######'

        if entry:
            logs.append(entry)

    return logs


def process_gateway_syslog(logs: list[dict[str, str]], dev: DeviceData) -> None:
    """
    Put the SEL-3620 system log from :func:`parse_gateway_syslog` into the
    device data model, as :class:`~peat.data.models.Event` objects with the
    dataset ``gateway_system_logs``.
    """
    for entry in logs:
        event = Event(
            created=utils.parse_date(entry["recvTime"]) if entry.get("recvTime") else None,
            dataset="gateway_system_logs",
            id=entry.get("id", ""),
            message=entry.get("msg", "").strip(),
            original=entry.get("msg", ""),
            provider=dev.name if dev.name else dev.get_id(),
            sequence=_to_int(entry["id"]) if entry.get("id") else None,
            severity=entry.get("severity", ""),
            extra={key: entry[key] for key in ("tag", "facility") if key in entry},
        )
        dev.store("event", event)


def parse_x509_export_links(content: str | bytes | None) -> list[str]:
    """
    Links of the ``Export`` buttons on the SEL-3620 X.509 certificates
    page (``X509.sel``), without duplicates, in order. The links are as
    they are in the page (relative or absolute).
    """
    if not content:
        return []

    links = []
    for link in gen_soup(content).find_all("a", class_="listButton"):
        href = link.get("href")
        if href and link.get_text().strip() == "Export" and str(href) not in links:
            links.append(str(href))

    return links


class GatewayPage(NamedTuple):
    """A page of the SEL-3620 web interface that PEAT reads."""

    #: Name of the page, e.g. ``LDAP.sel``
    page: str

    #: Key for the data in ``dev.extra``
    extra_key: str

    #: Key for the data in the result of the ``SELHTTP.gateway_*`` method
    result_key: str

    #: Description for log messages
    description: str

    #: If an empty response is a failure
    require_content: bool = False


#: SEL-3620 pages that PEAT reads, but doesn't parse yet. The pages are saved
#: (``http_files/``), and ``dev.extra`` gets an empty :class:`dict` for each.
#: Keyed by the name of the method of :class:`~peat.modules.sel.sel_http.SELHTTP`
#: without the ``gateway_`` prefix (e.g. ``SELHTTP.gateway_ldap()``).
GATEWAY_PAGES: Final[dict[str, GatewayPage]] = {
    "ldap": GatewayPage("LDAP.sel", "ldap", "ldap_data", "LDAP settings"),
    "radius": GatewayPage("RADIUS.sel", "radius_settings", "radius_settings", "RADIUS settings"),
    "local_groups": GatewayPage(
        "LocalGroups.sel", "local_groups", "local_groups", "local group configuration"
    ),
    "network_settings": GatewayPage(
        "NetworkSettings.sel",
        "gateway_network_settings",
        "gateway_network_settings",
        "network settings",
    ),
    "static_routes": GatewayPage(
        "StaticRoutes.sel", "static_routes", "static_routes", "static route configuration"
    ),
    "firewall": GatewayPage(
        "Firewall.sel", "firewall_settings", "firewall_settings", "firewall settings"
    ),
    "nat": GatewayPage("NAT.sel", "nat_settings", "nat_settings", "NAT settings"),
    "hosts": GatewayPage("Hosts.sel", "gateway_hosts", "gateway_hosts", "host configuration"),
    "snmp": GatewayPage("SNMP.sel", "snmp_settings", "snmp_settings", "SNMP settings"),
    "port_settings": GatewayPage(
        "SerialPortSettings.sel", "port_settings", "port_settings", "serial port settings"
    ),
    "port_profiles": GatewayPage(
        "SerialPortProfiles.sel", "port_profiles", "port_profiles", "serial port profiles"
    ),
    "port_mappings": GatewayPage(
        "PortMappings.sel", "port_mappings", "port_mappings", "port mappings"
    ),
    "ipsec": GatewayPage("IPsec.sel", "ipsec", "ipsec", "IPsec connections"),
    "macsec": GatewayPage("MACsec.sel", "macsec", "macsec", "MACsec connections"),
    "allowed_clients": GatewayPage(
        "AllowedClients.sel", "allowed_clients", "allowed_clients", "allowed clients"
    ),
    "sshkey": GatewayPage("SSH_Host_Key.sel", "ssh_host_key", "ssh_host_key", "SSH host keys"),
    "password_management": GatewayPage(
        "PasswordManagement.sel",
        "password_management",
        "password_management",
        "password management messages",
    ),
    "diagnostics": GatewayPage(
        "Diagnostics.sel",
        "gateway_diagnostics",
        "gateway_diagnostics",
        "diagnostic data",
        require_content=True,
    ),
    "proxy_reports": GatewayPage(
        "ProxyReports.sel", "proxy_reports", "proxy_reports", "proxy reports"
    ),
}


__all__ = [
    "GATEWAY_PAGES",
    "GatewayPage",
    "SoeRecord",
    "classify_soe_event",
    "derive_relay_session_url",
    "extract_login_token",
    "extract_pre_sections",
    "extract_pre_text",
    "parse_gateway_index",
    "parse_gateway_syslog",
    "parse_html_table",
    "parse_rtac_device_info",
    "parse_rtac_diagnostics",
    "parse_rtac_files",
    "parse_rtac_post_summary",
    "parse_soe_csv",
    "parse_web_accounts",
    "parse_x509_export_links",
    "process_gateway_syslog",
    "process_rtac_device_info",
    "process_rtac_diagnostics",
    "process_rtac_files",
    "process_rtac_post_summary",
    "process_soe_events",
    "process_web_accounts",
    "read_html",
]
