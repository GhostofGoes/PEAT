"""
Discovery of the engineering access paths of a SEL RTAC.

An RTAC can give engineers access to the IEDs (e.g. relays) it communicates
with, so they connect to the RTAC instead of to each IED. ACSELERATOR RTAC
has two ways to set this up:

- An **access point** is a port the RTAC listens on, with a
  ``Network Connection Type`` (Telnet, Raw TCP, SSH, ...) and a
  ``Local Port Number``. An **access point router** connects an access point
  (its source) to the access point of a device (its destination). Each SEL
  device has two of these: ``<Device>_<Protocol>_TAP`` is a transparent
  connection, which the RTAC interleaves with its own polling of the device,
  and ``<Device>_<Protocol>_AP`` is a direct transparent connection, which
  stops the RTAC's polling of the device (so SCADA data from it stops) while
  it's in use.
- A **SEL server** with the connection type ``Server - Ethernet Tunneled
  Serial`` (firmware R134 and newer) listens on one TCP port, the ``Server IP
  Port``, using the ``Serial Tunneling Mode`` (Telnet, Raw TCP, SSL/TLS or
  SSH). A client logs in to the RTAC if ``Perform Authentication`` is set
  (always for SSH), then the RTAC's ``WHO`` command lists the SEL devices and
  ``PORT <n>`` opens a transparent connection to one of them, if
  ``Enable Port Command`` is set. The ``n`` is the serial port number of a
  serial device, or the ``Virtual Port Number`` of an Ethernet device. The
  ``Termination String`` (Ctrl-D by default) ends the connection.

The functions in this module find these paths in the configuration of an
RTAC: in a project export (the ``device_info`` from
:mod:`~peat.modules.sel.rtac_parse`, with :func:`discover_from_export`), or
in the tables PEAT reads from the RTAC's PostgreSQL database (with
:func:`discover_from_postgres`). They don't connect to anything.
:class:`~peat.modules.sel.sel_rtac.SELRTAC` adds the results to the device
data, as the ``extra.engineering_access`` list (one entry per path, with the
keys in :data:`ENGINEERING_ACCESS_KEYS`) and as services.

Settings are matched by name without regard to case, spaces or punctuation,
so ``Local Port Number`` in an export matches a ``local_port_number`` column
in the database. The names of the database columns are not public, so the
database discovery uses the setting names and a few common variations.

The setting names and behaviors are from these public SEL documents:

- HD2014-34, "SEL-3530 RTAC Hands-On Session", Engineering Access Exercise
  (access points, access point routers and the SEL server)
- LWP0018-01, "Leveraging Security - Using the SEL RTAC's Built-In Security
  Features", Section 5 (the SEL server settings and session)
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Final, Literal

#: Keys of each entry in ``extra.engineering_access``, in order.
#: Refer to :meth:`Listener.entries`.
ENGINEERING_ACCESS_KEYS: Final[tuple[str, ...]] = (
    "name",
    "rtac_ip",
    "tcp_port",
    "transport",
    "kind",
    "sel_port",
    "device_name",
    "route",
    "needs_rtac_login",
    "termination_string",
    "source",
)

#: Transports of the TCP tunnels in ``extra.engineering_access``
TUNNEL_TRANSPORTS: Final[frozenset[str]] = frozenset({"telnet", "raw", "ssh", "tls"})

#: Default ``Termination String`` of a SEL server (Ctrl-D)
DEFAULT_TERMINATION_STRING: Final[str] = "\x04"

#: Prefix of the names the RTAC gives to its engineering access objects,
#: e.g. ``Eng_Access_40`` in the ``remote_devices`` table
ENG_ACCESS_PREFIX: Final[str] = "Eng_Access_"

#: Tables of the RTAC database (``schema_fw``) with engineering access
#: settings, for :func:`discover_from_postgres`. The rows of the tables of
#: one kind of object (e.g. access points) are joined to each other, and to
#: the name tables, by their ID columns (:data:`PG_JOIN_COLUMNS`). Each
#: access point, SEL server or SEL device has a row in one of the tables
#: of its kind.
PG_ACCESS_POINT_TABLES: Final[tuple[str, ...]] = (
    "access_points_mview",
    "access_point_ethernet_settings",
    "access_points",
)
PG_ROUTER_TABLES: Final[tuple[str, ...]] = ("access_point_routers",)
PG_SEL_SERVER_TABLES: Final[tuple[str, ...]] = (
    "sel_server_maps_mview",
    "sel_server_ethernet_settings",
    "sel_server_common_settings",
)
PG_SEL_CLIENT_TABLES: Final[tuple[str, ...]] = (
    "sel_client_maps_mview",
    "sel_client_common_settings",
    "sel_client_ethernet_settings",
)
#: Tables that only add settings to SEL devices (e.g. the serial port
#: number). They also have rows for other devices and for unused ports, so
#: a row that doesn't join a row of :data:`PG_SEL_CLIENT_TABLES` isn't used.
PG_SERIAL_PORT_TABLES: Final[tuple[str, ...]] = (
    "sel_virtual_ports",
    "serial_port_connections",
    "serial_ports",
)
#: Tables that only add the TCP port to access points and SEL servers.
#: They also have rows for other servers (e.g. DNP3), so a row that doesn't
#: join a row of :data:`PG_ACCESS_POINT_TABLES` or
#: :data:`PG_SEL_SERVER_TABLES` isn't used.
PG_LOCAL_PORT_TABLES: Final[tuple[str, ...]] = (
    "local_tcp_network_port_connections",
    "local_tcp_network_ports",
)
#: Tables with the names of connections and devices
PG_NAME_TABLES: Final[tuple[str, ...]] = (
    "connections",
    "remote_connections",
    "remote_devices",
    "access_points",
)
#: All of the tables :func:`discover_from_postgres` uses
PG_TABLES: Final[frozenset[str]] = frozenset(
    PG_ACCESS_POINT_TABLES
    + PG_ROUTER_TABLES
    + PG_SEL_SERVER_TABLES
    + PG_SEL_CLIENT_TABLES
    + PG_SERIAL_PORT_TABLES
    + PG_LOCAL_PORT_TABLES
    + PG_NAME_TABLES
)

#: Columns (normalized, refer to :func:`normalize`) that join the rows of
#: the database tables. Two rows are joined if they have the same value in
#: one of these columns, and no different values in any of these columns or
#: in :data:`PG_CHECK_COLUMNS`. Generic columns like ``id`` or
#: ``project_id`` are not used, since rows of different tables with the
#: same value of these are usually not related.
PG_JOIN_COLUMNS: Final[tuple[str, ...]] = (
    "connectionid",
    "accesspointid",
    "remotedeviceid",
    "remoteconnectionid",
    "selserverid",
    "selclientid",
    "serialportid",
    "localtcpnetworkportid",
)
#: Columns that don't join two rows (they may have the same value in every
#: row, e.g. if ``device_id`` is the ID of the RTAC), but rows with different
#: values in them are not joined
PG_CHECK_COLUMNS: Final[tuple[str, ...]] = ("deviceid",)

# --- Setting names (and common variations), by what they are ---
_NAME = ("Name", "Device Name", "Connection Name", "Access Point Name", "Router Name")
_AP_TYPE = (
    "Network Connection Type",
    "Network Connection",
    "Connection Type",
    "Serial Tunneling Mode",
    "Tunneling Mode",
)
_AP_PORT = (
    "Local Port Number",
    "Local Port",
    "Local TCP Port",
    "Local IP Port",
    "Listen Port",
    "Port Number",
    "TCP Port",
)
_SERVER_PORT = (
    "Server IP Port",
    "Server Port",
    "Local Port Number",
    "Local TCP Port",
    "Local IP Port",
    "TCP Port",
    "Port Number",
)
_SERVER_MODE = ("Serial Tunneling Mode", "Tunneling Mode", "Tunnel Mode")
_AUTHENTICATION = ("Perform Authentication", "Authentication", "Require Authentication")
_TERMINATION = ("Termination String", "Termination")
_PORT_COMMAND = ("Enable Port Command", "Port Command")
_VIRTUAL_PORT = ("Virtual Port Number", "Virtual Port", "SEL Virtual Port Number")
_SERIAL_PORT = (
    "Serial Port Number",
    "Serial Port",
    "Communications Port",
    "Comm Port",
    "COM Port",
    "Port",
)
# Settings of a SEL server that are kept in the extra of its service
_SERVER_EXTRA = {
    "virtual_port_number": _VIRTUAL_PORT,
    "disable_remote_access": ("Disable Remote Access",),
    "allow_anonymous_clients": ("Allow Anonymous SEL IP Clients", "Allow Anonymous Clients"),
    "enable_file_transfer_monitor": ("Enable File Transfer Monitor",),
    "verify_ssl_certificate": ("Verify SSL Certificate",),
    "pre_termination_timeout": ("Pre-Termination Timeout",),
    "post_termination_timeout": ("Post-Termination Timeout",),
}
_SERVER_BOOL_EXTRA = {
    "disable_remote_access",
    "allow_anonymous_clients",
    "enable_file_transfer_monitor",
    "verify_ssl_certificate",
}
_CLIENT_IPS = ("Client IP Address", "Client IP Addresses")
_LEGACY_PORT_COMMAND = ("Enable_Legacy_Port_Command", "Enable Legacy Port Command")
_LEGACY_PORT_COMMAND_ID = ("Legacy_Port_Command_ID", "Legacy Port Command ID")

# Prefixes of the source and destination columns of access point routers
_ROUTER_ROLES = (("source", "Source"), ("src", "Source"), ("destination", "Destination"))
_ROUTER_ROLES += (("dest", "Destination"), ("dst", "Destination"))

_CTRL_RE = re.compile(r"<\s*CTRL\s*-\s*([@A-Z\[\\\]^_])\s*>|\^([@A-Z\[\\\]^_])", re.IGNORECASE)
_NAMED_CHARS = {
    "CR": "\r",
    "LF": "\n",
    "ESC": "\x1b",
    "TAB": "\t",
    "NUL": "\x00",
    "SP": " ",
}
_NAMED_RE = re.compile(r"<\s*(" + "|".join(_NAMED_CHARS) + r")\s*>", re.IGNORECASE)
_PORT_NUMBER_RE = re.compile(
    r"^\s*(?:com|port|serial|ser|p)?[\s_\-]*0*(\d{1,3})\s*$", re.IGNORECASE
)


@dataclass
class Destination:
    """
    A device that a :class:`Listener` reaches.
    """

    name: str | None
    """Name of the destination as configured, e.g. ``Feeder_1_SEL_TAP``."""

    device_name: str | None
    """Name of the device in the RTAC configuration, e.g. ``Feeder_1``."""

    route: Literal["interleaved", "direct"] | None = None
    """
    ``interleaved`` for a transparent (``_TAP``) connection, ``direct`` for
    a direct transparent (``_AP``) connection, or :obj:`None` if unknown.
    """

    router: str | None = None
    """Name of the access point router, for access points."""

    sel_port: int | None = None
    """Port number of the device for the SEL server ``PORT`` command."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Other settings of the route, e.g. of the access point router."""

    def summary(self) -> dict[str, Any]:
        """The destination as a dict, for the ``extra`` of a service."""
        result = {
            "name": self.name,
            "device_name": self.device_name,
            "route": self.route,
            "router": self.router,
            "sel_port": self.sel_port,
        }
        result.update(self.extra)
        return {key: value for key, value in result.items() if value is not None}


@dataclass
class Listener:
    """
    A port the RTAC listens on for engineering access: an access point,
    or a SEL server.
    """

    kind: Literal["access_point", "sel_server"]
    name: str
    port: int | None
    """TCP or UDP port, or :obj:`None` if it isn't configured."""

    transport: str | None
    """
    ``telnet``, ``raw``, ``ssh``, ``tls``, ``udp``, or :obj:`None`
    if the connection type isn't known.
    """

    connection_type: str = ""
    """The configured connection type or tunneling mode, e.g. ``Raw TCP``."""

    needs_rtac_login: bool = False
    termination_string: str | None = None
    port_command: bool = True
    """If the SEL server ``PORT`` command is enabled."""

    destinations: list[Destination] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)
    """Other settings, for the ``extra`` of the service."""

    source: str = "export"
    """Where the listener was found: ``export`` or ``postgres``."""

    @property
    def is_tunnel(self) -> bool:
        """If this is a TCP port with a transport PEAT can use for a tunnel."""
        return bool(self.port) and self.transport in TUNNEL_TRANSPORTS

    @property
    def gives_access(self) -> bool:
        """If this listener reaches any devices (refer to :meth:`entries`)."""
        if not self.is_tunnel:
            return False
        if self.kind == "sel_server":
            return self.port_command
        return bool(self.destinations)

    def add_destination(self, destination: Destination) -> None:
        """Add a destination, unless it's already there."""
        if destination not in self.destinations:
            self.destinations.append(destination)

    def entries(self, rtac_ip: str | None) -> list[dict[str, Any]]:
        """
        The ``extra.engineering_access`` entries for this listener, one for
        each device it reaches. Each entry has the keys in
        :data:`ENGINEERING_ACCESS_KEYS`:

        - ``name``: the destination as configured in the access point router
          (e.g. ``Feeder_1_SEL_TAP``), or the name of the SEL server
        - ``rtac_ip``: IP address of the RTAC to connect to
        - ``tcp_port``: TCP port on the RTAC
        - ``transport``: ``telnet``, ``raw``, ``ssh`` or ``tls``
        - ``kind``: ``access_point`` (the port connects directly to the device),
          or ``sel_server`` (send ``PORT <sel_port>`` to reach the device)
        - ``sel_port``: port number for the SEL server ``PORT`` command
        - ``device_name``: name of the device in the RTAC configuration
        - ``route``: ``interleaved`` (``_TAP``), ``direct`` (``_AP``), or :obj:`None`
        - ``needs_rtac_login``: if the RTAC asks for its own login first
        - ``termination_string``: what ends the session (SEL servers only)
        - ``source``: ``export`` or ``postgres``

        An access point without a route, a SEL server without the ``PORT``
        command, and a listener whose port or transport isn't known have no
        entries. A SEL server with no known SEL devices has one entry with
        no ``sel_port`` or ``device_name``, since ``WHO`` lists its devices.
        """
        if not self.gives_access:
            return []

        destinations = self.destinations
        if self.kind == "sel_server" and not destinations:
            destinations = [Destination(name=None, device_name=None, route="interleaved")]

        sel_server = self.kind == "sel_server"
        entries = []
        for dest in destinations:
            entry = {
                "name": self.name if sel_server else (dest.name or dest.device_name),
                "rtac_ip": rtac_ip if rtac_ip else None,
                "tcp_port": self.port,
                "transport": self.transport,
                "kind": self.kind,
                "sel_port": dest.sel_port if sel_server else None,
                "device_name": dest.device_name,
                "route": dest.route,
                "needs_rtac_login": self.needs_rtac_login,
                "termination_string": self.termination_string,
                "source": self.source,
            }
            entries.append({key: entry[key] for key in ENGINEERING_ACCESS_KEYS})
        return entries


@dataclass
class Discovery:
    """
    Results of :func:`discover_from_export` or :func:`discover_from_postgres`.
    """

    listeners: list[Listener] = field(default_factory=list)
    engineering_access_devices: list[str] = field(default_factory=list)
    """Names of the RTAC's engineering access objects, e.g. ``Eng_Access_40``."""

    warnings: list[str] = field(default_factory=list)
    """Problems with the configuration, to log."""

    notes: list[str] = field(default_factory=list)
    """Details of the configuration, to log at the debug level."""

    def entries(self, rtac_ip: str | None) -> list[dict[str, Any]]:
        """The ``extra.engineering_access`` entries of all of the listeners."""
        return merge_entries([], [e for lst in self.listeners for e in lst.entries(rtac_ip)])

    def add_eng_access_name(self, name: Any) -> None:
        if isinstance(name, str) and name.startswith(ENG_ACCESS_PREFIX):
            if name not in self.engineering_access_devices:
                self.engineering_access_devices.append(name)


# ---------- Value conversion ----------


def normalize(name: Any) -> str:
    """Lowercase letters and digits of a setting or column name, for matching."""
    return re.sub(r"[^0-9a-z]", "", str(name).lower())


def get_setting(settings: dict, names: Iterable[str], default: Any = None) -> Any:
    """
    Value of the first setting in ``names`` that's in ``settings`` and isn't
    empty. Names are compared with :func:`normalize`.
    """
    if not isinstance(settings, dict):
        return default
    normalized = {}
    for key, value in settings.items():
        normalized.setdefault(normalize(key), value)
    for name in names:
        value = normalized.get(normalize(name))
        if value is not None and not (isinstance(value, str) and not value.strip()):
            return value
    return default


def to_port(value: Any) -> int | None:
    """TCP or UDP port number (1 to 65535), or :obj:`None`."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, int) and 0 < value < 65536:
        return value
    return None


def to_bool(value: Any, default: bool | None = None) -> bool | None:
    """Boolean value of a setting (``True``, ``"true"``, ``"Y"``, 1, ...)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "t", "yes", "y", "1", "on", "enabled"}:
            return True
        if text in {"false", "f", "no", "n", "0", "off", "disabled"}:
            return False
    return default


def to_text(value: Any) -> str:
    """The setting as text, or ``""`` if it isn't text."""
    return value.strip() if isinstance(value, str) else ""


def port_number(value: Any) -> int | None:
    """
    Port number of a serial or virtual port, e.g. ``3``, ``"Com_03"``,
    ``"COM3"`` or ``"Port 3"`` (1 to 999), or :obj:`None`.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 1000 else None
    if isinstance(value, str):
        match = _PORT_NUMBER_RE.match(value)
        if match:
            number = int(match.group(1))
            return number if number > 0 else None
    return None


def transport_from_text(value: Any) -> str | None:
    """
    Transport of an access point ``Network Connection Type`` or a
    ``Serial Tunneling Mode``: ``telnet``, ``raw``, ``ssh``, ``tls`` or
    ``udp``, or :obj:`None` if it isn't known (e.g. a number from the database).
    """
    text = to_text(value).lower()
    if not text:
        return None
    if "udp" in text:
        return "udp"
    if "ssh" in text:
        return "ssh"
    if "ssl" in text or "tls" in text:
        return "tls"
    if "telnet" in text:
        return "telnet"
    if "raw" in text or "tcp" in text:
        return "raw"
    return None


def parse_termination_string(value: Any) -> str | None:
    """
    Convert a ``Termination String`` setting to the characters it stands
    for: ``<CTRL-D>`` (or ``^D``) is ``"\\x04"``, and ``<CR>``, ``<LF>``,
    ``<ESC>``, ``<TAB>``, ``<NUL>`` and ``<SP>`` are those characters. Other
    text is used as-is. Returns :obj:`None` if the setting is empty.
    """
    if not isinstance(value, str) or not value:
        return None
    text = _CTRL_RE.sub(lambda m: chr(ord((m.group(1) or m.group(2)).upper()) - 64), value)
    return _NAMED_RE.sub(lambda m: _NAMED_CHARS[m.group(1).upper()], text)


def route_from_type(value: Any) -> Literal["interleaved", "direct"] | None:
    """
    Route of a destination from its type (``TAP`` or ``AP``),
    or from words like ``interleaved`` or ``direct``.
    """
    text = to_text(value).lower()
    if not text:
        return None
    if text == "tap" or "interleav" in text:
        return "interleaved"
    if text == "ap" or "direct" in text:
        return "direct"
    if "transparent" in text:
        return "interleaved"
    return None


def client_ips(value: Any) -> list[str]:
    """IP addresses in a ``Client IP Address`` setting (a comma-separated list)."""
    ips = []
    for part in re.split(r"[,;\s]+", to_text(value)):
        try:
            ips.append(str(ipaddress.ip_address(part)))
        except ValueError:
            continue
    return ips


def merge_entries(existing: list[dict], new: Iterable[dict]) -> list[dict]:
    """
    Add engineering access entries to a list, without duplicates,
    sorted by port, SEL port and device name.
    """
    merged = [dict(e) for e in existing if isinstance(e, dict)]
    for entry in new:
        if entry not in merged:
            merged.append(dict(entry))
    merged.sort(
        key=lambda e: (
            e.get("tcp_port") or 0,
            e.get("sel_port") or 0,
            str(e.get("device_name") or ""),
            str(e.get("name") or ""),
            str(e.get("source") or ""),
        )
    )
    return merged


#: Keys that identify a path to a device in ``extra.engineering_access``,
#: for :func:`unique_paths`
PATH_KEYS: Final[tuple[str, ...]] = (
    "rtac_ip",
    "tcp_port",
    "transport",
    "kind",
    "sel_port",
    "device_name",
    "route",
)


def unique_paths(entries: Iterable[dict]) -> list[dict]:
    """
    Copies of engineering access entries, with one entry for each path to
    a device (the same values of :data:`PATH_KEYS`), e.g. if a path is in
    both a project export and the database. The first entry of a path is
    kept, with ``needs_rtac_login`` set if any of the entries of the path
    have it, and values that are :obj:`None` filled in from the others.
    """
    paths: dict[tuple, dict] = {}
    for entry in entries:
        key = tuple(str(entry.get(k)) for k in PATH_KEYS)
        if key not in paths:
            paths[key] = dict(entry)
            continue
        kept = paths[key]
        kept["needs_rtac_login"] = bool(kept.get("needs_rtac_login")) or bool(
            entry.get("needs_rtac_login")
        )
        for name, value in entry.items():
            if kept.get(name) is None:
                kept[name] = value
    return list(paths.values())


# ---------- Kinds of devices ----------


def is_access_point(device: dict) -> bool:
    """If a device from a project export is an access point."""
    return "accesspoint" in normalize(device.get("Protocol", ""))


def is_sel_server(device: dict) -> bool:
    """
    If a device from a project export is a SEL protocol server, e.g. with
    the connection type ``Server - Ethernet Tunneled Serial``.
    """
    protocol = normalize(device.get("Protocol", ""))
    text = protocol + normalize(device.get("Connection Type", ""))
    return protocol.startswith("sel") and "server" in text and "client" not in protocol


def is_sel_client(device: dict) -> bool:
    """If a device from a project export is a SEL protocol device (client)."""
    return normalize(device.get("Protocol", "")).startswith("sel") and not is_sel_server(device)


# ---------- Listeners from settings ----------


def access_point_listener(name: str, settings: dict, source: str) -> Listener | None:
    """
    Make a :class:`Listener` from the settings of an access point.

    Returns:
        The listener, or :obj:`None` if the access point doesn't listen
        (e.g. an outgoing connection)
    """
    connection_type = to_text(get_setting(settings, _AP_TYPE))
    if "outgoing" in connection_type.lower():
        return None

    transport = transport_from_text(connection_type)
    authentication = to_bool(get_setting(settings, _AUTHENTICATION))
    listener = Listener(
        kind="access_point",
        name=name,
        port=to_port(get_setting(settings, _AP_PORT)),
        transport=transport,
        connection_type=connection_type,
        needs_rtac_login=transport == "ssh" or bool(authentication),
        source=source,
    )
    if authentication is not None:
        listener.settings["perform_authentication"] = authentication
    return listener


def sel_server_listener(name: str, settings: dict, source: str) -> Listener:
    """Make a :class:`Listener` from the settings of a SEL server."""
    mode = to_text(get_setting(settings, _SERVER_MODE))
    transport = transport_from_text(mode)
    authentication = to_bool(get_setting(settings, _AUTHENTICATION))

    listener = Listener(
        kind="sel_server",
        name=name,
        port=to_port(get_setting(settings, _SERVER_PORT)),
        transport=transport,
        connection_type=mode,
        # Authentication is always done with SSH
        needs_rtac_login=transport == "ssh" or bool(authentication),
        termination_string=(
            parse_termination_string(get_setting(settings, _TERMINATION))
            or DEFAULT_TERMINATION_STRING
        ),
        port_command=to_bool(get_setting(settings, _PORT_COMMAND), default=True),
        source=source,
    )

    if authentication is not None:
        listener.settings["perform_authentication"] = authentication
    raw_termination = get_setting(settings, _TERMINATION)
    if isinstance(raw_termination, str):
        listener.settings["termination_string_setting"] = raw_termination
    listener.settings["enable_port_command"] = listener.port_command
    for key, names in _SERVER_EXTRA.items():
        value = get_setting(settings, names)
        if key in _SERVER_BOOL_EXTRA:
            value = to_bool(value)
        if isinstance(value, bool | int | float | str):
            listener.settings[key] = value
    ips = client_ips(get_setting(settings, _CLIENT_IPS))
    if ips:
        listener.settings["allowed_client_ips"] = ips

    return listener


def sel_client_port(settings: dict, serial: bool) -> int | None:
    """
    Port number of a SEL device for the SEL server ``PORT`` command: the
    serial port number of a serial device, or the virtual port number.
    """
    if serial:
        number = port_number(get_setting(settings, _SERIAL_PORT))
        if number:
            return number
    return port_number(get_setting(settings, _VIRTUAL_PORT))


# ---------- Access point routers ----------


@dataclass
class _Endpoint:
    name: str
    protocol: str = ""
    type: str = ""
    label: str = ""


def _strip_suffix(name: str) -> tuple[str, Literal["interleaved", "direct"] | None]:
    """Remove a ``_TAP`` or ``_AP`` suffix from a name, and get the route it means."""
    upper = name.upper()
    if upper.endswith("_TAP"):
        return name[:-4], "interleaved"
    if upper.endswith("_AP"):
        return name[:-3], "direct"
    return name, None


def _find_device(name: str, devices: dict[str, dict]) -> str | None:
    """
    Name of the device in ``devices`` that an endpoint name refers to:
    the name itself, the name without the ``_TAP`` or ``_AP`` suffix, or
    that without the protocol (e.g. ``Feeder_1`` for ``Feeder_1_SEL_TAP``).
    """
    if name in devices:
        return name
    base, _ = _strip_suffix(name)
    if base in devices:
        return base
    if "_" in base:
        without_protocol = base.rsplit("_", 1)[0]
        if without_protocol in devices:
            return without_protocol
    return None


def _device_of_access_point(
    name: str, devices: dict[str, dict]
) -> tuple[str | None, Literal["interleaved", "direct"] | None]:
    """
    The device that the access point of a device belongs to, and its route:
    ``Feeder_1`` and ``direct`` for ``Feeder_1_SEL_AP``. Returns
    ``(None, None)`` if the name doesn't have a ``_TAP`` or ``_AP`` suffix, or
    if there's no device (that isn't an access point) with the name without
    the suffix (e.g. ``Serial_AP``, an access point of the RTAC).
    """
    base, route = _strip_suffix(name)
    if route is None:
        return None, None
    candidates = [base]
    if "_" in base:
        candidates.append(base.rsplit("_", 1)[0])  # without the protocol
    for candidate in candidates:
        if candidate in devices and not is_access_point(devices[candidate]):
            return candidate, route
    return None, None


def _resolve_endpoints(
    router_name: str,
    endpoints: list[_Endpoint],
    devices: dict[str, dict],
    listeners: dict[str, Listener],
    warnings: list[str],
) -> None:
    """
    Add the destinations of an access point router to its access point.

    The access point is the endpoint that's an access point (regardless of
    whether it's the ``Source`` or the ``Destination`` in the export), and
    the other endpoints are the destinations.
    """
    access_points: list[tuple[_Endpoint, Listener | None]] = []
    targets: list[_Endpoint] = []
    for endpoint in endpoints:
        device = _find_device(endpoint.name, devices)
        is_ap = (device is not None and is_access_point(devices[device])) or (
            "accesspoint" in normalize(endpoint.protocol)
        )
        if is_ap:
            access_points.append((endpoint, listeners.get(device) if device else None))
        else:
            targets.append(endpoint)

    # A route between two access points, e.g. from a network access point to
    # an access point on a serial port: the one with a port is the listener
    if len(access_points) > 1 and not targets:
        with_port = [ap for ap in access_points if ap[1] is not None and ap[1].port]
        if len(with_port) == 1:
            targets = [ap[0] for ap in access_points if ap is not with_port[0]]
            access_points = with_port

    listener = None
    if len(access_points) == 1:
        listener = access_points[0][1]
    elif not access_points:
        # The source is the access point the client connects to
        sources = [e for e in endpoints if e.label == "Source"]
        missing = sources[0].name if sources else "?"
        warnings.append(
            f"Access point router '{router_name}' doesn't have a known access point "
            f"(source '{missing}'), so the port its connections come in on isn't known"
        )
        return

    if listener is None:
        names = [ap[0].name for ap in access_points]
        warnings.append(
            f"Access point router '{router_name}': its access point ({', '.join(names)}) "
            f"isn't a port the RTAC listens on (e.g. an outgoing connection), or its "
            f"settings aren't in the configuration"
        )
        return

    if not targets:
        warnings.append(f"Access point router '{router_name}' doesn't have a destination")
        return

    for target in targets:
        device = _find_device(target.name, devices)
        route = route_from_type(target.type)
        if device is not None and is_access_point(devices[device]):
            # The access point of a device (e.g. "Feeder_1_SEL_AP") is the device
            # with the route of the suffix. Other access points are the device,
            # and the "_AP" suffix of their name doesn't mean "direct".
            owner, suffix_route = _device_of_access_point(target.name, devices)
            device_name = owner if owner else target.name
            if route is None:
                route = suffix_route
        else:
            base, suffix_route = _strip_suffix(target.name)
            device_name = device if device else base
            if route is None:
                route = suffix_route
        listener.add_destination(
            Destination(name=target.name, device_name=device_name, route=route, router=router_name)
        )


def _router_extra(settings: dict) -> dict[str, Any]:
    extra = {}
    legacy = to_bool(get_setting(settings, _LEGACY_PORT_COMMAND))
    if legacy is not None:
        extra["legacy_port_command"] = legacy
    legacy_id = get_setting(settings, _LEGACY_PORT_COMMAND_ID)
    if isinstance(legacy_id, int | str) and not isinstance(legacy_id, bool):
        extra["legacy_port_command_id"] = legacy_id
    return extra


# ---------- Project exports ----------


def discover_from_export(device_info: dict) -> Discovery:
    """
    Find the engineering access paths in a parsed RTAC project export.

    - ``Devices`` that are access points (protocol ``AccessPointServer``):
      ``Network Connection Type`` and ``Local Port Number``.
    - ``AccessPointRouters``: the access point and the destinations. The
      route is ``interleaved`` for a destination named ``<Device>_..._TAP``
      (or with the type ``TAP``), and ``direct`` for ``<Device>_..._AP``.
    - ``Devices`` that are SEL servers: ``Server IP Port``,
      ``Serial Tunneling Mode``, ``Perform Authentication``,
      ``Termination String``, ``Enable Port Command`` and others.
    - ``Devices`` that are SEL devices (clients) are the devices a SEL server
      reaches, with the serial port number (serial devices, if the export has
      it) or the ``Virtual Port Number`` for the ``PORT`` command.

    Args:
        device_info: The parsed export (``Devices`` and ``AccessPointRouters``)

    Returns:
        The access points and SEL servers, and the names of any
        ``Eng_Access_*`` devices
    """
    discovery = Discovery()
    devices = device_info.get("Devices") or {}
    if not isinstance(devices, dict):
        devices = {}
    devices = {str(name): dev for name, dev in devices.items() if isinstance(dev, dict)}

    listeners: dict[str, Listener] = {}
    clients: list[Destination] = []
    for name, device in devices.items():
        discovery.add_eng_access_name(name)
        settings = device.get("Settings") or {}

        if is_sel_client(device):
            connection_type = normalize(device.get("Connection Type", ""))
            serial = "serial" in connection_type and "ethernet" not in connection_type
            clients.append(
                Destination(
                    name=name,
                    device_name=name,
                    route="interleaved",
                    sel_port=sel_client_port(settings, serial),
                )
            )
            continue

        if is_access_point(device):
            listener = access_point_listener(name, settings, "export")
            mode = get_setting(settings, _AP_TYPE)
        elif is_sel_server(device):
            listener = sel_server_listener(name, settings, "export")
            mode = get_setting(settings, _SERVER_MODE)
        else:
            continue

        # Access points with no port are e.g. on a serial port. SEL servers
        # with no port (or port 0) don't listen on the network.
        if listener is None or (listener.kind == "sel_server" and not listener.port):
            continue
        listeners[name] = listener
        _check_transport(discovery, listener, mode)

    routers = device_info.get("AccessPointRouters") or {}
    if isinstance(routers, dict):
        for router_name, router in routers.items():
            if not isinstance(router, dict):
                continue
            _add_router(
                str(router_name),
                _export_router_endpoints(router),
                router.get("Settings") or {},
                devices,
                listeners,
                discovery.warnings,
            )

    _add_sel_server_destinations(listeners.values(), clients)
    discovery.listeners = list(listeners.values())
    return discovery


def _check_transport(discovery: Discovery, listener: Listener, mode: Any, where: str = "") -> None:
    """
    Log a listener with a port, but without a known transport: a warning if
    its connection type or tunneling mode (``mode``) is one PEAT doesn't
    know (e.g. a number), or a note if it doesn't have one (e.g. a SEL
    server for SCADA, which isn't for engineering access).
    """
    if not listener.port or listener.transport is not None:
        return
    if listener.kind == "sel_server":
        setting, what = "tunneling mode", "SEL server"
    else:
        setting, what = "connection type", "access point"
    if mode is None:
        discovery.notes.append(
            f"The {what} '{listener.name}' (port {listener.port}) doesn't have a "
            f"{setting}{where}, so it isn't used for engineering access"
        )
    else:
        discovery.warnings.append(
            f"Unknown {setting} {mode!r} of the {what} '{listener.name}' "
            f"(port {listener.port}){where}"
        )


def _export_router_endpoints(router: dict) -> list[_Endpoint]:
    """Endpoints of an access point router from :func:`parse_accesspointrouters`."""
    endpoints = []
    candidates = [("Source", router.get("Source"))]
    destinations = router.get("Destinations")
    if isinstance(destinations, list) and destinations:
        candidates.extend(("Destination", d) for d in destinations)
    else:
        candidates.append(("Destination", router.get("Destination")))

    for label, endpoint in candidates:
        if not isinstance(endpoint, dict):
            continue
        name = endpoint.get("device_name")
        if name is None or name == "":
            continue
        endpoints.append(
            _Endpoint(
                name=str(name),
                protocol=str(endpoint.get("device_protocol") or ""),
                type=str(endpoint.get("type") or ""),
                label=label,
            )
        )
    return endpoints


def _add_sel_server_destinations(
    listeners: Iterable[Listener], clients: list[Destination]
) -> None:
    """The devices a SEL server reaches are the SEL devices (clients) of the RTAC."""
    for listener in listeners:
        if listener.kind != "sel_server":
            continue
        for client in clients:
            listener.add_destination(
                Destination(
                    name=client.name,
                    device_name=client.device_name,
                    route="interleaved",
                    sel_port=client.sel_port,
                )
            )


# ---------- PostgreSQL database ----------


def _table_rows(tables: dict, name: str) -> list[dict]:
    """
    Rows of a table, with normalized column names (refer to :func:`normalize`).
    The table can be a dict of rows (keyed by the first column, as in
    ``pulled-postgres-config.json``) or a list of rows.
    """
    table = tables.get(name)
    if isinstance(table, dict):
        table = list(table.values())
    if not isinstance(table, list):
        return []
    rows = []
    for row in table:
        if not isinstance(row, dict):
            continue
        normalized = {}
        for key, value in row.items():
            # Keep the first value that isn't empty if two columns have the same name
            if normalized.get(normalize(key)) is None:
                normalized[normalize(key)] = value
        rows.append(normalized)
    return rows


def _join_value(row: dict, column: str) -> Any:
    """Value of a join column, or :obj:`None` if it's empty or not an ID."""
    value = row.get(column)
    if value is None or isinstance(value, bool) or value == "":
        return None
    return str(value)


def _joins(row: dict, other: dict) -> bool:
    """
    If two rows are related: they have the same value in one of
    :data:`PG_JOIN_COLUMNS`, and no different values in any of these
    or :data:`PG_CHECK_COLUMNS`.
    """
    joined = False
    for column in PG_JOIN_COLUMNS + PG_CHECK_COLUMNS:
        value = _join_value(row, column)
        other_value = _join_value(other, column)
        if value is None or other_value is None:
            continue
        if value != other_value:
            return False
        if column in PG_JOIN_COLUMNS:
            joined = True
    return joined


def _merge_rows(
    tables: dict, names: Iterable[str], required: Iterable[str] | None = None
) -> list[dict]:
    """
    Merge the rows of related tables into records. A row is merged into the
    first record that joins to it (:func:`_joins`) and doesn't have a row from
    the same table yet. Values that are already in the record are kept.

    Args:
        tables: The tables (refer to :func:`discover_from_postgres`)
        names: Names of the tables to merge, in order. The ``required``
            tables must be first.
        required: Only return the records that have a row from one of these
            tables. The other tables only add settings: their names (e.g. the
            name of a serial port) are not added to the records.
            Default: all of the tables are required.
    """
    names = list(names)
    required_tables = set(names if required is None else required)
    name_columns = {normalize(name) for name in _NAME}
    records: list[tuple[set[str], dict]] = []
    for table in names:
        for row in _table_rows(tables, table):
            if table not in required_tables:
                row = {k: v for k, v in row.items() if k not in name_columns}
            for record_tables, record in records:
                if table not in record_tables and _joins(row, record):
                    record_tables.add(table)
                    for key, value in row.items():
                        if record.get(key) is None:
                            record[key] = value
                    break
            else:
                records.append(({table}, dict(row)))
    return [record for record_tables, record in records if record_tables & required_tables]


def _record_name(record: dict, name_rows: list[dict]) -> str:
    """Name of a record, or the name of the first row of a name table it joins to."""
    name = to_text(get_setting(record, _NAME))
    if name:
        return name
    for row in name_rows:
        if _joins(record, row):
            name = to_text(get_setting(row, _NAME))
            if name:
                return name
    return ""


def _columns(record: dict) -> str:
    return ", ".join(sorted(record))


def _with_mode(record: dict, names: tuple[str, ...], fragments: tuple[str, ...]) -> dict:
    """
    The settings of a database record. If the record doesn't have a column
    with one of the ``names`` of the connection type or tunneling mode, the
    first column that has one of the ``fragments`` in its name (e.g.
    ``serial_tunneling_mode_id``) is used, so a value that can't be
    interpreted (e.g. an ID) is in the warning about it.
    """
    if get_setting(record, names) is not None:
        return record
    for column, value in record.items():
        if any(f in column for f in fragments) and value is not None and value != "":
            return {**record, normalize(names[0]): value}
    return record


def discover_from_postgres(tables: dict) -> Discovery:
    """
    Find the engineering access paths in the tables of the RTAC database.

    The column names of these tables are not public. The columns are
    matched to the setting names of a project export without regard to
    case and punctuation (e.g. ``local_port_number`` to
    ``Local Port Number``), with some common variations. The rows of
    related tables are joined by their ID columns (:data:`PG_JOIN_COLUMNS`):
    two rows are joined if they have the same value in one of these columns,
    and no different values in the others. Values that are numbers instead
    of names (e.g. the ID of a tunneling mode) can't be interpreted, and a
    warning with the column names of the row is added for them.

    - Access points with a port: :data:`PG_ACCESS_POINT_TABLES`, and the
      port from :data:`PG_LOCAL_PORT_TABLES` if those tables don't have it.
      Access points without a port are e.g. the ``_TAP`` and ``_AP`` access
      points of devices.
    - Access point routers: :data:`PG_ROUTER_TABLES`. The source and
      destination are the columns that start with ``source`` or ``src``,
      and ``destination``, ``dest`` or ``dst``. They are names, or IDs of rows
      in the other tables (e.g. ``source_access_point_id`` is looked up in
      the ``access_point_id`` column), or lists of these.
    - SEL servers: :data:`PG_SEL_SERVER_TABLES`, and the port from
      :data:`PG_LOCAL_PORT_TABLES` if those tables don't have it.
    - SEL devices: :data:`PG_SEL_CLIENT_TABLES`, with the serial port from
      :data:`PG_SERIAL_PORT_TABLES`. Rows of these tables that don't join a
      SEL device (e.g. the serial ports of DNP3 devices) are not used.
    - Names: :data:`PG_NAME_TABLES`. Names that start with ``Eng_Access_``
      are recorded.

    Args:
        tables: Rows of the tables (the tables in :data:`PG_TABLES`), keyed
            by table name. The rows of each table are a list of dicts, or a
            dict of dicts (the format of ``pulled-postgres-config.json``).

    Returns:
        The access points and SEL servers, and the names of any
        ``Eng_Access_*`` objects
    """
    discovery = Discovery()
    name_rows = [row for table in PG_NAME_TABLES for row in _table_rows(tables, table)]
    for row in name_rows:
        discovery.add_eng_access_name(to_text(get_setting(row, _NAME)))

    listeners: dict[str, Listener] = {}
    devices: dict[str, dict] = {}

    access_points = _merge_rows(
        tables, PG_ACCESS_POINT_TABLES + PG_LOCAL_PORT_TABLES, required=PG_ACCESS_POINT_TABLES
    )
    for index, record in enumerate(access_points):
        name = _record_name(record, name_rows) or f"access_point_{index}"
        settings = _with_mode(record, _AP_TYPE, ("connectiontype",))
        listener = access_point_listener(name, settings, "postgres")
        if listener is None or not listener.port or name in listeners:
            continue
        listeners[name] = listener
        devices[name] = {"Protocol": "AccessPointServer"}
        _check_transport(
            discovery,
            listener,
            get_setting(settings, _AP_TYPE),
            f" in the RTAC database (columns: {_columns(record)})",
        )

    sel_servers = _merge_rows(
        tables, PG_SEL_SERVER_TABLES + PG_LOCAL_PORT_TABLES, required=PG_SEL_SERVER_TABLES
    )
    for index, record in enumerate(sel_servers):
        name = _record_name(record, name_rows) or f"sel_server_{index}"
        settings = _with_mode(record, _SERVER_MODE, ("tunnelingmode", "tunnelmode"))
        listener = sel_server_listener(name, settings, "postgres")
        if not listener.port or name in listeners:
            continue
        listeners[name] = listener
        _check_transport(
            discovery,
            listener,
            get_setting(settings, _SERVER_MODE),
            f" in the RTAC database (columns: {_columns(record)})",
        )

    clients = []
    sel_clients = _merge_rows(
        tables, PG_SEL_CLIENT_TABLES + PG_SERIAL_PORT_TABLES, required=PG_SEL_CLIENT_TABLES
    )
    for record in sel_clients:
        name = _record_name(record, name_rows)
        if not name or name in listeners:
            continue
        serial = _join_value(record, "serialportid") is not None
        devices.setdefault(name, {"Protocol": "SELClient"})
        clients.append(
            Destination(
                name=name,
                device_name=name,
                route="interleaved",
                sel_port=sel_client_port(record, serial),
            )
        )

    # Names of IDs are looked up in the rows of all of the tables
    lookup_rows = [row for table in sorted(PG_TABLES) for row in _table_rows(tables, table)]
    for index, row in enumerate(_table_rows(tables, "access_point_routers")):
        router_name = to_text(get_setting(row, _NAME)) or f"access_point_router_{index}"
        endpoints = _postgres_router_endpoints(row, lookup_rows)
        _add_router(router_name, endpoints, row, devices, listeners, discovery.warnings)

    _add_sel_server_destinations(listeners.values(), clients)
    discovery.listeners = list(listeners.values())
    return discovery


def _postgres_router_endpoints(row: dict, lookup_rows: list[dict]) -> list[_Endpoint]:
    """
    Source and destinations of an access point router row (refer to
    :func:`discover_from_postgres`).
    """
    endpoints = []
    for column, value in row.items():
        prefix, label = next(
            ((p, lbl) for p, lbl in _ROUTER_ROLES if column.startswith(p)), ("", "")
        )
        if not label:
            continue
        rest = column[len(prefix) :]
        if rest.endswith("type"):
            continue  # e.g. "destination_type", the type of the other column

        type_value = row.get(prefix + "type")
        values = value if isinstance(value, list | tuple) else [value]
        for item in values:
            name = ""
            if isinstance(item, str) and item.strip() and not item.strip().isdigit():
                # A name, e.g. "source_name" or "destination_access_point"
                if rest in _ROUTER_NAME_COLUMNS:
                    name = item.strip()
            elif rest.endswith("id") and item is not None and not isinstance(item, bool):
                name = _lookup_name(rest, item, lookup_rows)
            if name:
                endpoints.append(
                    _Endpoint(
                        name=name,
                        type=type_value if isinstance(type_value, str) else "",
                        label=label,
                    )
                )
    return endpoints


# Rest of the name of a source or destination column with a name (normalized)
_ROUTER_NAME_COLUMNS = frozenset(
    {"", "name", "devicename", "accesspoint", "accesspointname", "apname", "accesspoints"}
)


def _lookup_name(column: str, value: Any, rows: list[dict]) -> str:
    """
    Name of the row with the value in the column, e.g. ``accesspointid``.
    A column that is only ``id`` is looked up in the ``access_point_id``
    and ``connection_id`` columns.
    """
    if column == "id":
        candidates = ["accesspointid", "connectionid"]
    else:
        candidates = [column]
    for candidate in candidates:
        for row in rows:
            if _join_value(row, candidate) == str(value):
                name = to_text(get_setting(row, _NAME))
                if name:
                    return name
    return ""


def _add_router(
    router_name: str,
    endpoints: list[_Endpoint],
    settings: dict,
    devices: dict[str, dict],
    listeners: dict[str, Listener],
    warnings: list[str],
) -> None:
    """Add the destinations of an access point router, with its settings."""
    before = {name: len(listener.destinations) for name, listener in listeners.items()}
    _resolve_endpoints(router_name, endpoints, devices, listeners, warnings)
    extra = _router_extra(settings)
    if not extra:
        return
    for name, listener in listeners.items():
        for dest in listener.destinations[before.get(name, 0) :]:
            dest.extra.update(extra)


__all__ = [
    "DEFAULT_TERMINATION_STRING",
    "ENGINEERING_ACCESS_KEYS",
    "ENG_ACCESS_PREFIX",
    "PATH_KEYS",
    "PG_ACCESS_POINT_TABLES",
    "PG_CHECK_COLUMNS",
    "PG_JOIN_COLUMNS",
    "PG_LOCAL_PORT_TABLES",
    "PG_NAME_TABLES",
    "PG_ROUTER_TABLES",
    "PG_SEL_CLIENT_TABLES",
    "PG_SEL_SERVER_TABLES",
    "PG_SERIAL_PORT_TABLES",
    "PG_TABLES",
    "TUNNEL_TRANSPORTS",
    "Destination",
    "Discovery",
    "Listener",
    "discover_from_export",
    "discover_from_postgres",
    "merge_entries",
    "unique_paths",
]
