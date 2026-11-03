"""
Reach SEL relays (and other devices with the SEL ASCII interface) behind a SEL
RTAC, through its engineering access tunnels.

A SEL RTAC gives engineering access to the devices it polls in two ways
(refer to "RTAC engineering tunnels" in the SEL documentation, ``docs/sel.rst``):

- An **access point** is a TCP port on the RTAC. An access point router connects
  it to one device. A route to the device's ``<Device>_SEL_TAP`` access point is
  *interleaved*: the RTAC keeps polling the device between the engineering
  traffic. A route to ``<Device>_SEL_AP`` is *direct*: the RTAC stops polling the
  device while the connection is open, so SCADA has no data from it, and the
  device's ``Offline`` tag is set.
- The **SEL server** (a SEL device with the connection type "Server - Ethernet
  Tunneled Serial", RTAC firmware R134 and later) is one TCP port for all of the
  SEL devices of the RTAC. The client goes to access level 1 with ``ACC`` (prompts
  ``*`` and ``*>``), lists the devices with ``WHO`` (the port number, the name, and
  the connection type of each), and opens a transparent connection to one of them
  with ``PORT n`` ("Establishing connection..."). The termination string
  (Ctrl+D by default) ends the transparent connection, if nothing was sent for
  the "Pre-Termination Timeout" (1 second by default) before it.

Both can use Telnet, raw TCP, TLS, or SSH, and the RTAC may ask for the user name
and password of a RTAC user first (always with SSH).

:class:`RTACTunnel` describes one path to a device: the RTAC's IP address and TCP
port, the transport, and the SEL server port (``PORT n``) or the access point's
route. :class:`SELTunnel` opens the tunnel, and then works like
:class:`~peat.modules.sel.sel_telnet.SELTelnet`, so every SEL ASCII command works
the same way.

The behavior of the RTAC is from public SEL documents: the "SEL-3530 RTAC Hands-On
Session" (HD2014-34, Engineering Access Exercise, 20220218) and the white paper
"Leveraging Security - Using the SEL RTAC's Built-In Security Features" (LWP0018-01,
20160111, Section 5). It hasn't been tested on a RTAC yet.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import socket
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from time import monotonic, sleep
from typing import Any, ClassVar, Final

import paramiko

from peat import CommError, DeviceData, exit_handler, log
from peat.protocols import Telnet
from peat.protocols.expect import (
    Expecter,
    ExpectResult,
    PatternLike,
    ReadChunk,
    channel_reader,
    socket_reader,
)

from .sel_ascii import (
    CAN,
    FRAMED_PROMPT_RE,
    PASSWORD_RE,
    REDACTED_WRITE,
    UNFRAMED_PROMPT_RE,
    SELAscii,
    clean_lines,
)
from .sel_commands import SELCommandRefused, normalize_command
from .sel_telnet import SELTelnet

#: Transports of a tunnel (the RTAC's "Serial Tunneling Mode" or
#: "Network Connection Type" setting)
TRANSPORTS: Final = ("telnet", "raw", "ssh", "tls")

#: Kinds of tunnels: the RTAC's SEL server (``PORT n``), or an access point
KINDS: Final = ("sel_server", "access_point")

#: Routes of an access point: ``interleaved`` (to ``<Device>_SEL_TAP``, the RTAC
#: keeps polling the device) or ``direct`` (to ``<Device>_SEL_AP``, it doesn't)
ROUTES: Final = ("interleaved", "direct")

#: The default termination string of the RTAC's SEL server, Ctrl+D (``<CTRL-D>``)
DEFAULT_TERMINATION: Final = "\x04"

#: The default "Pre-Termination Timeout" of the RTAC's SEL server, in seconds
DEFAULT_PRE_TERMINATION: Final = 1.0

#: Keys of an engineering access entry, as in ``extra.engineering_access`` of a RTAC
ENTRY_KEYS: Final = (
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

_TRANSPORT_ALIASES: Final = {
    "telnet": "telnet",
    "raw": "raw",
    "raw tcp": "raw",
    "rawtcp": "raw",
    "raw_tcp": "raw",
    "tcp": "raw",
    "ssh": "ssh",
    "tls": "tls",
    "ssl": "tls",
    "ssl/tls": "tls",
}
_KIND_ALIASES: Final = {
    "sel_server": "sel_server",
    "sel server": "sel_server",
    "server": "sel_server",
    "access_point": "access_point",
    "access point": "access_point",
    "ap": "access_point",
}
_ROUTE_ALIASES: Final = {
    "interleaved": "interleaved",
    "tap": "interleaved",
    "transparent": "interleaved",
    "direct": "direct",
    "ap": "direct",
}

#: The RTAC asks for the user name of a RTAC user (at the end of the data so far)
LOGIN_RE: Final = re.compile(rb"(?i)(?:login|user ?name|user ?id)[ \t]*:[ \t]*\Z")

#: The RTAC asks for the password of the RTAC user. Relays ask "Password: ?"
#: (with a question mark), which isn't matched.
RTAC_PASSWORD_RE: Final = re.compile(rb"(?i)password[ \t]*:[ \t]*\Z")

#: The RTAC rejected the user name or password
LOGIN_FAILED_RE: Final = re.compile(
    rb"(?i)login incorrect|authentication failed|access denied|invalid (?:user|login|password)"
)

#: The RTAC opens the transparent connection after ``PORT n``
ESTABLISHING_RE: Final = re.compile(rb"(?i)establishing connection")

#: Messages of the RTAC when a transparent connection couldn't be opened
_PORT_FAILED_RE: Final = re.compile(r"(?i)fail|unable|invalid|not (?:available|found|connected)")

#: A row of the ``WHO`` table of the RTAC's SEL server, e.g. ``1  Feeder_1  Client - Serial``
WHO_ROW_RE: Final = re.compile(
    r"^\s*(?P<port>\d{1,3})\s+(?P<device>\S+)\s+(?P<protocol>\S.*?)\s*$"
)

#: The only commands PEAT sends to the RTAC itself (not to the device behind it).
#: The RTAC's ``PORT`` command opens a transparent connection; for a relay,
#: ``PORT`` is a command PEAT never sends (refer to sel_commands.py).
GATEWAY_COMMAND_RE: Final = re.compile(r"(?i)|ACC|WHO|PORT [0-9]{1,3}|QUI|QUIT")


class TunnelError(CommError):
    """A tunnel through a SEL RTAC couldn't be opened, or isn't allowed."""


class RTACLoginError(TunnelError):
    """
    The RTAC rejected the login of a RTAC user (also with SSH), or the password
    of its SEL server's ``ACC``. PEAT doesn't send that login to the RTAC again
    (refer to :meth:`SELTunnel.rejected_login`), so the RTAC's account isn't
    locked by failed logins through other paths.
    """

    def __init__(self, message: str, credential: str = "login") -> None:
        super().__init__(message)
        #: ``login`` (the RTAC user's name and password) or ``acc`` (the SEL server's ACC)
        self.credential: str = credential


def _login_key(credential: str, *values: str) -> str:
    # A digest, so the registry of rejected logins doesn't have the passwords
    return hashlib.sha256("\0".join((credential, *values)).encode("utf-8")).hexdigest()


def _choice(value: Any, aliases: Mapping[str, str], what: str) -> str:
    key = re.sub(r"\s+", " ", str(value).strip().lower())
    if key not in aliases:
        raise ValueError(f"invalid {what} '{value}' (allowed: {sorted(set(aliases.values()))})")
    return aliases[key]


def _int(value: Any, what: str, low: int, high: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"invalid {what} {value!r}")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"invalid {what} {value!r}") from None
    if not low <= number <= high:
        raise ValueError(f"{what} {number} isn't in {low}-{high}")
    return number


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(value)


def _float(value: Any, default: float, what: str) -> float:
    if value is None or value == "":
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid {what} {value!r}") from None
    if number < 0 or number > 600:
        raise ValueError(f"{what} {number} isn't in 0-600 seconds")
    return number


def safe_id(value: str) -> str:
    """
    A device ID (and the name of its output directory) made from ``value``:
    characters other than letters, digits, ``.``, ``_`` and ``-`` are replaced with
    ``-``, so there are no ``:`` (which Windows doesn't allow in file names)
    or path separators.
    """
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value).strip()).strip("-.")


def parse_termination_string(value: Any) -> str:
    """
    The termination string of a RTAC SEL server, from a setting or an option:
    ``<CTRL-D>``, ``CTRL-D``, ``Ctrl+D`` and ``^D`` are Ctrl+D (``"\\x04"``), and
    ``\\x04`` (with a backslash) is the character with that code. Empty or
    :obj:`None` is the default, Ctrl+D.
    """
    if value is None:
        return DEFAULT_TERMINATION
    text = str(value)
    if not text:
        return DEFAULT_TERMINATION

    control = re.fullmatch(
        r"(?i)\s*(?:<\s*ctrl[-+ ]?([a-z@\[\]\\^_])\s*>|ctrl[-+ ]?([a-z])|\^([a-z@]))\s*", text
    )
    if control:
        letter = next(g for g in control.groups() if g).upper()
        return chr(ord(letter) - 64)

    text = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    if len(text) > 255:
        raise ValueError("the termination string is longer than 255 characters")
    return text


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@dataclass
class RTACTunnel:
    """
    One path to a device through a SEL RTAC: an access point, or a port of the
    RTAC's SEL server (``PORT n``).

    The fields are the keys of the engineering access entries of a RTAC
    (``extra.engineering_access``), plus the timing of the termination and
    the device's passwords, which can be set in ``sel.rtac_tunnels``.
    """

    #: IP address (or host name) of the RTAC
    rtac_ip: str
    #: TCP port on the RTAC
    tcp_port: int
    #: ``telnet``, ``raw``, ``ssh``, or ``tls``
    transport: str = "telnet"
    #: ``sel_server`` (needs ``PORT n``) or ``access_point`` (straight to the device)
    kind: str = "access_point"
    #: Port of the device on the SEL server (``PORT n``, as ``WHO`` lists it).
    #: :obj:`None` for access points, or if it isn't known (``WHO`` lists them).
    sel_port: int | None = None
    #: Name of the device in the RTAC's configuration, if known
    device_name: str | None = None
    #: ``interleaved`` or ``direct``, or :obj:`None` if it isn't known (an access
    #: point with an unknown route may be direct). SEL server connections are interleaved.
    route: str | None = None
    #: The RTAC asks for a RTAC user's name and password first (always with SSH)
    needs_rtac_login: bool = False
    #: Termination string of the SEL server (Ctrl+D by default)
    termination_string: str = DEFAULT_TERMINATION
    #: Where the path is from: ``config`` (``sel.rtac_tunnels`` or ``--rtac-tunnel``),
    #: ``export`` or ``postgres`` (the RTAC's configuration), or ``who``
    source: str = "config"
    #: Name of the path in the RTAC (e.g. the destination of the access point router)
    name: str | None = None
    #: Seconds without sending anything before the termination string
    #: (the SEL server's "Pre-Termination Timeout")
    pre_term_s: float = DEFAULT_PRE_TERMINATION
    #: Seconds to wait after the termination string ("Post-Termination Timeout")
    post_term_s: float = 0.0
    #: Passwords of the device's access levels (like ``sel.creds``), if they're
    #: different from the ones in the options
    creds: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(
        cls,
        entry: Mapping[str, Any],
        default_rtac_ip: str = "",
        source: str = "",
    ) -> RTACTunnel:
        """
        Make a tunnel from an engineering access entry (a :class:`dict` with the
        keys in :data:`ENTRY_KEYS`, from a RTAC or from ``sel.rtac_tunnels``).
        Only ``rtac_ip`` and ``tcp_port`` are required. Without ``kind``, an
        entry with a ``sel_port`` is a SEL server, otherwise an access point.

        Raises:
            ValueError: The entry isn't valid
        """
        if not isinstance(entry, Mapping):
            raise ValueError(f"expected a dict, got {type(entry).__name__}")

        rtac_ip = str(entry.get("rtac_ip") or default_rtac_ip or "").strip().strip("[]")
        if not rtac_ip:
            raise ValueError("no 'rtac_ip'")
        if entry.get("tcp_port") in (None, ""):
            raise ValueError("no 'tcp_port'")
        tcp_port = _int(entry["tcp_port"], "tcp_port", 1, 65535)

        transport = _choice(entry.get("transport") or "telnet", _TRANSPORT_ALIASES, "transport")

        sel_port = None
        if entry.get("sel_port") not in (None, ""):
            sel_port = _int(entry["sel_port"], "sel_port", 1, 999)

        if entry.get("kind"):
            kind = _choice(entry["kind"], _KIND_ALIASES, "kind")
        else:
            kind = "sel_server" if sel_port is not None else "access_point"
        if kind == "access_point":
            # PORT n is only for SEL servers
            sel_port = None

        route = None
        if entry.get("route"):
            route = _choice(entry["route"], _ROUTE_ALIASES, "route")
        if kind == "sel_server" and route is None:
            # A transparent connection of the SEL server is interleaved with the polling
            route = "interleaved"

        creds = entry.get("creds") or {}
        if not isinstance(creds, Mapping):
            raise ValueError("'creds' must be a dict of access level passwords")

        return cls(
            rtac_ip=rtac_ip,
            tcp_port=tcp_port,
            transport=transport,
            kind=kind,
            sel_port=sel_port,
            device_name=str(entry["device_name"]) if entry.get("device_name") else None,
            route=route,
            # Perform Authentication is always on for SSH
            needs_rtac_login=_bool(entry.get("needs_rtac_login")) or transport == "ssh",
            termination_string=parse_termination_string(entry.get("termination_string")),
            source=str(entry.get("source") or source or "config"),
            name=str(entry["name"]) if entry.get("name") else None,
            pre_term_s=_float(
                entry.get("pre_term_s", entry.get("pre_termination_timeout")),
                DEFAULT_PRE_TERMINATION,
                "pre_term_s",
            ),
            post_term_s=_float(
                entry.get("post_term_s", entry.get("post_termination_timeout")),
                0.0,
                "post_term_s",
            ),
            creds={str(k).lower(): v for k, v in creds.items() if v},
        )

    @classmethod
    def from_spec(cls, spec: str, source: str = "config") -> RTACTunnel:
        """
        Make a tunnel from the format of the ``--rtac-tunnel`` argument:
        ``RTAC_IP:TCP_PORT[:SEL_PORT][:TRANSPORT][:ROUTE][:login]``. The fields
        after the port can be in any order, and empty: a number is the SEL server
        port (``PORT n``), ``telnet``, ``raw``, ``ssh`` or ``tls`` is the transport
        (Telnet by default), ``interleaved`` (or ``tap``) or ``direct`` (or ``ap``)
        is the route of an access point, and ``login`` means that the RTAC asks
        for a RTAC user's login (``needs_rtac_login``). An IPv6 address is
        written in brackets (``[2001:db8::1]:3254:1``).

        Examples: ``192.0.2.10:3254:1`` (SEL server, Telnet, ``PORT 1``),
        ``192.0.2.10:3254:2:ssh``, ``192.0.2.10:3254:1:login``,
        ``192.0.2.10:51001:raw:interleaved`` (an access point to a ``_TAP``).

        Raises:
            ValueError: The format isn't valid
        """
        text = str(spec).strip()
        if text.startswith("["):
            host, sep, rest = text[1:].partition("]")
            if not sep or not rest.startswith(":"):
                raise ValueError(f"invalid tunnel '{spec}': expected '[IPv6]:PORT...'")
            fields = rest[1:].split(":")
        else:
            host, *fields = text.split(":")

        if not host or not fields or not fields[0]:
            raise ValueError(
                f"invalid tunnel '{spec}': expected 'RTAC_IP:TCP_PORT[:SEL_PORT][:TRANSPORT]'"
            )

        entry: dict[str, Any] = {"rtac_ip": host, "tcp_port": fields[0], "source": source}
        for value in fields[1:]:
            word = value.strip().lower()
            if not word:
                continue
            if word.isdigit() and "sel_port" not in entry:
                entry["sel_port"] = word
            elif word in _TRANSPORT_ALIASES and "transport" not in entry:
                entry["transport"] = word
            elif word in _ROUTE_ALIASES and "route" not in entry:
                entry["route"] = word
            elif word == "login" and "needs_rtac_login" not in entry:
                entry["needs_rtac_login"] = True
            else:
                raise ValueError(f"invalid tunnel '{spec}': unexpected '{value}'")

        return cls.from_dict(entry)

    @classmethod
    def coerce(
        cls,
        value: RTACTunnel | Mapping[str, Any] | str,
        default_rtac_ip: str = "",
        source: str = "",
    ) -> RTACTunnel:
        """
        A tunnel from a :class:`RTACTunnel`, an engineering access entry
        (:meth:`from_dict`), or the ``--rtac-tunnel`` format (:meth:`from_spec`).

        Raises:
            ValueError: The value isn't valid
        """
        if isinstance(value, RTACTunnel):
            return value
        if isinstance(value, str):
            return cls.from_spec(value, source=source or "config")
        return cls.from_dict(value, default_rtac_ip=default_rtac_ip, source=source)

    @property
    def target_id(self) -> str:
        """
        ID of the path, e.g. ``192.0.2.10_3254_p1`` (``PORT 1`` of the SEL server
        on TCP port 3254) or ``192.0.2.10_51001`` (an access point). It has no ``:``.
        """
        ident = f"{self.rtac_ip}_{self.tcp_port}"
        if self.kind == "sel_server" and self.sel_port is not None:
            ident += f"_p{self.sel_port}"
        return safe_id(ident)

    @property
    def endpoint(self) -> str:
        """The RTAC's address and TCP port, e.g. ``192.0.2.10:3254``."""
        host = f"[{self.rtac_ip}]" if ":" in self.rtac_ip else self.rtac_ip
        return f"{host}:{self.tcp_port}"

    @property
    def may_be_direct(self) -> bool:
        """
        If the path may be a direct route, which stops the RTAC's polling of the
        device: a ``direct`` route, or an access point whose route isn't known.
        """
        return self.route == "direct" or (self.kind == "access_point" and self.route is None)

    @property
    def path_key(self) -> tuple:
        """What makes two paths the same path."""
        return (self.rtac_ip.lower(), self.tcp_port, self.kind, self.sel_port)

    def describe(self) -> str:
        """A description for messages, e.g. ``SEL server 192.0.2.10:3254 PORT 1 (telnet)``."""
        if self.kind == "sel_server":
            port = f" PORT {self.sel_port}" if self.sel_port is not None else ""
            text = f"SEL server {self.endpoint}{port}"
        else:
            text = f"access point {self.endpoint} ({self.route or 'unknown'} route)"
        if self.device_name:
            text += f" to '{self.device_name}'"
        return f"{text} ({self.transport})"

    def with_port(self, sel_port: int, device_name: str | None = None) -> RTACTunnel:
        """A copy of this SEL server path for one port, e.g. from a row of ``WHO``."""
        return replace(
            self,
            sel_port=sel_port,
            device_name=device_name or self.device_name,
            creds=dict(self.creds),
        )

    def to_dict(self) -> dict[str, Any]:
        """The path as an engineering access entry (the keys in :data:`ENTRY_KEYS`)."""
        return {
            "name": self.name,
            "rtac_ip": self.rtac_ip,
            "tcp_port": self.tcp_port,
            "transport": self.transport,
            "kind": self.kind,
            "sel_port": self.sel_port,
            "device_name": self.device_name,
            "route": self.route,
            "needs_rtac_login": self.needs_rtac_login,
            "termination_string": self.termination_string,
            "source": self.source,
        }

    def gateway_info(self) -> dict[str, Any]:
        """
        How a device was reached, for ``extra.gateway`` of the device
        (``type``, ``ip``, ``tcp_port``, ``sel_port``, ``transport``, ``kind``,
        ``route``, ``name``, ``device_name``, ``source``).
        """
        return {
            "type": "SEL RTAC",
            "ip": self.rtac_ip,
            "tcp_port": self.tcp_port,
            "sel_port": self.sel_port,
            "transport": self.transport,
            "kind": self.kind,
            "route": self.route,
            "name": self.name,
            "device_name": self.device_name,
            "source": self.source,
        }

    @property
    def rtac_ip_is_ip(self) -> bool:
        """If ``rtac_ip`` is an IP address (not a host name)."""
        return _is_ip(self.rtac_ip)


def parse_who_output(text: str) -> list[dict[str, Any]]:
    """
    Parse the table of the ``WHO`` command of a RTAC's SEL server, e.g.::

        Port#  Device                 Protocol
        1      Feeder_1               Client - Serial
        254    Remote_Access_Server   Server - Ethernet

    Returns:
        The rows, as dicts with ``port`` (:class:`int`), ``device``, and ``protocol``
    """
    rows = []
    for line in clean_lines(text):
        match = WHO_ROW_RE.match(line)
        if match:
            rows.append(
                {
                    "port": int(match.group("port")),
                    "device": match.group("device"),
                    "protocol": match.group("protocol"),
                }
            )
    return rows


def is_device_row(row: Mapping[str, Any]) -> bool:
    """If a row of ``WHO`` is a device the RTAC polls (a client), not a server."""
    return "server" not in str(row.get("protocol", "")).lower()


def tls_client_context(legacy: bool = False) -> ssl.SSLContext:
    """
    TLS context for a RTAC's tunnel port. The certificate isn't verified (RTACs
    use a self-signed certificate by default). With ``legacy``, TLS 1.0 and
    weak ciphers are allowed too, for older firmware.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # must be set before verify_mode
    ctx.verify_mode = ssl.CERT_NONE
    if legacy:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


class ByteStream:
    """
    A connection to a RTAC that isn't Telnet: raw TCP (:class:`SocketStream`),
    TLS, or a SSH channel (:class:`SSHStream`). Bytes are sent and received as
    they are, so ``0xFF`` isn't a Telnet command.

    It has the methods of :class:`~peat.protocols.telnet.Telnet` that
    :class:`SELTunnel` uses. The data received is recorded in ``all_output``
    and ``raw_output``, and saved to ``raw-tunnel-output.json`` of
    ``output_dev`` when the connection is closed.
    """

    ENCODING: str = "latin-1"
    READ_DELAY: float = 0.15
    RAW_OUTPUT_FILE: str = "raw-tunnel-output.json"

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
        output_dev: DeviceData | None = None,
    ) -> None:
        self.ip: str = host
        self.port: int = port
        self.timeout: float = timeout
        #: Device the raw output is saved to (the device behind the RTAC)
        self.output_dev: DeviceData | None = output_dev
        self.connected: bool = False
        self.all_output: list[str] = []
        self.raw_output: list[bytes] = []
        #: Details of the connection (e.g. the TLS version, or the SSH host key)
        self.info: dict[str, Any] = {}
        self._expecter: Expecter | None = None
        self._secrets: set[str] = set()
        self.log = log.bind(classname=self.__class__.__name__, target=f"{host}:{port}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    # -- transport (implemented by subclasses) ------------------------------

    def _connect(self) -> ReadChunk:
        raise NotImplementedError

    def _send(self, data: bytes) -> None:
        raise NotImplementedError

    def _close_transport(self) -> None:
        raise NotImplementedError

    # -- Telnet-like interface ------------------------------------------------

    def open(self) -> None:
        """
        Connect.

        Raises:
            CommError: The connection failed
        """
        if self.connected:
            return
        try:
            reader = self._connect()
        except CommError:
            self._close_transport()
            raise
        except Exception as ex:
            self._close_transport()
            raise CommError(f"Failed to connect to {self.ip}:{self.port}: {ex}") from ex
        self._expecter = Expecter(reader)
        self.connected = True
        self.log.info(f"Connected to {self.ip}:{self.port}")

    def test_connection(self) -> bool:
        try:
            self.open()
        except CommError:
            return False
        return True

    @property
    def expecter(self) -> Expecter:
        if self._expecter is None:
            self.open()
        return self._expecter

    def register_secret(self, secret: str) -> None:
        if secret:
            self._secrets.add(secret)

    def _add_data(self, raw: bytes, strip_whitespace: bool = False) -> str:
        recorded = raw
        text = raw.decode(self.ENCODING, errors="replace")
        shown = text
        for secret in self._secrets:
            recorded = recorded.replace(
                secret.encode(self.ENCODING, errors="replace"), b"<redacted>"
            )
            shown = shown.replace(secret, "<redacted>")
        self.raw_output.append(recorded)
        self.all_output.append(shown)
        return text.strip() if strip_whitespace else text

    def write_raw(self, data: bytes, sensitive: bool = False) -> None:
        """
        Send bytes as they are.

        Raises:
            CommError: Not connected, or the connection failed
        """
        if not self.connected:
            raise CommError(f"Not connected to {self.ip}:{self.port}")
        if not sensitive:
            self.log.trace3(f"Writing {data!r}")
        try:
            self._send(data)
        except (OSError, EOFError, paramiko.SSHException) as ex:
            raise CommError(f"Failed to send to {self.ip}:{self.port}: {ex}") from ex

    def expect(
        self,
        patterns: Sequence[PatternLike],
        timeout: float | None = None,
        idle_timeout: float | None = None,
        settle: float | Sequence[float] = 0.0,
        window: int | None = None,
        accept=None,
    ) -> ExpectResult:
        """Read until a pattern matches (refer to :meth:`peat.protocols.telnet.Telnet.expect`)."""
        result = self.expecter.expect(
            patterns,
            self.timeout if timeout is None else timeout,
            idle_timeout=idle_timeout,
            settle=settle,
            window=window,
            accept=accept,
        )
        if result.data:
            self._add_data(result.data)
        if result.eof:
            self.log.debug("Connection closed by the RTAC")
        return result

    def read_available(self) -> bytes:
        data = self.expecter.read_available()
        if data:
            self._add_data(data)
        return data

    def read(self, delay: float | None = None, strip_whitespace: bool = True) -> str:
        """Sleep, then read everything that arrived (for ``legacy_timing``)."""
        sleep(self.READ_DELAY if delay is None else delay)
        data = self.expecter.read_available()
        if not data and self.expecter.eof:
            raise EOFError("connection closed")
        return self._add_data(data, strip_whitespace)

    def read_until(
        self,
        until: bytes | str,
        delay: float = 0.15,
        timeout: float | None = None,
        strip_whitespace: bool = True,
    ) -> str:
        if isinstance(until, str):
            until = until.encode(self.ENCODING)
        sleep(delay)
        result = self.expecter.expect(
            [re.escape(until)], self.timeout if timeout is None else timeout
        )
        return self._add_data(result.data, strip_whitespace)

    def disconnect(self) -> None:
        """Close the connection, and save the raw output to the device's files."""
        if not self.connected:
            self._close_transport()
            return
        self._close_transport()
        self.connected = False
        self._expecter = None
        self.log.debug(f"Disconnected from {self.ip}:{self.port}")

        if self.all_output and self.output_dev is not None:
            try:
                self.output_dev.write_file(
                    self.all_output, self.RAW_OUTPUT_FILE, merge_existing=True
                )
            except Exception as ex:
                self.log.warning(f"Failed to write raw output to file: {ex}")


class SocketStream(ByteStream):
    """Raw TCP, or TLS (``tls=True``), to a RTAC."""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
        output_dev: DeviceData | None = None,
        tls: bool = False,
    ) -> None:
        super().__init__(host, port, timeout, output_dev)
        self.tls: bool = tls
        self._sock: socket.socket | None = None

    def _connect(self) -> ReadChunk:
        sock = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        if self.tls:
            sock = self._wrap_tls(sock)
        sock.settimeout(self.timeout)
        self._sock = sock
        return socket_reader(sock)

    def _wrap_tls(self, sock: socket.socket) -> ssl.SSLSocket:
        try:
            tls = tls_client_context().wrap_socket(sock, server_hostname=None)
        except ssl.SSLError as ex:
            # e.g. old firmware that only has TLS 1.0: one more try, on a new connection
            sock.close()
            self.log.debug(f"TLS handshake failed ({ex}), trying again with legacy TLS settings")
            sock = socket.create_connection((self.ip, self.port), timeout=self.timeout)
            try:
                tls = tls_client_context(legacy=True).wrap_socket(sock, server_hostname=None)
            except Exception:
                sock.close()
                raise
            self.info["tls_legacy"] = True

        self.info["tls_version"] = tls.version()
        der = tls.getpeercert(binary_form=True)
        if der:
            self.info["tls_certificate_sha256"] = hashlib.sha256(der).hexdigest().upper()
        return tls

    def _send(self, data: bytes) -> None:
        if self._sock is None:
            raise OSError("not connected")
        self._sock.sendall(data)

    def _close_transport(self) -> None:
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


class SSHStream(ByteStream):
    """
    An interactive SSH channel (``invoke_shell``) to a RTAC. The RTAC user's
    name and password are the SSH login (one attempt). The host key is accepted
    and recorded (``info["ssh_host_key"]``), since RTACs generate their own.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
        output_dev: DeviceData | None = None,
        username: str = "",
        password: str = "",
    ) -> None:
        super().__init__(host, port, timeout, output_dev)
        self.username: str = username
        self._password: str = password
        self._client: paramiko.SSHClient | None = None
        self._channel: paramiko.Channel | None = None

    def _connect(self) -> ReadChunk:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client = client
        try:
            client.connect(
                hostname=self.ip,
                port=self.port,
                username=self.username,
                password=self._password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException:
            raise RTACLoginError(
                f"The RTAC at {self.ip}:{self.port} rejected the SSH login of user "
                f"'{self.username}' (PEAT doesn't try again)"
            ) from None

        transport = client.get_transport()
        key = transport.get_remote_server_key() if transport else None
        if key is not None:
            digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode()
            self.info["ssh_host_key"] = {
                "type": key.get_name(),
                "fingerprint": f"SHA256:{digest.rstrip('=')}",
            }

        channel = client.invoke_shell(term="vt100", width=255, height=50)
        channel.settimeout(self.timeout)
        self._channel = channel
        return channel_reader(channel)

    def _send(self, data: bytes) -> None:
        if self._channel is None:
            raise OSError("not connected")
        self._channel.sendall(data)

    def _close_transport(self) -> None:
        channel, self._channel = self._channel, None
        client, self._client = self._client, None
        for obj in (channel, client):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass


class SELTunnel(SELTelnet):
    """
    SEL ASCII session with a device behind a SEL RTAC, through one of the RTAC's
    engineering access tunnels (refer to the module docstring).

    :meth:`connect` (which the first command calls) opens the tunnel:

    #. Connect to the RTAC's TCP port with the tunnel's transport. If the RTAC
       asks for a login (``login:``, ``password:``), send the RTAC user's name and
       password (``rtac_creds``), once. With SSH, they're the SSH login.
    #. SEL server: wait for its prompt (``*``), send ``ACC`` (and its password,
       ``rtac_creds["acc"]``, if the RTAC asks for one), list the devices with
       ``WHO`` (:attr:`who_rows`), send ``PORT n``, wait for "Establishing
       connection...", and send a carriage return to get the device's prompt.
    #. Access point: send a carriage return, and wait for the device's prompt.

    After that, the device's prompt is tracked as with Telnet, and every SEL
    ASCII command works the same way. PEAT only sends ``ACC``, ``WHO``, ``PORT n``,
    and ``QUI`` to the RTAC itself, besides the login, a carriage return (to get a
    prompt), CAN (to cancel a password dialog), and the termination string.

    A login that the RTAC rejected (the RTAC user's, also with SSH, or the SEL
    server's ``ACC`` password) isn't sent to that RTAC again, through any path
    (:class:`RTACLoginError`, :meth:`rejected_login`), until
    :meth:`forget_rejected_logins` is called (at the start of each pass over
    gateways), so failed logins through several paths don't lock the RTAC's account.

    :meth:`disconnect` sends ``QUI`` to the device (not ``EXIT``, which serial ports
    don't have), and for a SEL server, waits for the pre-termination timeout without
    sending anything, sends the termination string, waits for the SEL server's
    prompt, sends ``QUI`` to the SEL server, and closes the connection, so the
    transparent connection isn't left open. If PEAT stopped sending to the device
    (:attr:`~peat.modules.sel.sel_ascii.SELAscii.halted`, e.g. a password dialog
    that couldn't be cancelled), the device isn't sent ``QUI``, but the tunnel is
    still closed. As on serial, :attr:`halted` stays set after the tunnel is
    closed, since the device's port keeps its state.

    File transfers (``FILE`` commands) aren't sent unless ``allow_file_transfer``
    is set (``sel.tunnel_file_transfer``), since the RTAC's File Transfer Monitor
    switches an interleaved connection to direct during a file transfer.
    """

    #: How data was transferred, in the metadata of files (``File.extra["transport"]``)
    transport_name: str = "rtac_tunnel"
    #: Maximum number of prompts answered while opening the tunnel
    MAX_DIALOG_STEPS: int = 8

    #: Logins that RTACs rejected (digests), by the RTAC's address (lowercase).
    #: Shared by all tunnels, refer to :meth:`rejected_login`.
    _rejected_logins: ClassVar[dict[str, set[str]]] = {}

    def __init__(
        self,
        tunnel: RTACTunnel | Mapping[str, Any] | str,
        timeout: float = 5.0,
        legacy_timing: bool = False,
        idle_timeout: float = 30.0,
        rtac_creds: Mapping[str, Any] | None = None,
        allow_file_transfer: bool = False,
        output_dev: DeviceData | None = None,
        enter_device: bool = True,
    ) -> None:
        """
        Args:
            tunnel: The path to the device (refer to :meth:`RTACTunnel.coerce`)
            timeout: Seconds to wait for each step of the RTAC's dialog, and for
                responses to commands with little output (refer to
                :class:`~peat.modules.sel.sel_ascii.SELAscii`)
            legacy_timing: Use fixed delays instead of waiting for the device's prompts
            idle_timeout: Refer to :class:`~peat.modules.sel.sel_ascii.SELAscii`
            rtac_creds: The RTAC user's name and password (``user``, ``pass``),
                and the password of the SEL server's ``ACC`` (``acc``), if the
                RTAC asks for them. They're never guessed.
            allow_file_transfer: Allow ``FILE`` commands (``sel.tunnel_file_transfer``)
            output_dev: Device that files and the raw output are saved to (the device
                behind the RTAC, not the RTAC). It can be set later (``output_dev``),
                e.g. when the device is identified. Without it, the raw output is
                only in the protocol log.
            enter_device: Open the connection to the device (``PORT n``). If
                :obj:`False`, only connect to the SEL server and run ``WHO``.
        """
        tunnel = RTACTunnel.coerce(tunnel)
        self.tunnel: RTACTunnel = tunnel
        super().__init__(
            tunnel.target_id,
            tunnel.tcp_port,
            timeout,
            legacy_timing=legacy_timing,
            idle_timeout=idle_timeout,
        )
        # The endpoint (the RTAC). The address (the identity of the device in
        # logs and in the passwords PEAT remembers) is the path, without ":".
        self.ip = tunnel.rtac_ip
        self.output_dev = output_dev
        self.rtac_creds: dict[str, str] = {
            str(k).lower(): str(v) for k, v in (rtac_creds or {}).items() if v
        }
        self.allow_file_transfer: bool = allow_file_transfer
        self.enter_device: bool = enter_device
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=tunnel.target_id,
            gateway=tunnel.endpoint,
        )

        #: Rows of ``WHO`` on the SEL server (refer to :func:`parse_who_output`)
        self.who_rows: list[dict[str, Any]] = []
        #: Details of the tunnel's connection, e.g. the TLS version or SSH host key
        self.session_info: dict[str, Any] = {}
        #: The connection to the device is open (after ``PORT n``, or on an access point)
        self.in_device: bool = False

        self._stream: Telnet | ByteStream | None = None
        self._port_open: bool = False
        self._opened: bool = False
        self._exit_callback = self.disconnect

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.tunnel.describe()}, timeout={self.timeout})"

    # -- rejected logins ------------------------------------------------------------

    @staticmethod
    def _login_keys(tunnel: RTACTunnel, creds: Mapping[str, str]) -> dict[str, str]:
        """Digests of the logins a path would use: ``login``, and ``acc`` for a SEL server."""
        keys = {}
        user, password = creds.get("user", ""), creds.get("pass", "")
        if user or password:
            keys["login"] = _login_key("login", user, password)
        if tunnel.kind == "sel_server" and creds.get("acc"):
            keys["acc"] = _login_key("acc", creds["acc"])
        return keys

    @classmethod
    def rejected_login(cls, tunnel: RTACTunnel, creds: Mapping[str, Any] | None) -> str:
        """
        If the RTAC of ``tunnel`` rejected a login that the path would use: the
        RTAC user (``user`` and ``pass`` in ``creds``, the same for every path to
        the RTAC, and for SSH), or for a SEL server, the ``ACC`` password (``acc``).

        Returns:
            What was rejected (e.g. "the login of RTAC user 'engineer'"), or an
            empty string
        """
        rejected = cls._rejected_logins.get(tunnel.rtac_ip.lower())
        if not rejected:
            return ""
        creds = {str(k).lower(): str(v) for k, v in (creds or {}).items() if v}
        keys = cls._login_keys(tunnel, creds)
        if keys.get("login") in rejected:
            return f"the login of RTAC user '{creds.get('user', '')}'"
        if keys.get("acc") in rejected:
            return "the SEL server's ACC password"
        return ""

    @classmethod
    def forget_rejected_logins(cls, rtac_ip: str | None = None) -> None:
        """Forget the logins that a RTAC (or every RTAC) rejected, so they're tried again."""
        if rtac_ip is None:
            cls._rejected_logins.clear()
        else:
            cls._rejected_logins.pop(rtac_ip.lower(), None)

    def _remember_rejection(self, credential: str) -> None:
        key = self._login_keys(self.tunnel, self.rtac_creds).get(credential)
        if key:
            self._rejected_logins.setdefault(self.tunnel.rtac_ip.lower(), set()).add(key)

    def _check_rejected(self, credential: str) -> None:
        """
        Raises:
            RTACLoginError: The RTAC rejected this login before (it isn't sent again)
        """
        key = self._login_keys(self.tunnel, self.rtac_creds).get(credential)
        if key and key in self._rejected_logins.get(self.tunnel.rtac_ip.lower(), ()):
            if credential == "login":
                what = f"the login of RTAC user '{self.rtac_creds.get('user', '')}'"
            else:
                what = "the SEL server's ACC password"
            raise RTACLoginError(
                f"The RTAC at {self.tunnel.endpoint} rejected {what} before, PEAT "
                f"doesn't send it again",
                credential,
            )

    # -- connection -------------------------------------------------------------

    @property
    def comm(self) -> Telnet | ByteStream:
        """
        The connection to the RTAC. The tunnel is opened when it's first used.
        After :meth:`disconnect`, or if the connection was lost, it isn't opened
        again by a command (call :meth:`connect`), so a lost tunnel doesn't
        make a new session with the RTAC and the device for each command.
        """
        if self._stream is None or not self._stream.connected:
            if self._opened:
                raise CommError(f"The tunnel {self.tunnel.describe()} is closed")
            self.connect()
        return self._stream

    @comm.setter
    def comm(self, obj: Telnet | ByteStream) -> None:
        self._stream = obj

    def register_secret(self, secret: str) -> None:
        SELAscii.register_secret(self, secret)
        if secret and self._stream is not None:
            self._stream.register_secret(secret)

    def test_connection(self) -> bool:
        """Open the tunnel (refer to :meth:`connect`). Returns if it worked."""
        try:
            self.connect()
        except (CommError, SELCommandRefused) as ex:
            self.log.error(f"Failed to open {self.tunnel.describe()}: {ex}")
            return False
        return True

    def _new_stream(self) -> Telnet | ByteStream:
        tunnel = self.tunnel
        if tunnel.transport == "telnet":
            stream = Telnet(tunnel.rtac_ip, tunnel.tcp_port, self.timeout)
            stream.ENCODING = self.ENCODING
            stream.PRE_WRITE_SLEEP = self.PRE_WRITE_SLEEP
            stream.POST_WRITE_SLEEP = self.POST_WRITE_SLEEP
            stream.READ_DELAY = self.READ_DELAY
            stream.output_dev = self.output_dev
        elif tunnel.transport == "ssh":
            user, password = self.rtac_creds.get("user", ""), self.rtac_creds.get("pass", "")
            if not user or not password:
                raise TunnelError(
                    f"{tunnel.describe()} needs the name and password of a RTAC user "
                    f"(sel.rtac_tunnel_creds), PEAT doesn't guess them"
                )
            self._check_rejected("login")
            stream = SSHStream(
                tunnel.rtac_ip, tunnel.tcp_port, self.timeout, self.output_dev, user, password
            )
        else:
            stream = SocketStream(
                tunnel.rtac_ip,
                tunnel.tcp_port,
                self.timeout,
                self.output_dev,
                tls=tunnel.transport == "tls",
            )

        for secret in self._secrets | set(self.rtac_creds.values()):
            stream.register_secret(secret)
        return stream

    def connect(self) -> None:
        """
        Open the tunnel to the device (refer to the class docstring).

        Raises:
            RTACLoginError: The RTAC rejected the login (now, or before)
            TunnelError: The RTAC refused the port, or didn't respond as expected
            CommError: The connection failed
        """
        if self._stream is not None and self._stream.connected:
            return
        self._check_halted()

        tunnel = self.tunnel
        self.log.info(
            f"Opening {tunnel.describe()} (the RTAC may log this engineering access session)"
        )
        for secret in self.rtac_creds.values():
            SELAscii.register_secret(self, secret)

        stream = self._new_stream()
        self._stream = stream
        self._opened = True
        self.in_device = False
        self._port_open = False
        try:
            if isinstance(stream, Telnet):
                stream.comm  # noqa: B018 (connects)
            else:
                stream.open()
                self.session_info.update(stream.info)
        except CommError as ex:
            self._stream = None
            if isinstance(ex, RTACLoginError):
                self._remember_rejection(ex.credential)
            raise
        exit_handler.register(self._exit_callback, "CONNECTION")

        try:
            prompt = self._open_dialog()
            if tunnel.kind == "sel_server":
                self._sel_server_session(prompt)
            else:
                self._enter_device(prompt)
        except Exception as ex:
            if isinstance(ex, RTACLoginError):
                self._remember_rejection(ex.credential)
            self._abort()
            raise

    def _abort(self) -> None:
        """Close a tunnel that couldn't be opened completely."""
        try:
            if self._port_open:
                self._terminate_port()
        except Exception as ex:
            self.log.debug(f"Failed to end the transparent connection: {ex}")
        self._close_stream()

    def _close_stream(self) -> None:
        stream, self._stream = self._stream, None
        if stream is not None:
            try:
                leftover = stream.read_available() if stream.connected else b""
                if leftover:
                    self._record(leftover)
            except Exception:
                pass
            # The raw output is saved to the device behind the RTAC, never to the
            # RTAC's device. Without a device (e.g. before it's identified), it's
            # only in the protocol log (all_output and raw_output of this object).
            stream.output_dev = self.output_dev
            if self.output_dev is None:
                stream.all_output.clear()
            stream.disconnect()
        self.in_device = False
        self._port_open = False
        exit_handler.unregister(self._exit_callback, "CONNECTION")

    # -- the RTAC's dialog ----------------------------------------------------------

    def _gateway_write(
        self,
        data: str | bytes,
        sensitive: bool = False,
        terminator: bool = True,
        check: bool = True,
    ) -> None:
        """
        Send something to the RTAC itself: one of the commands in
        :data:`GATEWAY_COMMAND_RE`, an answer to its login (``check=False``),
        or the termination string (``terminator=False``).
        """
        if isinstance(data, str):
            data = data.encode(self.ENCODING, errors="replace")
        if check and not sensitive and not GATEWAY_COMMAND_RE.fullmatch(data.decode("latin-1")):
            raise SELCommandRefused(f"PEAT won't send {data!r} to the RTAC {self.tunnel.endpoint}")
        if terminator:
            data += self.LINE_TERMINATOR.encode(self.ENCODING)
        self.all_writes.append(REDACTED_WRITE + b"\r\n" if sensitive else data)
        self._stream.write_raw(data, sensitive=sensitive)

    def _gateway_expect(
        self,
        extra: Sequence[re.Pattern] = (),
        timeout: float | None = None,
    ) -> ExpectResult:
        """
        Wait for a prompt (patterns 0 and 1) or one of the ``extra`` patterns
        (2, 3, ...) from the RTAC. The data is recorded.
        """
        patterns = [FRAMED_PROMPT_RE, UNFRAMED_PROMPT_RE, *extra]
        settle = [0.0, self.PROMPT_SETTLE] + [0.1] * len(extra)
        result = self._stream.expect(
            patterns,
            timeout=self.timeout if timeout is None else timeout,
            settle=settle,
            accept=self._accept_prompt,
        )
        if result.data:
            self._record(result.data)
        return result

    @staticmethod
    def _prompt(result: ExpectResult) -> str:
        if result.match is not None and result.index in (0, 1):
            return result.match.group("prompt").decode("ascii")
        return ""

    def _text(self, result: ExpectResult) -> str:
        return " ".join(clean_lines(self._decode(result.data)))[:300]

    def _open_dialog(self) -> str:
        """
        Answer the RTAC's login, if it asks, until a prompt arrives (the SEL
        server's ``*`` or ``*>``, or the device's prompt on an access point).

        Returns:
            The prompt
        """
        tunnel = self.tunnel
        login_sent = password_sent = woke = cancelled = False
        # A device behind an access point (or a SEL server that doesn't greet)
        # only shows its prompt for a carriage return, so don't wait long for it,
        # unless the RTAC may ask for a login first (the path says so, or a RTAC
        # user is configured): a carriage return at a late "login:" would be an
        # empty user name, which the RTAC may count as a failed login.
        may_ask_login = tunnel.needs_rtac_login or bool(
            self.rtac_creds.get("user") or self.rtac_creds.get("pass")
        )
        wait = self.timeout if may_ask_login else min(float(self.timeout), 1.0)

        for _ in range(self.MAX_DIALOG_STEPS):
            result = self._gateway_expect(
                [LOGIN_RE, RTAC_PASSWORD_RE, LOGIN_FAILED_RE, PASSWORD_RE],
                timeout=wait,
            )
            wait = self.timeout

            if result.index == 5:
                # The device behind an access point is still in a password
                # dialog (e.g. a serial port left that way): cancel it (CAN)
                if cancelled:
                    self._halt("the device's password dialog couldn't be cancelled")
                    raise TunnelError(f"The device behind {tunnel.describe()} asks for a password")
                self.log.warning(
                    f"The device behind {tunnel.describe()} asks for a password, cancelling"
                )
                self._gateway_write(CAN, terminator=False, check=False)
                cancelled = True
                continue

            rejected = (login_sent or password_sent) and (
                result.index == 4
                or (result.index == 2 and login_sent)
                or (result.index == 3 and password_sent)
            )
            if rejected:
                raise RTACLoginError(
                    f"The RTAC at {tunnel.endpoint} rejected the login of RTAC user "
                    f"'{self.rtac_creds.get('user', '')}' (PEAT doesn't send it to this "
                    f"RTAC again)"
                )
            if result.index == 4:
                # e.g. "Access denied" before PEAT sent anything
                raise TunnelError(
                    f"The RTAC at {tunnel.endpoint} refused the connection "
                    f"('{self._text(result)}')"
                )
            if result.index == 2:
                user = self.rtac_creds.get("user", "")
                if not user:
                    raise TunnelError(
                        f"The RTAC at {tunnel.endpoint} asks for a RTAC user's login. "
                        f"Set sel.rtac_tunnel_creds (PEAT doesn't guess RTAC passwords)."
                    )
                self._check_rejected("login")
                self.log.info(f"Logging in to the RTAC at {tunnel.endpoint} as '{user}'")
                self._gateway_write(user, check=False)
                login_sent = True
                continue
            if result.index == 3:
                password = self.rtac_creds.get("pass", "")
                if not password:
                    raise TunnelError(
                        f"The RTAC at {tunnel.endpoint} asks for a RTAC user's password. "
                        f"Set sel.rtac_tunnel_creds (PEAT doesn't guess RTAC passwords)."
                    )
                self._check_rejected("login")
                self._gateway_write(password, sensitive=True)
                password_sent = True
                continue

            prompt = self._prompt(result)
            if prompt:
                self.session_info["rtac_login"] = login_sent
                return prompt

            if result.eof:
                raise TunnelError(
                    f"The RTAC at {tunnel.endpoint} closed the connection ('{self._text(result)}')"
                )
            if woke:
                break
            # Nothing yet: a carriage return makes the SEL server or the device show its prompt
            self._gateway_write("")
            woke = True

        raise TunnelError(f"No prompt from {tunnel.describe()}")

    def _sel_server_session(self, prompt: str) -> None:
        tunnel = self.tunnel
        if prompt not in ("*", "*>"):
            raise TunnelError(
                f"{tunnel.endpoint} doesn't look like a RTAC SEL server: its prompt is "
                f"'{prompt}', not '*'. If it's an access point, set its kind to 'access_point'."
            )
        if prompt == "*":
            prompt = self._sel_server_acc()

        self.who_rows = self._sel_server_who()
        if not self.enter_device:
            return

        port = tunnel.sel_port
        if port is None:
            raise TunnelError(f"No SEL server port (PORT n) for {tunnel.describe()}")
        if self.who_rows:
            row = next((r for r in self.who_rows if r["port"] == port), None)
            if row is None:
                raise TunnelError(f"WHO on {tunnel.endpoint} doesn't list port {port}")
            if not is_device_row(row):
                raise TunnelError(
                    f"Port {port} on {tunnel.endpoint} is '{row['device']}' "
                    f"({row['protocol']}), not a device"
                )
            self.session_info["who_row"] = row

        self._enter_device(self._sel_server_port(port))

    def _sel_server_acc(self) -> str:
        """Go to the SEL server's access level 1 (``ACC``). Returns the prompt."""
        tunnel = self.tunnel
        self._gateway_write("ACC")
        result = self._gateway_expect([PASSWORD_RE, RTAC_PASSWORD_RE])

        if result.index in (2, 3):
            password = self.rtac_creds.get("acc", "")
            if not password:
                self._gateway_cancel()
                raise TunnelError(
                    f"The SEL server at {tunnel.endpoint} asks for an ACC password. "
                    f"Set it in sel.rtac_tunnel_creds (acc)."
                )
            try:
                self._check_rejected("acc")
            except RTACLoginError:
                self._gateway_cancel()
                raise
            self._gateway_write(password, sensitive=True)
            result = self._gateway_expect([PASSWORD_RE, RTAC_PASSWORD_RE])
            if result.index in (2, 3):
                self._gateway_cancel()
                raise RTACLoginError(
                    f"The SEL server at {tunnel.endpoint} rejected the ACC password "
                    f"(PEAT doesn't send it to this RTAC again)",
                    "acc",
                )

        prompt = self._prompt(result)
        if prompt != "*>":
            raise TunnelError(
                f"ACC failed on the SEL server at {tunnel.endpoint} "
                f"(prompt '{prompt or 'none'}', '{self._text(result)}')"
            )
        return prompt

    def _gateway_cancel(self) -> None:
        # CAN (Ctrl+X) ends the password dialog
        try:
            self._gateway_write(CAN, terminator=False, check=False)
            self._gateway_expect(timeout=self.timeout)
        except Exception as ex:
            self.log.debug(f"Failed to cancel the dialog: {ex}")

    def _sel_server_who(self) -> list[dict[str, Any]]:
        """List the SEL server's devices (``WHO``)."""
        self._gateway_write("WHO")
        result = self._gateway_expect(timeout=self.COMMAND_TIMEOUT)
        if not self._prompt(result):
            self.log.warning(f"No prompt after WHO on {self.tunnel.endpoint}")
        rows = parse_who_output(self._decode(result.before))
        if rows:
            listed = ", ".join(f"{r['port']} {r['device']} ({r['protocol']})" for r in rows)
            self.log.info(f"Devices on the SEL server {self.tunnel.endpoint}: {listed}")
        else:
            self.log.warning(f"Failed to parse the output of WHO on {self.tunnel.endpoint}")
        return rows

    def _sel_server_port(self, port: int) -> str:
        """Open the transparent connection (``PORT n``). Returns the device's prompt."""
        tunnel = self.tunnel
        self._gateway_write(f"PORT {port}")
        result = self._gateway_expect([ESTABLISHING_RE], timeout=self.COMMAND_TIMEOUT)
        if result.index != 2:
            raise TunnelError(
                f"The SEL server at {tunnel.endpoint} didn't open port {port} "
                f"('{self._text(result)}')"
            )
        self._port_open = True

        # The device shows its prompt for a carriage return
        result = self._gateway_expect([PASSWORD_RE], timeout=min(float(self.timeout), 0.5))
        if not self._prompt(result) and result.index != 2 and not result.eof:
            self._gateway_write("")
            result = self._gateway_expect([PASSWORD_RE])

        if result.index == 2:
            # The device's port is still in a password dialog (e.g. from an
            # earlier session): cancel it (CAN), as SELAscii does
            self.log.warning(
                f"The device on port {port} of {tunnel.endpoint} asks for a password, cancelling"
            )
            self._gateway_write(CAN, terminator=False, check=False)
            result = self._gateway_expect([PASSWORD_RE])
            if not self._prompt(result):
                self._halt("the device's password dialog couldn't be cancelled")
                raise TunnelError(
                    f"The device on port {port} of {tunnel.endpoint} asks for a password"
                )

        prompt = self._prompt(result)
        text = self._text(result)
        if not prompt:
            raise TunnelError(f"No prompt from the device on port {port} of {tunnel.endpoint}")
        if prompt in ("*", "*>") and _PORT_FAILED_RE.search(text):
            # The SEL server's prompt after an error, not the device's: the
            # transparent connection isn't open
            self._port_open = False
            raise TunnelError(
                f"The SEL server at {tunnel.endpoint} failed to open port {port}: '{text}'"
            )
        return prompt

    def _enter_device(self, prompt: str) -> None:
        """The connection to the device is open: track the device's prompt from now on."""
        self.in_device = True
        self.access_level = ""
        self.priv_level = 0
        self._set_level_from_prompt(prompt)
        self._first_command = True
        self.log.info(
            f"Connected to the device through {self.tunnel.describe()} "
            f"(prompt '{prompt}', access level {self.access_level or 'unknown'})"
        )

    def _quiet(self, seconds: float) -> None:
        """Read (and record) for ``seconds``, without sending anything."""
        deadline = monotonic() + seconds
        while (remaining := deadline - monotonic()) > 0:
            result = self._stream.expect([], timeout=remaining)
            if result.data:
                self._record(result.data)
            if result.eof:
                return

    def _terminate_port(self) -> bool:
        """
        End the SEL server's transparent connection: nothing is sent for the
        pre-termination timeout, then the termination string, and the SEL
        server shows its prompt. Then ``QUI`` logs out of the SEL server.

        Returns:
            If the SEL server showed its prompt
        """
        tunnel = self.tunnel
        terminator = (tunnel.termination_string or DEFAULT_TERMINATION).encode("latin-1")
        self._quiet(tunnel.pre_term_s + 0.25)
        self._gateway_write(terminator, terminator=False, check=False)
        if tunnel.post_term_s:
            self._quiet(tunnel.post_term_s)
        self._port_open = False

        result = self._gateway_expect(timeout=self.timeout)
        if self._prompt(result) in ("*", "*>"):
            self.log.debug(f"Transparent connection on {tunnel.endpoint} ended")
            self._gateway_write("QUI")
            self._gateway_expect(timeout=min(float(self.timeout), 1.0))
            return True

        self.log.warning(
            f"The SEL server at {tunnel.endpoint} didn't show its prompt after the "
            f"termination string, closing the connection"
        )
        return False

    # -- SEL ASCII session ----------------------------------------------------------

    def _check_command(self, command: bytes, terminator: bool, sensitive: bool = False) -> None:
        super()._check_command(command, terminator, sensitive=sensitive)
        if terminator and not self.allow_file_transfer:
            text = command.decode("latin-1", errors="replace")
            if normalize_command(text).startswith("FIL"):
                message = (
                    f"PEAT won't send '{text}' through {self.tunnel.describe()}: file "
                    f"transfers through RTAC tunnels need sel.tunnel_file_transfer (the "
                    f"RTAC's File Transfer Monitor switches the connection to direct)"
                )
                self.log.error(message)
                raise SELCommandRefused(message)

    def can_download_files(self) -> bool:
        if not self.allow_file_transfer:
            self.log.info(
                f"Not downloading files through {self.tunnel.describe()} "
                f"(sel.tunnel_file_transfer isn't enabled)"
            )
            return False
        return super().can_download_files()

    def list_files(self, directory: str | None = None) -> list[str]:
        if not self.allow_file_transfer:
            self.log.info(f"Not listing files through {self.tunnel.describe()}")
            return []
        return super().list_files(directory)

    def _send_exit_commands(self) -> None:
        # QUIT returns the device to access level 0. EXIT isn't sent: it ends a
        # Telnet session of the device, and serial ports don't have it.
        if self.legacy_timing:
            self.write("quit")
            return
        self._flush()
        self._send("quit")
        if self._seen_prompt:
            result = self._expect(timeout=self.timeout)
            self.exit_output = self._decode(result.data)

    def disconnect(self) -> None:
        """
        Leave the device and close the tunnel (refer to the class docstring).
        """
        stream = self._stream
        if stream is not None and stream.connected:
            if self.in_device and not (self._no_exit_commands or self.halted):
                try:
                    self._send_exit_commands()
                except Exception as ex:
                    self.log.debug(f"Failed to log out of the device: {ex}")
            elif self.in_device:
                self.log.debug(f"Leaving {self.address} without QUIT")

            if self.tunnel.kind == "sel_server":
                try:
                    if self._port_open:
                        self._terminate_port()
                    else:
                        self._gateway_write("QUI")
                        self._gateway_expect(timeout=min(float(self.timeout), 1.0))
                except Exception as ex:
                    self.log.debug(f"Failed to end the SEL server session: {ex}")

        self._close_stream()

        self.priv_level = 0
        self.access_level = ""
        self._attempted_levels.clear()
        self._first_command = True
        self._no_exit_commands = False
        # NOTE: "halted" stays set, as on serial: closing the tunnel doesn't
        # reset a dialog on the device's port (refer to the class docstring)

    def _protocol_log_name(self) -> str:
        return f"rtac-tunnel_{self.address}"

    def _protocol_log_extra(self) -> dict[str, Any]:
        return {
            "gateway": self.tunnel.gateway_info(),
            "who": self.who_rows,
            "session_info": self.session_info,
        }


__all__ = [
    "DEFAULT_PRE_TERMINATION",
    "DEFAULT_TERMINATION",
    "ENTRY_KEYS",
    "KINDS",
    "ROUTES",
    "TRANSPORTS",
    "ByteStream",
    "RTACLoginError",
    "RTACTunnel",
    "SELTunnel",
    "SSHStream",
    "SocketStream",
    "TunnelError",
    "is_device_row",
    "parse_termination_string",
    "parse_who_output",
    "safe_id",
    "tls_client_context",
]
