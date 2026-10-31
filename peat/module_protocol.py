"""
Metadata about the network and serial protocols used by PEAT device modules.

Protocols a module uses to identify devices (``peat scan``) are derived from
its :attr:`~peat.device.DeviceModule.ip_methods` and
:attr:`~peat.device.DeviceModule.serial_methods`. Protocols used to pull from or
push to devices are declared by modules in
:attr:`~peat.device.DeviceModule.protocols` as :class:`ModuleProtocol` objects.

This metadata is used to describe modules (``--list-modules`` and
``--module-info``) and to select modules by protocol or port
(``-p/--protocols`` and the ``PROTOCOL_FILTER`` option).
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal, get_args

from pydantic import conint, constr, root_validator, validator

from peat import consts
from peat.consts import PeatError
from peat.data.base_model import BaseModel

#: Operations that use protocols to communicate with devices (parse doesn't)
PROTOCOL_OPERATIONS: tuple[str, ...] = get_args(consts.ProtocolOperationType)

#: All operations a device module can support, in display order
MODULE_OPERATIONS: tuple[str, ...] = get_args(consts.OperationType)

#: Values allowed for :attr:`ModuleProtocol.transport`
TransportType = Literal["tcp", "udp", "both", "serial", "other"]

# "_0" rather than "0_", so the docs don't render "a-z0-9_" as a reST link target
_NAME_PATTERN = r"^[a-z][a-z_0-9-]*$"

ProtocolName = constr(strip_whitespace=True, to_lower=True, regex=_NAME_PATTERN)
PortNumber = conint(ge=1, le=65535)


def normalize_protocol_name(name: str) -> str:
    """
    Convert a protocol name into a valid :attr:`ModuleProtocol.name`.

    Names of the protocols in ``ip_methods`` and ``serial_methods`` can be any
    string, e.g. ``opc.ua`` in a third-party module. Characters other than
    lowercase letters, digits, ``_`` and ``-`` are replaced with ``_``.

    >>> from peat.module_protocol import normalize_protocol_name
    >>> normalize_protocol_name("Modbus/TCP")
    'modbus_tcp'
    >>> normalize_protocol_name("opc.ua")
    'opc_ua'
    >>> normalize_protocol_name("104")
    'proto_104'
    >>> normalize_protocol_name("")
    'unknown'

    Args:
        name: Protocol name

    Returns:
        The normalized name. Names that are already valid are unchanged.
        If nothing is left after normalizing, ``unknown`` is returned.
    """
    norm = re.sub(r"[^a-z0-9_\-]+", "_", str(name).strip().lower()).strip("_-")
    if not norm:
        return "unknown"
    if not norm[0].isalpha():
        norm = f"proto_{norm}"
    return norm


class ModuleProtocol(BaseModel):
    """
    A protocol used by a device module, e.g. FTP on TCP port 21 for pulling.

    Protocols used to identify devices (scanning) are derived automatically
    from a module's ``ip_methods`` and ``serial_methods``. Modules declare the
    protocols they use to pull from or push to devices in
    :attr:`DeviceModule.protocols <peat.device.DeviceModule.protocols>`.

    .. code-block:: python

       ModuleProtocol(
           name="ftp",
           transport="tcp",
           ports=[21],
           operations=["pull", "push"],
           description="Download config files (pull), upload config files (push)",
       )
    """

    name: ProtocolName
    """
    Lowercase name of the protocol, e.g. ``ftp``, ``https``, or ``modbus_tcp``.

    By convention, this is the key of the protocol's options in the device
    options (``device_options`` in the YAML config), where the port and
    timeout for the protocol are configured. It's the same name used for
    :attr:`IPMethod.protocol <peat.api.identify_methods.IPMethod.protocol>`.
    Similar protocols, such as ``http`` and ``https``, are separate entries.
    """

    transport: TransportType
    """
    Transport used by the protocol.

    Allowed values:

    - ``tcp``
    - ``udp``
    - ``both`` (TCP and UDP)
    - ``serial`` (e.g. RS-232 or RS-485)
    - ``other`` (e.g. raw Ethernet)
    """

    ports: list[PortNumber] = []
    """
    Default port(s) used by the protocol. Required if the transport is
    ``tcp``, ``udp`` or ``both``, and must be empty if it's ``serial``.
    The port used at runtime is configurable (``<options key>.port``).
    """

    operations: list[consts.ProtocolOperationType]
    """
    Operations that use the protocol: ``scan``, ``pull``, and/or ``push``.
    At least one operation is required.
    """

    description: str = ""
    """
    What the module uses the protocol for, e.g. "Download configuration files".
    """

    options_key: ProtocolName | None = None
    """
    Key of the device options that configure this protocol (e.g. port and
    timeout), if it's different from :attr:`name`. For example, ``sftp`` is
    configured by the ``ssh`` options and ``umas`` by the ``modbus_tcp`` options.
    """

    @validator("ports")
    def _normalize_ports(cls, v: list[int]) -> list[int]:
        return sorted(set(v))

    @validator("operations")
    def _normalize_operations(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one operation is required")
        return [op for op in PROTOCOL_OPERATIONS if op in v]

    @root_validator(skip_on_failure=True)
    def _check_ports(cls, values: dict) -> dict:
        transport, ports = values["transport"], values["ports"]
        if transport in ("tcp", "udp", "both") and not ports:
            raise ValueError(f"ports are required for transport '{transport}'")
        if transport == "serial" and ports:
            raise ValueError("ports must be empty for serial protocols")
        return values

    @property
    def configured_by(self) -> str:
        """
        Key of the device options that configure this protocol.
        """
        return self.options_key or self.name

    @property
    def transports(self) -> set[str]:
        """
        Transport(s) used by the protocol (``both`` is ``{"tcp", "udp"}``).
        """
        return {"tcp", "udp"} if self.transport == "both" else {self.transport}

    def matches(self, term: "ProtocolFilterTerm") -> bool:
        """
        If this protocol matches a term of a protocol filter.

        - Port terms match if any of the protocol's ports are in the term's
          port range, and the term's transport (if any) is used by the protocol.
        - Name terms match the protocol name or its options key exactly, or as
          a prefix followed by ``_`` (``modbus`` matches ``modbus_tcp``).
          The term ``serial`` also matches any serial protocol.

        Args:
            term: Filter term, from :func:`parse_protocol_filter`

        Returns:
            If the protocol matches the term
        """
        if term.port_range is not None:
            low, high = term.port_range
            if not any(low <= port <= high for port in self.ports):
                return False
            return term.transport is None or term.transport in self.transports

        candidates = {self.name, self.configured_by}
        return (
            term.name in candidates
            or any(c.startswith(f"{term.name}_") for c in candidates)
            or (term.name == "serial" and self.transport == "serial")
        )


@dataclass(frozen=True)
class ProtocolFilterTerm:
    """
    A single parsed term of a protocol filter (``-p`` or ``PROTOCOL_FILTER``).

    A term is either a protocol name (``name`` is set) or a port range
    (``port_range`` is set) with an optional transport.
    """

    raw: str
    """Normalized text of the term, e.g. ``161/udp``."""

    name: str | None = None
    """Protocol name, e.g. ``ftp``."""

    port_range: tuple[int, int] | None = None
    """Inclusive range of ports, e.g. ``(20, 25)``. A single port is ``(502, 502)``."""

    transport: Literal["tcp", "udp"] | None = None
    """Transport the port(s) must use, if specified (``161/udp``)."""


_TERM_REGEX = re.compile(
    r"^(?:(?P<low>\d{1,5})(?:-(?P<high>\d{1,5}))?(?:/(?P<transport>tcp|udp))?"
    r"|(?P<name>[a-z][a-z0-9_\-]*))$"
)


def parse_protocol_filter(
    values: str | int | Iterable[str | int] | None,
) -> list[ProtocolFilterTerm]:
    """
    Parse protocol filter values into terms.

    Accepted forms (case-insensitive, comma- and/or space-separated):

    - Protocol name: ``ftp``, ``https``, ``modbus`` (prefix of ``modbus_tcp``), ``serial``
    - Port: ``502``
    - Port range: ``20-25``
    - Port or port range with a transport: ``161/udp``, ``44818/tcp``

    Example:

    >>> from peat.module_protocol import parse_protocol_filter
    >>> [term.raw for term in parse_protocol_filter("FTP, 502 161/udp")]
    ['ftp', '502', '161/udp']
    >>> parse_protocol_filter(["20-25"])[0].port_range
    (20, 25)

    Args:
        values: Filter value(s), e.g. from the ``-p`` argument

    Returns:
        The parsed terms, in order, with duplicates removed. If ``values``
        is :obj:`None` or empty, an empty list is returned.

    Raises:
        PeatError: If a term is invalid
    """
    if values is None:
        return []
    if isinstance(values, (str, int)):
        values = [values]

    terms: list[ProtocolFilterTerm] = []
    for value in values:
        for raw in re.split(r"[\s,]+", str(value)):
            raw = raw.strip().lower()
            if not raw:
                continue

            match = _TERM_REGEX.match(raw)
            if not match:
                raise PeatError(
                    f"Invalid protocol filter '{raw}'. Expected a protocol name "
                    f"(e.g. 'ftp'), port (e.g. '502'), port range (e.g. '20-25'), "
                    f"or port with transport (e.g. '161/udp')"
                )

            if match["name"]:
                term = ProtocolFilterTerm(raw=raw, name=match["name"])
            else:
                low = int(match["low"])
                high = int(match["high"]) if match["high"] else low
                if not 1 <= low <= high <= 65535:
                    raise PeatError(f"Invalid port or port range in protocol filter: '{raw}'")
                term = ProtocolFilterTerm(
                    raw=raw, port_range=(low, high), transport=match["transport"]
                )

            if term not in terms:
                terms.append(term)

    return terms


__all__ = [
    "MODULE_OPERATIONS",
    "PROTOCOL_OPERATIONS",
    "ModuleProtocol",
    "ProtocolFilterTerm",
    "normalize_protocol_name",
    "parse_protocol_filter",
]
