"""
Simple Network Management Protocol (:term:`SNMP`) functionality for PEAT.

Under the hood, PEAT uses the lovely open-source
`PySNMP <https://github.com/etingof/pysnmp>`__
package (NOTE: as of May 2024, we now use
`a fork <https://github.com/lextudio/pysnmp>`__).

The code in this file is essentially a wrapper around
``pysnmp`` with error handling, logging, and other additions.

``1.3.6.1. = iso.org.dod.internet = Any network device``.

**Using MIBs**

Responses are resolved against every :term:`MIB` loaded into the
:class:`SNMP` instance's engine. PySNMP's built-in MIBs (e.g. ``SNMPv2-MIB``)
are always available, the MIBs in ``peat/protocols/mibs`` (e.g. ``IF-MIB``) are
always added as a source, and device modules can add their own vendor MIB
directories with the ``mib_paths`` argument. Call :meth:`SNMP.load_mibs` with
the MIB module names before querying, then use :meth:`SNMP.walk` and
:meth:`SNMP.get_table`. Each response :class:`dict` includes the MIB object
name, the table it belongs to (if any), the decoded index and a typed
``value`` (see :func:`value_to_python`), e.g. enumerations are converted to
their MIB labels and ``IpAddress`` values to dotted-quad strings.

**Building custom MIBs**

Vendor MIBs are compiled offline into PySNMP Python modules using ``mibdump``
(included with ``pysmi``, which PEAT already depends on through ``pysnmp``).
Do NOT pass ``--generate-mib-texts``, so the vendor's DESCRIPTION texts are not
included in PEAT, and commit only the generated ``.py`` file (with a provenance
header naming the source MIB file, version and checksum), never the ``.mib``
text. Refer to the "Using vendor SNMP MIBs" section of the module developer
guide for the full procedure.

NOTE: once the MIBs are generated, make sure they're included in the PyInstaller
spec files that are used to build the PEAT executables (``distribution/peat.spec``
and ``distribution/sneakypeat.spec``).

- Example: ``mibdump --mib-source=file:///tmp/mibsrc --destination-format=pysnmp
  --destination-directory=peat/modules/<vendor>/mibs --no-python-compile MY-MIB``

References/further reading:

- https://github.com/lextudio/pysnmp
- https://www.pysnmp.com/
- https://github.com/etingof/pysnmp/docs/pysnmp-hlapi-tutorial.rst

Authors:

- Christopher Goes
"""

import os.path
import re
import threading
from collections.abc import Iterable, Iterator
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

from pyasn1.codec.native.encoder import encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ
from pysnmp.error import PySnmpError
from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
    nextCmd,
)
from pysnmp.hlapi.varbinds import CommandGeneratorVarBinds
from pysnmp.proto import errind, rfc1902
from pysnmp.smi.builder import DirMibSource, MibBuilder

import peat
from peat import config, consts, exit_handler, log, state, utils

# https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
INTERFACE_MAP: Final[dict[int, str]] = {
    1: "other",
    6: "ethernet",
    24: "loopback",
}

#: IANAifType-MIB labels (from MIB-resolved ``ifType`` values) to PEAT interface types.
#: Complements :data:`INTERFACE_MAP`, which maps the raw integer values.
IFTYPE_LABEL_MAP: Final[dict[str, str]] = {
    "other": "other",
    "ethernetCsmacd": "ethernet",
    "softwareLoopback": "loopback",
}

#: Maximum length of string values returned by :func:`value_to_python`.
#: Device responses are untrusted, this bounds the size of any one value.
MAX_VALUE_LENGTH: Final[int] = 4096

# DISPLAY-HINTs that describe text (e.g. DisplayString is "255a")
_TEXT_DISPLAY_HINT: Final[re.Pattern] = re.compile(r"\d*[at]")
_WHITESPACE_CHARS: Final[dict[int, int | None]] = str.maketrans("", "", "\r\n\t")


def value_to_python(value: Any) -> str | int | None:
    """
    Convert a (MIB-resolved) PySNMP/pyasn1 value into a JSON-friendly Python value.

    - Enumerated ``INTEGER`` (with ``namedValues`` from a MIB) => MIB label,
      e.g. ``"operationnal"``. Numbers not in the enumeration are returned as :class:`int`.
    - ``Integer32``, ``Counter32``, ``Counter64``, ``Gauge32``, ``Unsigned32``
      and ``TimeTicks`` => :class:`int` (``TimeTicks`` are hundredths of a second)
    - ``IpAddress`` => dotted-quad string, e.g. ``"192.0.2.10"``
    - ``OBJECT IDENTIFIER`` => dotted OID string, e.g. ``"1.3.6.1.4.1.3833.1.7.255.20"``
    - ``OCTET STRING`` with a non-text ``DISPLAY-HINT`` (e.g. ``PhysAddress``)
      => formatted string, e.g. ``"00:80:f4:01:02:03"``
    - Other ``OCTET STRING`` (including ``DisplayString``) => text (trailing NUL
      bytes removed) if it's printable UTF-8, otherwise lowercase hex
    - ``Null``, ``noSuchObject``, ``noSuchInstance``, ``endOfMibView`` => :obj:`None`

    Strings are truncated to :data:`MAX_VALUE_LENGTH` characters.

    Args:
        value: the value to convert

    Returns:
        The converted value, or :obj:`None` if there is no value
    """
    # NOTE: rfc1905 exception values (noSuchObject, etc.) are subclasses of Null
    if value is None or isinstance(value, univ.Null):
        return None

    try:
        if isinstance(value, ObjectIdentity):  # OID values resolved using a MIB
            return str(value.getOid())
        if isinstance(value, univ.ObjectIdentifier):
            return str(value)
        if isinstance(value, rfc1902.IpAddress):  # NOTE: subclass of OctetString
            return value.prettyPrint()
        if isinstance(value, univ.Integer):
            number = int(value)
            named = getattr(value, "namedValues", None)
            if named and number in named:
                return str(named.getName(number))
            return number
        if isinstance(value, univ.OctetString):
            hint = str(getattr(value, "displayHint", "") or "")
            if hint and not _TEXT_DISPLAY_HINT.fullmatch(hint):
                return str(value.prettyPrint())[:MAX_VALUE_LENGTH]

            raw = value.asOctets()[: MAX_VALUE_LENGTH * 4]
            try:
                text = raw.rstrip(b"\x00").decode("utf-8")
            except UnicodeDecodeError:
                return raw.hex()[:MAX_VALUE_LENGTH]
            # Allow common whitespace in text, but not other control characters
            if not text.translate(_WHITESPACE_CHARS).isprintable():
                return raw.hex()[:MAX_VALUE_LENGTH]
            return text[:MAX_VALUE_LENGTH]

        return str(value.prettyPrint())[:MAX_VALUE_LENGTH]
    except Exception:  # pyasn1 objects without a value, unexpected types, etc.
        return None


def normalize_iftype(value: int | str) -> str:
    """
    Convert a ``ifType`` value (raw integer or IANAifType-MIB label)
    to a PEAT interface type, e.g. ``6`` or ``"ethernetCsmacd"`` => ``"ethernet"``.
    """
    if isinstance(value, int):
        return INTERFACE_MAP.get(value, str(value))
    if not value:
        return ""
    return IFTYPE_LABEL_MAP.get(value, utils.convert_to_snake_case(str(value)))


def group_table_rows(values: Iterable[dict]) -> dict[str, list[dict]]:
    """
    Group MIB-resolved table column values (as returned by :meth:`SNMP.walk`) into rows.

    Values that aren't table columns (e.g. scalars or unresolved OIDs) are ignored.
    Rows are ordered by first appearance, which is the agent's (lexicographic) order.

    Args:
        values: response dicts from :meth:`SNMP.get` or :meth:`SNMP.walk`

    Returns:
        Rows by table name, e.g. ``{"ifTable": [{"_index": "1", "_index_parts": [1],
        "ifIndex": 1, "ifDescr": "eth0", ...}, ...]}``. ``_index`` is the row's
        index as a string, and ``_index_parts`` the decoded index values.
    """
    tables: dict[str, dict[str, dict]] = {}

    for val in values:
        if val.get("node_type") != "MibTableColumn" or not val.get("table"):
            continue

        rows = tables.setdefault(val["table"], {})
        if val["index"] not in rows:
            rows[val["index"]] = {
                "_index": val["index"],
                "_index_parts": list(val.get("index_parts", [])),
            }
        rows[val["index"]][val["object_name"]] = val.get("value")

    return {name: list(rows.values()) for name, rows in tables.items()}


# Resolves response variable bindings using the MIBs loaded into a SNMP engine
_VAR_BINDS: Final[CommandGeneratorVarBinds] = CommandGeneratorVarBinds()

# Time of the last SNMP.all_output key (of any instance), refer to _output_key()
_last_output_time: datetime | None = None
_output_time_lock: Final[threading.Lock] = threading.Lock()


def _output_key() -> str:
    """
    Key for a query's values in :attr:`SNMP.all_output`: the current UTC time
    (ISO 8601), unique and increasing across all :class:`SNMP` instances.

    The wall clock can be coarse (15.6 ms on Windows before Python 3.13), so
    queries completing within the same clock tick would otherwise get the same
    key and overwrite each other's values, including when the outputs of several
    instances are merged into a device's ``raw-snmp-output.json``. If the clock
    hasn't advanced past the previous key, the key is 1 microsecond after it.
    """
    global _last_output_time

    with _output_time_lock:
        now = utils.utc_now()
        if _last_output_time is not None and now <= _last_output_time:
            now = _last_output_time + timedelta(microseconds=1)
        _last_output_time = now

    return now.isoformat()


class SNMP:
    """
    Generic wrapper for Simple Network Management Protocol (SNMP) functionality.
    """

    def __init__(
        self,
        ip: str,
        port: int = 161,
        timeout: float = 1.0,
        community: str = "public",
        snmp_version: int = 1,
        mib_paths: list[str | Path] | None = None,
    ) -> None:
        """
        Args:
            ip: IP address of the SNMP device
            port: UDP port of the SNMP device
            timeout: Number of seconds to wait for a response
            community: SNMP Community string to use
                (this is a plain-text credential used for authentication).
            snmp_version: Version of SNMP to use (1 = v1 | 2 = v2c)
            mib_paths: List of directories with MIB modules to use for lookups.
                These are ``.py`` files compiled from a MIB by ``pysmi``.
                Use :meth:`~SNMP.load_mibs` to load MIB modules from them.
        """
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout
        self.community: str = community
        self.snmp_version: int = snmp_version
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )

        # TODO: globally cache MIB file loads so they only happen once per PEAT run
        self.mib_paths: list[str] = [
            # Include MIBs that are included with PEAT
            str(Path(Path(__file__).parent, "mibs").resolve()),
        ]
        if mib_paths:
            for path in mib_paths:
                # Convert Path object to absolute path str for use with PySNMP
                if isinstance(path, Path):
                    path = str(path.resolve())
                if not os.path.exists(path):
                    self.log.error(f"MIB '{path}' doesn't exist, skipping...")
                    continue
                self.mib_paths.append(path)
        self.log.trace2(f"mib_paths: {self.mib_paths}")

        # SNMPv1 (1) => mpModel 0
        # SNMPv2c (2) => mpModel 1
        mp_model = self.snmp_version - 1
        if mp_model < 0 or mp_model > 1:
            state.error = True
            raise ValueError(f"Invalid SNMP version: {self.snmp_version}")

        self.engine = SnmpEngine()
        self.community_data = CommunityData(self.community, mpModel=mp_model)
        self.transport = UdpTransportTarget((self.ip, self.port), timeout=self.timeout)
        self.context = ContextData()

        #: Values of every query, by the (unique) UTC time the query completed.
        #: Saved to the device's ``raw-snmp-output.json`` file on exit.
        self.all_output: dict[str, list[dict]] = {}
        #: Error from the last query (:meth:`~SNMP.get`), e.g. a PySNMP
        #: ``ErrorIndication`` for a timeout, or :obj:`None` if there wasn't one.
        self.last_error: Any = None
        self._mib_sources_added: bool = False

        # auto-save output to disk on exit
        exit_handler.register(self._save_all_output, "FILE")

        self.log.trace2(f"Initialized {repr(self)}")

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout}, "
            f"'{self.community}', {self.snmp_version}, {self.mib_paths})"
        )

    @property
    def timed_out(self) -> bool:
        """
        If the last query (:meth:`~SNMP.get`, :meth:`~SNMP.walk` or
        :meth:`~SNMP.get_table`) ended because the agent stopped responding.
        Walks return the values retrieved before the timeout, so use this
        to tell a partial walk apart from a complete one.
        """
        return isinstance(self.last_error, errind.RequestTimedOut)

    def _save_all_output(self) -> None:
        """
        Save the raw output to disk as an artifact.
        """
        if self.all_output:
            try:
                dev = peat.data.datastore.get(self.ip)
                dev.write_file(self.all_output, "raw-snmp-output.json", merge_existing=True)
            except Exception as ex:
                self.log.warning(f"Failed to write raw output to file: {ex}")

    def get(
        self,
        identity: str | tuple,
        single_query: bool = True,
        query_limit: int = 0,
        walk_whole_mib: bool = False,
        return_partial: bool = False,
    ) -> list[dict]:
        """
        Gets the value(s) of a SNMP object.

        The SNMP object is referenced by passing a :class:`tuple` to the
        ``identity``argument. This is then passed directly to PySNMP.
        Additionally, a custom MIB definition can be used by providing an
        absolute file path to the ``mib_path`` argument.

        The object identity can be one of the following:

        - OID
        - MIB name (this will enumerate the entire MIB)
        - MIB name + object name
        - MIB name + object name + instance number (for an enumeration/table)
        - Any of the above + a custom MIB definition file to use

        Examples:

        .. code-block:: python

           from pathlib import Path
           from peat.protocols.snmp import SNMP

           snmp = SNMP(ip="192.0.2.1")
           # OID
           snmp.get("1.3.6.1.2.1.1.1.0")
           # "Walk" all values out of a MIB
           snmp.get("SNMPv2-MIB", single_query=False)
           # MIB + Object
           snmp.get(("SNMPv2-MIB", "sysDescr"))
           # MIB + Object + Instance
           snmp.get(("SNMPv2-MIB", "sysDescr", 0))
           # Directory with a custom MIB module ("MyMib.py") as a Path object (absolute path)
           snmp_with_mib = SNMP(ip="192.0.2.1", mib_paths=[Path("/path/mibs/")])
           snmp_with_mib.get(("MyMib", "myObj"))
           # Directory with a custom MIB module as a raw string (absolute path)
           snmp_with_mib = SNMP(ip="192.0.2.1", mib_paths=["/path/mibs/"])
           snmp_with_mib.get(("MyMib", "myObj"))

        Each value is a :class:`dict` with the keys ``index``, ``index_parts``,
        ``mib_name``, ``object_name``, ``pretty_name``, ``oid``, ``node_type``,
        ``table``, ``value`` (refer to :func:`value_to_python`), ``value_encoded``,
        ``value_string`` and ``value_string_original``.

        Args:
            identity: Tuple used to reference the SNMP object.
                Refer to function documentation above for details.
            single_query: If :obj:`True`, the OID will be queried once with ``getCmd``.
                Otherwise, it will be iterated over using ``nextCmd`` until there is no
                more data (for OIDs with "sub values", e.g. tables or enumerations).
            query_limit: If ``single_query`` is :obj:`False`, limit the iteration to this
                number of queries and stop. This is cheap workaround if you don't have a MIB.
            walk_whole_mib: If all values in a MIB should be walked.
                This sets ``lexicographicMode=True`` in PySNMP ``nextCmd``.
            return_partial: If an error occurs after some values were retrieved
                (e.g. a timeout part way through a walk), return those values
                instead of an empty :class:`list`.

        Values that can't be resolved using the loaded MIBs (e.g. a table
        column with a malformed index) are returned as unresolved raw OIDs
        (empty ``mib_name`` and ``object_name``) instead of aborting the query.
        Errors are logged and saved to :attr:`~SNMP.last_error`.

        Returns:
            :class:`list` of values, or an empty :class:`list` if the get failed.

        Raises:
            ValueError: If a critical error occurred, such as a invalid type being passed
        """
        if not identity:
            state.error = True
            raise ValueError(f"{self.ip}: empty identity provided")

        if isinstance(identity, bytes):  # Handle bytes, just in case
            identity = identity.decode()

        if not isinstance(identity, (str, tuple)):
            state.error = True
            raise ValueError(f"{self.ip}: identity is not str or tuple (value={identity})")

        if isinstance(identity, str):
            identity = (identity,)  # Convert str to 1-item tuple

        self.log.trace(f"SNMP query: {identity}")
        self._add_mib_sources()

        self.last_error = None
        values: list[dict] = []
        seen_oids: set[str] = set()
        unresolved: list[str] = []
        query_counter = 0

        # Keep querying nextCmd until it's exhausted
        # For getCmd, it'll usually just iterate once and finish
        try:
            for error_indication, error_status, error_index, var_binds in self._query(
                identity, single_query, walk_whole_mib
            ):
                if error_indication or error_status:
                    if error_indication:  # SNMP engine errors, e.g. a timeout
                        self.last_error = error_indication
                        self.log.debug(f"SNMP engine error: {error_indication}")
                    else:  # SNMP agent errors
                        errloc = var_binds[int(error_index) - 1] if error_index else "?"
                        pretty_err = error_status.prettyPrint()
                        self.log.debug(f"SNMP agent error: '{pretty_err}' at location {errloc}")

                    if not (return_partial and values):
                        return []

                    self.log.debug(
                        f"Returning {len(values)} partial results for query {identity} after error"
                    )
                    break

                for raw_name, raw_value in var_binds:
                    var_name, var_value = self._resolve_var_bind(raw_name, raw_value, unresolved)
                    var_dict = self._var_bind_to_dict(var_name, var_value)

                    # Skip empty values (e.g. noSuchObject or the end of a SNMPv1 walk)
                    # and OIDs that were already returned (pysnmp re-yields the last
                    # response when a SNMPv1 walk reaches the end of the agent's MIB view).
                    if var_dict is None or var_dict["oid"] in seen_oids:
                        continue
                    seen_oids.add(var_dict["oid"])

                    values.append(var_dict)
                    if config.DEBUG >= 2:
                        self.log.trace2(f"var_dict: {consts.convert(var_dict)}")

                query_counter += 1
                if query_limit and query_counter >= query_limit:
                    break
        except (PySnmpError, PyAsn1Error) as ex:
            # Raised by PySNMP while sending a request or decoding a response
            # (device data is untrusted). The engine remains usable afterwards.
            self.last_error = ex
            self.log.warning(
                f"SNMP query {identity} failed after {len(values)} value(s): "
                f"{ex.__class__.__name__}: {ex}"
            )
            if not (return_partial and values):
                return []

        if unresolved:
            examples = ", ".join(unresolved[:5]) + (", ..." if len(unresolved) > 5 else "")
            self.log.warning(
                f"{len(unresolved)} value(s) from SNMP query {identity} couldn't be "
                f"resolved using the loaded MIBs (e.g. a malformed table index) and "
                f"were kept as raw OIDs: {examples}"
            )

        self.all_output[_output_key()] = deepcopy(values)

        return values

    def walk(self, identity: str | tuple, max_varbinds: int = 0) -> list[dict]:
        """
        Walk a SNMP subtree (e.g. a MIB group or table) with GetNext requests.

        The walk stays within the subtree of ``identity``. If an error or timeout
        occurs part way through, the values retrieved so far are returned, and
        :attr:`~SNMP.last_error` and :attr:`~SNMP.timed_out` tell why the walk ended.

        .. code-block:: python

           snmp = SNMP(ip="192.0.2.1")
           snmp.load_mibs("IF-MIB")
           # "ifTable" from IF-MIB
           values = snmp.walk("1.3.6.1.2.1.2.2", max_varbinds=500)

        Args:
            identity: Object to walk, refer to :meth:`~SNMP.get` for details
            max_varbinds: Maximum number of GetNext requests to make
                (``0`` means no limit). This bounds the network traffic for
                agents with large tables or that misbehave.

        Returns:
            :class:`list` of values, or an empty :class:`list` if nothing was retrieved
        """
        return self.get(
            identity, single_query=False, query_limit=max_varbinds, return_partial=True
        )

    def get_table(self, identity: str | tuple, max_varbinds: int = 0) -> list[dict]:
        """
        Walk a MIB table and return its rows.

        A MIB defining the table must be loaded (refer to :meth:`~SNMP.load_mibs`).
        Refer to :func:`group_table_rows` for the format of rows.

        Args:
            identity: The table to walk, e.g. ``"1.3.6.1.2.1.2.2"`` for ``ifTable``
            max_varbinds: Maximum number of GetNext requests to make (``0`` means no limit)

        Returns:
            The table rows, or an empty :class:`list` if nothing was retrieved
        """
        tables = group_table_rows(self.walk(identity, max_varbinds=max_varbinds))

        return next(iter(tables.values()), [])

    def load_mibs(self, *mib_names: str) -> list[str]:
        """
        Load MIB modules into this instance's SNMP engine.

        Loaded MIBs are used to resolve object names, value types, enumerations
        and table indices of responses, including for queries using numeric OIDs.
        MIB modules are searched for in PySNMP's built-in MIBs, the MIBs
        included with PEAT (``peat/protocols/mibs``) and ``mib_paths``.
        They're loaded from the pre-compiled ``.py`` files, nothing is downloaded.

        .. note::
           Call this before making queries.

        Args:
            mib_names: Names of MIB modules to load, e.g. ``"IF-MIB"``

        Returns:
            Names of the MIB modules that were successfully loaded.
            This method never raises an exception for MIBs that fail to load.
        """
        self._add_mib_sources()
        mib_builder = self.engine.getMibBuilder()
        loaded = []

        for mib_name in mib_names:
            try:
                mib_builder.loadModules(mib_name)
            except Exception as ex:
                self.log.warning(f"Failed to load MIB '{mib_name}': {ex}")
                continue

            # NOTE: loadModules() doesn't raise an error for missing modules
            if mib_name in mib_builder.mibSymbols:
                self.log.trace(f"Loaded MIB '{mib_name}'")
                loaded.append(mib_name)
            else:
                self.log.warning(f"MIB '{mib_name}' not found (MIB paths: {self.mib_paths})")

        return loaded

    def _add_mib_sources(self) -> None:
        """
        Add :attr:`mib_paths` as MIB sources to the SNMP engine (only done once).
        """
        if self._mib_sources_added:
            return

        self.engine.getMibBuilder().addMibSources(*[DirMibSource(p) for p in self.mib_paths])
        self._mib_sources_added = True

    def _query(self, identity: tuple, single_query: bool, walk_whole_mib: bool) -> Iterator[tuple]:
        """
        Create the PySNMP query generator. This is the only method that does network I/O.

        The response variable bindings aren't resolved using the MIBs here
        (``lookupMib=False``), :meth:`~SNMP._resolve_var_bind` resolves them one at
        a time, so a single malformed value doesn't abort the whole query.

        Returns:
            Iterator yielding ``(error_indication, error_status, error_index, var_binds)``,
            where ``var_binds`` are raw ``(ObjectName, value)`` pairs
        """
        object_type = ObjectType(ObjectIdentity(*identity))

        if single_query:
            querier = getCmd(
                self.engine,
                self.community_data,
                self.transport,
                self.context,
                object_type,
                lookupMib=False,
            )
        else:
            querier = nextCmd(
                self.engine,
                self.community_data,
                self.transport,
                self.context,
                object_type,
                lexicographicMode=walk_whole_mib,
                lookupMib=False,
            )

        if querier is None:
            raise ValueError(f"{self.ip}: bad querier iterator (single_query={single_query})")

        return querier

    def _resolve_var_bind(self, name: Any, value: Any, unresolved: list[str]) -> tuple[Any, Any]:
        """
        Resolve a raw response variable binding using the MIBs loaded into the engine,
        e.g. to decode the table index and convert the value to the MIB's type.

        Args:
            name: OID of the variable (``ObjectName``)
            value: Value of the variable
            unresolved: OIDs that couldn't be resolved are appended to this list

        Returns:
            ``(ObjectIdentity, value)`` resolved using the MIBs, or the raw
            ``(name, value)`` if it couldn't be resolved (e.g. a malformed index
            with more or less sub-identifiers than the MIB's INDEX clause allows).
        """
        try:
            resolved = _VAR_BINDS.unmakeVarBinds(self.engine, [(name, value)], lookupMib=True)
            return resolved[0][0], resolved[0][1]
        except (PySnmpError, PyAsn1Error, ValueError, TypeError, IndexError) as ex:
            self.log.debug(f"Couldn't resolve {name} using the loaded MIBs: {ex}")
            unresolved.append(str(name))
            return name, value

    @staticmethod
    def _var_bind_to_dict(
        var_name: ObjectIdentity | univ.ObjectIdentifier, var_value: Any
    ) -> dict | None:
        """
        Convert a response variable binding into a PEAT SNMP value :class:`dict`.

        ``var_name`` is either resolved using a MIB (``ObjectIdentity``) or a
        raw OID (``ObjectName``) that couldn't be resolved.

        Returns:
            The value dict, or :obj:`None` if there is no value (``Null``,
            ``noSuchObject``, ``noSuchInstance`` or ``endOfMibView``).
        """
        if var_value is None or isinstance(var_value, univ.Null):
            return None

        # https://stackoverflow.com/questions/41544110/pysnmp-form-dictionary-from-table
        # ('SNMPv2-MIB', 'sysDescr', (<ObjectName value object, tagSet <TagSet object, tags 0:0:6>, payload [0]>,))  # noqa: E501
        try:
            mib_name, object_name, object_instance_id = var_name.getMibSymbol()
            node_type = type(var_name.getMibNode()).__name__
            label = var_name.getLabel()
            oid = str(var_name.getOid())
            pretty_name = var_name.prettyPrint()
        except Exception:  # OID couldn't be resolved
            mib_name, object_name, object_instance_id = "", "", ()
            node_type = ""
            label = ()
            oid = str(var_name)
            pretty_name = oid

        if isinstance(var_value, ObjectIdentity):  # OID value, resolved using a MIB
            value_encoded = str(var_value.getOid())
            value_string = var_value.prettyPrint()
        else:
            value_encoded = encode(var_value)
            try:
                # Some ASN.1 classes get garbled when you force them to strings
                # A lot of them have a function that stringifies the class
                value_string = str(var_value.prettyOut(var_value))
            except Exception:
                value_string = str(var_value)

        var_dict = {
            # NOTE: prettyPrint() is needed for non-integer indices, e.g. IpAddress
            "index": ".".join(i.prettyPrint() for i in object_instance_id),
            "index_parts": [value_to_python(i) for i in object_instance_id],
            "mib_name": mib_name,
            "object_name": object_name,
            # "SNMPv2-MIB::sysDescr.0"
            "pretty_name": pretty_name,
            "oid": oid,
            # Type of MIB node, e.g. "MibScalar" or "MibTableColumn"
            "node_type": node_type,
            # Name of the table, for table columns, e.g. "ifTable"
            "table": label[-3] if node_type == "MibTableColumn" and len(label) >= 3 else "",
            # Python value converted using the MIB, e.g. enum label or int
            "value": value_to_python(var_value),
            "value_encoded": value_encoded,
            "value_string": value_string,
            "value_string_original": value_string,
        }

        # auto-convert interface types to PEAT-standard names
        if object_name == "ifType":
            if var_dict["value_encoded"] in INTERFACE_MAP:
                var_dict["value_string"] = INTERFACE_MAP[var_dict["value_encoded"]]
            else:
                var_dict["value_string"] = utils.convert_to_snake_case(var_dict["value_string"])

        return var_dict

    def verify(self, identity: str | tuple, to_find: str | list[str]) -> bool:
        """
        Checks if a string is in the response data for an SNMP query.

        Args:
            identity: Tuple used to reference the SNMP object.
            find: String(s) to search the response for

        Returns:
            If the verification succeeded

        Raises:
            ValueError: If a critical error occurred, such as a invalid type being passed
        """
        self.log.debug(
            f"Verifying SNMP device with identity '{identity}' and search string {to_find}"
        )

        try:
            data = self.get(identity)
            if data:
                data = str(data[0]["value_string"]).lower()
        except Exception as ex:
            self.log.error(f"Failed SNMP verification due to unhandled exception: {ex}")
            data = None

        # Check if the desired string or strings is in the response
        if data is None:
            is_valid = False
        elif isinstance(to_find, str) and to_find.lower() in str(data):
            is_valid = True
        elif isinstance(to_find, list) and any(x.lower() in str(data) for x in to_find):
            is_valid = True
        else:
            is_valid = False

        if is_valid:
            log.info("SNMP verification succeeded")
        else:
            log.debug("SNMP verification failed")

        return is_valid


# TODO: move to class or delete, since SNMP.get() can do this with a MIB name parameter
def snmp_walk(
    ip: str,
    mib_name: str,
    mib_src: str | Path,
    community: str = "public",
    timeout: float = 0.5,
    port: int = 161,
    snmp_version: int = 1,
) -> dict:
    """
    Walks an SNMP MIB and returns a dictionary of names and values

    Args:
        ip: IPv4 address of the SNMP device
        mib_name: Name of the mib to reference
        mib_src: Filesystem path to the MIB file, which must be a PySNMP module (optional)
        timeout: Number of seconds to wait for a response
        community: SNMP Community string to use
        port: Port the device's SNMP server is listening on
        snmp_version: Version of SNMP to use (1 = v1 | 2 = v2c)

    Returns:
        A dictionary of names and values. An empty :class:`dict` is returned
        if there was an error.
    """
    if isinstance(mib_src, Path):
        mib_src = str(mib_src.resolve())

    # Create an instance of the builder
    mib_builder = MibBuilder()

    # Set an alternative path to compiled MIBs
    mib_sources = (DirMibSource(mib_src),)
    mib_builder.setMibSources(*mib_sources)

    # Loading modules
    mib_builder.loadModules(mib_name)

    # Perform the walk
    walk_results = {}
    for error_indication, error_status, error_index, var_binds in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=snmp_version - 1),
        UdpTransportTarget((ip, port), timeout=timeout),
        ContextData(),
        ObjectType(ObjectIdentity(mib_name).addMibSource(mib_src)),
        lexicographicMode=False,
        lookupNames=True,
        lookupValues=True,
    ):
        if error_indication:
            log.debug(f"SNMP Walk error for {ip}:{port}: {error_indication}")
            break

        if error_status:
            errloc = var_binds[int(error_index) - 1] if error_index else "?"
            pretty_err = error_status.prettyPrint()
            log.debug(f"SNMP agent error for {ip}:{port}: '{pretty_err}' at location {errloc}")
            break

        for varBind in var_binds:
            try:
                name = varBind[0].prettyPrint()
                name = name[len(mib_name) + 2 : name.find(".")]
                value = varBind[1].prettyPrint()
                log.trace(f"SNMP value for {ip}:{port}: {value}")
                walk_results[name] = value
            except Exception as err:
                log.error(f"{type(err).__name__}: {err}")
                return walk_results

    return walk_results


__all__ = [
    "IFTYPE_LABEL_MAP",
    "INTERFACE_MAP",
    "SNMP",
    "group_table_rows",
    "normalize_iftype",
    "snmp_walk",
    "value_to_python",
]
