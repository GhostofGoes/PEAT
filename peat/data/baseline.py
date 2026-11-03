"""
Baseline comparison: check device data against expected states.

A :class:`~peat.data.models.Baseline` describes the expected state of one
device (``scope="device"``) or of every device of a type (``scope="device_type"``)
as a :class:`~peat.data.models.DeviceData` snapshot (``expected``) and/or as
:class:`~peat.data.models.BaselineRule` constraints (``rules``).
:func:`compare_device` checks a device against a baseline and returns
:class:`~peat.data.models.BaselineFinding` objects.

The functions in this module are pure: they do no I/O, never modify the compared
device (except :func:`store_findings`), and never call
:meth:`~peat.data.models.DeviceData.populate_fields` (no DNS/ARP lookups).
Loading, saving and the command line interface are in :mod:`peat.api.baseline_api`.

Paths address the exported device data (``DeviceData.dict(exclude_defaults=True)``,
converted to JSON-friendly values): ``segment(.segment)*``, where a segment is
``name``, ``name[key=value,...]`` (list items whose fields have these values) or
``name[*]`` (all list items). Examples: ``firmware.version``,
``service[protocol=ftp].enabled``, ``service[*].security.default_credentials``.
"""

from __future__ import annotations

import fnmatch
import functools
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from peat import consts, log
from peat.data.data_utils import strip_empty_and_private, strip_key
from peat.data.models import Baseline, BaselineFinding, BaselineRule, DeviceData

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
_IDENTITY_IGNORE: tuple[str, ...] = (
    # identity/context set by PEAT or the user, not by the device
    "label",
    "comment",
    "asset",
    "id",
    "successful_pulls",
    "related",
    "mac_vendor",
    "*.mac_vendor",
    "description.full",
    "os.full",
    # unstructured or own-index or analysis output
    "extra",
    "*.extra",
    "event",
    "memory",
    "uefi_image",
    "uefi_hashes",
    "baseline_findings",
    "logic.formats",
    "logic.original",
    "*.original",
    "*.local_path",
    "*.peat_module",
    "*.device",
    # where PEAT read the SCL file: a path on the PEAT host for "peat parse"
    # (the device CID file of a pull is also in "files")
    "iec61850.scl_file",
)

# Volatile values of a device
_VOLATILE_IGNORE: tuple[str, ...] = (
    "uptime",
    "*.uptime",
    "start_time",
    "statistics",
    "*.statistics",
    "protocol_statistics",
    "hardware.memory_available",
    "hardware.memory_usage",
    "hardware.storage_available",
    "hardware.storage_usage",
    "clock.time",
    "clock.observed",
    "clock.offset",
    "clock.last_sync",
    # the protocol of the ACTIVE time source (e.g. irig_b -> internal when the
    # IRIG-B signal is lost) and the sync state; the configured sources are compared
    "clock.source",
    "clock.synchronized",
    "clock.sources.offset",
    "clock.sources.last_sync",
    "clock.sources.state",
    "clock.sources.selected",
    "clock.sources.stratum",
    "indicators.state",
    "indicators.value",
    "indicators.blink_rate",
    "indicators.health",
    "indicators.timestamp",
    "processes.pid",
    "processes.start",
    "processes.state",
    "processes.cpu_percent",
    "processes.memory_bytes",
    "processes.memory_percent",
    "processes.threads_count",
    "processes.parent",
    "processes.entity_id",
    "relationships.first_seen",
    "relationships.last_seen",
    "relationships.count",
    "relationships.state",
    # the ephemeral client port changes with every connection; the server port is
    # part of the relationship id (a new server port is a new relationship)
    "relationships.local.port",
    "relationships.remote.port",
    "logic.tasks.scan_count",
    "logic.tasks.scan_time_*",
    "logic.tasks.overruns",
    "logic.tasks.cpu_percent",
    "files.created",
    "files.mtime",
    "*.file.created",
    "*.file.mtime",
    "iec61850.header.history",
    "interface.connected",
    # live redundancy state (active/standby port of a failover pair, RSTP port
    # role, state and neighbor); protocol, mode, LAN and members are configuration
    "interface.redundancy.state",
    "interface.redundancy.role",
    "interface.redundancy.partner",
    "service.status",
    "service.process_pid",
    "interface.services.status",
    "interface.services.process_pid",
)

DEFAULT_IGNORE: tuple[str, ...] = (
    *_IDENTITY_IGNORE,
    *_VOLATILE_IGNORE,
    # Patterns are anchored at the document root: repeat them for the modules of
    # a device (DeviceData.module, which are DeviceData objects)
    *(f"module.{p}" for p in (*_IDENTITY_IGNORE, *_VOLATILE_IGNORE) if not p.startswith("*")),
)
"""
Paths that are never compared in snapshot comparisons (:mod:`fnmatch` patterns
of selector-free paths; a pattern also matches everything below it). These are
values set by PEAT or the user instead of the device, data stored in other indices,
unstructured ``extra`` data, raw ``original`` blobs, and volatile values such as
counters, uptimes, clocks, live states and process IDs, of the device and of its
modules. :attr:`Baseline.ignore
<peat.data.models.Baseline.ignore>` adds patterns to this list.
"""

# Added to the ignore list when Baseline.scope == "device_type" (a "typical device"
# profile, OT-2): per-unit identity and site addressing, never device-type properties.
DEVICE_TYPE_IGNORE: tuple[str, ...] = (
    "ip",
    "mac",
    "hostname",
    "name",
    "serial_number",
    "geo",
    "boot_time",
    "interface.ip",
    "interface.mac",
    "interface.hostname",
    "interface.subnet_mask",
    "interface.gateway",
    "interface.id",
    "interface.description",
    "files.hash",
    "files.size",
    "files.owner",
    "files.group",
    "relationships",
    "routes",
    "clock.sources.address",
    "iec61850.ied_name",
    "iec61850.access_points.ip",
    "iec61850.access_points.subnet_mask",
    "iec61850.access_points.gateway",
    "iec61850.header",
    "iec61850.functional_locations",
    "iec61850.publications.address.mac",
    "iec61850.publications.address.appid",
    "iec61850.publications.reference",
    "iec61850.subscriptions",
    "iec61850.report_controls.clients",
    "users.id",
    "x509",
    "ssh_keys",
    "logic.hash",
    "logic.name",
    "module.serial_number",
    "module.mac",
    "module.ip",
    "module.hostname",
    "module.interface.ip",
    "module.interface.mac",
    "module.interface.hostname",
    "module.interface.subnet_mask",
    "module.interface.gateway",
    "module.interface.id",
)
"""
Paths additionally ignored for ``scope="device_type"`` baselines ("typical device"
profiles): per-unit identity (addresses, names, serial numbers, file hashes,
certificates) and site-specific data (relationships, routes, IEC 61850 addressing).
They are removed from both documents before list items are aligned, together with
the service ``listen_address`` values that are an address of the unit itself (a
wildcard ``0.0.0.0``/``::`` or loopback listen address is a property of the device
type and is compared) and the input files of ``peat parse`` (``files`` items whose
``local_path`` is their ``path``, a location on the PEAT host).
"""

# Files in these categories change on every pull (logs, SER/event records): only
# their disappearance is reported, never content/size/time changes (OT-13).
VOLATILE_FILE_CATEGORIES = frozenset({"log", "event_record", "diagnostic", "report"})

# A relationship that disappears is only reported if it was configured; peers seen
# only in ARP/netstat/logs come and go between pulls (OT-13).
STABLE_RELATIONSHIP_EVIDENCE = frozenset({"config", "scl", "user"})

# Routes of these types are transient (e.g. FortiGate route cache entries, one per
# recently used destination): they are never reported as missing, new or changed.
# Routes with a MAC address next hop (``extra.gateway_mac``) are too: they are ARP
# entries (host routes cloned from ARP on BSD-derived stacks, e.g. the GE UR routing
# table) and come and go with the ARP table.
VOLATILE_ROUTE_TYPES = frozenset({"cache"})

# list field name -> ("first", fields) = first non-empty field identifies the item,
#                    ("all", fields)   = tuple of all fields identifies the item
LIST_KEYS: dict[str, tuple[str, tuple[str, ...]]] = {
    "interface": ("first", ("name", "serial_port", "ip", "mac", "id")),
    "service": ("all", ("protocol", "port")),
    "services": ("all", ("protocol", "port")),
    "users": ("first", ("name", "id")),
    "files": ("first", ("path", "name")),
    "ssh_keys": ("all", ("type", "user", "host", "id")),
    "relationships": ("first", ("id",)),
    "processes": ("all", ("type", "name")),
    "indicators": ("all", ("type", "name", "interface")),
    "routes": ("all", ("destination", "gateway", "interface")),
    "software": ("all", ("name", "path")),
    "registers": ("all", ("protocol", "group", "address")),
    "tag": ("all", ("name", "address")),
    "io": ("all", ("direction", "address", "name")),
    "module": ("first", ("slot", "serial_number", "name")),
    "vlans": ("first", ("id",)),
    "sources": ("all", ("protocol", "address")),
    "tasks": ("first", ("name",)),
    "access_points": ("first", ("name",)),
    "logical_devices": ("all", ("access_point", "inst")),
    "publications": ("all", ("type", "ld_inst", "name")),
    "report_controls": ("all", ("ld_inst", "ln", "name")),
    "subscriptions": (
        "all",
        ("service_type", "publisher_ied", "publisher_ld_inst", "control_block"),
    ),
    "protocol_statistics": ("all", ("interface", "type", "transport", "protocol")),
}

# first path segment -> (category, default severity) for snapshot differences
PATH_CATEGORY: dict[str, tuple[str, str]] = {
    "firmware": ("firmware", "high"),
    "boot_firmware": ("firmware", "high"),
    "os": ("firmware", "medium"),
    "software": ("software", "medium"),
    "logic": ("logic", "high"),
    "iec61850": ("settings", "medium"),
    "service": ("ports_services", "medium"),
    "users": ("accounts", "medium"),
    "ssh_keys": ("authentication", "medium"),
    "x509": ("authentication", "medium"),
    "files": ("files", "medium"),
    "interface": ("network", "low"),
    "routes": ("network", "low"),
    "relationships": ("network", "low"),
    "hardware": ("hardware", "medium"),
    "module": ("hardware", "medium"),
    "serial_number": ("hardware", "high"),
    "part_number": ("hardware", "medium"),
    "description": ("hardware", "low"),
    "name": ("identity", "low"),
    "hostname": ("identity", "low"),
    "ip": ("identity", "medium"),
    "mac": ("identity", "medium"),
    "health": ("health", "medium"),
    "indicators": ("health", "low"),
    "processes": ("software", "medium"),
    # operating mode: a key switch / run mode change is a strong tamper indicator (OT-13)
    "key_switch": ("settings", "high"),
    "run_mode": ("settings", "high"),
    "clock": ("settings", "medium"),
}
# Baseline kinds that captured a COMPLETE device state: new values are reported as
# "unexpected". Other kinds (engineer/factory snapshots) only check what they specify,
# unless the baseline is marked complete (Baseline.complete, e.g. an approved copy
# of an observed state, see reports_new_values()).
OBSERVED_KINDS = ("first_observed", "previous_observed")

# Maximum number of snapshot differences reported per device and baseline
MAX_FINDINGS_PER_BASELINE = 1000

_SEG_RE = re.compile(r"^(?P<name>[^\[\]]+)(?:\[(?P<sel>[^\]]*)\])?$")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def device_to_doc(dev: DeviceData) -> dict:
    """
    JSON-friendly dict of a DeviceData for comparison. Does NOT call
    populate_fields()/export() (no DNS/ARP side effects).

    Paths (e.g. ``files[].path``) are in POSIX form on every OS (see
    :func:`posix_path`), so they align and match rule selectors the same way
    whichever OS created the baseline or the device data.

    The logic and firmware files of the device and its modules have no location
    values if they are only a file on the PEAT host (:func:`_without_host_file_paths`).
    """
    raw = strip_key(dev.dict(exclude_defaults=True), "original", ("files", "module"))
    return _without_host_file_paths(strip_empty_and_private(consts.convert(_posix_paths(raw))))


# File values that describe a file on the PEAT host, not on the device
_HOST_FILE_FIELDS = (
    "path",
    "directory",
    "name",
    "extension",
    "mime_type",
    "owner",
    "group",
    "uid",
    "gid",
)


def _without_host_file_paths(doc: dict) -> dict:
    """
    ``doc`` (a device document) without the location values of the ``logic``,
    ``firmware`` and ``boot_firmware`` files of the device and its modules
    (:data:`_HOST_FILE_FIELDS`) when the file is only a file on the PEAT host:
    its ``path`` is its ``local_path``, i.e. the module gave no path on the
    device. That is the file PEAT wrote to the run's device directory
    (e.g. ``logic.txt``, ``firmware.bin``, ControlLogix ``parsed-logic.json``) or
    the input file of ``peat parse``, so its location changes with every run and
    differs between units. Its ``hash`` and ``size`` (the content) stay.
    Modifies and returns ``doc``.
    """
    for key in ("logic", "firmware", "boot_firmware"):
        obj = doc.get(key)
        file = obj.get("file") if isinstance(obj, dict) else None
        if _is_input_file(file):
            for field in _HOST_FILE_FIELDS:
                file.pop(field, None)
    for module in doc.get("module") or []:
        if isinstance(module, dict):
            _without_host_file_paths(module)
    return doc


def posix_path(path: PurePath) -> str:
    """
    A device file path in POSIX form: ``/SETTINGS/SET_1.TXT``. ``str()`` of a path
    is OS-dependent (``\\SETTINGS\\SET_1.TXT`` on Windows), and paths in device
    data written on Windows have backslashes, which are separators here too.
    """
    return path.as_posix().replace("\\", "/")


def _posix_paths(value: Any) -> Any:
    """Recursively convert :class:`~pathlib.PurePath` values with :func:`posix_path`."""
    if isinstance(value, PurePath):
        return posix_path(value)
    if isinstance(value, dict):
        return {k: _posix_paths(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_posix_paths(v) for v in value]
    return value


def split_path(path: str) -> list[tuple[str, dict[str, str] | None]]:
    """
    Split a baseline path into ``(name, selector)`` segments, e.g.
    ``"service[protocol=ftp].enabled"`` ->
    ``[("service", {"protocol": "ftp"}), ("enabled", None)]``.
    """
    parts: list[tuple[str, dict[str, str] | None]] = []
    for seg in re.split(r"\.(?![^\[]*\])", path):
        m = _SEG_RE.match(seg.strip())
        if not m:
            raise ValueError(f"invalid baseline path segment '{seg}' in '{path}'")
        sel = m.group("sel")
        selector = None
        if sel is not None:
            selector = {}
            if sel.strip() not in ("", "*"):
                for pair in sel.split(","):
                    k, _, v = pair.partition("=")
                    selector[k.strip()] = v.strip()
        parts.append((m.group("name"), selector))
    return parts


def plain_path(path: str) -> str:
    """Remove ``[...]`` selectors: ``interface[name=eth0].mtu`` -> ``interface.mtu``."""
    return re.sub(r"\[[^\]]*\]", "", path)


def _matches_selector(item: Any, selector: dict[str, str]) -> bool:
    if not isinstance(item, dict):
        return False
    for key, want in selector.items():
        have = item.get(key, "")
        # booleans are exported as JSON true/false: accept "true"/"false" too
        if str(have) != want and not (
            isinstance(have, bool) and str(have).lower() == want.lower()
        ):
            return False
    return True


def resolve_path(doc: dict, path: str) -> list[tuple[str, Any]]:
    """All ``(concrete_path, value)`` pairs addressed by ``path`` in ``doc``."""
    results: list[tuple[str, Any]] = [("", doc)]
    for name, selector in split_path(path):
        nxt: list[tuple[str, Any]] = []
        for prefix, value in results:
            if not isinstance(value, dict) or name not in value:
                continue
            child = value[name]
            child_path = f"{prefix}.{name}" if prefix else name
            if selector is None:
                nxt.append((child_path, child))
            elif isinstance(child, list):
                for item in child:
                    if _matches_selector(item, selector):
                        nxt.append((f"{child_path}[{item_label(name, item)}]", item))
        results = nxt
    return results


def item_key(list_name: str, item: Any) -> tuple:
    """
    Identity of a list item for aligning lists in snapshot comparisons
    (:data:`LIST_KEYS`), as a tuple of ``(field, value)`` pairs.
    """
    if not isinstance(item, dict):
        return ("value", json.dumps(item, sort_keys=True, default=str))
    mode, fields = LIST_KEYS.get(list_name, ("first", ("id", "name")))
    if mode == "first":
        for f in fields:
            if item.get(f) not in (None, ""):
                return ((f, str(item[f])),)
        return (("json", json.dumps(item, sort_keys=True, default=str)),)
    return tuple((f, str(item.get(f, ""))) for f in fields if item.get(f) not in (None, ""))


def index_items(list_name: str, items: list, ignore: tuple[str, ...] = (), path: str = "") -> dict:
    """
    ``{(item_key, n): item}``; ``n`` numbers items that share a key (``#n`` in paths).

    The keys are computed without the values that ``ignore`` matches (patterns for
    the items of the list at ``path``), so items without key fields are aligned by
    the values that are compared, never by e.g. their ``statistics``.
    """
    seen: dict = {}
    counts: dict = {}
    for item in items:
        key = item_key(list_name, strip_paths(item, ignore, path) if ignore else item)
        n = counts.get(key, 0)
        counts[key] = n + 1
        seen[(key, n)] = item
    return seen


def item_label(list_name: str, item: Any) -> str:
    """Selector text of a list item in finding paths, e.g. ``protocol=http,port=80``."""
    return ",".join(f"{k}={v}" for k, v in item_key(list_name, item))


def is_ignored(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """If ``path`` (selectors removed) or one of its parents matches one of ``patterns``."""
    return _is_ignored_plain(plain_path(path), tuple(patterns))


@functools.lru_cache(maxsize=4096)
def _is_ignored_plain(path: str, patterns: tuple[str, ...]) -> bool:
    # cached: every item of a list has the same selector-free paths
    return any(
        fnmatch.fnmatchcase(path, pat) or fnmatch.fnmatchcase(path, f"{pat}.*") for pat in patterns
    )


def _equal(a: Any, b: Any) -> bool:
    return a == b or (
        not isinstance(a, (dict, list)) and not isinstance(b, (dict, list)) and str(a) == str(b)
    )


def _category(path: str) -> tuple[str, str]:
    return PATH_CATEGORY.get(plain_path(path).split(".")[0], ("settings", "low"))


def _render(template: str, **kw: Any) -> str:
    class _Safe(dict):
        def __missing__(self, key):
            return "{" + key + "}"

    try:
        return template.format_map(
            _Safe(
                {
                    k: json.dumps(v, default=str) if not isinstance(v, str) else v
                    for k, v in kw.items()
                }
            )
        )
    except (ValueError, IndexError):
        return template


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def evaluate_rule(doc: dict, rule: BaselineRule) -> tuple[str, Any]:
    """Return ``(result, offending_or_actual_value)`` for one rule."""
    values = [v for _, v in resolve_path(doc, rule.path)]
    op, exp = rule.operator, rule.value
    if op == "present":
        return ("pass" if values else "fail"), (values[0] if len(values) == 1 else values)
    if op == "absent":
        return ("pass" if not values else "fail"), (values[0] if len(values) == 1 else values)
    if not values:
        return ("pass" if op in ("not_equals", "not_in") else "unknown"), None
    try:
        if op == "equals":
            bad = [v for v in values if not _equal(v, exp)]
        elif op == "not_equals":
            bad = [v for v in values if _equal(v, exp)]
        elif op == "in":
            bad = [v for v in values if not any(_equal(v, e) for e in (exp or []))]
        elif op == "not_in":
            bad = [v for v in values if any(_equal(v, e) for e in (exp or []))]
        elif op == "regex":
            bad = [v for v in values if not re.search(str(exp), str(v))]
        elif op == "min":
            bad = [v for v in values if float(v) < float(exp)]
        elif op == "max":
            bad = [v for v in values if float(v) > float(exp)]
        else:
            return "error", values
    except (TypeError, ValueError, re.error):
        return "error", values
    shown = bad if bad else values
    return ("fail" if bad else "pass"), (shown[0] if len(shown) == 1 else shown)


# --------------------------------------------------------------------------- #
# Snapshot diff
# --------------------------------------------------------------------------- #
def diff_docs(
    expected: Any,
    actual: Any,
    path: str,
    *,
    ignore: tuple[str, ...],
    report_new_leaves: bool,
    out: list[tuple[str, str, Any, Any]],
) -> None:
    """Append ``(difference, path, expected, actual)`` tuples to ``out``."""
    if path and is_ignored(path, ignore):
        return
    if isinstance(expected, dict) and isinstance(actual, dict):
        if not path or plain_path(path).rsplit(".", 1)[-1] == "module":
            # a device or module: route cache entries come and go between pulls,
            # only compare its other routes
            expected = _without_volatile_routes(expected)
            actual = _without_volatile_routes(actual)
        for key in sorted(set(expected) | set(actual)):
            sub = f"{path}.{key}" if path else key
            if key not in actual and not _is_object_list(expected[key]):
                value = _without_ignored(expected[key], sub, ignore)
                if value is not None:
                    out.append(("missing", sub, value, None))
            elif key not in expected and not (report_new_leaves and _is_object_list(actual[key])):
                value = _without_ignored(actual[key], sub, ignore) if report_new_leaves else None
                if value is not None:
                    out.append(("unexpected", sub, None, value))
            else:
                # A list of objects on one side only (empty lists are not exported)
                # is compared item by item with an empty list, so the rules for
                # missing and new list items apply (e.g. observed-only peers, new
                # log files). A new list is only reported if new values are.
                diff_docs(
                    expected.get(key, []),
                    actual.get(key, []),
                    sub,
                    ignore=ignore,
                    report_new_leaves=report_new_leaves,
                    out=out,
                )
        return
    list_name = plain_path(path).rsplit(".", 1)[-1]
    if (
        isinstance(expected, list)
        and isinstance(actual, list)
        and any(isinstance(x, dict) for x in expected + actual)
    ):
        exp_idx = index_items(list_name, expected, ignore, path)
        act_idx = index_items(list_name, actual, ignore, path)
        for k in sorted(set(exp_idx) | set(act_idx), key=str):
            label = ",".join(f"{a}={b}" for a, b in k[0]) + (f"#{k[1]}" if k[1] else "")
            sub = f"{path}[{label}]"
            if k not in act_idx:
                item = exp_idx[k]
                if (
                    list_name == "relationships"
                    and isinstance(item, dict)
                    and not set(item.get("evidence", [])) & STABLE_RELATIONSHIP_EVIDENCE
                ):
                    continue  # observed-only peer not seen this time: not a deviation
                if list_name == "files" and _is_input_file(item):
                    continue  # a "peat parse" input file (PEAT host path), not a device file
                value = _without_ignored(item, sub, ignore)
                if value is not None:
                    out.append(("missing", sub, value, None))
            elif k not in exp_idx:
                item = act_idx[k]
                if list_name == "files" and (
                    _is_input_file(item)
                    or (
                        isinstance(item, dict)
                        and set(item.get("category", [])) & VOLATILE_FILE_CATEGORIES
                    )
                ):
                    continue  # parse input file, or a new log/event-record file
                value = _without_ignored(item, sub, ignore)
                if value is not None:
                    out.append(("unexpected", sub, None, value))
            elif (
                list_name == "files"
                and isinstance(exp_idx[k], dict)
                and set(exp_idx[k].get("category", [])) & VOLATILE_FILE_CATEGORIES
            ):
                continue  # log/event-record files change on every pull
            else:
                diff_docs(
                    exp_idx[k],
                    act_idx[k],
                    sub,
                    ignore=ignore,
                    report_new_leaves=report_new_leaves,
                    out=out,
                )
        return
    if not _equal(expected, actual):
        out.append(("change", path, expected, actual))


def _is_object_list(value: Any) -> bool:
    return isinstance(value, list) and any(isinstance(x, dict) for x in value)


def _is_volatile_route(item: Any) -> bool:
    """If a route is a route cache entry (:data:`VOLATILE_ROUTE_TYPES`) or an ARP entry."""
    if not isinstance(item, dict):
        return False
    extra = item.get("extra")
    return str(item.get("type", "")).lower() in VOLATILE_ROUTE_TYPES or bool(
        isinstance(extra, dict) and extra.get("gateway_mac")
    )


def _without_volatile_routes(doc: dict) -> dict:
    """
    ``doc`` (a device or module) without the routes of :data:`VOLATILE_ROUTE_TYPES`
    and the ARP entries (:func:`_is_volatile_route`), and without ``routes`` if only
    those were in it (so an empty route table on the other side is not reported as
    ``missing``/``unexpected`` ``routes``).
    """
    routes = doc.get("routes")
    if not isinstance(routes, list) or not any(_is_volatile_route(r) for r in routes):
        return doc
    out = {k: v for k, v in doc.items() if k != "routes"}
    kept = [r for r in routes if not _is_volatile_route(r)]
    if kept:
        out["routes"] = kept
    return out


def _is_input_file(item: Any) -> bool:
    """
    If a ``files`` item is a file PEAT read on its own host (a ``peat parse`` input,
    e.g. an SCD file): its ``path`` is its ``local_path``, not a path on the device.
    """
    return (
        isinstance(item, dict)
        and bool(item.get("local_path"))
        and item.get("local_path") == item.get("path")
    )


def _is_unit_address(value: Any) -> bool:
    """If a listen address is an address of the unit itself (not a wildcard or loopback)."""
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return True
    return not (address.is_unspecified or address.is_loopback)


def _without_unit_identity(doc: Any) -> Any:
    """
    Copy of ``doc`` (a device document) without the per-unit values that
    :data:`DEVICE_TYPE_IGNORE` patterns can't express: service ``listen_address``
    values that are an address of the unit (wildcard and loopback addresses stay,
    so a service that moves from loopback to all addresses is reported), and the
    ``peat parse`` input files (:func:`_is_input_file`) of the device and its modules.
    Objects and list items that only contained removed values are removed as well.
    """
    if isinstance(doc, dict):
        out = {}
        for key, value in doc.items():
            if key == "listen_address" and _is_unit_address(value):
                continue
            if key == "files" and isinstance(value, list):
                value = [item for item in value if not _is_input_file(item)]
            stripped = _without_unit_identity(value)
            if not _emptied(doc[key], stripped):
                out[key] = stripped
        return out
    if isinstance(doc, list):
        items = [(v, _without_unit_identity(v)) for v in doc]
        return [stripped for v, stripped in items if not _emptied(v, stripped)]
    return doc


def _device_type_doc(doc: dict, patterns: tuple[str, ...]) -> dict:
    """``doc`` without per-unit identity (:data:`DEVICE_TYPE_IGNORE`) and ``patterns``."""
    return strip_paths(_without_unit_identity(doc), patterns)


def _without_ignored(value: Any, path: str, ignore: tuple[str, ...]) -> Any:
    """
    ``value`` without its ignored leaves, or :obj:`None` if it is ignored entirely
    (a subtree that only exists on one side is reported only if it has a leaf that
    is not ignored, e.g. ``firmware`` when only ``firmware.version`` is ignored).
    """
    if is_ignored(path, ignore):
        return None
    if isinstance(value, dict):
        stripped = strip_paths(value, ignore, path)
        return None if _emptied(value, stripped) else stripped
    return value


def store_findings(dev: DeviceData, findings: list[BaselineFinding]) -> None:
    """
    Store findings on ``dev`` (``compare_to_baseline(store=True)``): findings of
    the same baselines from an earlier comparison are REPLACED, so a re-compare
    never leaves a stale ``fail`` next to a new ``pass`` (m9).
    """
    ids = {f.baseline_id for f in findings}
    dev.baseline_findings[:] = [f for f in dev.baseline_findings if f.baseline_id not in ids]
    for finding in findings:
        dev.store("baseline_findings", finding, append=True)


# --------------------------------------------------------------------------- #
# Device-type profiles ("typical SEL-2032")
# --------------------------------------------------------------------------- #
def strip_paths(doc: Any, patterns: tuple[str, ...], path: str = "") -> Any:
    """
    Copy of ``doc`` without the leaves/subtrees matched by ``patterns`` (ignore syntax).
    Objects and list items that only contained stripped values are removed as well
    (e.g. ``logic`` if it only had a ``name``), like empty values in exported data.
    """
    if isinstance(doc, dict):
        out = {}
        for key, value in doc.items():
            sub = f"{path}.{key}" if path else key
            if not is_ignored(sub, patterns):
                stripped = strip_paths(value, patterns, sub)
                if not _emptied(value, stripped):
                    out[key] = stripped
        return out
    if isinstance(doc, list):
        items = [(v, strip_paths(v, patterns, path)) for v in doc]
        return [stripped for v, stripped in items if not _emptied(v, stripped)]
    return doc


def _emptied(before: Any, after: Any) -> bool:
    return after in ({}, []) and before not in ({}, [])


def intersect_docs(docs: list[Any], path: str = "") -> Any:
    """
    The part of ``docs`` that is identical in ALL of them: what a "typical"
    device of the type looks like. Dicts keep common keys with common values;
    lists of dicts keep items present in every doc (aligned with ``LIST_KEYS``);
    other values are kept only if equal everywhere. Returns ``None`` if nothing
    is common.
    """
    first = docs[0]
    if all(isinstance(d, dict) for d in docs):
        out = {}
        for key in first:
            if all(key in d for d in docs):
                sub = f"{path}.{key}" if path else key
                common = intersect_docs([d[key] for d in docs], sub)
                if common not in (None, {}, []):
                    out[key] = common
        return out
    list_name = plain_path(path).rsplit(".", 1)[-1]
    if all(isinstance(d, list) for d in docs) and any(
        isinstance(x, dict) for d in docs for x in d
    ):
        indexes = [index_items(list_name, d) for d in docs]
        out = []
        for key in indexes[0]:
            if all(key in idx for idx in indexes[1:]):
                common = intersect_docs([idx[key] for idx in indexes], path)
                if common not in (None, {}, []):
                    out.append(common)
        return out
    return first if all(_equal(first, d) for d in docs[1:]) else None


def varying_paths(devices: list[DeviceData]) -> list[str]:
    """
    Selector-free paths of values that differ between ``devices`` (after removing
    :data:`DEFAULT_IGNORE` and :data:`DEVICE_TYPE_IGNORE`): values present in some
    of the devices, or with different values, that are therefore not part of their
    common profile (:func:`device_type_profile`). List items that only some devices
    have are not included (an extra service is still reported as ``unexpected``).

    :func:`~peat.api.baseline_api.create_baseline` adds these paths to
    :attr:`Baseline.ignore <peat.data.models.Baseline.ignore>` of a device type
    profile built from several devices, so comparing a unit against the profile
    does not report the values that already differed between the units it was built
    from as ``unexpected``.
    """
    if len(devices) < 2:
        return []
    patterns = tuple(DEFAULT_IGNORE) + DEVICE_TYPE_IGNORE
    docs = [_device_type_doc(device_to_doc(d), patterns) for d in devices]
    common = intersect_docs(docs) or {}
    diffs: list[tuple[str, str, Any, Any]] = []
    for doc in docs:
        diff_docs(common, doc, "", ignore=(), report_new_leaves=True, out=diffs)
    paths: set[str] = set()
    for difference, path, expected, actual in diffs:
        # list items (path ends with a selector) stay reported
        if not path.endswith("]"):
            _leaf_paths(path, expected if difference == "missing" else actual, paths)
    return sorted(paths)


def _leaf_paths(path: str, value: Any, out: set[str]) -> None:
    """Selector-free paths of the leaves of ``value`` (except lists of objects)."""
    if isinstance(value, dict):
        for key, child in value.items():
            _leaf_paths(f"{path}.{key}", child, out)
    elif not (isinstance(value, list) and any(isinstance(x, dict) for x in value)):
        # lists of objects are not ignored: their items are aligned and compared
        out.add(plain_path(path))


def device_type_profile(devices: list[DeviceData]) -> DeviceData:
    """
    ``expected`` snapshot of a ``scope="device_type"`` baseline built from one or
    more pulls of devices of the same type: per-unit identity removed
    (``DEVICE_TYPE_IGNORE`` + ``DEFAULT_IGNORE``, listen addresses of the unit
    itself and ``peat parse`` input files), and with 2+ devices only what all of
    them share.
    """
    patterns = tuple(DEFAULT_IGNORE) + DEVICE_TYPE_IGNORE
    docs = [_device_type_doc(device_to_doc(d), patterns) for d in devices]
    common = docs[0] if len(docs) == 1 else (intersect_docs(docs) or {})
    return DeviceData.parse_obj(common)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def reports_new_values(baseline: Baseline) -> bool:
    """
    If values and list items that are absent from the snapshot of ``baseline`` are
    reported as ``unexpected``: its kind is in :data:`OBSERVED_KINDS`, or it is
    :attr:`complete <peat.data.models.Baseline.complete>`. Otherwise the snapshot only
    checks what it specifies (new items of the lists it has are still reported).
    """
    return baseline.kind in OBSERVED_KINDS or baseline.complete


def compare_device(
    dev: DeviceData,
    baseline: Baseline,
    include_passed: bool = True,
    timestamp: datetime | None = None,
) -> list[BaselineFinding]:
    """
    Compare a device to a baseline.

    Each enabled rule produces one finding (``pass``, ``fail``, ``unknown``
    or ``error``; ``pass`` findings are omitted if ``include_passed`` is
    :obj:`False`). If the baseline has an ``expected`` snapshot, each difference
    produces one ``fail`` finding (``change``, ``missing`` or ``unexpected``), at most
    :data:`MAX_FINDINGS_PER_BASELINE`.

    Args:
        dev: device to check (not modified)
        baseline: baseline to compare against
        include_passed: include findings of passed rules
        timestamp: time of the comparison (default: now, UTC)

    Returns:
        The findings, or an empty list if the baseline's selector does not match the device
    """
    if not baseline.selector.matches(dev):
        return []
    ts = timestamp or datetime.now(UTC)
    doc = device_to_doc(dev)
    common = {
        "baseline_id": baseline.id,
        "baseline_name": baseline.name,
        "baseline_kind": baseline.kind,
        "baseline_version": baseline.version,
        "timestamp": ts,
    }
    findings: list[BaselineFinding] = []
    for rule in baseline.rules:
        if not rule.enabled:
            continue
        result, actual = evaluate_rule(doc, rule)
        if result == "pass" and not include_passed:
            continue
        failed = result == "fail"
        findings.append(
            BaselineFinding(
                **common,
                rule_id=rule.id or f"{rule.path}:{rule.operator}",
                rule_name=rule.name,
                path=rule.path,
                category=rule.category or _category(rule.path)[0],
                result=result,
                difference="mismatch" if failed else "",
                operator=rule.operator,
                expected=rule.value,
                actual=actual,
                severity=rule.severity if failed else "",
                alert=rule.alert,
                reason=_render(rule.reason, expected=rule.value, actual=actual, path=rule.path)
                if failed and rule.reason
                else "",
                reference=rule.reference,
                standards=rule.standards,
            )
        )
    if baseline.expected is not None:
        diffs: list[tuple[str, str, Any, Any]] = []
        # + keys a lossy input format (parse/device summary) does not contain
        ignore = (
            tuple(DEFAULT_IGNORE)
            + tuple(baseline.ignore)
            + tuple(getattr(dev, "_cache", {}).get("omitted_keys", ()))
        )
        expected_doc, actual_doc = device_to_doc(baseline.expected), doc
        if baseline.scope == "device_type":
            # strip per-unit identity BEFORE aligning list items, so list keys that use
            # an identity field (e.g. clock.sources address) align on the rest (OT-2)
            ignore += DEVICE_TYPE_IGNORE
            expected_doc = _device_type_doc(expected_doc, DEVICE_TYPE_IGNORE)
            actual_doc = _device_type_doc(actual_doc, DEVICE_TYPE_IGNORE)
        diff_docs(
            expected_doc,
            actual_doc,
            "",
            ignore=ignore,
            report_new_leaves=reports_new_values(baseline),
            out=diffs,
        )
        for difference, path, exp, act in diffs[:MAX_FINDINGS_PER_BASELINE]:
            category, severity = _category(path)
            verb = {"change": "changed", "missing": "missing", "unexpected": "unexpected"}[
                difference
            ]
            findings.append(
                BaselineFinding(
                    **common,
                    path=path,
                    category=category,
                    result="fail",
                    difference=difference,
                    expected=exp,
                    actual=act,
                    severity=severity,
                    reason=f"{path} {verb} compared to baseline '{baseline.name or baseline.id}'",
                )
            )
        if len(diffs) > MAX_FINDINGS_PER_BASELINE:
            log.warning(f"Truncated {len(diffs)} differences for baseline {baseline.id}")
    return findings


__all__ = [
    "DEFAULT_IGNORE",
    "DEVICE_TYPE_IGNORE",
    "LIST_KEYS",
    "MAX_FINDINGS_PER_BASELINE",
    "OBSERVED_KINDS",
    "PATH_CATEGORY",
    "STABLE_RELATIONSHIP_EVIDENCE",
    "VOLATILE_FILE_CATEGORIES",
    "VOLATILE_ROUTE_TYPES",
    "compare_device",
    "device_to_doc",
    "device_type_profile",
    "diff_docs",
    "evaluate_rule",
    "index_items",
    "intersect_docs",
    "is_ignored",
    "item_key",
    "item_label",
    "plain_path",
    "posix_path",
    "reports_new_values",
    "resolve_path",
    "split_path",
    "store_findings",
    "strip_paths",
    "varying_paths",
]
