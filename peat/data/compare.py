"""
Structured comparison ("diff") of device data.

The main entry points are :meth:`DeviceData.compare() <peat.data.models.DeviceData.compare>`
and :func:`compare_device_data`. Both compare the normalized export form of the data
(the same data that is written to ``device-data-full.json``), so a
:class:`~peat.data.models.DeviceData` object can be compared to another object or to
a previously exported JSON file (e.g. a baseline).

Lists of sub-models (interfaces, services, files, registers, etc.) are matched by
identity keys (:data:`LIST_IDENTITY_KEYS`) instead of by position, so reordering
does not produce changes, and changes are reported with readable paths such as
``interface[name=eth0].ip`` or ``service[port=23,protocol=telnet]``.

Example:

>>> from peat.data.compare import compare_device_data
>>> old = {"name": "plc-1", "service": [{"port": 21, "protocol": "ftp"}]}
>>> new = {
...     "name": "plc-1",
...     "service": [{"port": 21, "protocol": "ftp"}, {"port": 23, "protocol": "telnet"}],
... }
>>> diff = compare_device_data(old, new)
>>> diff.is_same
False
>>> [(c.kind, c.path) for c in diff.changes]
[('added', 'service[port=23,protocol=telnet]')]
>>> print(diff.format())
+ service[port=23,protocol=telnet]: {"port": 23, "protocol": "telnet"}
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, deque
from collections.abc import Iterable, Mapping
from fnmatch import fnmatchcase
from itertools import islice
from typing import Any, Literal

from peat import consts, log

from .base_model import BaseModel

MAX_DEPTH: int = 64
"""
Maximum nesting depth that is compared recursively. Values nested deeper than
this are compared as a single value. This bounds the work done on untrusted data.
"""

DEFAULT_COMPARE_EXCLUDES: tuple[str, ...] = (
    # Values that change on every pull, even if nothing on the device changed
    "uptime",
    "start_time",
    "successful_pulls",
    # Timestamp set by PEAT when data is ingested
    "ingested",
    # Derived from other fields by populate_fields(), would double-report changes
    "related",
    # Logs and live memory reads always differ between pulls
    "event",
    "memory",
    # Location and timestamps of the copy of a file on the system running PEAT
    "local_path",
    "files.created",
    "files.mtime",
    "*.file.created",
    "*.file.mtime",
)
"""
Patterns excluded from comparison by default (``use_default_excludes=True``).

These are values that differ between two pulls of an unchanged device, or that
are specific to the system running PEAT. Refer to :func:`compare_device_data`
for the pattern syntax.

In addition, values of files that were read from the copy of the file on the
system running PEAT, instead of from the device, are ignored by default.
For any file with a ``local_path``, these are the ``owner`` and ``group``,
and the ``path`` and ``directory`` if they are the location of the local copy.
"""

_SERVICE_KEYS: tuple[tuple[str, ...], ...] = (
    ("port", "protocol", "transport"),
    ("port", "protocol"),
    ("port", "transport"),
    ("port",),
    ("protocol",),
)

LIST_IDENTITY_KEYS: dict[str, tuple[tuple[str, ...], ...]] = {
    "interface": (("name",), ("mac",), ("ip",), ("serial_port",), ("id",)),
    "service": _SERVICE_KEYS,
    "interface.services": _SERVICE_KEYS,
    "files": (("path",), ("directory", "name"), ("hash.sha256",), ("name",)),
    # Points of different types (e.g. DNP3 analog and binary inputs) can have
    # the same address, so "measurement_type" and "group" are part of the identity
    "registers": (
        ("protocol", "group", "measurement_type", "address"),
        ("protocol", "group", "address"),
        ("protocol", "measurement_type", "address"),
        ("protocol", "address"),
        ("address",),
        ("name",),
        ("tag",),
    ),
    "tag": (("name",), ("address",)),
    "io": (("name",), ("id",), ("address",)),
    "event": (("id",), ("dataset", "sequence")),
    "memory": (("device", "address"), ("address",)),
    # The key itself identifies a key best, so changed key material is never paired
    "ssh_keys": (("original",), ("id",), ("host", "user", "type")),
    "users": (("domain", "name"), ("name",), ("id",), ("uid",)),
    "uefi_image": (("path",), ("guid",), ("name",)),
    "uefi_hashes": (("file_system", "pathname"), ("pathname",)),
    "module": (("slot",), ("serial_number",), ("name",), ("id",)),
}
"""
Identity keys used to match items in lists of sub-models when ``ignore_order=True``.

Keys are the field path of the list (without list selectors, sub-modules in
``module`` use the same keys as the top-level device). Values are tuples of
candidate keys in priority order. Each candidate is a tuple of field names
(dotted names read nested values, e.g. ``hash.sha256``).

Two items are never paired if any of their candidate keys is set in both items
with different values, e.g. the services ``53/tcp`` and ``53/udp``. Otherwise, items
that are identical (ignoring excluded fields) are paired first. Remaining items are
paired by the first candidate key whose fields are all set and equal in both items,
e.g. a service with no ``protocol`` is paired with a service on the same ``port``
that has a ``protocol``. Items that can't be paired are reported as removed or added.
Identity keys are read from all fields, including excluded and not included fields.
"""

_DIGEST_FIELDS = frozenset({"original"})
"""
Identity fields that may contain sensitive raw data (e.g. SSH private keys).
Their values are shown in change paths as a SHA-256 digest prefix.
"""

_MAX_CANDIDATES = 100
"""
Maximum number of items with the same identity key value that are checked for
conflicting higher-priority keys when pairing one item. Bounds the work done
on untrusted data. Items that aren't paired are reported as removed and added.
"""

# Device values used in paths are only displayed as-is if they match these
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:/@+\-]{1,64}")
_SAFE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]{0,63}")
_MAX_QUOTED_LEN = 80


class Change(BaseModel):
    """
    A single difference between two sets of device data.
    """

    kind: Literal["added", "removed", "changed"]
    """
    Type of change. ``added``: only present in the new data. ``removed``: only present
    in the old data. ``changed``: present in both, with different values.
    """

    path: str
    """
    Location of the change, e.g. ``firmware.version``, ``interface[name=eth0].ip``
    or ``service[port=23,protocol=telnet]``. Items in lists of sub-models are selected
    by their identity key values (``[key=value]``), or by index (``[3]``) if they have
    no identity keys. If several items in a list have the same identity, the index
    of the item is added (``[name=x,index=3]``). Indices are positions in the old
    list, or in the new list for ``added`` items. Values from the device that contain
    special characters are JSON-quoted, and raw data (``original``) is shown as
    a digest (``[original=sha256:...]``).
    """

    old: Any = None
    """Value in the old data (``None`` if ``added``)."""

    new: Any = None
    """Value in the new data (``None`` if ``removed``)."""


class DeviceDiff(BaseModel):
    """
    Result of comparing two sets of device data.

    Returned by :meth:`DeviceData.compare() <peat.data.models.DeviceData.compare>`
    and :func:`compare_device_data`.
    """

    changes: list[Change] = []
    """All changes, in the order of the fields in the data."""

    same_values: int = 0
    """Number of values that are the same in both sets of data."""

    different_values: int = 0
    """
    Number of values that differ (added, removed, or changed). An added or removed
    sub-model counts every value it contains.
    """

    @property
    def added(self) -> list[Change]:
        """Changes that are only present in the new data."""
        return [c for c in self.changes if c.kind == "added"]

    @property
    def removed(self) -> list[Change]:
        """Changes that are only present in the old data."""
        return [c for c in self.changes if c.kind == "removed"]

    @property
    def changed(self) -> list[Change]:
        """Changes to values that are present in both sets of data."""
        return [c for c in self.changes if c.kind == "changed"]

    @property
    def is_same(self) -> bool:
        """If there are no differences (after exclusions were applied)."""
        return not self.changes

    @property
    def similarity(self) -> float:
        """
        Ratio of values that are the same, from ``0.0`` (nothing in common)
        to ``1.0`` (identical). Two empty sets of data are identical.
        """
        total = self.same_values + self.different_values
        if not total:
            return 1.0
        return self.same_values / total

    def summary(self) -> dict[str, int | float | bool]:
        """
        Counts of changes and the similarity, as a JSON-friendly :class:`dict`.
        """
        return {
            "is_same": self.is_same,
            "similarity": round(self.similarity, 4),
            "total_changes": len(self.changes),
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "same_values": self.same_values,
            "different_values": self.different_values,
        }

    def export(self) -> dict:
        """
        The summary and all changes, as a JSON-serializable :class:`dict`.
        """
        return {
            "summary": self.summary(),
            "changes": [consts.convert(c.dict()) for c in self.changes],
        }

    def format(self, max_changes: int | None = None, max_value_length: int = 120) -> str:
        """
        Human-readable text listing of the changes, one change per line.

        Lines start with ``+`` (added), ``-`` (removed) or ``~`` (changed).
        Values are JSON-encoded with non-ASCII and control characters escaped,
        so the output is safe to print to a terminal.

        Args:
            max_changes: Maximum number of changes to include. If there are more,
                a final line with the number of changes not shown is added.
            max_value_length: Values longer than this are truncated
                (minimum of 10 characters).

        Returns:
            The formatted changes, or ``"No differences"``
        """
        if not self.changes:
            return "No differences"

        limit = max(10, max_value_length)
        shown = self.changes if max_changes is None else self.changes[: max(0, max_changes)]
        lines = []
        for change in shown:
            if change.kind == "added":
                lines.append(f"+ {change.path}: {_short(change.new, limit)}")
            elif change.kind == "removed":
                lines.append(f"- {change.path}: {_short(change.old, limit)}")
            else:
                lines.append(
                    f"~ {change.path}: {_short(change.old, limit)} -> {_short(change.new, limit)}"
                )

        if len(shown) < len(self.changes):
            lines.append(f"... and {len(self.changes) - len(shown)} more changes")

        return "\n".join(lines)


def compare_device_data(
    old: Any,
    new: Any,
    *,
    include: str | Iterable[str] | None = None,
    exclude: str | Iterable[str] | None = None,
    use_default_excludes: bool = True,
    include_original: bool = False,
    ignore_order: bool = True,
) -> DeviceDiff:
    """
    Compare two sets of device data and return the differences.

    The differences describe how to get from ``old`` to ``new``.

    Both inputs are normalized the same way before they are compared: data is
    converted to its JSON form (e.g. :class:`dict` keys become strings), and empty
    values and private fields (names starting with ``_``) are removed. A device
    is therefore the same as its own exported ``device-data-full.json``.

    Exclusion patterns are matched against the path of a field without any
    list selectors, e.g. ``interface.services.port`` or ``logic.file.hash.md5``:

    - A pattern without a ``.`` matches a field with that name at any depth,
      e.g. ``"uptime"`` excludes ``uptime`` and ``interface[...].uptime``
      (the same behavior as ``exclude_fields`` of
      :meth:`~peat.data.models.DeviceData.export`).
    - Otherwise, the pattern is matched against the whole path with
      :func:`fnmatch.fnmatchcase`, e.g. ``"logic.*"`` or ``"*.extra"``.
      Paths inside sub-modules (``module``) are matched with and without
      the ``module.`` prefix, so ``"files.mtime"`` also excludes
      ``module.files.mtime``.

    .. note::
       ``device-data-summary.json`` files leave out some fields. To compare a
       summary to full data, exclude them:
       ``exclude=["registers", "tag", "io", "files", "raw-values"]``
       (``memory``, ``event`` and ``original`` are excluded by default).

    Args:
        old: The old (or baseline) data. Either a :class:`~peat.data.models.DeviceData`
            or a :class:`dict` of exported data, e.g. loaded from a
            ``device-data-full.json`` file.
        new: The new data, same types as ``old``.
        include: Only compare these fields. Either top-level fields, e.g.
            ``["firmware", "logic"]``, or dotted paths without list selectors,
            e.g. ``"firmware.version"`` or ``"interface.ip"``.
        exclude: Patterns of fields to exclude from comparison, in addition to
            :data:`DEFAULT_COMPARE_EXCLUDES` (if enabled).
        use_default_excludes: Exclude the patterns in :data:`DEFAULT_COMPARE_EXCLUDES`,
            which are values that are expected to differ between two pulls of
            an unchanged device (e.g. ``uptime``), and values of files that are from
            the local copy of the file instead of the device (e.g. ``owner``).
        include_original: Compare ``original`` fields (raw data, e.g. raw firmware).
            These are excluded by default, changes to them are still detected
            through the ``hash`` fields.
        ignore_order: Match items in lists by their identity keys
            (:data:`LIST_IDENTITY_KEYS`) or value instead of their position,
            and compare lists of simple values (e.g. ``users[...].roles``) as sets.

    Returns:
        The differences between the data

    Raises:
        TypeError: If ``old`` or ``new`` is not a DeviceData or :class:`dict`
        ValueError: If the data is nested too deeply to be processed, or ``include``
            is empty or names a field that is not in the data model or the data
    """
    old_data = _normalize(old, include_original, use_default_excludes, "old")
    new_data = _normalize(new, include_original, use_default_excludes, "new")

    excludes = _as_list(exclude)
    if use_default_excludes:
        excludes.extend(DEFAULT_COMPARE_EXCLUDES)
    if not include_original:
        excludes.append("original")

    includes = None
    if include is not None:
        includes = _validate_includes(_as_list(include), old_data, new_data)

    differ = _Differ(excludes=excludes, includes=includes, ignore_order=ignore_order)
    differ.diff(old_data, new_data, "", "", 0)

    result = DeviceDiff.construct(
        changes=differ.changes,
        same_values=differ.same,
        different_values=differ.different,
    )
    log.debug(f"Compared device data: {result.summary()}")

    return result


def _as_list(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _normalize(obj: Any, include_original: bool, drop_host_values: bool, name: str) -> dict:
    """
    Convert DeviceData or a dict of exported data into the normalized form that
    is compared. Both types of input go through the same steps.
    """
    from .models import _NO_ADDRESS_RESOLUTION, DeviceData

    if not isinstance(obj, (DeviceData, Mapping)):
        raise TypeError(
            f"Can't compare '{name}': expected DeviceData or dict, got {type(obj).__name__}"
        )

    try:
        if isinstance(obj, DeviceData):
            # Don't make network requests (DNS, ARP) or add values that
            # depend on the network the comparison is run on.
            token = _NO_ADDRESS_RESOLUTION.set(True)
            try:
                raw = obj.export(include_original=include_original)
            finally:
                _NO_ADDRESS_RESOLUTION.reset(token)
        else:
            raw = consts.convert(dict(obj))

        data = _clean(raw)
        if drop_host_values:
            _drop_local_file_values(data)
    except RecursionError:
        raise ValueError(f"Can't compare '{name}': data is nested too deeply") from None

    # The timestamp of the file write, added by DeviceData.export_to_files().
    # DeviceData has no "created" field, so it's never device data.
    data.pop("created", None)
    return data


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, (str, dict, list)) and not value)


def _json_key(key: Any) -> str:
    """Convert a dict key the same way as :func:`json.dumps`."""
    if isinstance(key, str):
        return key
    if key is None or isinstance(key, (bool, int, float)):
        return json.dumps(key)
    return str(key)


def _clean(value: Any) -> Any:
    """
    Convert JSON-friendly data (output of :func:`~peat.consts.convert`) into the
    form it has after a JSON round trip, and recursively remove empty values and
    private keys. Unlike :func:`~peat.data.data_utils.strip_empty_and_private`,
    the result doesn't change if this is applied again.
    """
    if isinstance(value, dict):
        cleaned = {}
        for key, child in value.items():
            if isinstance(key, str) and key.startswith("_"):
                continue
            child = _clean(child)
            if not _is_empty(child):
                cleaned[_json_key(key)] = child
        return cleaned

    if isinstance(value, (list, tuple)):
        return [c for c in map(_clean, value) if not _is_empty(c)]

    if value is None or isinstance(value, (str, bool, int, float)):
        return value

    return str(value)


def _drop_local_file_values(value: Any, depth: int = 0) -> None:
    """
    Remove values of files that were read from the copy of the file on the system
    running PEAT instead of from the device (refer to :data:`DEFAULT_COMPARE_EXCLUDES`).
    These differ between runs, e.g. the run directory or the user running PEAT.
    """
    if depth > MAX_DEPTH:
        return

    if isinstance(value, dict):
        local_path = value.get("local_path")
        if isinstance(local_path, str) and local_path:
            local = local_path.replace("\\", "/")
            path = value.get("path")
            if isinstance(path, str) and path.replace("\\", "/") == local:
                del value["path"]

            directory = value.get("directory")
            parent = local.rsplit("/", 1)[0] + "/" if "/" in local else ""
            if isinstance(directory, str) and directory.replace("\\", "/") == parent:
                del value["directory"]

            # File ownership is read from the local copy if the module didn't set it
            value.pop("owner", None)
            value.pop("group", None)

        for child in value.values():
            _drop_local_file_values(child, depth + 1)

    elif isinstance(value, list):
        for child in value:
            _drop_local_file_values(child, depth + 1)


def _model_has_path(parts: list[str]) -> bool:
    """If a dotted path (without list selectors) is a field in the DeviceData model."""
    from .models import DeviceData

    model: type | None = DeviceData
    for part in parts:
        if model is None:
            return True  # Free-form data (e.g. "extra") or a simple value

        field = model.__fields__.get(part)  # type: ignore[attr-defined]
        if field is None:
            return False

        field_type = field.type_
        is_model = isinstance(field_type, type) and issubclass(field_type, BaseModel)
        model = field_type if is_model else None

    return True


def _data_has_path(value: Any, parts: list[str]) -> bool:
    """If a dotted path (without list selectors) is present in the data."""
    for index, part in enumerate(parts):
        if isinstance(value, list):
            return any(_data_has_path(item, parts[index:]) for item in value)
        if not isinstance(value, dict) or part not in value:
            return False
        value = value[part]
    return True


def _validate_includes(includes: list[str], old: dict, new: dict) -> set[str]:
    if not includes:
        raise ValueError("'include' is empty, there would be nothing to compare")

    unknown = [
        name
        for name in includes
        if not name
        or not (
            _model_has_path(name.split("."))
            or _data_has_path(old, name.split("."))
            or _data_has_path(new, name.split("."))
        )
    ]
    if unknown:
        names = ", ".join(_short(name, _MAX_QUOTED_LEN) for name in unknown)
        raise ValueError(f"Unknown fields in 'include': {names}")

    return set(includes)


def _short(value: Any, limit: int) -> str:
    """Escaped and truncated representation of a value for display."""
    try:
        text = json.dumps(value, ensure_ascii=True, default=str)
    except (TypeError, ValueError, RecursionError):
        text = f"<{type(value).__name__}>"

    if len(text) > limit:
        text = text[: limit - 3] + "..."

    return text


def _quote(value: Any) -> str:
    """Render a device-supplied value for use in a change path."""
    if isinstance(value, str) and _SAFE_VALUE.fullmatch(value):
        return value
    if isinstance(value, (bool, int, float)) or value is None:
        return json.dumps(value)
    return _short(value, _MAX_QUOTED_LEN)


def _join_key(path: str, key: Any) -> str:
    """Append a dict key to a change path."""
    key_str = str(key)
    if _SAFE_KEY.fullmatch(key_str):
        return f"{path}.{key_str}" if path else key_str
    return f"{path}[{_short(key_str, _MAX_QUOTED_LEN)}]"


def _canonical(value: Any) -> str:
    """Hashable canonical form of a value, used for order-insensitive comparisons."""
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    except (TypeError, ValueError):  # e.g. keys of mixed types can't be sorted
        try:
            return repr(value)
        except RecursionError:
            return f"<unique {id(value)}>"
    except RecursionError:
        # Too deep to represent, never considered equal to anything else
        return f"<unique {id(value)}>"


def _leaf_equal(a: Any, b: Any) -> bool:
    """
    Compare simple values. Booleans are not equal to numbers, integers and
    floats are compared by value, and NaN equals NaN.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b

    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
            return True
        return a == b

    if type(a) is not type(b):
        return False

    try:
        return bool(a == b)
    except RecursionError:
        return _canonical(a) == _canonical(b)


def _get_field(item: dict, field: str) -> Any:
    """Get a (possibly dotted) field from a dict."""
    value: Any = item
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _identity(item: Any, fields: tuple[str, ...]) -> tuple | None:
    """Values of the identity fields of an item, or None if any of them is unset."""
    if not isinstance(item, dict):
        return None

    values = []
    for field in fields:
        value = _get_field(item, field)
        if value is None or (isinstance(value, (str, list, dict)) and not value):
            return None
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            value = _canonical(value)
        values.append(value)

    return tuple(values)


def _strip_module_prefix(schema: str) -> str:
    while schema.startswith("module."):
        schema = schema[len("module.") :]
    return schema


class _Differ:
    """Recursive differ over normalized (JSON-friendly) export data."""

    def __init__(self, excludes: list[str], includes: set[str] | None, ignore_order: bool) -> None:
        self.name_patterns = [p for p in excludes if "." not in p]
        self.path_patterns = [p for p in excludes if "." in p]
        self.includes = includes
        self.ignore_order = ignore_order
        self.changes: list[Change] = []
        self.same = 0
        self.different = 0
        self._skip_cache: dict[str, bool] = {}

    # -- Exclusions --

    def is_skipped(self, schema: str) -> bool:
        """If a field is excluded, or not included (if ``include`` was used)."""
        cached = self._skip_cache.get(schema)
        if cached is not None:
            return cached

        name = schema.rsplit(".", 1)[-1]
        stripped = _strip_module_prefix(schema)
        skipped = any(fnmatchcase(name, p) for p in self.name_patterns) or any(
            fnmatchcase(schema, p) or fnmatchcase(stripped, p) for p in self.path_patterns
        )

        # Included: the field, its children, and its parents (to get to the field)
        if not skipped and self.includes is not None:
            skipped = not any(
                schema == p or schema.startswith(p + ".") or p.startswith(schema + ".")
                for p in self.includes
            )

        self._skip_cache[schema] = skipped
        return skipped

    def _child_schema(self, schema: str, key: Any) -> str | None:
        """Schema path of a dict key, or None if the key is excluded."""
        child = f"{schema}.{key}" if schema else str(key)
        if self.is_skipped(child):
            return None
        return child

    # -- Results --

    def record(self, kind: str, path: str, old: Any, new: Any, weight: int) -> None:
        self.different += weight
        self.changes.append(Change(kind=kind, path=path or ".", old=old, new=new))

    def prune(self, value: Any, schema: str, depth: int) -> tuple[Any, int]:
        """
        Remove excluded fields from a value and count the values it contains.

        Returns:
            Tuple of the pruned value and the number of values in it
        """
        if depth > MAX_DEPTH:
            return value, 1

        if isinstance(value, dict):
            pruned = {}
            count = 0
            for key, child in value.items():
                child_schema = self._child_schema(schema, key)
                if child_schema is None:
                    continue
                pruned[key], child_count = self.prune(child, child_schema, depth + 1)
                count += child_count
            return pruned, max(count, 1)

        if isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value):
            items = [self.prune(v, schema, depth + 1) for v in value]
            return [i[0] for i in items], max(sum(i[1] for i in items), 1)

        # Simple values and lists of simple values are counted as one value
        return value, 1

    # -- Comparison --

    def diff(self, old: Any, new: Any, path: str, schema: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            if _canonical(old) == _canonical(new):
                self.same += 1
            else:
                self.record("changed", path, old, new, 1)
            return

        if isinstance(old, dict) and isinstance(new, dict):
            self._diff_dicts(old, new, path, schema, depth)
        elif isinstance(old, list) and isinstance(new, list):
            self._diff_lists(old, new, path, schema, depth)
        elif _leaf_equal(old, new):
            self.same += 1
        else:
            old_pruned, old_count = self.prune(old, schema, depth)
            new_pruned, new_count = self.prune(new, schema, depth)
            self.record("changed", path, old_pruned, new_pruned, max(old_count, new_count))

    def _diff_dicts(self, old: dict, new: dict, path: str, schema: str, depth: int) -> None:
        keys = list(old.keys()) + [k for k in new.keys() if k not in old]

        for key in keys:
            child_schema = self._child_schema(schema, key)
            if child_schema is None:
                continue

            child_path = _join_key(path, key)
            if key not in new:
                self._record_subtree("removed", child_path, old[key], child_schema, depth + 1)
            elif key not in old:
                self._record_subtree("added", child_path, new[key], child_schema, depth + 1)
            else:
                self.diff(old[key], new[key], child_path, child_schema, depth + 1)

    def _record_subtree(self, kind: str, path: str, value: Any, schema: str, depth: int) -> None:
        pruned, count = self.prune(value, schema, depth)
        if kind == "added":
            self.record(kind, path, None, pruned, count)
        else:
            self.record(kind, path, pruned, None, count)

    def _diff_lists(self, old: list, new: list, path: str, schema: str, depth: int) -> None:
        if not self.ignore_order:
            for index in range(max(len(old), len(new))):
                item_path = f"{path}[{index}]"
                if index >= len(new):
                    self._record_subtree("removed", item_path, old[index], schema, depth + 1)
                elif index >= len(old):
                    self._record_subtree("added", item_path, new[index], schema, depth + 1)
                else:
                    self.diff(old[index], new[index], item_path, schema, depth + 1)
            return

        # Lists of simple values are compared as a multiset (order doesn't matter)
        if not any(isinstance(v, (dict, list)) for v in [*old, *new]):
            if sorted(map(_canonical, old)) == sorted(map(_canonical, new)):
                self.same += 1
            else:
                self.record("changed", path, old, new, 1)
            return

        self._diff_keyed_lists(old, new, path, schema, depth)

    def _diff_keyed_lists(self, old: list, new: list, path: str, schema: str, depth: int) -> None:
        """
        Pair up items from the two lists, then compare the pairs.

        1. Identical items (ignoring excluded fields) are paired, regardless of position
        2. Remaining items are paired by identity keys, in priority order
        3. Anything left over was removed (old) or added (new)

        Items with an identity key that is set in both items with different
        values are never paired, and are not paired by lower-priority keys.
        """
        key_specs = LIST_IDENTITY_KEYS.get(_strip_module_prefix(schema), ())
        levels = len(key_specs)
        old_ids = [[_identity(item, fields) for fields in key_specs] for item in old]
        new_ids = [[_identity(item, fields) for fields in key_specs] for item in new]

        def take(bucket: deque[int] | None, i: int, level: int) -> int | None:
            """Remove and return the first item in bucket that doesn't conflict with old[i]."""
            if not bucket:
                return None
            for position, j in enumerate(islice(bucket, _MAX_CANDIDATES)):
                if not _conflicts(old_ids[i], new_ids[j], level):
                    del bucket[position]
                    return j
            return None

        # old index -> (new index, index of the key spec used, None if identical)
        pairs: dict[int, tuple[int, int | None]] = {}

        # Identical items
        by_value: dict[str, deque[int]] = {}
        for j, item in enumerate(new):
            by_value.setdefault(self._canonical_pruned(item, schema, depth), deque()).append(j)

        remaining_old = []
        for i, item in enumerate(old):
            match = take(by_value.get(self._canonical_pruned(item, schema, depth)), i, levels)
            if match is None:
                remaining_old.append(i)
            else:
                pairs[i] = (match, None)

        used_new = {j for j, _ in pairs.values()}
        remaining_new = [j for j in range(len(new)) if j not in used_new]

        # Items with matching identity keys and no conflicting higher-priority keys
        for level in range(levels):
            if not remaining_old or not remaining_new:
                break

            by_key: dict[tuple, deque[int]] = {}
            for j in remaining_new:
                key = new_ids[j][level]
                if key is not None:
                    by_key.setdefault(key, deque()).append(j)

            still_old = []
            for i in remaining_old:
                key = old_ids[i][level]
                match = take(by_key.get(key), i, level) if key is not None else None
                if match is None:
                    still_old.append(i)
                else:
                    pairs[i] = (match, level)

            remaining_old = still_old
            used_new = {j for j, _ in pairs.values()}
            remaining_new = [j for j in remaining_new if j not in used_new]

        # Selectors of the items in change paths
        entries: list[tuple[str, int, int, str]] = []  # (kind, old index, new index, selector)
        for i in range(len(old)):
            if i not in pairs:
                entries.append(("removed", i, -1, _item_selector(old_ids[i], key_specs, i)))
                continue

            j, matched_level = pairs[i]
            matched_key = old_ids[i][matched_level] if matched_level is not None else None
            if matched_level is None or matched_key is None:
                selector = _item_selector(old_ids[i], key_specs, i)
            else:
                selector = _selector(key_specs[matched_level], matched_key)
            entries.append(("pair", i, j, selector))

        for j in remaining_new:
            entries.append(("added", -1, j, _item_selector(new_ids[j], key_specs, j)))

        # Make selectors of items with the same identity unique
        counts = Counter(selector for *_, selector in entries)

        # Compare pairs and report removals (in the order of the old list), then additions
        for kind, i, j, selector in entries:
            if counts[selector] > 1 and "=" in selector:
                selector += f",index={j if kind == 'added' else i}"

            item_path = f"{path}[{selector}]"
            if kind == "pair":
                self.diff(old[i], new[j], item_path, schema, depth + 1)
            elif kind == "removed":
                self._record_subtree("removed", item_path, old[i], schema, depth + 1)
            else:
                self._record_subtree("added", item_path, new[j], schema, depth + 1)

    def _canonical_pruned(self, item: Any, schema: str, depth: int) -> str:
        """Canonical form of a list item, ignoring excluded fields."""
        return _canonical(self.prune(item, schema, depth + 1)[0])


def _conflicts(old_ids: list[tuple | None], new_ids: list[tuple | None], level: int) -> bool:
    """If any of the first ``level`` identity keys is set in both items with different values."""
    for index in range(level):
        a = old_ids[index]
        b = new_ids[index]
        if a is not None and b is not None and a != b:
            return True
    return False


def _selector(fields: tuple[str, ...], key: tuple) -> str:
    parts = []
    for field, value in zip(fields, key, strict=True):
        if field.rsplit(".", 1)[-1] in _DIGEST_FIELDS:
            digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()
            parts.append(f"{field}=sha256:{digest[:16]}")
        else:
            parts.append(f"{field}={_quote(value)}")
    return ",".join(parts)


def _item_selector(
    ids: list[tuple | None], key_specs: tuple[tuple[str, ...], ...], index: int
) -> str:
    """Selector for an item using its first set identity key, or its index."""
    for fields, key in zip(key_specs, ids, strict=True):
        if key is not None:
            return _selector(fields, key)
    return str(index)


__all__ = [
    "DEFAULT_COMPARE_EXCLUDES",
    "LIST_IDENTITY_KEYS",
    "MAX_DEPTH",
    "Change",
    "DeviceDiff",
    "compare_device_data",
]
