"""
Build the view model of the HTML report from the contents of a run directory.

All decisions (merging, counting, truncation, redaction, status) are made here
in plain Python, so they can be tested without HTML. Every user-visible string
is sanitized with :func:`~peat.report.sanitize.clean_text` when the view model
objects are created. The templates only loop over the data and print it
(and Jinja2 autoescapes everything).
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from humanfriendly import format_size

from peat import __version__, config, consts, log, state, utils
from peat.run_results import DeviceResults, RunResults, check_data, is_anchored, load_json_file

from . import consts as rc
from .sanitize import (
    anchor_id,
    clean_text,
    hosts_overview,
    ip_sort_key,
    redact_argv,
    redact_mapping,
    redact_url_credentials,
    safe_href,
)

_BADGE_ICONS = {
    "good": "\u2713",
    "warning": "\u26a0",
    "serious": "\u25b2",
    "critical": "\u2717",
    "neutral": "\u2022",
    "info": "i",
}

_STATUS_BADGES = {
    "pulled": "good",
    "parsed": "good",
    "verified": "info",
    "online": "neutral",
    "pull failed": "serious",
}

# Commands that can be identified from a run directory
_KNOWN_COMMANDS = rc.REPORT_COMMANDS | {"report"}

_LEVEL_RE = re.compile(r'"level":"(?P<level>[A-Z0-9]+)"')
_TIMESTAMP_RE = re.compile(r'^\{"@timestamp":"(?P<ts>[^"]+)"')
_WARN_LEVELS = frozenset({"WARNING", "ERROR", "CRITICAL"})

# Stop scanning device events after this many lines (for the summary values only)
_MAX_EVENT_SCAN = 200_000


# --- View model ---------------------------------------------------------------


@dataclass(frozen=True)
class Badge:
    """Status label, always shown with an icon (never just a color)."""

    kind: str
    label: str

    @property
    def icon(self) -> str:
        return _BADGE_ICONS[self.kind]


@dataclass
class Cell:
    """A value in a table or key-value list. ``text`` is sanitized on creation."""

    text: Any = ""
    #: Sort key (``data-sort``), e.g. a number or :func:`ip_sort_key` value
    sort: Any = None
    #: Link, ONLY from :func:`safe_href` or ``#`` + :func:`anchor_id`
    href: str | None = None
    badges: list[Badge] = field(default_factory=list)
    mono: bool = False

    def __post_init__(self) -> None:
        self.text = clean_text(self.text)
        if self.sort is not None:
            self.sort = clean_text(self.sort, max_len=200)


@dataclass
class Column:
    label: str
    numeric: bool = False
    sortable: bool = True


@dataclass
class Table:
    id: str
    caption: str
    columns: list[Column]
    rows: list[list[Cell]]
    total_rows: int = 0
    empty_text: str = "None"
    filterable: bool = True
    sortable: bool = True

    @property
    def truncated(self) -> bool:
        return self.total_rows > len(self.rows)


@dataclass
class KV:
    label: str
    value: Cell


@dataclass
class Tile:
    label: str
    value: str
    badge: Badge | None = None


@dataclass
class Block:
    """Pretty-printed JSON shown in a collapsed ``<details>`` element."""

    title: str
    text: str
    truncated: bool = False


@dataclass
class OperationSection:
    anchor: str
    title: str
    items: list[KV] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)


@dataclass
class DeviceSection:
    anchor: str
    title: str
    subtitle: str
    badges: list[Badge]
    open: bool
    identity: list[KV] = field(default_factory=list)
    counts: list[KV] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    blocks: list[Block] = field(default_factory=list)
    links: list[Cell] = field(default_factory=list)


def _empty_table(table_id: str, caption: str) -> Table:
    return Table(id=table_id, caption=caption, columns=[Column("Value")], rows=[])


@dataclass
class ReportContext:
    """Everything the report template needs."""

    title: str
    run_name: str
    command: str
    generated_at: str
    generator_version: str
    mode: str  # "live" or "regenerated"
    status: Badge
    extra_badges: list[Badge] = field(default_factory=list)
    tiles: list[Tile] = field(default_factory=list)
    toc: list[tuple[str, str]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    run_items: list[KV] = field(default_factory=list)
    operations: list[OperationSection] = field(default_factory=list)
    hosts_table: Table = field(default_factory=lambda: _empty_table("hosts-table", "Hosts"))
    devices: list[DeviceSection] = field(default_factory=list)
    modules_table: Table = field(default_factory=lambda: _empty_table("modules-table", "Modules"))
    logs_items: list[KV] = field(default_factory=list)
    logs_table: Table = field(default_factory=lambda: _empty_table("logs-table", "Messages"))
    files_table: Table = field(default_factory=lambda: _empty_table("files-table", "Files"))
    outside_files_table: Table = field(
        default_factory=lambda: _empty_table("outside-files-table", "Other files")
    )
    elastic_table: Table = field(
        default_factory=lambda: _empty_table("elastic-table", "Elasticsearch exports")
    )
    config_items: list[KV] = field(default_factory=list)
    config_table: Table = field(default_factory=lambda: _empty_table("config-table", "Settings"))
    config_hosts_table: Table = field(
        default_factory=lambda: _empty_table("config-hosts-table", "Hosts")
    )
    environment_items: list[KV] = field(default_factory=list)
    interfaces_table: Table = field(
        default_factory=lambda: _empty_table("interfaces-table", "Interfaces")
    )


# --- Live run information ---------------------------------------------------


@dataclass
class LiveRunInfo:
    """
    Information about the current PEAT run that isn't (yet) in the run directory.
    """

    command: str
    argv: list[str]
    start_time: datetime
    end_time: datetime
    error: bool
    peat_version: str
    sysinfo: dict
    #: Files that will be written after the report (when PEAT exits)
    pending_files: list[Path] = field(default_factory=list)

    @classmethod
    def from_current_run(cls, command: str) -> LiveRunInfo:
        """
        Collect the information about the current run.

        This waits for queued log messages to be written, so the JSON
        log file is complete when the report reads it.
        """
        log.complete()
        pending = []
        if config.META_DIR:
            pending = [Path(config.META_DIR, f"peat_{n}.yaml") for n in ("configuration", "state")]
        return cls(
            command=command,
            argv=list(sys.argv),
            start_time=consts.START_TIME_UTC,
            end_time=utils.utc_now(),
            error=bool(state.error),
            peat_version=__version__,
            sysinfo=dict(consts.SYSINFO),
            pending_files=pending,
        )


# --- Helpers ---------------------------------------------------------------


def _get(data: Any, dotted: str) -> Any:
    """Get a nested value, e.g. ``_get(dev, "description.vendor.name")``."""
    for part in dotted.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _fmt(value: Any) -> str:
    """Format a value for display."""
    if value is None or value in ("", [], {}):
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_fmt(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, default=str, sort_keys=True)
    return str(value)


def _kv(label: str, value: Any, *, mono: bool = False, href: str | None = None) -> KV:
    return KV(label=label, value=Cell(_fmt(value), mono=mono, href=href))


def _kvs(pairs: Iterable[tuple[str, Any]]) -> list[KV]:
    """Key-value items, skipping empty values."""
    return [_kv(label, value) for label, value in pairs if _fmt(value) != ""]


def _num_cell(value: Any) -> Cell:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return Cell(f"{value:,}" if isinstance(value, int) else f"{value:g}", sort=value)
    return Cell(_fmt(value))


def _size_cell(size: int | None) -> Cell:
    if size is None:
        return Cell("")
    return Cell(format_size(size), sort=size)


def _make_table(
    table_id: str,
    caption: str,
    columns: list[Column],
    rows: Iterable[list[Cell]],
    empty_text: str = "None",
    max_rows: int | None = None,
    total_rows: int | None = None,
) -> Table:
    """
    Build a table, keeping at most ``MAX_TABLE_ROWS`` rows (but counting all of them).

    If ``total_rows`` is given, ``rows`` are only the rows to show (they're
    still limited), and ``total_rows`` is the total number of rows.
    """
    limit = rc.MAX_TABLE_ROWS if max_rows is None else max_rows
    kept: list[list[Cell]] = []
    total = 0
    for row in rows:
        total += 1
        if len(kept) < limit:
            kept.append(row)
        elif total_rows is not None:
            break
    return Table(
        id=table_id,
        caption=caption,
        columns=columns,
        rows=kept,
        total_rows=max(total, total_rows or 0),
        empty_text=empty_text,
    )


def _json_block(title: str, data: Any) -> Block:
    text = json.dumps(redact_mapping(data), indent=2, default=str, sort_keys=False)
    truncated = len(text) > rc.MAX_JSON_BLOCK
    if truncated:
        text = text[: rc.MAX_JSON_BLOCK]
    return Block(title=title, text=clean_text(text, max_len=0), truncated=truncated)


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _fmt_time(value: datetime | None) -> str:
    if not value:
        return ""
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _join_cmdline(argv: list[str]) -> str:
    if consts.WINDOWS:
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


# --- Intermediate data --------------------------------------------------------


@dataclass
class _LogScan:
    found: bool = False
    counts: Counter = field(default_factory=Counter)
    first: dict | None = None
    last_timestamp: str | None = None
    entries: list[dict] = field(default_factory=list)
    num_warn: int = 0
    malformed: int = 0


@dataclass
class _Device:
    key: str
    record: dict = field(default_factory=dict)
    statuses: set[str] = field(default_factory=set)
    module: str = ""
    results: DeviceResults | None = None

    @property
    def address(self) -> str:
        return str(
            self.record.get("ip") or self.record.get("serial_port") or self.record.get("id") or ""
        )

    @property
    def title(self) -> str:
        r = self.record
        return str(r.get("label") or r.get("name") or r.get("hostname") or r.get("id") or self.key)

    @property
    def has_data(self) -> bool:
        return self.results is not None or bool(set(self.record) - {"id", "ip"})


# --- Builder -----------------------------------------------------------------


#: Same order as :attr:`DeviceData._ID_KEY_ORDER <peat.data.models.DeviceData._ID_KEY_ORDER>`,
#: which :meth:`~peat.data.models.DeviceData.get_id` uses for the device IDs
#: in summaries (e.g. ``pull_devices``).
_DEVICE_ID_KEYS = ("label", "ip", "name", "hostname", "mac", "serial_port", "id", "part_number")


def _device_id(record: dict) -> str | None:
    """
    The ID PEAT used for a device record (the first non-empty value in
    :data:`_DEVICE_ID_KEYS`, like :meth:`~peat.data.models.DeviceData.get_id`).
    """
    for key in _DEVICE_ID_KEYS:
        value = record.get(key)
        if value and isinstance(value, (str, int)):
            return str(value)
    return None


def _record_ids(record: dict) -> set[str]:
    """IDs that refer to a device record: its ``id``, ``ip`` and PEAT device ID."""
    ids = {str(record[k]) for k in ("id", "ip") if record.get(k)}
    dev_id = _device_id(record)
    if dev_id:
        ids.add(dev_id)
    return ids


class _ReportBuilder:
    def __init__(
        self,
        results: RunResults,
        live: LiveRunInfo | None,
        report_path: Path,
        now: datetime,
    ) -> None:
        self.results = results
        self.live = live
        self.report_path = report_path
        self.base_dir = report_path.parent
        self.now = now
        self.problems: list[str] = list(results.load_errors)
        self.conf: dict = results.config_data or {}
        self.state: dict = results.state_data or {}
        self.summaries: dict[str, list[tuple[Path, dict]]] = {}
        self.logs = _LogScan()
        self.devices: list[_Device] = []
        self.anchors: dict[str, str] = {}  # device key -> section anchor
        self.hashed_bytes = 0  # Total size of the files hashed for the report

    # -- Framework --

    def section(self, name: str, func: Callable[[], Any], default: Any = None) -> Any:
        """Build a section, recording a problem instead of failing if it can't be built."""
        try:
            return func()
        except Exception as ex:
            log.warning(f"Report section '{name}' could not be generated: {ex}")
            log.opt(exception=True).debug(f"Traceback for report section '{name}'")
            self.problems.append(f"Section '{name}' could not be generated: {ex}")
            return default

    def href(self, path: Path) -> str:
        return safe_href(path, self.base_dir)

    def summary(self, kind: str) -> dict:
        items = self.summaries.get(kind)
        return items[0][1] if items else {}

    # -- Loading --

    def load_summaries(self) -> None:
        for kind, files in self.results.summary_files().items():
            for f in files:
                data = load_json_file(f)
                if not isinstance(data, dict):
                    self.problems.append(f"Failed to load summary file {f.name}")
                    continue
                self.summaries.setdefault(kind, []).append((f, data))

    def scan_logs(self) -> None:
        f = self.results.json_log_file()
        if not f:
            self.problems.append("The JSON log file (logs/json-log.jsonl) was not found")
            return
        self.logs.found = True
        with f.open(encoding="utf-8", errors="replace") as fp:
            for raw in fp:
                line = raw.strip()
                if not line:
                    continue
                if not line.endswith("}"):
                    self.logs.malformed += 1
                    continue
                match = _LEVEL_RE.search(line)
                level = match.group("level") if match else ""
                ts = _TIMESTAMP_RE.match(line)
                if ts:
                    self.logs.last_timestamp = ts.group("ts")
                if self.logs.first is not None and level not in _WARN_LEVELS:
                    self.logs.counts[level or "UNKNOWN"] += 1
                    continue
                try:
                    record = json.loads(line)
                except (ValueError, RecursionError):
                    self.logs.malformed += 1
                    continue
                if not isinstance(record, dict) or check_data(record):
                    self.logs.malformed += 1
                    continue
                level = str(_get(record, "log.level") or "UNKNOWN")
                self.logs.counts[level] += 1
                if self.logs.first is None:
                    self.logs.first = record
                if level in _WARN_LEVELS:
                    self.logs.num_warn += 1
                    if len(self.logs.entries) < rc.MAX_LOG_ENTRIES:
                        self.logs.entries.append(record)
        if self.logs.malformed:
            self.problems.append(
                f"{self.logs.malformed} malformed line(s) in logs/json-log.jsonl were "
                f"skipped (e.g. if PEAT was interrupted)"
            )

    # -- Devices --

    def collect_devices(self) -> None:
        index: dict[str, _Device] = {}
        # Devices by the ID PEAT used for them (e.g. in "pull_devices"). This is only
        # used to find the targets of failed pulls, since it can be ambiguous (e.g. a name).
        by_device_id: dict[str, _Device] = {}

        def lookup(record: dict, *extra_keys: str) -> _Device:
            keys = [
                str(k)
                for k in (record.get("id"), record.get("ip"), record.get("label"), *extra_keys)
                if k
            ]
            for k in keys:
                if k in index:
                    dev = index[k]
                    break
            else:
                dev = _Device(key=keys[0] if keys else f"unknown-{len(self.devices)}")
                self.devices.append(dev)
            for k in keys:
                index.setdefault(k, dev)
            dev_id = _device_id(record)
            if dev_id:
                by_device_id.setdefault(dev_id, dev)
            for k, v in record.items():
                if v not in (None, "", [], {}):
                    dev.record.setdefault(k, v)
            return dev

        # Richest data first, other sources fill gaps
        for dres in self.results.devices():
            summary = dres.load_summary()
            if summary is None and dres.summary_file:
                self.problems.append(f"Failed to load {dres.dir_name}/{dres.summary_file.name}")
            dev = lookup(summary or {}, dres.dir_name)
            dev.results = dres

        pull = self.summary("pull-summary")
        pulled_ids: set[str] = set()
        for rec in pull.get("pull_results") or []:
            if isinstance(rec, dict):
                dev = lookup(rec)
                dev.statuses.add("pulled")
                pulled_ids.update(_record_ids(rec))

        scan = self.summary("scan-summary")
        for rec in scan.get("hosts_verified") or []:
            if isinstance(rec, dict):
                dev = lookup(rec)
                dev.statuses.add("verified")
                dev.module = dev.module or str(rec.get("peat_module") or "")

        parse = self.summary("parse-summary")
        for item in parse.get("parse_results") or []:
            if isinstance(item, dict) and isinstance(item.get("results"), dict):
                dev = lookup(item["results"])
                dev.statuses.add("parsed")
                dev.module = dev.module or str(item.get("module") or "")

        for host in scan.get("hosts_online") or []:
            if isinstance(host, str):
                lookup({"id": host}).statuses.add("online")

        for target in pull.get("pull_devices") or []:
            if isinstance(target, str) and target not in pulled_ids:
                dev = by_device_id.get(target) or lookup({"id": target})
                dev.statuses.add("pull failed")

        for dev in self.devices:
            dev.module = dev.module or str(dev.record.get("peat_module") or "")
        self.devices.sort(key=lambda d: ip_sort_key(d.address or d.key))
        for dev in self.devices:
            if dev.has_data:
                self.anchors[dev.key] = anchor_id("dev", dev.key)

    # -- Sections --

    def command(self) -> str:
        if self.live and self.live.command:
            return self.live.command
        args = _get(self.logs.first, "process.args")
        if isinstance(args, list) and len(args) > 1 and args[1] in _KNOWN_COMMANDS:
            return str(args[1])
        prefix = self.results.name.split("_", 1)[0]
        if prefix in _KNOWN_COMMANDS:
            return prefix
        for kind in ("pull", "scan", "parse"):
            if f"{kind}-summary" in self.summaries:
                return kind
        return "unknown"

    def argv(self) -> list[str]:
        argv = self.live.argv if self.live else _get(self.logs.first, "process.args")
        if not isinstance(argv, list) or not argv:
            return []
        return redact_argv(["peat", *[str(a) for a in argv[1:]]])

    def times(self) -> tuple[datetime | None, datetime | None]:
        if self.live:
            return self.live.start_time, self.live.end_time
        start = _parse_time(_get(self.logs.first, "process.start"))
        end = _parse_time(self.logs.last_timestamp)
        return start, end

    def run_id(self) -> str | None:
        for items in self.summaries.values():
            for _, data in items:
                if data.get("peat_run_id"):
                    return str(data["peat_run_id"])
        return self.results.run_id

    def peat_version(self) -> str:
        if self.live:
            return self.live.peat_version
        for items in self.summaries.values():
            for _, data in items:
                if data.get("peat_version"):
                    return str(data["peat_version"])
        version = _get(self.logs.first, "peat.version")
        return str(version) if version else "unknown"

    def status(self) -> Badge:
        failed = self.live.error if self.live else bool(self.state.get("ERROR"))
        errors = self.logs.counts["ERROR"] + self.logs.counts["CRITICAL"]
        if failed:
            return Badge("critical", "Failed")
        if errors:
            return Badge("serious", "Completed with errors")
        if self.logs.counts["WARNING"]:
            return Badge("warning", "Completed with warnings")
        return Badge("good", "Succeeded")

    def run_items(self, command: str) -> list[KV]:
        start, end = self.times()
        meta = self.conf.get("METADATA")
        if not isinstance(meta, dict):
            meta = {}
        argv = self.argv()
        items = [
            _kv("Command", command),
            _kv("Command line", _join_cmdline(argv) if argv else "", mono=True),
            _kv("PEAT version", self.peat_version()),
            _kv("Run ID", self.run_id()),
            _kv("Run directory", self.results.path, mono=True, href=self.href(self.results.path)),
            _kv("Started", _fmt_time(start)),
            _kv("Finished", _fmt_time(end)),
        ]
        if start and end:
            items.append(_kv("Duration", utils.fmt_duration(end - start)))
        items.extend(
            _kvs(
                [
                    ("Configuration name", meta.get("name")),
                    ("Configuration description", meta.get("description")),
                    ("Configuration author", meta.get("author")),
                ]
            )
        )
        return [kv for kv in items if kv.value.text]

    def tiles(self) -> list[Tile]:
        scan = self.summary("scan-summary")
        pull = self.summary("pull-summary")
        parse = self.summary("parse-summary")
        tiles = []
        if scan:
            targets = scan.get("scan_targets")
            tiles.append(Tile("Targets", _fmt(len(targets) if isinstance(targets, list) else 0)))
            tiles.append(Tile("Active hosts", _fmt(scan.get("num_hosts_active", 0))))
            tiles.append(Tile("Verified devices", _fmt(scan.get("num_hosts_verified", 0))))
        if pull:
            attempted = len(pull.get("pull_devices") or [])
            pulled = int(pull.get("num_pull_results") or 0)
            badge = (
                Badge("serious", f"{attempted - pulled} failed") if attempted > pulled else None
            )
            tiles.append(Tile("Pulled devices", f"{pulled} of {attempted}", badge))
        if parse:
            failures = int(parse.get("num_parse_failures") or 0)
            badge = Badge("serious", f"{failures} failed") if failures else None
            tiles.append(Tile("Files parsed", _fmt(parse.get("num_files_parsed", 0)), badge))
        tiles.append(Tile("Devices with data", _fmt(sum(1 for d in self.devices if d.has_data))))
        warnings = self.logs.counts["WARNING"]
        errors = self.logs.counts["ERROR"] + self.logs.counts["CRITICAL"]
        tiles.append(
            Tile("Warnings", _fmt(warnings), Badge("warning", "Review") if warnings else None)
        )
        tiles.append(Tile("Errors", _fmt(errors), Badge("critical", "Review") if errors else None))
        return tiles

    def operations(self) -> list[OperationSection]:
        sections = []
        renderers = {
            "scan-summary": ("Scan", self._scan_op),
            "pull-summary": ("Pull", self._pull_op),
            "parse-summary": ("Parse", self._parse_op),
        }
        order = ["scan-summary", "pull-summary", "push-summary", "parse-summary"]
        kinds = sorted(self.summaries, key=lambda k: (order.index(k) if k in order else 99, k))
        for kind in kinds:
            items = self.summaries[kind]
            title, renderer = renderers.get(kind, (kind.replace("-", " ").capitalize(), None))
            for i, (path, data) in enumerate(items):
                op_title = title if i == 0 else f"{title} ({i + 1})"
                op = OperationSection(anchor=anchor_id("op", f"{kind}-{i}"), title=op_title)
                if renderer:
                    renderer(op, data)
                else:
                    self._generic_op(op, data)
                op.items.append(_kv("Summary file", path.name, mono=True, href=self.href(path)))
                sections.append(op)
        return sections

    @staticmethod
    def _duration(data: dict, key: str) -> str:
        value = data.get(key)
        return utils.fmt_duration(value) if isinstance(value, (int, float)) else ""

    @staticmethod
    def _list_preview(values: Any, limit: int = 20) -> str:
        if not isinstance(values, list):
            return _fmt(values)
        shown = ", ".join(_fmt(v) for v in values[:limit])
        more = f" (and {len(values) - limit} more)" if len(values) > limit else ""
        return f"{shown}{more}"

    def _scan_op(self, op: OperationSection, data: dict) -> None:
        targets = data.get("scan_targets")
        if not isinstance(targets, list):
            targets = []
        active = data.get("num_hosts_active")
        inactive = len(targets) - active if isinstance(active, int) and targets else None
        op.items.extend(
            _kvs(
                [
                    ("Duration", self._duration(data, "scan_duration")),
                    ("Scan type", data.get("scan_type")),
                    ("Modules", self._list_preview(data.get("scan_modules"))),
                    ("Targets (as given)", self._list_preview(data.get("scan_original_targets"))),
                    ("Targets (resolved)", len(targets)),
                    ("Active hosts", active),
                    ("Inactive targets", inactive),
                    ("Online hosts", data.get("num_hosts_online")),
                    ("Verified devices", data.get("num_hosts_verified")),
                ]
            )
        )

    def _pull_op(self, op: OperationSection, data: dict) -> None:
        attempted = data.get("pull_devices") or []
        pulled = {
            i
            for r in data.get("pull_results") or []
            if isinstance(r, dict)
            for i in _record_ids(r)
        }
        failed = [t for t in attempted if isinstance(t, str) and t not in pulled]
        op.items.extend(
            _kvs(
                [
                    ("Duration", self._duration(data, "pull_duration")),
                    ("Communication type", data.get("pull_comm_type")),
                    ("Modules", self._list_preview(data.get("pull_modules"))),
                    ("Targets (as given)", self._list_preview(data.get("pull_original_targets"))),
                    ("Devices attempted", len(attempted) if isinstance(attempted, list) else ""),
                    ("Devices pulled", data.get("num_pull_results")),
                    ("Failed pulls", self._list_preview(failed)),
                ]
            )
        )

    def _parse_op(self, op: OperationSection, data: dict) -> None:
        op.items.extend(
            _kvs(
                [
                    ("Duration", self._duration(data, "parse_duration")),
                    ("Modules", self._list_preview(data.get("parse_modules"))),
                    ("Input paths", self._list_preview(data.get("input_paths"))),
                    ("Files parsed", data.get("num_files_parsed")),
                    ("Successes", data.get("num_parse_successes")),
                    ("Failures", data.get("num_parse_failures")),
                ]
            )
        )
        cols = [Column("File"), Column("Path"), Column("Module")]

        def rows(items: Any, with_device: bool) -> Iterable[list[Cell]]:
            for item in items if isinstance(items, list) else []:
                if not isinstance(item, dict):
                    continue
                row = [
                    Cell(item.get("name")),
                    Cell(item.get("path"), mono=True),
                    Cell(item.get("module")),
                ]
                if with_device:
                    res = item.get("results")
                    if not isinstance(res, dict):
                        res = {}
                    key = str(res.get("id") or res.get("ip") or "")
                    anchor = self.anchors.get(key)
                    row.append(Cell(key, href=f"#{anchor}" if anchor else None))
                yield row

        op.tables.append(
            _make_table(
                f"{op.anchor}-results",
                "Parsed files",
                [*cols, Column("Device")],
                rows(data.get("parse_results"), True),
            )
        )
        if data.get("parse_failures"):
            op.tables.append(
                _make_table(
                    f"{op.anchor}-failures",
                    "Files that failed to parse",
                    cols,
                    rows(data.get("parse_failures"), False),
                )
            )

    def _generic_op(self, op: OperationSection, data: dict) -> None:
        # Redact the whole summary, so values of secret-like keys are redacted
        redacted = redact_mapping(data)
        for key, value in list(redacted.items())[:50]:
            label = str(key).replace("_", " ").capitalize()
            if isinstance(value, (list, dict)):
                op.items.append(_kv(label, f"{len(value)} item(s)"))
            else:
                op.items.append(_kv(label, value))
        op.blocks.append(_json_block("Full summary", data))

    def hosts_table(self) -> Table:
        cols = [
            Column("Device"),
            Column("Address"),
            Column("MAC"),
            Column("Name"),
            Column("Vendor"),
            Column("Model"),
            Column("Type"),
            Column("Firmware"),
            Column("PEAT module"),
            Column("Status"),
        ]

        def rows() -> Iterable[list[Cell]]:
            for dev in self.devices:
                r = dev.record
                anchor = self.anchors.get(dev.key)
                yield [
                    Cell(dev.title, href=f"#{anchor}" if anchor else None),
                    Cell(dev.address, sort=ip_sort_key(dev.address), mono=True),
                    Cell(r.get("mac"), mono=True),
                    Cell(r.get("name") or r.get("hostname")),
                    Cell(_get(r, "description.vendor.name") or _get(r, "description.vendor.id")),
                    Cell(_get(r, "description.model") or _get(r, "description.product")),
                    Cell(r.get("type")),
                    Cell(_get(r, "firmware.version")),
                    Cell(dev.module),
                    Cell(badges=self._device_badges(dev)),
                ]

        return _make_table(
            "hosts-table",
            "Hosts and devices found or processed in this run",
            cols,
            rows(),
            empty_text="No hosts or devices",
        )

    @staticmethod
    def _device_badges(dev: _Device) -> list[Badge]:
        order = ["pulled", "parsed", "verified", "online", "pull failed"]
        return [Badge(_STATUS_BADGES[s], s) for s in order if s in dev.statuses]

    def device_sections(self) -> list[DeviceSection]:
        with_data = [d for d in self.devices if d.has_data]
        expand = len(with_data) <= rc.MAX_OPEN_DEVICES
        sections: list[DeviceSection] = []
        for dev in with_data:

            def build(dev: _Device = dev) -> DeviceSection:
                return self._device_section(dev, expand)

            sections.append(
                self.section(
                    f"device {dev.title}",
                    build,
                    DeviceSection(
                        anchor=self.anchors[dev.key],
                        title=clean_text(dev.title, max_len=200),
                        subtitle="",
                        badges=[Badge("critical", "Error building section")],
                        open=expand,
                    ),
                )
            )
        return sections

    def _device_section(self, dev: _Device, expand: bool) -> DeviceSection:
        r = dev.record
        anchor = self.anchors[dev.key]
        vendor = _get(r, "description.vendor.name") or _get(r, "description.vendor.id")
        model = _get(r, "description.model") or _get(r, "description.product")
        subtitle = " | ".join(_fmt(v) for v in (dev.address, vendor, model, r.get("type")) if v)
        section = DeviceSection(
            anchor=anchor,
            title=clean_text(dev.title, max_len=200),
            subtitle=clean_text(subtitle, max_len=300),
            badges=self._device_badges(dev),
            open=expand,
        )
        mac = r.get("mac")
        if mac and r.get("mac_vendor"):
            mac = f"{mac} ({r['mac_vendor']})"
        section.identity = _kvs(
            [
                ("ID", r.get("id")),
                ("Label", r.get("label")),
                ("Name", r.get("name")),
                ("Hostname", r.get("hostname")),
                ("IP address", r.get("ip")),
                ("MAC address", mac),
                ("Serial port", r.get("serial_port")),
                ("Type", r.get("type")),
                ("Vendor", vendor),
                ("Brand", _get(r, "description.brand")),
                ("Product", _get(r, "description.product")),
                ("Model", _get(r, "description.model")),
                ("Description", _get(r, "description.full")),
                ("Part number", r.get("part_number")),
                ("Serial number", r.get("serial_number")),
                ("Firmware version", _get(r, "firmware.version")),
                ("Firmware revision", _get(r, "firmware.revision")),
                ("Firmware release date", _get(r, "firmware.release_date")),
                ("Boot firmware version", _get(r, "boot_firmware.version")),
                ("OS", _get(r, "os.full") or _get(r, "os.name")),
                ("OS version", _get(r, "os.version")),
                ("Architecture", r.get("architecture")),
                ("Run mode", r.get("run_mode")),
                ("Status", r.get("status")),
                ("Uptime", r.get("uptime")),
                ("Start time", r.get("start_time")),
                ("Timezone", _get(r, "geo.timezone")),
                ("Logic name", _get(r, "logic.name")),
                ("Logic author", _get(r, "logic.author")),
                ("Logic last updated", _get(r, "logic.last_updated")),
                ("PEAT module", dev.module),
                ("Comment", r.get("comment")),
            ]
        )

        dres = dev.results
        counts = []
        names = ("event", "registers", "tag", "io", "memory", "files", "users", "ssh_keys")
        for name in names:
            if dres and name in dres.jsonl_files():
                count = dres.count_jsonl(name)
            else:
                count = len(r.get(name) or []) if isinstance(r.get(name), list) else 0
            if count:
                counts.append(_kv(name.replace("_", " ").capitalize(), f"{count:,}"))
        if dres and "event" in dres.jsonl_files():
            counts.extend(self._event_summary(dres))
        section.counts = counts

        section.tables = [t for t in self._device_tables(dev, anchor) if t.total_rows]
        if isinstance(r.get("extra"), dict) and r["extra"]:
            section.blocks.append(_json_block("Extra data reported for the device", r["extra"]))

        if dres:
            for label, f in (
                ("Device data summary", dres.summary_file),
                ("Full device data", dres.full_file),
            ):
                if f:
                    section.links.append(Cell(label, href=self.href(f)))
            section.links.append(Cell("Device directory", href=self.href(dres.path)))
        return section

    @staticmethod
    def _event_summary(dres: DeviceResults) -> list[KV]:
        earliest = latest = None
        datasets: Counter = Counter()
        for i, event in enumerate(dres.iter_jsonl("event")):
            if i >= _MAX_EVENT_SCAN:
                break
            created = _parse_time(event.get("created"))
            if created:
                earliest = created if earliest is None or created < earliest else earliest
                latest = created if latest is None or created > latest else latest
            if event.get("dataset"):
                datasets[str(event["dataset"])] += 1
        top = ", ".join(f"{name} ({count:,})" for name, count in datasets.most_common(5))
        return _kvs(
            [
                ("Earliest event", _fmt_time(earliest)),
                ("Latest event", _fmt_time(latest)),
                ("Top event datasets", top),
            ]
        )

    def _device_tables(self, dev: _Device, anchor: str) -> list[Table]:
        r = dev.record
        dres = dev.results

        def records(name: str) -> list[dict]:
            values = r.get(name)
            return [v for v in values if isinstance(v, dict)] if isinstance(values, list) else []

        tables = [
            _make_table(
                f"{anchor}-interfaces",
                "Network interfaces",
                [
                    Column("Type"),
                    Column("Name"),
                    Column("IP"),
                    Column("MAC"),
                    Column("Subnet mask"),
                    Column("Gateway"),
                    Column("Enabled"),
                    Column("Services", numeric=True),
                ],
                (
                    [
                        Cell(i.get("type")),
                        Cell(i.get("name")),
                        Cell(i.get("ip"), sort=ip_sort_key(i.get("ip") or ""), mono=True),
                        Cell(i.get("mac"), mono=True),
                        Cell(i.get("subnet_mask"), mono=True),
                        Cell(i.get("gateway"), mono=True),
                        Cell(_fmt(i.get("enabled"))),
                        _num_cell(len(i.get("services") or [])),
                    ]
                    for i in records("interface")
                ),
            ),
            _make_table(
                f"{anchor}-services",
                "Services",
                [
                    Column("Port", numeric=True),
                    Column("Transport"),
                    Column("Protocol"),
                    Column("Status"),
                    Column("Enabled"),
                ],
                (
                    [
                        _num_cell(s.get("port")),
                        Cell(s.get("transport")),
                        Cell(s.get("protocol")),
                        Cell(s.get("status")),
                        Cell(_fmt(s.get("enabled"))),
                    ]
                    for s in records("service")
                ),
            ),
            _make_table(
                f"{anchor}-modules",
                "Modules (e.g. I/O cards)",
                [
                    Column("Slot"),
                    Column("Type"),
                    Column("Model"),
                    Column("Serial number"),
                    Column("Firmware"),
                ],
                (
                    [
                        Cell(m.get("slot")),
                        Cell(m.get("type")),
                        Cell(_get(m, "description.model") or _get(m, "description.product")),
                        Cell(m.get("serial_number")),
                        Cell(_get(m, "firmware.version")),
                    ]
                    for m in records("module")
                ),
            ),
        ]

        users = list(dres.iter_jsonl("users")) if dres and "users" in dres.jsonl_files() else []
        tables.append(
            _make_table(
                f"{anchor}-users",
                "Users",
                [Column("Name"), Column("Full name"), Column("Roles"), Column("Permissions")],
                (
                    [
                        Cell(u.get("name") or u.get("id")),
                        Cell(u.get("full_name")),
                        Cell(_fmt(u.get("roles"))),
                        Cell(_fmt(u.get("permissions"))),
                    ]
                    for u in (users or records("users"))
                ),
            )
        )

        # Files reported by the device (File models), with hashes
        files = list(dres.iter_jsonl("files")) if dres and "files" in dres.jsonl_files() else []
        files = files or records("files")
        tables.append(
            _make_table(
                f"{anchor}-files",
                "Files reported by the device",
                [
                    Column("Path"),
                    Column("Size", numeric=True),
                    Column("Modified"),
                    Column("SHA-256 (or MD5)"),
                ],
                (
                    [
                        Cell(f.get("path") or f.get("name"), mono=True),
                        _num_cell(f.get("size")),
                        Cell(f.get("mtime")),
                        Cell(_get(f, "hash.sha256") or _get(f, "hash.md5"), mono=True),
                    ]
                    for f in files
                ),
            )
        )

        if dres:
            artifacts = dres.artifact_files()
            tables.append(
                _make_table(
                    f"{anchor}-artifacts",
                    "Files saved by PEAT for this device",
                    [Column("File"), Column("Size", numeric=True), Column("SHA-256")],
                    # Only the files that are shown are hashed
                    self._artifact_rows(dres, artifacts[: rc.MAX_TABLE_ROWS]),
                    total_rows=len(artifacts),
                )
            )
        return tables

    def _artifact_rows(self, dres: DeviceResults, files: list[Path]) -> Iterable[list[Cell]]:
        """
        Rows for files saved by PEAT. The hashes are always calculated from the
        files (never taken from the run's data), within the size limits.
        """
        for f in files:
            rel = f.relative_to(dres.path).as_posix()
            try:
                size: int | None = f.stat().st_size
            except OSError:
                size = None
            if size is None:
                sha256 = "not computed (unreadable)"
            elif size > rc.ARTIFACT_HASH_MAX_BYTES:
                sha256 = f"not computed (larger than {utils.fmt_size(rc.ARTIFACT_HASH_MAX_BYTES)})"
            elif self.hashed_bytes + size > rc.ARTIFACT_HASH_TOTAL_MAX_BYTES:
                limit = utils.fmt_size(rc.ARTIFACT_HASH_TOTAL_MAX_BYTES)
                sha256 = (
                    f"not computed (the report's limit of {limit} of hashed files was reached)"
                )
            else:
                self.hashed_bytes += size
                try:
                    sha256 = utils.calc_hash(f, "sha256")
                except OSError as ex:
                    sha256 = f"not computed ({ex.strerror or ex})"
            yield [
                Cell(rel, href=self.href(f), mono=True),
                _size_cell(size),
                Cell(sha256, mono=True),
            ]

    def modules_table(self) -> Table:
        names: Counter = Counter()
        used: set[str] = set()
        for kind in ("scan-summary", "pull-summary", "parse-summary"):
            mods = self.summary(kind).get(kind.split("-")[0] + "_modules")
            if isinstance(mods, list):
                used.update(str(m) for m in mods)
        for dev in self.devices:
            if dev.module:
                names[dev.module] += 1
        used.update(names)

        def rows() -> Iterable[list[Cell]]:
            from peat import module_api

            for name in sorted(used):
                try:
                    mod = module_api.get_module(name)
                except Exception:
                    mod = None
                yield [
                    Cell(name),
                    Cell(getattr(mod, "vendor_name", "") if mod else ""),
                    Cell(getattr(mod, "device_type", "") if mod else ""),
                    _num_cell(names.get(name, 0)),
                ]

        return _make_table(
            "modules-table",
            "PEAT device modules used in this run",
            [
                Column("Module"),
                Column("Vendor"),
                Column("Device type"),
                Column("Devices", numeric=True),
            ],
            rows(),
            empty_text="No module information was found",
        )

    def logs_section(self) -> tuple[list[KV], Table]:
        counts = self.logs.counts
        items = []
        f = self.results.json_log_file()
        if f:
            items.append(_kv("JSON log", f.name, mono=True, href=self.href(f)))
        logs_dir = self.results.dirs.get("logs")
        if logs_dir and (logs_dir / "peat.log").is_file():
            items.append(
                _kv("Text log", "peat.log", mono=True, href=self.href(logs_dir / "peat.log"))
            )
        items.extend(
            _kvs(
                [
                    ("Warnings", counts["WARNING"] if self.logs.found else None),
                    ("Errors", counts["ERROR"] if self.logs.found else None),
                    ("Critical errors", counts["CRITICAL"]),
                    ("Total log messages", sum(counts.values()) if self.logs.found else None),
                ]
            )
        )

        def rows() -> Iterable[list[Cell]]:
            kinds = {"WARNING": "warning", "ERROR": "serious", "CRITICAL": "critical"}
            for rec in self.logs.entries:
                level = str(_get(rec, "log.level") or "")
                message = _get(rec, "event.original") or rec.get("message") or ""
                err_type, err_msg = _get(rec, "error.type"), _get(rec, "error.message")
                error = (
                    f"{err_type or ''}: {err_msg or ''}".strip(": ") if err_type or err_msg else ""
                )
                ts = _parse_time(rec.get("@timestamp"))
                yield [
                    Cell(_fmt_time(ts) if ts else rec.get("@timestamp"), mono=True),
                    Cell(badges=[Badge(kinds.get(level, "neutral"), level.lower() or "unknown")]),
                    Cell(_get(rec, "log.logger"), mono=True),
                    Cell(redact_url_credentials(str(message))),
                    Cell(redact_url_credentials(error)),
                ]

        table = _make_table(
            "logs-table",
            "Warning and error messages",
            [
                Column("Time"),
                Column("Level"),
                Column("Logger"),
                Column("Message"),
                Column("Error"),
            ],
            rows(),
            empty_text="No warnings or errors were logged",
            max_rows=rc.MAX_LOG_ENTRIES,
        )
        table.total_rows = max(table.total_rows, self.logs.num_warn)
        return items, table

    def files_tables(self) -> tuple[Table, Table, Table]:
        totals = {"count": 0, "size": 0}

        def rows() -> Iterable[list[Cell]]:
            for f in self.results.iter_files():
                if f == self.report_path:
                    continue
                try:
                    size = f.stat().st_size
                except OSError:
                    size = None
                totals["count"] += 1
                totals["size"] += size or 0
                rel = f.relative_to(self.results.path)
                folder = rel.parts[0] if len(rel.parts) > 1 else ""
                yield [
                    Cell(rel.as_posix(), href=self.href(f), mono=True),
                    _size_cell(size),
                    Cell(folder),
                ]
            if self.live:
                for f in self.live.pending_files:
                    if not f.exists():
                        yield [
                            Cell(self._rel(f), mono=True),
                            Cell("(written when PEAT exits)"),
                            Cell(f.parent.name),
                        ]

        files = _make_table(
            "files-table",
            "Files in the run directory",
            [Column("File"), Column("Size", numeric=True), Column("Folder")],
            rows(),
            empty_text="No files were found",
        )
        files.caption += f" ({totals['count']:,} files, {utils.fmt_size(totals['size'])})"

        # Paths are shown as recorded. The run directory may have been moved, or the
        # run may have been on another OS: on Windows, "/x" isn't absolute (see is_anchored)
        written = self.state.get("WRITTEN_FILES")
        outside = set()
        for item in written if isinstance(written, list) else []:
            text = str(item)
            if is_anchored(text) and self.results.map_saved_path(text) is None:
                outside.add(text)

        outside_table = _make_table(
            "outside-files-table",
            "Files written outside the run directory",
            [Column("File")],
            ([Cell(p, mono=True)] for p in sorted(outside)),
            empty_text="None",
        )

        def elastic_rows() -> Iterable[list[Cell]]:
            for index, paths in self.results.elastic_doc_files().items():
                docs = 0
                for p in paths:
                    try:
                        with p.open("rb") as fp:
                            docs += sum(1 for line in fp if line.strip())
                    except OSError as ex:
                        self.problems.append(f"Failed to read {self._rel(p)}: {ex}")
                yield [
                    Cell(index, mono=True),
                    _num_cell(docs),
                    Cell(", ".join(self._rel(p) for p in paths), mono=True),
                ]

        elastic = _make_table(
            "elastic-table",
            "Documents exported to Elasticsearch/OpenSearch (local copies)",
            [Column("Index"), Column("Documents", numeric=True), Column("Files")],
            elastic_rows(),
            empty_text="No Elasticsearch or OpenSearch exports in this run",
        )
        return files, outside_table, elastic

    def _rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.results.path).as_posix()
        except ValueError:
            return str(path)

    def config_section(self) -> tuple[list[KV], Table, Table]:
        conf = self.conf
        highlights = [
            "DEBUG",
            "VERBOSE",
            "DRY_RUN",
            "ASSUME_ONLINE",
            "INTENSIVE_SCAN",
            "PULL_SKIP_SCAN",
            "PUSH_SKIP_SCAN",
            "DEFAULT_TIMEOUT",
            "MAX_THREADS",
            "RESOLVE_HOSTNAME",
            "RESOLVE_IP",
            "RESOLVE_MAC",
            "HASH_ALGORITHMS",
            "ELASTIC_SERVER",
            "ADDITIONAL_MODULES",
            "HTML_REPORT",
        ]
        items = []
        for key in highlights:
            if key in conf:
                value = redact_mapping(conf[key])
                items.append(_kv(key.lower(), _fmt(value) if _fmt(value) != "" else "(not set)"))
        meta_dir = self.results.dirs.get("meta")
        if meta_dir and meta_dir.is_dir():
            for f in sorted(meta_dir.iterdir()):
                if f.is_file() and not f.is_symlink():
                    label = "Saved configuration" if f.name.startswith("peat_") else "Config file"
                    items.append(_kv(label, f.name, mono=True, href=self.href(f)))

        from peat.settings import Configuration

        # Same env_prefix as peat.settings.config, but without loading the environment
        defaults = Configuration("report-defaults", env_prefix="PEAT_", init_env=False).export()
        skip = {"METADATA", "OUT_DIR", "RUN_DIR", "ZEEK_DIR", "ZEEK_LOGDIR", "DEVICE_OPTIONS"}

        def rows() -> Iterable[list[Cell]]:
            for key, value in sorted(conf.items()):
                if key in skip or key.endswith("_DIR") or key == "HOSTS":
                    continue
                if key in defaults and defaults[key] == value:
                    continue
                yield [
                    Cell(key.lower(), mono=True),
                    Cell(_fmt(redact_mapping({key: value})[key]), mono=True),
                ]

        table = _make_table(
            "config-table",
            "Settings that differ from the defaults (secrets redacted)",
            [Column("Setting"), Column("Value")],
            rows(),
            empty_text="All settings are the defaults",
        )
        hosts = hosts_overview(conf.get("HOSTS"))
        hosts_table = _make_table(
            "config-hosts-table",
            "Hosts in the configuration (host options are not shown)",
            [Column("Label"), Column("Identifiers"), Column("PEAT module"), Column("Comment")],
            (
                [
                    Cell(h["label"]),
                    Cell(h["identifiers"], mono=True),
                    Cell(h["peat_module"]),
                    Cell(h["comment"]),
                ]
                for h in hosts
            ),
            empty_text="No hosts in the configuration",
        )
        device_options = conf.get("DEVICE_OPTIONS")
        if isinstance(device_options, dict) and device_options:
            summary = redact_mapping({"DEVICE_OPTIONS": device_options})["DEVICE_OPTIONS"]
            items.append(_kv("device_options", summary))
        return items, table, hosts_table

    def environment_section(self) -> tuple[list[KV], Table]:
        st = self.state
        if self.live:
            info = self.live.sysinfo
            items = _kvs(
                [
                    ("Hostname", info.get("hostname")),
                    ("User", info.get("username")),
                    ("Operating system", info.get("os_full")),
                    (
                        "Python",
                        f"{info.get('python_version', '')} ({info.get('python_impl', '')})",
                    ),
                    ("Timezone", info.get("timezone")),
                    ("Containerized", info.get("containerized")),
                    ("Podman", info.get("podman")),
                ]
            )
        else:
            first = self.logs.first or {}
            items = _kvs(
                [
                    ("Hostname", _get(first, "observer.hostname")),
                    ("User", _get(first, "observer.user.name")),
                    ("Operating system", _get(first, "observer.os.full")),
                    ("Python", _get(first, "peat.python_version")),
                    ("Timezone", _get(first, "observer.geo.timezone")),
                    ("Containerized", _get(first, "peat.containerized")),
                    ("Podman", _get(first, "peat.podman")),
                ]
            )
        items.extend(
            _kvs(
                [
                    ("Raw socket capable", st.get("RAW_SOCKET_CAPABLE")),
                    ("Superuser/Administrator", st.get("SUPERUSER_PRIVS")),
                    ("Default interface", st.get("DEFAULT_INTERFACE_NAME")),
                    ("Default interface IP", st.get("DEFAULT_INTERFACE_IP")),
                    ("Default gateway", st.get("DEFAULT_GATEWAY")),
                ]
            )
        )

        def rows() -> Iterable[list[Cell]]:
            details = st.get("LOCAL_INTERFACE_DETAILS")
            for name, iface in sorted(details.items()) if isinstance(details, dict) else []:
                iface = iface if isinstance(iface, dict) else {}
                inet = iface.get("af_inet")
                link = iface.get("af_link")
                addrs = [a for a in inet if isinstance(a, dict)] if isinstance(inet, list) else []
                macs = (
                    [a.get("addr") for a in link if isinstance(a, dict) and a.get("addr")]
                    if isinstance(link, list)
                    else []
                )
                yield [
                    Cell(name, mono=True),
                    Cell(", ".join(str(a.get("addr", "")) for a in addrs), mono=True),
                    Cell(", ".join(str(a.get("netmask", "")) for a in addrs), mono=True),
                    Cell(", ".join(str(m) for m in macs), mono=True),
                ]

        table = _make_table(
            "interfaces-table",
            "Network interfaces of the system running PEAT",
            [Column("Interface"), Column("IPv4 address"), Column("Netmask"), Column("MAC")],
            rows(),
            empty_text="No interface information was recorded",
        )
        return items, table

    # -- Assemble --

    def build(self) -> ReportContext:
        self.section("summaries", self.load_summaries)
        self.section("logs", self.scan_logs)
        self.section("devices", self.collect_devices)

        command = self.section("command", self.command, "unknown")
        ctx = ReportContext(
            title=clean_text(f"PEAT {command} report: {self.results.name}", max_len=300),
            run_name=clean_text(self.results.name, max_len=300),
            command=clean_text(command, max_len=50),
            generated_at=_fmt_time(self.now),
            generator_version=clean_text(__version__),
            mode="live" if self.live else "regenerated",
            status=self.section("status", self.status, Badge("neutral", "Unknown")),
        )
        if self.conf.get("DRY_RUN"):
            ctx.extra_badges.append(Badge("info", "Dry run"))
        ctx.run_items = self.section("overview", lambda: self.run_items(command), [])
        ctx.tiles = self.section("tiles", self.tiles, [])
        ctx.operations = self.section("operations", self.operations, [])
        ctx.hosts_table = self.section("hosts", self.hosts_table, ctx.hosts_table)
        ctx.devices = self.section("device details", self.device_sections, [])
        ctx.modules_table = self.section("modules", self.modules_table, ctx.modules_table)
        ctx.logs_items, ctx.logs_table = self.section(
            "warnings and errors", self.logs_section, ([], ctx.logs_table)
        )
        ctx.files_table, ctx.outside_files_table, ctx.elastic_table = self.section(
            "files",
            self.files_tables,
            (ctx.files_table, ctx.outside_files_table, ctx.elastic_table),
        )
        ctx.config_items, ctx.config_table, ctx.config_hosts_table = self.section(
            "configuration",
            self.config_section,
            ([], ctx.config_table, ctx.config_hosts_table),
        )
        ctx.environment_items, ctx.interfaces_table = self.section(
            "environment", self.environment_section, ([], ctx.interfaces_table)
        )
        ctx.toc = [
            ("overview", "Overview"),
            ("operations", "Operations"),
            ("hosts", "Hosts"),
            ("devices", "Device details"),
            ("modules", "Modules"),
            ("logs", "Warnings and errors"),
            ("files", "Files"),
            ("config", "Configuration"),
            ("environment", "Environment"),
        ]
        if self.problems:
            ctx.toc.insert(0, ("problems", "Problems"))
        ctx.problems = [clean_text(p, max_len=1000) for p in self.problems]
        return ctx


def build_report_context(
    results: RunResults,
    live: LiveRunInfo | None = None,
    *,
    report_path: Path | None = None,
    now: datetime | None = None,
) -> ReportContext:
    """
    Build the report's view model from the contents of a run directory.

    A section that can't be built (e.g. due to unexpected content) is left out,
    and the problem is listed in :attr:`ReportContext.problems` instead of failing.

    Args:
        results: The run directory to report on
        live: Information about the current run, if the report is for the
            run that is currently finishing (:obj:`None` if regenerating)
        report_path: Where the report will be written (links are relative to it).
            Defaults to ``peat-report.html`` in the run directory.
        now: Time the report was generated (defaults to the current time)
    """
    report_path = Path(report_path) if report_path else results.path / rc.REPORT_FILENAME
    builder = _ReportBuilder(results, live, report_path.resolve(), now or utils.utc_now())
    return builder.build()


__all__ = [
    "KV",
    "Badge",
    "Block",
    "Cell",
    "Column",
    "DeviceSection",
    "LiveRunInfo",
    "OperationSection",
    "ReportContext",
    "Table",
    "Tile",
    "build_report_context",
]
