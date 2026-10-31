"""
Read-only access to the contents of a PEAT run directory (``RUN_DIR``) after a run.

A run directory is the per-run folder PEAT creates inside ``OUT_DIR``
(e.g. ``./peat_results/pull_default-config_<timestamp>_<run_id>/``), containing
the ``devices/``, ``summaries/``, ``logs/`` and ``peat_metadata/`` sub-directories.

This module is used by ``peat report`` (the HTML report) and is intended to be
reused by anything else that needs to read the results of a previous run.
It never writes anything, and it is tolerant of partial, old, or hand-made
run directories: missing or malformed content results in :obj:`None` or empty
values (with a logged warning), never an exception. The only exception raised
is :class:`~peat.consts.PeatError` from :meth:`RunResults.open` if the path
isn't a directory.

.. warning::
   The contents of a run directory are untrusted input (they may contain
   data reported by devices, or the directory may have come from another
   system). Because of that:

   - YAML files are loaded *without* PEAT's custom ``!ENV``/``!JOIN`` tags,
     so environment variables on the analyst's system are never expanded.
   - Nothing outside the run directory is read: sub-directories that are
     symlinks to (or configured as) paths outside of it are ignored, file
     symlinks are skipped and directory symlinks aren't followed when
     listing files.
   - Decoded JSON and YAML data that is nested deeper than
     :data:`MAX_DATA_DEPTH`, or YAML that expands to more than
     :data:`MAX_YAML_NODES` values (e.g. "billion laughs" aliases),
     is rejected like a malformed file.

Usage:

.. code-block:: python

   from peat.run_results import RunResults, find_run_dirs

   for run_dir in find_run_dirs(["./peat_results/"]):
       results = RunResults.open(run_dir)
       print(results.name, results.run_id, len(results.devices()))
       scan_summary = results.load_summary("scan-summary")
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml
from loguru import logger as log

from .consts import PeatError

#: Default sub-directory names, relative to the run directory
#: (the basenames of the ``Configuration.*_DIR`` settings).
DEFAULT_SUBDIRS: dict[str, str] = {
    "devices": "devices",
    "summaries": "summaries",
    "logs": "logs",
    "meta": "peat_metadata",
    "elastic": "elastic_data",
    "heat_artifacts": "heat_artifacts",
    "temp": "temp",
}

#: Configuration keys of the sub-directories, used as a fallback lookup
#: in the saved configuration if a default sub-directory doesn't exist.
_CONFIG_DIR_KEYS: dict[str, str] = {
    "devices": "DEVICE_DIR",
    "summaries": "SUMMARIES_DIR",
    "logs": "LOG_DIR",
    "meta": "META_DIR",
    "elastic": "ELASTIC_DIR",
    "heat_artifacts": "HEAT_ARTIFACTS_DIR",
    "temp": "TEMP_DIR",
}

_RUN_DIR_MARKERS = ("peat_metadata", "summaries", "devices")

#: Maximum nesting depth of decoded JSON/YAML data. Deeper data is rejected,
#: since it can exhaust the stack of code that processes it recursively.
MAX_DATA_DEPTH = 64

#: Maximum number of values (including dictionary keys) in decoded YAML data,
#: counting values shared via anchors and aliases each time they're used.
#: Larger data is rejected ("billion laughs" protection).
MAX_YAML_NODES = 1_000_000

#: Prefix of the data files written by
#: :meth:`~peat.data.models.DeviceData.export_to_files`.
DEVICE_DATA_PREFIX = "device-data-"

JSON_LOG_FILENAME = "json-log.jsonl"

# Summary files: "scan-summary.json", or a duplicate written by
# utils.write_file(), e.g. "scan-summary.json.1"
_SUMMARY_RE = re.compile(r"^(?P<kind>.+)\.json(?:\.(?P<index>\d+))?$")
_RUN_ID_RE = re.compile(r"_(?P<run_id>\d{12})$")


class _PlainSafeLoader(yaml.SafeLoader):
    """
    :class:`yaml.SafeLoader` without PEAT's custom ``!ENV`` and ``!JOIN`` tags.

    :mod:`peat.settings_manager` registers those tags globally on
    :class:`yaml.SafeLoader`. Run directories may come from elsewhere, and
    the environment of the system reading them must never be expanded into
    the loaded data (or a report).
    """


_PlainSafeLoader.yaml_constructors = {
    k: v for k, v in yaml.SafeLoader.yaml_constructors.items() if k not in ("!ENV", "!JOIN")
}


def check_data(data: Any, max_nodes: int | None = None) -> str | None:
    """
    Check the nesting depth (:data:`MAX_DATA_DEPTH`) and, optionally, the number
    of values of decoded JSON/YAML data, without recursion.

    Args:
        data: The decoded data
        max_nodes: Maximum number of values (:obj:`None` for no limit)

    Returns:
        Why the data is rejected, or :obj:`None` if it's acceptable

    >>> check_data({"a": [1, 2]}) is None
    True
    >>> check_data([1, 2, 3], max_nodes=3)
    'more than 3 values'
    """
    stack: list[tuple[Any, int]] = [(data, 1)]
    nodes = 0
    while stack:
        obj, depth = stack.pop()
        nodes += 1
        if max_nodes is not None and nodes > max_nodes:
            return f"more than {max_nodes:,} values"
        if isinstance(obj, (dict, list)):
            if depth > MAX_DATA_DEPTH:
                return f"nested deeper than {MAX_DATA_DEPTH} levels"
            if isinstance(obj, dict):
                stack.extend((k, depth + 1) for k in obj)
                stack.extend((v, depth + 1) for v in obj.values())
            else:
                stack.extend((v, depth + 1) for v in obj)
    return None


def load_json_file(path: Path) -> Any | None:
    """
    Load a JSON file.

    Returns:
        The decoded data, or :obj:`None` if the file couldn't be read or
        decoded, or is nested deeper than :data:`MAX_DATA_DEPTH`
        (a warning is logged).
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError) as ex:
        log.warning(f"Failed to load JSON file '{path}': {ex}")
        return None
    problem = check_data(data)
    if problem:
        log.warning(f"Failed to load JSON file '{path}': the data is {problem}")
        return None
    return data


def load_yaml_file(path: Path) -> Any | None:
    """
    Load a YAML file using a safe loader without PEAT's ``!ENV``/``!JOIN`` tags.

    Returns:
        The decoded data, or :obj:`None` if the file couldn't be read or
        decoded, uses unknown tags, is nested deeper than :data:`MAX_DATA_DEPTH`
        or expands to more than :data:`MAX_YAML_NODES` values (a warning is logged).
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        data = yaml.load(text, Loader=_PlainSafeLoader)
    except (OSError, yaml.YAMLError, RecursionError) as ex:
        log.warning(f"Failed to load YAML file '{path}': {ex}")
        return None
    problem = check_data(data, MAX_YAML_NODES)
    if problem:
        log.warning(f"Failed to load YAML file '{path}': the data is {problem}")
        return None
    return data


def is_anchored(path: str) -> bool:
    r"""
    If ``path`` has a root or a drive on POSIX *or* Windows, i.e. it isn't
    relative to the current (or the run) directory on either OS.

    Paths in a run directory may have been written on another OS, and
    :meth:`~pathlib.PurePath.is_absolute` isn't enough on Windows: ``/x``
    and ``\x`` are relative to the current drive (``run_dir / "/x"`` is
    ``\x`` on the drive of ``run_dir``), and ``C:x`` is relative to the
    current directory of drive ``C:``.

    >>> [is_anchored(p) for p in ("/x", "\\x", "C:\\x", "C:x", "x", "../x")]
    [True, True, True, True, False, False]
    """
    return bool(PurePosixPath(path).root or PureWindowsPath(path).anchor)


def _is_regular_file(path: Path) -> bool:
    """If ``path`` is a regular file, and not a symlink."""
    return not path.is_symlink() and path.is_file()


def _contained_dir(root: Path, candidate: Path) -> Path | None:
    """
    The resolved ``candidate`` if it's a directory inside ``root``
    (after resolving symlinks and ``..``), otherwise :obj:`None`.
    """
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError):
        return None
    if resolved != root and resolved.is_relative_to(root) and resolved.is_dir():
        return resolved
    return None


def _upper_keys(data: Any) -> dict | None:
    if not isinstance(data, dict):
        return None
    return {str(k).upper(): v for k, v in data.items()}


def _strip_keys(obj: Any, drop_keys: tuple[str, ...]) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_keys(v, drop_keys) for k, v in obj.items() if k not in drop_keys}
    if isinstance(obj, list):
        return [_strip_keys(v, drop_keys) for v in obj]
    return obj


def _iter_jsonl_file(path: Path, drop_keys: tuple[str, ...] = ()) -> Iterator[dict]:
    """
    Stream the JSON objects in a JSON Lines file, skipping malformed lines.
    """
    bad_lines = 0
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except (ValueError, RecursionError):
                    bad_lines += 1
                    continue
                if not isinstance(record, dict) or check_data(record):
                    bad_lines += 1
                    continue
                yield _strip_keys(record, drop_keys) if drop_keys else record
    except OSError as ex:
        log.warning(f"Failed to read JSON Lines file '{path}': {ex}")
    if bad_lines:
        log.warning(f"Skipped {bad_lines} malformed line(s) in '{path}'")


def _count_lines(path: Path) -> int:
    """
    Count the non-empty lines in a file without decoding them.
    """
    count = 0
    try:
        with Path(path).open("rb") as fp:
            for line in fp:
                if line.strip():
                    count += 1
    except OSError as ex:
        log.warning(f"Failed to read file '{path}': {ex}")
    return count


def _walk_files(root: Path) -> Iterator[Path]:
    """
    Every regular file under ``root``, recursively, in a deterministic order.

    Directory symlinks are not followed and file symlinks are skipped.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            file = Path(dirpath, name)
            if not file.is_symlink() and file.is_file():
                yield file


def is_run_dir(path: str | Path) -> bool:
    """
    If ``path`` looks like a PEAT run directory.

    A run directory has at least one of the ``peat_metadata``, ``summaries``
    or ``devices`` sub-directories, or a PEAT log file in ``logs``.
    """
    path = Path(path)
    return path.is_dir() and (
        any((path / m).is_dir() for m in _RUN_DIR_MARKERS)
        or (path / "logs" / JSON_LOG_FILENAME).is_file()
        or (path / "logs" / "peat.log").is_file()
    )


def find_run_dirs(
    paths: Iterable[str | Path], exclude: Iterable[str | Path | None] = ()
) -> list[Path]:
    """
    Resolve paths to PEAT run directories.

    Each path is either a run directory, or a directory whose *direct*
    children are run directories (e.g. ``OUT_DIR``, ``./peat_results/``).
    Paths that are neither are logged as errors and skipped. Children
    that are symlinks are skipped.

    Args:
        paths: Paths to resolve
        exclude: Run directories to leave out of the results, e.g. the run
            directory of the current PEAT run. :obj:`None` values are ignored.

    Returns:
        Resolved absolute paths of the run directories, in the order they
        were found, without duplicates.
    """
    excluded = {Path(e).expanduser().resolve() for e in exclude if e}
    found: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser().resolve()
        if not p.is_dir():
            log.error(f"Not a directory: {raw}")
            continue
        if is_run_dir(p):
            candidates = [p]
        else:
            try:
                # Symlinks aren't followed when expanding a directory
                candidates = sorted(c for c in p.iterdir() if not c.is_symlink() and is_run_dir(c))
            except OSError as ex:
                log.error(f"Failed to list directory '{raw}': {ex}")
                continue
        if not candidates:
            log.error(f"'{raw}' is not a PEAT run directory and contains no run directories")
        for c in candidates:
            if c not in excluded and c not in found:
                found.append(c)
    return found


@dataclass
class DeviceResults:
    """
    The output files of a single device in a run's ``devices/`` directory.
    """

    path: Path

    @property
    def dir_name(self) -> str:
        """Name of the device's directory (usually the device ID or IP)."""
        return self.path.name

    @property
    def summary_file(self) -> Path | None:
        """``device-data-summary.json``, if it exists."""
        f = self.path / f"{DEVICE_DATA_PREFIX}summary.json"
        return f if _is_regular_file(f) else None

    @property
    def full_file(self) -> Path | None:
        """``device-data-full.json``, if it exists."""
        f = self.path / f"{DEVICE_DATA_PREFIX}full.json"
        return f if _is_regular_file(f) else None

    def jsonl_files(self) -> dict[str, Path]:
        """
        The ``device-data-<name>.jsonl`` files, keyed by ``<name>``
        (e.g. ``"event"``, ``"files"``, ``"interface"``).
        """
        files = {}
        for f in sorted(self.path.glob(f"{DEVICE_DATA_PREFIX}*.jsonl")):
            if _is_regular_file(f):
                files[f.stem[len(DEVICE_DATA_PREFIX) :]] = f
        return files

    def artifact_files(self) -> list[Path]:
        """
        Files saved by PEAT modules for the device (e.g. downloaded configuration
        files), which is every regular file in the device's directory (recursive)
        that isn't a ``device-data-*`` file. Symlinks are skipped.
        """
        return [
            f
            for f in _walk_files(self.path)
            if not (f.parent == self.path and f.name.startswith(DEVICE_DATA_PREFIX))
        ]

    def load_summary(self) -> dict | None:
        """Load ``device-data-summary.json``."""
        if not self.summary_file:
            return None
        data = load_json_file(self.summary_file)
        return data if isinstance(data, dict) else None

    def load_full(self) -> dict | None:
        """
        Load ``device-data-full.json``.

        .. warning::
           This file includes raw data (e.g. firmware blobs) and can be very large.
        """
        if not self.full_file:
            return None
        data = load_json_file(self.full_file)
        return data if isinstance(data, dict) else None

    def iter_jsonl(self, name: str, drop_keys: tuple[str, ...] = ("original",)) -> Iterator[dict]:
        """
        Stream the records in ``device-data-<name>.jsonl``.

        Malformed lines are skipped (and a warning logged). Keys in
        ``drop_keys`` are removed recursively, by default ``original``,
        which can contain raw file contents.
        """
        f = self.jsonl_files().get(name)
        if f:
            yield from _iter_jsonl_file(f, drop_keys)

    def count_jsonl(self, name: str) -> int:
        """
        Number of records in ``device-data-<name>.jsonl`` (non-empty lines,
        counted without decoding them). Returns 0 if the file doesn't exist.
        """
        f = self.jsonl_files().get(name)
        return _count_lines(f) if f else 0


@dataclass
class RunResults:
    """
    The contents of a PEAT run directory.

    Create using :meth:`open` (an existing run directory) or
    :meth:`from_config` (the current run, using PEAT's configuration).
    """

    path: Path
    #: Resolved sub-directories, keyed by the names in :data:`DEFAULT_SUBDIRS`.
    #: Values are :obj:`None` if the directory doesn't exist or is disabled.
    dirs: dict[str, Path | None] = field(default_factory=dict)
    #: Saved configuration, with upper-case keys (like ``config.export()``)
    config_data: dict | None = None
    #: Saved state, with upper-case keys (like ``state.export()``)
    state_data: dict | None = None
    #: Human-readable descriptions of problems encountered while opening the run
    load_errors: list[str] = field(default_factory=list)

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        dirs: dict[str, Path | None] | None = None,
        config_data: dict | None = None,
        state_data: dict | None = None,
    ) -> RunResults:
        """
        Open an existing run directory.

        Sub-directories are resolved in this order: an explicit value in
        ``dirs``, the default relative names (:data:`DEFAULT_SUBDIRS`), then
        the ``*_DIR`` paths from the saved configuration (e.g. a non-default
        ``DEVICE_DIR``), mapped into ``path`` if the run directory was moved.

        Only directories inside ``path`` are used (after resolving symlinks),
        except for explicit values in ``dirs``. Anything else is ignored
        and noted in :attr:`load_errors`, since the run directory may have
        come from another system.

        Args:
            path: The run directory
            dirs: Explicit sub-directory paths (see :attr:`dirs`)
            config_data: Configuration to use instead of the saved configuration
            state_data: State to use instead of the saved state

        Raises:
            PeatError: ``path`` isn't a directory
        """
        run_path = Path(path).expanduser().resolve()
        if not run_path.is_dir():
            raise PeatError(f"Run directory doesn't exist or isn't a directory: {path}")

        results = cls(path=run_path)
        explicit = dirs or {}
        for key, name in DEFAULT_SUBDIRS.items():
            if key in explicit:
                value = explicit[key]
                results.dirs[key] = Path(value) if value else None
                continue
            default = run_path / name
            results.dirs[key] = _contained_dir(run_path, default)
            if not results.dirs[key] and (default.is_symlink() or default.is_dir()):
                results.load_errors.append(
                    f"Ignored '{name}': it's a symlink that points outside "
                    f"the run directory, or is broken"
                )

        results.config_data = _upper_keys(config_data) or results.load_config()
        results.state_data = _upper_keys(state_data) or results.load_state()

        # Fallback: non-default sub-directory locations recorded in the configuration
        if results.config_data:
            for key, conf_key in _CONFIG_DIR_KEYS.items():
                if results.dirs.get(key) or key in explicit:
                    continue
                candidate = results._configured_dir(conf_key, results.config_data.get(conf_key))
                if candidate:
                    results.dirs[key] = candidate

        if not results.config_data:
            results.load_errors.append("No saved PEAT configuration was found")
        return results

    def _configured_dir(self, key: str, value: Any) -> Path | None:
        """
        A sub-directory from the saved configuration, if it's inside the run
        directory (see :meth:`map_saved_path`). Paths outside the run
        directory aren't used (or even checked).
        """
        if not value or not isinstance(value, str):
            return None
        candidate = self.map_saved_path(value)
        if candidate is None:
            if is_anchored(value):
                self.load_errors.append(
                    f"The configured {key.lower()} '{value}' is outside the "
                    f"run directory and wasn't used"
                )
            return None
        return _contained_dir(self.path, candidate)

    def map_saved_path(self, value: str) -> Path | None:
        """
        Map a path recorded by the run (e.g. in the saved configuration or
        state) to the same location in :attr:`path`.

        Paths under the saved ``RUN_DIR`` (from POSIX or Windows) are mapped
        into :attr:`path`, in case the run directory was moved or copied,
        or was created on another OS. Paths under :attr:`path` are used as-is.

        This is a lexical check, nothing is accessed: the result may not exist,
        and symlinks or ``..`` in it may point outside of :attr:`path`.

        Returns:
            The path in the run directory, or :obj:`None` if ``value`` isn't
            in the run directory (including relative paths)
        """
        rel: tuple[str, ...] | None = None
        saved_run_dir = (self.config_data or {}).get("RUN_DIR")
        if isinstance(saved_run_dir, str) and saved_run_dir:
            # The run may have been on another OS
            for pure_path in (PurePosixPath, PureWindowsPath):
                try:
                    rel = pure_path(value).relative_to(pure_path(saved_run_dir)).parts
                except ValueError:
                    continue
                break
        if rel is None:
            try:
                rel = Path(value).relative_to(self.path).parts
            except ValueError:
                return None
        # On Windows, a part with a root or a drive (e.g. "\x" or "C:x" from a
        # POSIX path) replaces the run directory when joined to it
        if any(is_anchored(part) for part in rel):
            return None
        return self.path.joinpath(*rel)

    @classmethod
    def from_config(cls, conf: Any = None, st: Any = None) -> RunResults:
        """
        The current run, using the configured ``*_DIR`` values and the
        in-memory configuration and state (``config.export()`` and
        ``state.export()``), since their YAML dumps aren't written until
        PEAT exits.

        Disabled directories (empty or :obj:`None`) are :obj:`None` in :attr:`dirs`.

        Args:
            conf: Configuration to use, defaults to :data:`peat.settings.config`
            st: State to use, defaults to :data:`peat.settings.state`
        """
        if conf is None or st is None:
            from .settings import config, state

            conf = config if conf is None else conf
            st = state if st is None else st

        run_dir = conf.RUN_DIR
        results = cls(path=Path(run_dir).resolve() if run_dir else Path.cwd())
        for key, conf_key in _CONFIG_DIR_KEYS.items():
            value = getattr(conf, conf_key, None)
            results.dirs[key] = Path(value) if value else None
        results.config_data = _upper_keys(conf.export())
        results.state_data = _upper_keys(st.export())
        return results

    @property
    def name(self) -> str:
        """Name of the run directory."""
        return self.path.name

    @property
    def run_id(self) -> str | None:
        """
        The run's ``RUN_ID``, from the summaries (``peat_run_id``), or
        the 12-digit suffix of the run directory's name, or :obj:`None`.
        """
        for files in self.summary_files().values():
            for f in files:
                data = load_json_file(f)
                if isinstance(data, dict) and data.get("peat_run_id"):
                    return str(data["peat_run_id"])
        match = _RUN_ID_RE.search(self.name)
        return match.group("run_id") if match else None

    def summary_files(self) -> dict[str, list[Path]]:
        """
        Summary files in ``summaries/``, keyed by kind, e.g.
        ``{"scan-summary": [scan-summary.json, scan-summary.json.1]}``.

        Duplicates (from multiple writes in a run) are sorted by their number.
        """
        summaries_dir = self.dirs.get("summaries")
        if not summaries_dir or not summaries_dir.is_dir():
            return {}
        found: dict[str, list[tuple[int, Path]]] = {}
        for f in summaries_dir.iterdir():
            match = _SUMMARY_RE.match(f.name)
            if not match or not f.is_file() or f.is_symlink():
                continue
            index = int(match.group("index") or 0)
            found.setdefault(match.group("kind"), []).append((index, f))
        return {kind: [f for _, f in sorted(files)] for kind, files in sorted(found.items())}

    def load_summary(self, kind: str, index: int = 0) -> dict | None:
        """
        Load a summary, e.g. ``load_summary("pull-summary")``.

        Args:
            kind: Summary kind (filename without ``.json``)
            index: Which of the files to load if there are duplicates
                (``0`` is ``<kind>.json``)
        """
        files = self.summary_files().get(kind, [])
        if index >= len(files) or index < -len(files):
            return None
        data = load_json_file(files[index])
        return data if isinstance(data, dict) else None

    def devices(self) -> list[DeviceResults]:
        """
        The device directories in ``devices/``, sorted by name.
        """
        devices_dir = self.dirs.get("devices")
        if not devices_dir or not devices_dir.is_dir():
            return []
        try:
            return [
                DeviceResults(path=d)
                for d in sorted(devices_dir.iterdir())
                if d.is_dir() and not d.is_symlink()
            ]
        except OSError as ex:
            log.warning(f"Failed to list device directory '{devices_dir}': {ex}")
            return []

    def _load_meta(self, name: str) -> dict | None:
        meta_dir = self.dirs.get("meta")
        if not meta_dir:
            return None
        for ext, loader in ((".json", load_json_file), (".yaml", load_yaml_file)):
            f = meta_dir / f"peat_{name}{ext}"
            if _is_regular_file(f):
                data = _upper_keys(loader(f))
                if data is None:
                    self.load_errors.append(f"Failed to load {f.name}")
                return data
        return None

    def load_config(self) -> dict | None:
        """
        Load the saved configuration (``peat_metadata/peat_configuration.json``
        or ``.yaml``), with upper-case keys.
        """
        return self._load_meta("configuration")

    def load_state(self) -> dict | None:
        """
        Load the saved state (``peat_metadata/peat_state.json`` or ``.yaml``),
        with upper-case keys.
        """
        return self._load_meta("state")

    def json_log_file(self) -> Path | None:
        """The JSON log file (``logs/json-log.jsonl``), if it exists."""
        logs_dir = self.dirs.get("logs")
        if not logs_dir:
            return None
        f = logs_dir / JSON_LOG_FILENAME
        return f if _is_regular_file(f) else None

    def iter_json_logs(self) -> Iterator[dict]:
        """
        Stream the records in the JSON log file.

        Malformed lines (e.g. a truncated final line if PEAT crashed) are skipped.
        """
        f = self.json_log_file()
        if f:
            yield from _iter_jsonl_file(f)

    def elastic_doc_files(self) -> dict[str, list[Path]]:
        """
        Documents saved locally when pushing to Elasticsearch/OpenSearch
        (``elastic_data/<run_id>/<index>.jsonl``), keyed by index name.
        """
        elastic_dir = self.dirs.get("elastic")
        if not elastic_dir or not elastic_dir.is_dir():
            return {}
        found: dict[str, list[Path]] = {}
        for f in _walk_files(elastic_dir):
            if f.suffix == ".jsonl":
                found.setdefault(f.stem, []).append(f)
        return dict(sorted(found.items()))

    def iter_files(self) -> Iterator[Path]:
        """
        Every regular file in the run directory (recursive, sorted).
        Directory symlinks are not followed and file symlinks are skipped.
        """
        yield from _walk_files(self.path)


__all__ = ["DeviceResults", "RunResults", "find_run_dirs", "is_anchored", "is_run_dir"]
