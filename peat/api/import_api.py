"""
Import the results of previous PEAT runs (``peat_results``) into
Elasticsearch or OpenSearch (including Malcolm), and upload the files
collected from devices to Thorium.

This is the API behind ``peat import``. It reads run directories with
:mod:`peat.run_results`, and never modifies them.

Data pushed to Elasticsearch/OpenSearch is rebuilt from the files in the
run directory, using the same code as a live run:

- Devices (``devices/<device>/device-data-full.json``, or if it's missing,
  ``device-data-summary.json`` and the ``device-data-*.jsonl`` files) are
  loaded as :class:`~peat.data.models.DeviceData` and exported with
  :meth:`~peat.data.models.DeviceData.export_to_elastic` (the host data and
  the events, files, registers, tags, I/O, memory, etc. indices)
- Summaries (``summaries/{scan,pull,parse}-summary.json``)
- The saved configuration and state (``peat_metadata/``), if
  :attr:`~peat.settings.Configuration.ELASTIC_SAVE_CONFIG` and
  :attr:`~peat.settings.Configuration.ELASTIC_SAVE_STATE` are enabled.
  Usernames and passwords in URLs (e.g. ``ELASTIC_SERVER``) are removed,
  since the server being imported to may not be the server they're for.
- The JSON logs (``logs/json-log.jsonl``), if
  :attr:`~peat.settings.Configuration.ELASTIC_SAVE_LOGS` is enabled

Imported documents are attributed to the original run (``agent.id``, the date
of dated index names, and generated ``@timestamp`` values are from the original
run, see :meth:`~peat.elastic.Elastic.attribute_to_run`) and have deterministic
document IDs, so importing the same run again updates the existing documents
instead of creating duplicates.

Usage:

.. code-block:: python

   from peat import Elastic, config, import_results, state

   state.elastic = Elastic("http://localhost:9200/")
   summary = import_results(["./peat_results/"])
"""

from __future__ import annotations

import hashlib
import timeit
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from peat import __version__, config, consts, log, state, utils
from peat.data.base_model import BaseModel
from peat.data.models import DeviceData
from peat.run_results import (
    DEVICE_DATA_PREFIX,
    DeviceResults,
    RunResults,
    find_run_dirs,
    load_json_file,
)

if TYPE_CHECKING:
    from peat.elastic import Elastic
    from peat.thorium import Thorium

#: JSON files larger than this (in bytes) aren't imported
MAX_JSON_FILE_SIZE = 1024 * 1024 * 1024  # 1 GiB

#: Number of log records pushed in each bulk request
LOG_CHUNK_SIZE = 1000

#: Maximum number of attempts to fix device data that fails validation
#: (e.g. from a different version of PEAT) by removing the invalid fields
MAX_VALIDATION_ATTEMPTS = 10

#: Summary kinds (file names without ``.json``) and the configuration
#: options with the names of their Elasticsearch indices
SUMMARY_INDEX_OPTIONS: dict[str, str] = {
    "scan-summary": "ELASTIC_SCAN_INDEX",
    "pull-summary": "ELASTIC_PULL_INDEX",
    "parse-summary": "ELASTIC_PARSE_INDEX",
}

#: Kind of the summary written by ``peat import`` (``summaries/import-summary.json``).
#: Run directories with this summary are skipped, since they're previous imports
#: (their logs, configuration and state were already pushed when they ran).
IMPORT_SUMMARY_KIND = "import-summary"


@dataclass
class RunImportResult:
    """
    Results of importing a single run directory.
    """

    run_name: str
    run_path: str
    run_id: str | None = None
    run_start: str | None = None
    devices_found: int = 0
    devices_imported: int = 0
    devices_failed: int = 0
    summaries_imported: int = 0
    metadata_imported: int = 0
    log_records: int = 0
    files_found: int = 0
    files_uploaded: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        """If anything failed to import."""
        return bool(self.errors)

    def error(self, message: str) -> None:
        """Log an error and record it in :attr:`errors`."""
        log.error(message)
        self.errors.append(message)


def run_start_time(run_id: str | None) -> datetime | None:
    """
    When a run started, decoded from its ``RUN_ID``.

    ``RUN_ID`` (:data:`peat.consts.RUN_ID`) is the UNIX timestamp of the
    start of the run (UTC), followed by two random digits.

    Returns:
        The start time (timezone-aware, UTC), or :obj:`None` if ``run_id``
        isn't a valid ``RUN_ID``
    """
    if not run_id or not str(run_id).isdigit() or len(str(run_id)) != 12:
        return None
    start = datetime.fromtimestamp(int(str(run_id)[:-2]), UTC)
    # Sanity check, PEAT didn't exist before 2015
    if not (datetime(2015, 1, 1, tzinfo=UTC) <= start <= utils.utc_now()):
        return None
    return start


def gen_doc_id(results: RunResults, run_id: str | None, *parts: Any) -> str:
    """
    Deterministic Elasticsearch document ID for imported data, so
    importing the same run multiple times doesn't create duplicates.

    Format: ``peat~<run-id>~import~<hash>``, where ``<hash>`` is derived
    from ``run_id`` (or the run directory name, if the run ID is unknown)
    and ``parts``.
    """
    key = "|".join(str(p) for p in (run_id or results.name, *parts))
    digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:20]
    return f"peat~{run_id or 'unknown'}~import~{digest}"


def _new_result(results: RunResults) -> RunImportResult:
    res = RunImportResult(run_name=results.name, run_path=results.path.as_posix())
    res.run_id = results.run_id
    start = run_start_time(res.run_id)
    res.run_start = start.isoformat() if start else None
    return res


def _file_too_large(path: Path, res: RunImportResult, optional: bool = False) -> bool:
    """
    Check if a JSON file is larger than :data:`MAX_JSON_FILE_SIZE` (or can't be read).

    Args:
        path: The file
        res: Results to record the error in
        optional: Only log a warning instead of recording an error,
            e.g. if the data can be loaded from another file instead
    """
    try:
        size = path.stat().st_size
    except OSError as ex:
        message = f"Failed to read '{path}': {ex}"
    else:
        if size <= MAX_JSON_FILE_SIZE:
            return False
        message = (
            f"Skipping '{path}': file is too large ({size} bytes, "
            f"the maximum is {MAX_JSON_FILE_SIZE} bytes)"
        )
    if optional:
        log.warning(message)
    else:
        res.error(message)
    return True


def _drop_path(data: Any, loc: tuple) -> bool:
    """
    Remove the value at ``loc`` (a pydantic error location) from ``data``.
    """
    parent = data
    for key in loc[:-1]:
        if isinstance(parent, dict) and key in parent:
            parent = parent[key]
        elif isinstance(parent, list) and isinstance(key, int) and 0 <= key < len(parent):
            parent = parent[key]
        else:
            return False
    last = loc[-1]
    if isinstance(parent, dict) and last in parent:
        del parent[last]
        return True
    if isinstance(parent, list) and isinstance(last, int) and 0 <= last < len(parent):
        del parent[last]
        return True
    return False


def build_device(data: dict, source: str) -> DeviceData | None:
    """
    Create a :class:`~peat.data.models.DeviceData` object from exported
    device data (e.g. the contents of ``device-data-full.json``).

    Fields that fail validation (e.g. unknown fields in data from a different
    version of PEAT) are removed, with a warning, and validation is retried.

    Args:
        data: The exported device data. It may be modified.
        source: Description of where the data came from, for log messages

    Returns:
        The device, or :obj:`None` if the data couldn't be loaded
    """
    data.pop("created", None)  # Added by DeviceData.export_to_files()

    for _ in range(MAX_VALIDATION_ATTEMPTS):
        try:
            return DeviceData(**data)
        except ValidationError as ex:
            # Remove the deepest fields first, and later list items before
            # earlier ones, so the remaining locations stay valid.
            locs = sorted(
                {tuple(err["loc"]) for err in ex.errors()},
                key=lambda loc: (len(loc), [str(p).zfill(12) for p in loc]),
                reverse=True,
            )
            dropped = [loc for loc in locs if loc and _drop_path(data, loc)]
            if not dropped:
                log.error(f"Failed to load device data from {source}: {ex}")
                return None
            names = ", ".join(".".join(str(p) for p in loc) for loc in dropped)
            log.warning(f"Removed invalid or unknown field(s) from {source}: {names}")
        except Exception as ex:
            log.error(f"Failed to load device data from {source}: {ex}")
            return None

    log.error(f"Failed to load device data from {source}: too many invalid fields")
    return None


def load_device(dev_res: DeviceResults, res: RunImportResult) -> DeviceData | None:
    """
    Load the data for a device in a run's ``devices/`` directory.

    Uses ``device-data-full.json`` if it exists. Otherwise (or if it can't be
    loaded), the device is rebuilt from ``device-data-summary.json`` and the
    ``device-data-*.jsonl`` files (this excludes the raw ``original`` data of
    firmware and logic).

    Returns:
        The device, or :obj:`None` if the device has no data or it couldn't be loaded
    """
    full_file = dev_res.full_file
    if full_file and not _file_too_large(full_file, res, optional=True):
        data = dev_res.load_full()
        dev = build_device(data, f"'{full_file}'") if data is not None else None
        if dev is not None:
            return dev
        log.warning(f"Failed to load '{full_file}', trying device-data-summary.json")

    summary_file = dev_res.summary_file
    if not summary_file or _file_too_large(summary_file, res):
        return None
    data = dev_res.load_summary()
    if data is None:
        return None

    # Models that are excluded from the summary are in .jsonl files
    for name, path in dev_res.jsonl_files().items():
        if name in data or _file_too_large(path, res):
            continue
        records = []
        for record in dev_res.iter_jsonl(name, drop_keys=()):
            record.pop("device_id", None)  # Added by DeviceData.export_to_files()
            records.append(record)
        if records:
            data[name] = records

    return build_device(data, f"'{summary_file}' and .jsonl files")


def _assign_doc_ids(dev: DeviceData, results: RunResults, run_id: str | None, dev_key: str):
    """
    Pre-assign deterministic document IDs to the device and its models.
    :func:`~peat.data.models.export_models_to_elastic` uses existing IDs.
    """
    # Do these now, so the lists don't change when exporting
    dev.populate_fields()
    dev.purge_duplicates()

    dev._elastic_doc_id = gen_doc_id(results, run_id, "device", dev_key)
    for attr in dev.get_attr_names(list):
        for position, item in enumerate(getattr(dev, attr)):
            if isinstance(item, BaseModel) and not isinstance(item, DeviceData):
                item._elastic_doc_id = gen_doc_id(
                    results, run_id, "device", dev_key, attr, position
                )


def _clean_log_record(record: dict) -> dict:
    """
    Make sure values that :meth:`~peat.elastic.Elastic.gen_body` uses
    have the expected types (the log file is untrusted input).
    """
    if not isinstance(record.get("message", ""), str):
        record["message"] = str(record["message"])
    tags = record.get("tags")
    if tags is not None:
        if isinstance(tags, list):
            record["tags"] = [str(t) for t in tags if isinstance(t, (str, int, float))]
        else:
            del record["tags"]
    return record


def _import_devices(elastic: Elastic, results: RunResults, run_id, res: RunImportResult):
    for dev_res in results.devices():
        if not (dev_res.full_file or dev_res.summary_file):
            log.debug(f"Skipping '{dev_res.path}': no device data files")
            continue
        res.devices_found += 1

        dev = load_device(dev_res, res)
        if dev is None:
            res.devices_failed += 1
            res.error(f"Failed to load device '{dev_res.dir_name}' from run '{results.name}'")
            continue

        try:
            _assign_doc_ids(dev, results, run_id, dev_res.dir_name)
            success = dev.export_to_elastic(elastic)
        except Exception as ex:
            log.opt(exception=True).debug(f"Traceback for device '{dev_res.dir_name}'")
            success = False
            log.error(f"Exception exporting device '{dev_res.dir_name}': {ex}")

        if success:
            res.devices_imported += 1
        else:
            res.devices_failed += 1
            res.error(
                f"Failed to export device '{dev_res.dir_name}' from run "
                f"'{results.name}' to {elastic.type}"
            )


def _import_summaries(elastic: Elastic, results: RunResults, run_id, res: RunImportResult):
    for kind, files in results.summary_files().items():
        option = SUMMARY_INDEX_OPTIONS.get(kind)
        if not option:
            log.debug(f"Skipping summary '{kind}' (no Elasticsearch index for it)")
            continue
        index = getattr(config, option, None)
        if not index:
            continue
        for position, path in enumerate(files):
            if _file_too_large(path, res):
                continue
            data = load_json_file(path)
            if not isinstance(data, dict):
                res.error(f"Failed to load summary '{path}'")
                continue
            doc_id = gen_doc_id(results, run_id, "summary", kind, position)
            if elastic.push(index, data, doc_id=doc_id):
                res.summaries_imported += 1
            else:
                res.error(f"Failed to push summary '{path.name}' from run '{results.name}'")


def _import_metadata(elastic: Elastic, results: RunResults, run_id, res: RunImportResult):
    to_push = []
    if config.ELASTIC_SAVE_CONFIG and config.ELASTIC_CONFIG_INDEX and results.config_data:
        raw_config = dict(results.config_data)
        # Same as a live run: the dynamic mappings for these fields
        # can vary and cause pushes to fail.
        for opt in ["DEVICE_OPTIONS", "HOSTS"]:
            raw_config.pop(opt, None)
        to_push.append(("configuration", config.ELASTIC_CONFIG_INDEX, raw_config))
    if config.ELASTIC_SAVE_STATE and config.ELASTIC_STATE_INDEX and results.state_data:
        to_push.append(("state", config.ELASTIC_STATE_INDEX, dict(results.state_data)))

    for name, index, data in to_push:
        # The server being imported to may not be the server the credentials are for
        data = utils.redact_url_credentials(data)
        if elastic.push(index, data, doc_id=gen_doc_id(results, run_id, name)):
            res.metadata_imported += 1
        else:
            res.error(f"Failed to push the {name} of run '{results.name}'")


def _import_logs(elastic: Elastic, results: RunResults, run_id, res: RunImportResult):
    if not config.ELASTIC_SAVE_LOGS or not config.ELASTIC_LOG_INDEX:
        return
    log_file = results.json_log_file()
    if not log_file:
        return

    chunk: list[tuple[str, dict]] = []
    failed = False
    for line_num, record in enumerate(results.iter_json_logs()):
        doc_id = gen_doc_id(results, run_id, "log", line_num)
        chunk.append((doc_id, _clean_log_record(record)))
        if len(chunk) >= LOG_CHUNK_SIZE:
            failed |= not elastic.bulk_push(config.ELASTIC_LOG_INDEX, chunk)
            res.log_records += len(chunk)
            chunk = []
    if chunk:
        failed |= not elastic.bulk_push(config.ELASTIC_LOG_INDEX, chunk)
        res.log_records += len(chunk)

    if failed:
        res.error(f"Failed to push some log records from run '{results.name}'")


def import_run_to_elastic(
    elastic: Elastic, results: RunResults, res: RunImportResult | None = None
) -> RunImportResult:
    """
    Push the data from a run directory to Elasticsearch/OpenSearch.

    Args:
        elastic: The Elasticsearch/OpenSearch instance to push to
        results: The run directory
        res: Results object to update, a new one is created if unset

    Returns:
        The results of the import
    """
    if res is None:
        res = _new_result(results)
    run_id = res.run_id
    start = run_start_time(run_id)
    if not start:
        log.warning(
            f"Couldn't determine when run '{results.name}' happened, the current "
            f"time will be used for the documents and index names"
        )

    with elastic.attribute_to_run(run_id, start):
        _import_devices(elastic, results, run_id, res)
        _import_summaries(elastic, results, run_id, res)
        _import_metadata(elastic, results, run_id, res)
        _import_logs(elastic, results, run_id, res)

    return res


def thorium_tags(
    results: RunResults, run_id: str | None, dev_res: DeviceResults, device: dict | None
) -> dict[str, list[str] | str]:
    """
    Thorium tags for files collected from a device.

    Args:
        results: The run directory
        run_id: ``RUN_ID`` of the run, if known
        dev_res: The device's directory
        device: The device's summary (``device-data-summary.json``), if available
    """
    device = device if isinstance(device, dict) else {}
    description = device.get("description")
    description = description if isinstance(description, dict) else {}
    vendor = description.get("vendor")
    vendor = vendor if isinstance(vendor, dict) else {}

    def _str(value: Any) -> str:
        return value if isinstance(value, str) else ""

    tags: dict[str, list[str] | str] = {
        "source": "PEAT",
        "peat_run_id": run_id or "",
        "peat_run_name": results.name,
        "peat_device_id": _str(device.get("id")) or dev_res.dir_name,
        "peat_device_ip": _str(device.get("ip")),
        "peat_device_mac": _str(device.get("mac")),
        "peat_device_hostname": _str(device.get("hostname")),
        "peat_device_name": _str(device.get("name")),
        "peat_device_type": _str(device.get("type")),
        "peat_device_vendor": _str(vendor.get("name")) or _str(vendor.get("id")),
        "peat_device_brand": _str(description.get("brand")),
        "peat_device_model": _str(description.get("model")),
        "peat_device_product": _str(description.get("product")),
    }
    return {key: value for key, value in tags.items() if value}


def _has_device_data(dev_res: DeviceResults) -> bool:
    """If a device directory has PEAT's ``device-data-*`` files."""
    return bool(dev_res.full_file or dev_res.summary_file or dev_res.jsonl_files())


def import_run_to_thorium(
    thorium: Thorium, results: RunResults, res: RunImportResult | None = None
) -> RunImportResult:
    """
    Upload the files collected from devices in a run directory to Thorium.

    These are all files in the device directories except for PEAT's
    ``device-data-*`` files. Empty files are skipped. Files are always uploaded,
    since each device and run gets its own submission (name, description and
    tags) in Thorium, even if the contents are the same. Files that were already
    submitted with the same name, description and groups (e.g. when importing
    a run again) are counted as skipped.

    Only files inside the run directory are uploaded (symlinks are skipped), and
    only from device directories that have PEAT's ``device-data-*`` files, so
    unrelated files aren't uploaded if a path isn't really a PEAT run directory.

    Args:
        thorium: The Thorium instance to upload to
        results: The run directory
        res: Results object to update, a new one is created if unset

    Returns:
        The results of the import
    """
    if res is None:
        res = _new_result(results)
    run_root = results.path.resolve()

    for dev_res in results.devices():
        files = dev_res.artifact_files()
        if not files:
            continue
        if not _has_device_data(dev_res):
            log.warning(
                f"Not uploading the {len(files)} file(s) in '{dev_res.path}' to Thorium: "
                f"it doesn't have PEAT's device data files ({DEVICE_DATA_PREFIX}*), "
                f"so it may not be a PEAT device directory"
            )
            continue
        res.files_found += len(files)
        summary = None
        if dev_res.summary_file and not _file_too_large(dev_res.summary_file, res, optional=True):
            summary = dev_res.load_summary()
        tags = thorium_tags(results, res.run_id, dev_res, summary)
        log.info(
            f"Uploading {len(files)} file(s) from device '{dev_res.dir_name}' "
            f"(run '{results.name}') to Thorium"
        )

        for path in files:
            rel_path = path.relative_to(dev_res.path).as_posix()
            try:
                # Defense in depth, the loader already skips symlinks
                if path.is_symlink() or not path.resolve().is_relative_to(run_root):
                    log.warning(f"Skipping '{path}': it's outside the run directory")
                    res.files_skipped += 1
                    continue
                if path.stat().st_size == 0:
                    log.debug(f"Skipping empty file '{rel_path}'")
                    res.files_skipped += 1
                    continue
                submission = thorium.upload_file(
                    path,
                    tags={**tags, "peat_file_path": rel_path},
                    description=(
                        f"File '{rel_path}' collected by PEAT from device "
                        f"'{tags.get('peat_device_id', dev_res.dir_name)}' "
                        f"(PEAT run '{results.name}')"
                    ),
                )
                if submission is None:
                    log.debug(f"Skipping '{rel_path}' (already submitted to Thorium)")
                    res.files_skipped += 1
                    continue
                log.debug(f"Uploaded '{rel_path}' to Thorium: {submission.get('sha256', '')}")
                res.files_uploaded += 1
            except (OSError, consts.PeatError) as ex:
                res.files_failed += 1
                res.error(f"Failed to upload '{path}' to Thorium: {ex}")

    return res


def _count_lines(path: Path | None) -> int:
    if not path:
        return 0
    with path.open("rb") as fp:
        return sum(1 for line in fp if line.strip())


def plan_run_import(results: RunResults, res: RunImportResult) -> RunImportResult:
    """
    Count what would be imported from a run directory, for a dry run.
    Nothing is loaded or pushed.
    """
    devices = results.devices()
    res.devices_found = sum(1 for d in devices if d.full_file or d.summary_file)
    res.summaries_imported = sum(
        len(files)
        for kind, files in results.summary_files().items()
        if kind in SUMMARY_INDEX_OPTIONS
    )
    res.metadata_imported = int(bool(results.config_data)) + int(bool(results.state_data))
    try:
        res.log_records = _count_lines(results.json_log_file())
    except OSError as ex:
        log.warning(f"Failed to read the logs of run '{results.name}': {ex}")
    res.files_found = sum(len(d.artifact_files()) for d in devices if _has_device_data(d))
    return res


def _resolve_targets(
    elastic: Elastic | None, thorium: Thorium | None
) -> tuple[Elastic | None, Thorium | None, bool]:
    """
    Resolve the import targets from the arguments and configuration.

    Returns:
        The Elastic and Thorium instances (or :obj:`None` if not configured),
        and if the targets are usable (:obj:`False` if a configured target
        couldn't be initialized).
    """
    ok = True
    if elastic is None:
        elastic = state.elastic
        if elastic is None and config.ELASTIC_SERVER:
            log.error(
                "An Elasticsearch/OpenSearch server is configured, but PEAT "
                "failed to connect to it (see the errors above)"
            )
            if "://" not in config.ELASTIC_SERVER and Path(config.ELASTIC_SERVER).exists():
                log.error(
                    f"The path '{config.ELASTIC_SERVER}' was used as the server URL. "
                    f'Put "-e" after the paths to import, or specify the server URL.'
                )
            ok = False

    if thorium is None and config.THORIUM_URL:
        from peat.thorium import Thorium

        try:
            thorium = Thorium(
                config.THORIUM_URL,
                groups=config.THORIUM_GROUPS,
                verify_tls=config.THORIUM_VERIFY_TLS,
            )
        except consts.PeatError as ex:
            log.error(str(ex))
            ok = False

    return elastic, thorium, ok


def import_results(
    paths: list[str | Path],
    elastic: Elastic | None = None,
    thorium: Thorium | None = None,
    dry_run: bool | None = None,
) -> dict[str, Any] | None:
    """
    Import the results of previous PEAT runs.

    Data is pushed to Elasticsearch/OpenSearch and/or files are uploaded to
    Thorium, depending on what targets are configured. See the module
    documentation (:mod:`peat.api.import_api`) for details.

    Args:
        paths: Run directories, or directories containing run directories
            (e.g. ``./peat_results/``)
        elastic: Elasticsearch/OpenSearch instance to push data to.
            Defaults to :attr:`state.elastic <peat.settings.State.elastic>`
            if :attr:`~peat.settings.Configuration.ELASTIC_SERVER` is configured.
        thorium: Thorium instance to upload files to. Defaults to a new instance
            if :attr:`~peat.settings.Configuration.THORIUM_URL` is configured.
        dry_run: Only report what would be imported, without connecting to
            Thorium or importing anything. Like other commands' dry runs, the
            logs, configuration and state of the current run are still pushed
            to Elasticsearch/OpenSearch, if configured. Defaults to
            :attr:`~peat.settings.Configuration.DRY_RUN`.

    Returns:
        Summary of the import (also saved to ``import-summary.json``), or
        :obj:`None` if no targets are configured, a target couldn't be
        initialized, or there are no run directories to import.
        Failures of individual items are listed in the ``errors`` of each run.
    """
    start_time = timeit.default_timer()
    if dry_run is None:
        dry_run = bool(config.DRY_RUN)

    elastic, thorium, targets_ok = _resolve_targets(elastic, thorium)
    if not targets_ok:
        return None
    if not elastic and not thorium and not dry_run:
        log.error(
            "No import targets configured. Use -e/--elastic-server for "
            "Elasticsearch, OpenSearch or Malcolm, and/or --thorium-url for Thorium "
            "(or --dry-run to see what would be imported)."
        )
        return None

    # (run directory, loaded results or the exception from loading them)
    run_dirs: list[tuple[Path, RunResults | Exception]] = []
    for run_dir in find_run_dirs(paths, exclude=[config.RUN_DIR]):
        try:
            loaded: RunResults | Exception = RunResults.open(run_dir)
        except Exception as ex:
            log.opt(exception=True).debug(f"Traceback for loading '{run_dir}'")
            loaded = ex
        if isinstance(loaded, RunResults) and IMPORT_SUMMARY_KIND in loaded.summary_files():
            log.warning(
                f"Skipping '{run_dir.name}': it's a previous run of 'peat import' "
                f"(it has an {IMPORT_SUMMARY_KIND}.json)"
            )
            continue
        run_dirs.append((run_dir, loaded))
    if not run_dirs:
        log.error(f"No PEAT run directories to import found in {[str(p) for p in paths]}")
        return None

    if thorium and not dry_run:
        try:
            thorium.connect()
        except consts.PeatError as ex:
            log.error(f"Failed to connect to Thorium: {ex}")
            return None

    # Don't look up hostnames, MACs, etc. on the current network for imported devices
    for key in ["RESOLVE_IP", "RESOLVE_MAC", "RESOLVE_HOSTNAME"]:
        if not config.non_default(key):
            setattr(config, key, False)

    targets = []
    if elastic:
        targets.append(f"{elastic.type} ({elastic.safe_url})")
    if thorium:
        targets.append(f"Thorium ({thorium.safe_url})")
    log.info(
        f"{'Dry run of importing' if dry_run else 'Importing'} {len(run_dirs)} "
        f"run(s) to {', '.join(targets) or 'no targets'}"
    )

    run_results: list[RunImportResult] = []
    for num, (run_dir, results) in enumerate(run_dirs, start=1):
        log.info(f"Importing run {num} of {len(run_dirs)}: '{run_dir.name}'")
        res = RunImportResult(run_name=run_dir.name, run_path=run_dir.as_posix())
        run_results.append(res)
        try:
            if isinstance(results, Exception):
                raise results
            res = _new_result(results)
            run_results[-1] = res
            for problem in results.load_errors:
                log.warning(f"Run '{run_dir.name}': {problem}")

            if dry_run:
                plan_run_import(results, res)
                continue
            if elastic:
                import_run_to_elastic(elastic, results, res)
            if thorium:
                import_run_to_thorium(thorium, results, res)
        except Exception as ex:
            log.opt(exception=True).debug(f"Traceback for importing '{run_dir}'")
            res.error(f"Failed to import run '{run_dir.name}': {ex}")

        log.info(
            f"Run '{run_dir.name}': imported {res.devices_imported} of "
            f"{res.devices_found} device(s), {res.summaries_imported} summaries, "
            f"{res.metadata_imported} metadata dumps, {res.log_records} log records, "
            f"uploaded {res.files_uploaded} of {res.files_found} file(s) "
            f"({res.files_skipped} skipped), {len(res.errors)} error(s)"
        )

    summary: dict[str, Any] = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "import_duration": timeit.default_timer() - start_time,
        "import_dry_run": dry_run,
        "import_paths": [str(p) for p in paths],
        "import_targets": targets,
        "num_runs": len(run_results),
        "num_runs_failed": sum(1 for r in run_results if r.failed),
        "runs": [asdict(r) for r in run_results],
    }
    utils.save_results_summary(summary, "import-summary")

    failed = summary["num_runs_failed"]
    if dry_run:
        log.info(f"Dry run finished for {len(run_results)} run(s), nothing was imported")
    elif failed:
        log.error(f"Failed to import {failed} of {len(run_results)} run(s), see the errors above")
        state.error = True
    else:
        duration = utils.fmt_duration(summary["import_duration"])
        log.info(f"Imported {len(run_results)} run(s) in {duration}")
    return summary


__all__ = [
    "RunImportResult",
    "build_device",
    "import_results",
    "import_run_to_elastic",
    "import_run_to_thorium",
    "load_device",
    "run_start_time",
]
