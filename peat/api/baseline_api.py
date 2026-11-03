"""
Baselines: create expected device states and compare device data against them.

The comparison itself is implemented in :mod:`peat.data.baseline`. This module
loads PEAT device data and baseline files, creates baselines, runs comparisons
against baseline files and module known defaults
(:attr:`DeviceModule.known_defaults <peat.device.DeviceModule.known_defaults>`),
exports the findings, and implements the ``peat baseline-create``,
``peat baseline-compare`` and ``peat baseline-show`` commands.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from peat import (
    DeviceData,
    DeviceModule,
    PeatError,
    __version__,
    config,
    consts,
    log,
    module_api,
    state,
    utils,
)
from peat.data.baseline import compare_device as _compare_device
from peat.data.baseline import (
    device_to_doc,
    device_type_profile,
    split_path,
    store_findings,
    varying_paths,
)
from peat.data.data_utils import sort_model_list, strip_empty_and_private
from peat.data.models import (
    SEVERITY_NUMBER,
    Baseline,
    BaselineFinding,
    BaselineKind,
    BaselineProvenance,
    BaselineSelector,
    export_models_to_elastic,
)
from peat.protocols.addresses import address_to_pathname

# Keys added to host documents (DeviceData.elastic()) that are not DeviceData fields
_DERIVED_HOST_KEYS = ("tags", "indicator_states")

# Lists that are never part of a device snapshot (logs, memory, UEFI images, findings)
_SNAPSHOT_EXCLUDE = ("event", "memory", "uefi_image", "uefi_hashes", "baseline_findings")

_BASELINE_COMMANDS = ("baseline_create", "baseline_compare", "baseline_show")

# Device data keys that lossy input formats do not contain (dev._cache["omitted_keys"]):
# comparing them would report everything as "missing"/"unexpected"
_PARSE_SUMMARY_OMITTED = ("relationships", "baseline_findings")
_DEVICE_SUMMARY_OMITTED = (
    "files",
    "relationships",
    "registers",
    "tag",
    "io",
    "event",
    "memory",
    "baseline_findings",
)


# --------------------------------------------------------------------------- #
# Loading device data
# --------------------------------------------------------------------------- #
def load_device_data(
    source: str | Path | dict | list, errors: list[str] | None = None
) -> list[DeviceData]:
    """
    Load devices from PEAT output.

    Accepted sources:

    - a ``device-data-full.json`` or ``device-data-summary.json`` file (the
      top-level ``created`` key is removed and kept as ``dev._cache["observed"]``)
    - a parse summary (``parse-summary.json``, from ``parse_results[*].results``)
    - a JSON file with a list of device dicts
    - a directory: every ``device-data-full.json`` below it (recursively), or
      every ``device-data-summary.json`` if there are no full files
    - ``"-"``: JSON read from standard input (``stdin``)
    - an already-loaded :class:`dict` or :class:`list`

    The path of the source file is kept as ``dev._cache["source_file"]``. If the
    PEAT module that produced the data is known (parse summaries, or a single
    ``files[*].peat_module`` value), it is set as ``dev._module``.

    Parse summaries and ``device-data-summary.json`` files do not contain all
    device data (e.g. no ``relationships``; summaries also no ``files``): the
    missing keys are kept as ``dev._cache["omitted_keys"]`` and are not compared.
    The format of other inputs (standard input, other file names, a :class:`dict`
    or :class:`list`) is not known: a device without any of the lists a summary
    omits, or without ``relationships`` (e.g. a host document from ``peat pull -P``),
    is treated the same way, so the disappearance of all items of such a list is
    only detected with ``device-data-full.json`` files.

    .. note::
       This does not call :meth:`~peat.data.models.DeviceData.populate_fields`
       and does not add the devices to the :class:`~peat.data.store.Datastore`.

    Args:
        source: Where to load the device data from
        errors: if given, every file or item that failed to load (e.g. an
            unreadable file in a directory, an invalid device in a list) is
            appended to it, also when other devices were loaded

    Returns:
        The loaded devices, or an empty list if an error occurred (the error is logged)
    """
    if errors is None:
        errors = []

    if isinstance(source, (dict, list)):
        return _devices_from_json(source, origin="", errors=errors)

    if str(source) == "-":
        log.debug("Reading device data from standard input (stdin)")
        try:
            data = json.loads(sys.stdin.read())
        except ValueError as ex:
            log.error(f"Failed to read device data JSON from stdin: {ex}")
            errors.append("stdin")
            return []
        return _devices_from_json(data, origin="stdin", errors=errors)

    path = Path(os.path.expanduser(str(source)))
    if path.is_dir():
        files = sorted(path.rglob("device-data-full.json"))
        if not files:
            files = sorted(path.rglob("device-data-summary.json"))
        if not files:
            log.error(
                f"No device data (device-data-full.json or "
                f"device-data-summary.json files) found in directory '{path}'"
            )
            errors.append(path.as_posix())
            return []
        devices = []
        for file in files:
            devices.extend(_load_json_file(file, errors))
        return devices

    if not path.is_file():
        log.error(f"Device data source '{source}' does not exist")
        errors.append(str(source))
        return []

    return _load_json_file(path, errors)


def _load_json_file(path: Path, errors: list[str] | None = None) -> list[DeviceData]:
    if errors is None:
        errors = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as ex:
        log.error(f"Failed to read device data from '{path}': {ex}")
        errors.append(path.as_posix())
        return []
    devices = _devices_from_json(data, origin=path.resolve().as_posix(), errors=errors)
    log.debug(f"Loaded {len(devices)} devices from '{path}'")
    return devices


def _devices_from_json(
    data: Any, origin: str, errors: list[str] | None = None
) -> list[DeviceData]:
    if errors is None:
        errors = []
    where = f" in '{origin}'" if origin else ""
    label = origin or "input"

    # Parse summary: device data is the host document in parse_results[*].results
    if isinstance(data, dict) and "parse_results" in data:
        devices = []
        for n, result in enumerate(data.get("parse_results") or []):
            if isinstance(result, dict) and isinstance(result.get("results"), dict):
                dev = _device_from_dict(result["results"], origin, result.get("module", ""))
                if dev is None:
                    errors.append(f"{label}: parse_results[{n}]")
                    continue
                dev._cache["omitted_keys"] = _PARSE_SUMMARY_OMITTED
                devices.append(dev)
        if not devices:
            log.error(f"No device data found in the parse summary{where}")
            errors.append(label)
        return devices

    name = Path(origin).name if origin else ""

    if isinstance(data, dict):
        dev = _device_from_dict(data, origin)
        if dev is None:
            errors.append(label)
            return []
        omitted = _omitted_keys(data, name)
        if omitted:
            dev._cache["omitted_keys"] = omitted
        return [dev]

    if isinstance(data, list):
        devices = []
        for n, item in enumerate(data):
            if not isinstance(item, dict):
                log.error(f"Invalid device data{where}: expected objects in the list")
                errors.append(label)
                return []
            if isinstance(item.get("results"), dict) and "module" in item:  # parse result
                dev = _device_from_dict(item["results"], origin, item["module"])
                item_omitted = _PARSE_SUMMARY_OMITTED
            else:
                dev = _device_from_dict(item, origin)
                item_omitted = _omitted_keys(item, name)
            if dev is None:
                errors.append(f"{label}: [{n}]")
                continue
            if item_omitted:
                dev._cache["omitted_keys"] = item_omitted
            devices.append(dev)
        return devices

    log.error(f"Invalid device data{where}: expected a JSON object or list")
    errors.append(label)
    return []


def _omitted_keys(data: dict, file_name: str) -> tuple[str, ...]:
    """
    Keys of the device document ``data`` that are not compared because its format
    may not contain them. ``device-data-full.json`` files have all keys, and
    ``device-data-summary.json`` files none of :data:`_DEVICE_SUMMARY_OMITTED`.
    For other inputs (standard input, other file names, Python objects) the format
    is guessed from the keys, since empty lists are absent from every format: a
    document without any of these lists may be a device summary, and one without
    ``relationships`` may be a host document (``DeviceData.elastic()``, e.g. the
    output of ``peat pull -P``). A list such a document has is still compared.
    """
    if file_name == "device-data-full.json":
        return ()
    if file_name == "device-data-summary.json":
        return _DEVICE_SUMMARY_OMITTED
    # (baseline_findings are never compared)
    lists = tuple(key for key in _DEVICE_SUMMARY_OMITTED if key != "baseline_findings")
    if not any(key in data for key in lists):
        return lists  # maybe a device summary
    if "relationships" not in data:
        return ("relationships",)  # maybe a host document
    return ()


def _device_from_dict(data: dict, origin: str, module_name: str = "") -> DeviceData | None:
    data = dict(data)
    created = data.pop("created", None)
    for key in _DERIVED_HOST_KEYS:
        data.pop(key, None)
    if isinstance(data.get("module"), list):
        modules = []
        for mod in data["module"]:
            if isinstance(mod, dict):
                mod = {k: v for k, v in mod.items() if k not in _DERIVED_HOST_KEYS}
            modules.append(mod)
        data["module"] = modules

    try:
        dev = DeviceData.parse_obj(data)
    except ValidationError as ex:
        where = f" in '{origin}'" if origin else ""
        log.error(f"Invalid device data{where}: {ex}")
        return None

    if created:
        observed = _parse_time(created)
        if observed:
            dev._cache["observed"] = observed
    if origin:
        dev._cache["source_file"] = origin

    # Module that produced the data (selectors with "peat_module", known defaults)
    if not module_name:
        names = {f.peat_module for f in dev.files if f.peat_module}
        if len(names) == 1:
            module_name = names.pop()
    if module_name:
        module = module_api.get_module(module_name)
        if module:
            dev._module = module

    return dev


def _parse_time(value: Any) -> datetime | None:
    """Parse an ISO time; naive values are local time of the PEAT host (``created``)."""
    try:
        when = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except ValueError:
        log.debug(f"Invalid 'created' time in device data: {value!r}")
        return None
    return when.astimezone(UTC)


# --------------------------------------------------------------------------- #
# Creating, loading and saving baselines
# --------------------------------------------------------------------------- #
def create_baseline(
    dev: DeviceData | list[DeviceData],
    kind: BaselineKind = "first_observed",
    *,
    baseline_id: str = "",
    name: str = "",
    description: str = "",
    version: str = "1",
    author: str = "",
    scope: Literal["device", "device_type"] = "device",
    source_file: str | Path | None = None,
    ignore: list[str] | None = None,
) -> Baseline:
    """
    Create a snapshot baseline from device data.

    - Scope ``device`` (one device): the ``expected`` snapshot is the device's
      exported data without events, memory, UEFI data, baseline findings and raw
      ``original`` blobs (values that are never compared). The selector matches the
      device's ``id`` (``serial_number`` if it has no ``id``).
    - Scope ``device_type`` (one or more devices of ONE type, a "typical device"
      profile): the snapshot is :func:`~peat.data.baseline.device_type_profile`
      (per-unit identity removed; with several devices, only what all of them
      share), the values that differ between the devices are added to ``ignore``
      (:func:`~peat.data.baseline.varying_paths`), and the selector matches the
      ``vendor_id`` and ``model`` of the devices.

    The selector values are escaped, so glob characters in them (``*``, ``?``,
    ``[``) match only themselves.

    Defaults: ID ``<device id>@<observed time>`` (device) or
    ``<vendor>-<model>-typical`` (device type), name ``<device id> <kind>``
    (device) or ``Typical <vendor> <model>`` (device type). The provenance records
    the creation time, author (default: the OS user name), observation time (the
    ``created`` time of the loaded device data file, if known), source device and
    file (with its SHA-256), PEAT run ID and PEAT version.

    Args:
        dev: device, or devices of one type for ``scope="device_type"``
        kind: provenance class of the expected values
            (see :attr:`Baseline.kind <peat.data.models.Baseline.kind>`)
        baseline_id: baseline ID
        name: baseline name
        description: baseline description
        version: baseline version
        author: who created the baseline
        scope: ``device`` or ``device_type``
        source_file: file the device data came from (default: the file it was
            loaded from with :func:`load_device_data`, if any)
        ignore: additional path patterns to ignore in comparisons

    Returns:
        The new baseline

    Raises:
        PeatError: no device, several devices for scope ``device``, devices of
            different types, or invalid values
    """
    devices = list(dev) if isinstance(dev, (list, tuple)) else [dev]
    if not devices:
        raise PeatError("No device data to create a baseline from")

    now = utils.utc_now()
    ignore = list(ignore or [])

    # Lossy inputs (parse/device summaries) do not have these keys: a baseline
    # can't say anything about them, so they are not compared
    omitted = sorted({k for d in devices for k in d._cache.get("omitted_keys", ())})
    if omitted:
        log.warning(
            f"The device data may be a summary without {', '.join(omitted)} (or "
            f"has none of them): they are added to the baseline's 'ignore' list. "
            f"Use device-data-full.json files to include them."
        )
        ignore.extend(k for k in omitted if k not in ignore)
    provenance = BaselineProvenance(
        created=now,
        author=author or str(consts.SYSINFO.get("username", "")),
        run_id=str(consts.RUN_ID),
        peat_version=__version__,
    )

    if scope == "device":
        if len(devices) != 1:
            raise PeatError(
                f"A 'device' baseline is created from exactly one device "
                f"(got {len(devices)}). Create one baseline per device, or use "
                f"scope 'device_type' for a profile of several devices of one type."
            )
        device = devices[0]
        dev_id = device.get_id()
        doc = device_to_doc(device)
        for key in _SNAPSHOT_EXCLUDE:
            doc.pop(key, None)
        doc = _strip_blobs(doc)
        if isinstance(doc.get("logic"), dict):
            doc["logic"].pop("formats", None)  # parsed logic, may be large (ignored)
        expected = DeviceData.parse_obj(doc)

        observed = device._cache.get("observed")
        provenance.observed = observed
        provenance.device_id = dev_id
        ts = (observed or now).astimezone(UTC)
        baseline_id = baseline_id or f"{dev_id}@{ts:%Y%m%dT%H%M%SZ}"
        name = name or f"{dev_id} {kind}"
        if device.id:
            selector = BaselineSelector(device_id=_glob_escape(device.id))
        elif device.serial_number:
            selector = BaselineSelector(serial_number=_glob_escape(device.serial_number))
        else:
            log.warning(
                f"Device '{dev_id}' has no 'id' or 'serial_number': the baseline "
                f"'{baseline_id}' applies to ALL devices. Edit its 'selector'."
            )
            selector = BaselineSelector()
    elif scope == "device_type":
        types = {(d.description.vendor.id.lower(), d.description.model.lower()) for d in devices}
        if len(types) > 1:
            found = ", ".join(sorted(f"{v or '?'} {m or '?'}" for v, m in types))
            raise PeatError(
                f"A 'device_type' baseline is created from devices of ONE "
                f"vendor and model, got: {found}"
            )
        vendor_id = devices[0].description.vendor.id
        model = devices[0].description.model
        if not vendor_id and not model:
            raise PeatError(
                "Can't create a 'device_type' baseline: the device data has no "
                "vendor ID or model (description.vendor.id, description.model)"
            )
        if not model:
            log.warning(
                f"Device data has no model: the profile applies to every {vendor_id} device"
            )
        expected = device_type_profile(devices)
        for path in varying_paths(devices):
            if path not in ignore:
                ignore.append(path)
        type_name = "-".join(p for p in (vendor_id, model) if p).replace(" ", "-")
        baseline_id = baseline_id or f"{type_name}-typical"
        name = name or " ".join(p for p in ("Typical", vendor_id, model) if p)
        selector = BaselineSelector(vendor_id=_glob_escape(vendor_id), model=_glob_escape(model))
        observed = [d._cache["observed"] for d in devices if d._cache.get("observed")]
        if observed:
            provenance.observed = max(observed)
        if len(devices) == 1:
            provenance.device_id = devices[0].get_id()
        else:
            provenance.extra["device_ids"] = sorted(d.get_id() for d in devices)
    else:
        raise PeatError(f"Invalid baseline scope '{scope}' (expected 'device' or 'device_type')")

    if source_file is None:
        sources = sorted({d._cache["source_file"] for d in devices if d._cache.get("source_file")})
        if len(sources) == 1:
            source_file = sources[0]
        elif sources:
            provenance.extra["source_files"] = sources
    if source_file:
        provenance.source_file = Path(source_file).as_posix()
        if Path(source_file).is_file():
            provenance.source_hash = utils.calc_hash(Path(source_file), "sha256")

    try:
        baseline = Baseline(
            id=baseline_id,
            name=name,
            description=description,
            version=version,
            kind=kind,
            scope=scope,
            selector=selector,
            provenance=provenance,
            expected=expected,
            ignore=ignore,
        )
    except ValidationError as ex:
        raise PeatError(f"Invalid baseline values: {ex}") from ex

    log.debug(f"Created {scope} baseline '{baseline.id}' ({kind})")
    return baseline


def _glob_escape(value: str) -> str:
    """
    ``value`` as a :class:`~peat.data.models.BaselineSelector` glob that matches only
    itself: ``*``, ``?`` and ``[`` become ``[*]``, ``[?]`` and ``[[]`` (e.g. the ID
    ``TEMPLATE@bay[1]`` of an IED of an ICD file named ``bay[1].icd``).
    """
    return re.sub(r"([*?\[])", r"[\1]", value)


def _strip_blobs(value: Any) -> Any:
    """Remove raw ``original`` blobs at any depth (never compared, may be huge)."""
    if isinstance(value, dict):
        return {k: _strip_blobs(v) for k, v in value.items() if k != "original"}
    if isinstance(value, list):
        return [_strip_blobs(v) for v in value]
    return value


def load_baselines(path: str | Path) -> list[Baseline]:
    """
    Load baselines from a JSON file holding one baseline object or a list of them.

    Baselines without an ID get one derived from the file name. Every rule path
    is checked with :func:`~peat.data.baseline.split_path`.

    Args:
        path: Path of the JSON file

    Returns:
        The baselines in the file

    Raises:
        PeatError: the file can't be read or contains invalid baselines
    """
    file = Path(os.path.expanduser(str(path)))
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as ex:
        raise PeatError(f"Failed to read baseline file '{file}': {ex}") from ex

    items = data if isinstance(data, list) else [data]
    baselines: list[Baseline] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise PeatError(f"Invalid baseline file '{file}': expected JSON object(s)")
        try:
            baseline = Baseline.parse_obj(item)
        except ValidationError as ex:
            raise PeatError(f"Invalid baseline #{index + 1} in '{file}': {ex}") from ex
        for rule in baseline.rules:
            try:
                split_path(rule.path)
            except ValueError as ex:
                raise PeatError(
                    f"Invalid path in rule '{rule.id or rule.path}' of baseline "
                    f"#{index + 1} in '{file}': {ex}"
                ) from ex
        if not baseline.id:
            baseline.id = file.stem if len(items) == 1 else f"{file.stem}-{index + 1}"
            log.warning(f"Baseline #{index + 1} in '{file}' has no 'id', using '{baseline.id}'")
        baselines.append(baseline)

    log.debug(f"Loaded {len(baselines)} baselines from '{file}'")
    return baselines


def save_baselines(baselines: Baseline | list[Baseline], path: str | Path) -> Path:
    """
    Save baselines to a JSON file (fields with default values are omitted).

    One baseline is written as a JSON object, several as a JSON list.
    Parent directories are created.

    Args:
        baselines: the baseline(s) to save
        path: Path of the JSON file (overwritten if it exists)

    Returns:
        Path of the written file
    """
    items = baselines if isinstance(baselines, list) else [baselines]
    docs = [json.loads(b.json(exclude_defaults=True)) for b in items]
    file = Path(os.path.expanduser(str(path)))
    file.parent.mkdir(parents=True, exist_ok=True)
    data = docs[0] if len(docs) == 1 else docs
    file.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
    log.debug(f"Saved {len(docs)} baselines to '{file}'")
    return file


# --------------------------------------------------------------------------- #
# Comparing
# --------------------------------------------------------------------------- #
def get_known_defaults(
    dev: DeviceData | None = None,
    modules: list[str | type[DeviceModule]] | None = None,
) -> list[Baseline]:
    """
    Known-default baselines declared by PEAT modules
    (:meth:`DeviceModule.get_known_defaults <peat.device.DeviceModule.get_known_defaults>`).

    Modules searched: ``modules`` (names, aliases or classes) if given, else the
    module of ``dev`` (``dev._module``) if known, else every module whose
    ``vendor_id`` equals ``dev.description.vendor.id`` (case-insensitive), else all
    imported modules. Baselines with the same ID (inherited by several modules)
    are returned once.

    Args:
        dev: if given, only baselines whose selector matches this device are returned
        modules: PEAT modules to get the known defaults of

    Returns:
        The known-default baselines
    """
    if modules:
        mods = module_api.lookup_types(list(modules))
        if not mods:
            log.warning(f"No PEAT modules found for {modules}")
    elif dev is not None and dev._module:
        mods = [dev._module]
    else:
        mods = []
        if dev is not None and dev.description.vendor.id:
            vendor_id = dev.description.vendor.id.lower()
            mods = [
                m
                for m in module_api.classes
                if str(getattr(m, "vendor_id", "") or "").lower() == vendor_id
            ]
        if not mods:
            mods = module_api.classes

    results: list[Baseline] = []
    seen: set[str] = set()
    for mod in mods:
        for baseline in mod.get_known_defaults():
            if baseline.id in seen:
                continue
            seen.add(baseline.id)
            if dev is None or baseline.selector.matches(dev):
                results.append(baseline)
    return results


def compare_to_baseline(
    dev: DeviceData,
    baselines: Baseline | list[Baseline],
    *,
    store: bool = True,
    include_passed: bool = True,
) -> list[BaselineFinding]:
    """
    Compare a device to baselines.

    Runs :func:`peat.data.baseline.compare_device` for each baseline, with one
    shared timestamp. Baselines whose selector does not match the device produce
    no findings.

    Args:
        dev: the device to check
        baselines: the baseline(s) to compare against
        store: store the findings in ``dev.baseline_findings``. Earlier findings
            of the compared baselines are replaced
            (:func:`peat.data.baseline.store_findings`).
        include_passed: include findings of passed rules

    Returns:
        The findings, sorted
    """
    if isinstance(baselines, Baseline):
        baselines = [baselines]

    timestamp = utils.utc_now()
    findings: list[BaselineFinding] = []
    compared: set[str] = set()
    for baseline in baselines:
        if not baseline.selector.matches(dev):
            log.trace(f"Baseline '{baseline.id}' does not apply to device '{dev.get_id()}'")
            continue
        compared.add(baseline.id)
        findings.extend(
            _compare_device(dev, baseline, include_passed=include_passed, timestamp=timestamp)
        )

    sort_model_list(findings)
    if store and compared:
        # Also replace the old findings of baselines that have none this time
        dev.baseline_findings[:] = [
            f for f in dev.baseline_findings if f.baseline_id not in compared
        ]
        store_findings(dev, findings)

    log.debug(
        f"Compared device '{dev.get_id()}' to {len(compared)} baselines: "
        f"{len(findings)} findings ({sum(f.result == 'fail' for f in findings)} failed)"
    )
    return findings


def compare_to_known_defaults(
    dev: DeviceData, *, store: bool = True, include_passed: bool = True
) -> list[BaselineFinding]:
    """
    Compare a device to the known defaults of its PEAT module(s) (:func:`get_known_defaults`).

    Args:
        dev: the device to check
        store: store the findings in ``dev.baseline_findings``
        include_passed: include findings of passed rules

    Returns:
        The findings, sorted
    """
    return compare_to_baseline(
        dev, get_known_defaults(dev), store=store, include_passed=include_passed
    )


def summarize_findings(findings: list[BaselineFinding]) -> dict[str, Any]:
    """
    Summarize findings.

    Returns:
        :class:`dict` with ``total``, ``by_result``, ``by_severity`` and
        ``by_category`` (failed findings only), ``baselines`` (IDs) and
        ``max_severity`` (highest severity of a failed finding, or ``""``)
    """
    failed = [f for f in findings if f.result == "fail"]
    by_severity = Counter(f.severity for f in failed if f.severity)
    max_severity = ""
    if by_severity:
        max_severity = max(by_severity, key=lambda s: SEVERITY_NUMBER[s])
    return {
        "total": len(findings),
        "by_result": dict(sorted(Counter(f.result for f in findings).items())),
        "by_severity": dict(sorted(by_severity.items(), key=lambda i: -SEVERITY_NUMBER[i[0]])),
        "by_category": dict(sorted(Counter(f.category or "other" for f in failed).items())),
        "baselines": sorted({f.baseline_id for f in findings}),
        "max_severity": max_severity,
    }


def export_findings(dev: DeviceData, findings: list[BaselineFinding]) -> bool:
    """
    Export findings of a device: ``baseline-findings.json`` (a list of finding
    objects) in the device's output directory, if device file output is enabled
    (:attr:`DEVICE_DIR <peat.settings.Configuration.DEVICE_DIR>`), and the
    ``ELASTIC_BASELINE_FINDINGS_INDEX`` index, if Elasticsearch or OpenSearch is
    configured (:attr:`state.elastic <peat.settings.State.elastic>`).

    Args:
        dev: the device the findings are about
        findings: the findings to export

    Returns:
        :obj:`False` if the Elasticsearch/OpenSearch export failed, otherwise :obj:`True`
    """
    if config.DEVICE_DIR or dev._out_dir:
        data = [
            strip_empty_and_private(consts.convert(f.dict(exclude_defaults=True)))
            for f in findings
        ]
        path = dev.write_file(data, "baseline-findings.json", overwrite_existing=True)
        log.info(f"Saved {len(findings)} findings to {utils.short_pth_str(path, 4)}")

    if state.elastic and findings:
        log.info(
            f"Exporting {len(findings)} findings of device '{dev.get_id()}' to "
            f"{state.elastic.type} (index basename: {config.ELASTIC_BASELINE_FINDINGS_INDEX})"
        )
        if not export_models_to_elastic(findings, dev, state.elastic):
            return False
    return True


# --------------------------------------------------------------------------- #
# Command line interface
# --------------------------------------------------------------------------- #
def run_baseline(args: dict[str, Any]) -> int:
    """
    Run ``peat baseline-create``, ``peat baseline-compare`` or ``peat baseline-show``
    (dispatched on ``args["func"]``).

    Args:
        args: Command line arguments (from :mod:`peat.cli_args`)

    Returns:
        Exit code: 0 (success, even if there are findings), 1 (error: bad input,
        unreadable files, no device data, or no baseline applies to any device),
        or 3 (``baseline-compare --fail-on``: a failed finding with that severity
        or higher)
    """
    func = args.get("func")
    if func not in _BASELINE_COMMANDS:
        log.error(f"Unknown baseline command '{func}'")
        return 1

    if config.DRY_RUN:
        log.warning(f"Dry run enabled, skipping {func.replace('_', '-')}")
        return 0

    try:
        if func == "baseline_create":
            return _run_create(args)
        if func == "baseline_compare":
            return _run_compare(args)
        return _run_show(args)
    except PeatError as ex:
        log.error(str(ex))
        return 1


def _load_inputs(inputs: list[str]) -> list[DeviceData] | None:
    """
    Load all inputs; None if any input, or any file or device in an input,
    fails to load (the error is logged).
    """
    devices: list[DeviceData] = []
    for source in inputs:
        errors: list[str] = []
        loaded = load_device_data(source, errors)
        if errors:
            log.error(
                f"Failed to load device data from '{source}': {', '.join(errors)} "
                f"(see the errors above)"
            )
            return None
        if not loaded:
            log.error(f"No device data loaded from '{source}'")
            return None
        devices.extend(loaded)

    counts = Counter(d.get_id() for d in devices)
    for dev_id, count in sorted(counts.items()):
        if count > 1:
            log.warning(
                f"Device '{dev_id}' is in {count} inputs: its results are "
                f"written to the same files (the last one wins)"
            )
    return devices


def _load_baseline_args(args: dict[str, Any]) -> tuple[list[Baseline], bool, list[str] | None]:
    baselines: list[Baseline] = []
    for file in args.get("baseline_files") or []:
        baselines.extend(load_baselines(file))
    use_known = bool(args.get("known_defaults"))
    device_types = args.get("device_types") or None
    if device_types and not use_known:
        log.warning("-d/--device only limits --known-defaults, it has no effect without it")
    return baselines, use_known, device_types


def _run_create(args: dict[str, Any]) -> int:
    inputs = args.get("input_source") or []
    if not inputs:
        log.error(
            "No input given: specify PEAT device data files or directories, "
            "e.g. 'peat baseline-create peat_results/<run>/devices/'"
        )
        return 1

    devices = _load_inputs(inputs)
    if devices is None:
        return 1

    scope = args.get("baseline_scope") or "device"
    options = {
        "kind": args.get("baseline_kind") or "first_observed",
        "name": args.get("baseline_name") or "",
        "description": args.get("baseline_description") or "",
        "version": args.get("baseline_version") or "1",
        "author": args.get("baseline_author") or "",
        "scope": scope,
    }
    if scope == "device_type":
        baselines = [
            create_baseline(devices, baseline_id=args.get("baseline_id") or "", **options)
        ]
    else:
        if args.get("baseline_id") and len(devices) > 1:
            log.error(
                f"--baseline-id can only be used with one device "
                f"({len(devices)} devices were loaded)"
            )
            return 1
        baselines = [
            create_baseline(dev, baseline_id=args.get("baseline_id") or "", **options)
            for dev in devices
        ]

    output = args.get("baseline_output")
    if output:
        path = save_baselines(baselines if len(baselines) > 1 else baselines[0], output)
        log.info(f"Saved {len(baselines)} baselines to {path}")
    else:
        if not config.RUN_DIR:
            log.error("Output directory is disabled: use -w/--write-file to save the baseline")
            return 1
        used: set[str] = set()
        for baseline, dev in zip(
            baselines, devices if scope == "device" else [None] * len(baselines), strict=True
        ):
            stem = address_to_pathname(dev.get_id() if dev else baseline.id)
            filename = consts.sanitize_filename(f"baseline-{stem}.json")
            number = 2
            while filename in used:
                filename = consts.sanitize_filename(f"baseline-{stem}-{number}.json")
                number += 1
            used.add(filename)
            path = save_baselines(baseline, config.RUN_DIR / "baselines" / filename)
            log.info(f"Saved baseline '{baseline.id}' to {path}")

    if config.PRINT_RESULTS:
        docs = [json.loads(b.json(exclude_defaults=True)) for b in baselines]
        print(json.dumps(docs[0] if len(docs) == 1 else docs, indent=4), flush=True)  # noqa: T201
    return 0


def _run_compare(args: dict[str, Any]) -> int:
    inputs = args.get("input_source") or []
    if not inputs:
        log.error(
            "No input given: specify PEAT device data files or directories, "
            "e.g. 'peat baseline-compare -b baseline.json peat_results/<run>/devices/'"
        )
        return 1
    if not args.get("baseline_files") and not args.get("known_defaults"):
        log.error("Specify baseline files (-b/--baseline) and/or --known-defaults")
        return 1

    baselines, use_known, device_types = _load_baseline_args(args)
    devices = _load_inputs(inputs)
    if devices is None:
        return 1

    include_passed = not args.get("no_passed")
    fail_on = args.get("fail_on") or ""
    threshold = SEVERITY_NUMBER[fail_on] if fail_on else 0
    threshold_reached = False
    export_ok = True
    results = []
    tables = []

    for dev in devices:
        applicable = [b for b in baselines if b.selector.matches(dev)]
        if use_known:
            applicable.extend(get_known_defaults(dev, device_types))
        dev_id = dev.get_id()
        if not applicable:
            log.warning(f"No baseline applies to device '{dev_id}'")
            continue

        findings = compare_to_baseline(dev, applicable, include_passed=include_passed)
        summary = summarize_findings(findings)
        log.info(
            f"Device '{dev_id}': {summary['total']} findings from {len(applicable)} "
            f"baselines ({summary['by_result'].get('fail', 0)} failed)"
        )
        if not export_findings(dev, findings):
            export_ok = False

        if threshold and any(
            f.result == "fail" and SEVERITY_NUMBER[f.severity] >= threshold for f in findings
        ):
            threshold_reached = True

        results.append(
            {
                "device_id": dev_id,
                "source": dev._cache.get("source_file", ""),
                "baselines": [b.id for b in applicable],
                "summary": summary,
                "findings": [
                    strip_empty_and_private(consts.convert(f.dict(exclude_defaults=True)))
                    for f in findings
                ],
            }
        )
        tables.append(_findings_table(dev_id, [b.id for b in applicable], findings, summary))

    if not results:
        log.error(f"No baseline applies to any of the {len(devices)} devices")
        return 1

    run_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "compared": utils.utc_now().isoformat(),
        "fail_on": fail_on,
        "threshold_reached": threshold_reached,
        "devices": results,
    }
    utils.save_results_summary(run_summary, "baseline-summary")

    if config.PRINT_RESULTS:
        print(json.dumps({"devices": results}, indent=4), flush=True)  # noqa: T201
    else:
        print("\n\n".join(tables), flush=True)  # noqa: T201

    if not export_ok:
        return 1
    if threshold_reached:
        log.warning(f"Found failed findings with severity '{fail_on}' or higher")
        return 3
    return 0


def _findings_table(
    dev_id: str, baseline_ids: list[str], findings: list[BaselineFinding], summary: dict
) -> str:
    """Fixed-width text table of the findings that did not pass, and a summary line."""
    rows = [f for f in findings if f.result != "pass"]
    rows.sort(key=lambda f: (-SEVERITY_NUMBER[f.severity], f.result, f.path, f.rule_id))
    lines = [f"Device {dev_id} (baselines: {', '.join(baseline_ids)})"]
    if rows:
        path_width = min(max(len("PATH"), *(len(f.path) for f in rows)), 60)
        lines.append(
            f"{'SEVERITY':<8}  {'RESULT':<7}  {'DIFFERENCE':<10}  {'PATH':<{path_width}}  REASON"
        )
        for f in rows:
            lines.append(
                f"{f.severity or '-':<8}  {f.result:<7}  {f.difference or '-':<10}  "
                f"{f.path:<{path_width}}  {f.reason}".rstrip()
            )
    counts = summary["by_result"]
    text = (
        f"{dev_id}: {summary['total']} findings, {counts.get('fail', 0)} failed, "
        f"{counts.get('pass', 0)} passed"
    )
    other = summary["total"] - counts.get("fail", 0) - counts.get("pass", 0)
    if other:
        text += f", {other} unknown/error"
    if summary["max_severity"]:
        text += f" (max severity: {summary['max_severity']})"
    lines.append(text)
    return "\n".join(lines)


def _run_show(args: dict[str, Any]) -> int:
    if not args.get("baseline_files") and not args.get("known_defaults"):
        log.error("Specify baseline files (-b/--baseline) and/or --known-defaults")
        return 1

    baselines, use_known, device_types = _load_baseline_args(args)
    if use_known:
        known = get_known_defaults(None, device_types)
        if not known:
            log.warning("No known-default baselines found for the selected PEAT modules")
        baselines.extend(known)

    docs = [json.loads(b.json(exclude_defaults=True)) for b in baselines]
    print(json.dumps(docs, indent=4), flush=True)  # noqa: T201
    return 0


__all__ = [
    "compare_to_baseline",
    "compare_to_known_defaults",
    "create_baseline",
    "export_findings",
    "get_known_defaults",
    "load_baselines",
    "load_device_data",
    "run_baseline",
    "save_baselines",
    "summarize_findings",
]
