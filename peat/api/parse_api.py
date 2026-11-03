import sys
import timeit
from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatchcase
from operator import itemgetter
from pathlib import Path
from typing import TextIO

from peat import (
    DeviceData,
    DeviceModule,
    __version__,
    config,
    consts,
    datastore,
    log,
    module_api,
    state,
    utils,
)


def parse(
    filepaths: str | Path | list[str | Path],
    device_types: list[type[DeviceModule] | str] | None = None,
    sub_dirs: bool = True,
) -> dict[str, dict | list | str | float | int] | None:
    """
    Find and parse device and/or project files.

    Args:
        filepaths: File or directory paths to parse,
            or ``"-"`` to read from standard input (``stdin``).
        device_types: names, aliases, or classes of PEAT device modules to use.
            If :class:`None`, all currently imported modules are used.
        sub_dirs: If sub-directories of a directory path should be searched

    Returns:
        :ref:`pull-summary` as a :class:`dict`, or :obj:`None` if an error occurred
    """
    if isinstance(filepaths, (str, Path)):
        filepaths = [filepaths]

    log.info(f"Parsing {len(filepaths)} filepaths")

    paths = []
    for fp in filepaths:
        checked = utils.check_file(fp)
        if not checked:
            return None
        paths.append(checked)

    # Convert mixed device types/aliases into canonical PEAT device modules
    mods = module_api.lookup_types(device_types)
    if not mods:
        log.error("No valid device types specified for parse")
        return None

    log.debug(
        f"Filtering parse-capable modules out of {len(mods)} "
        f"modules ({[x.__name__ for x in mods]})"
    )
    resolved_types = []
    for mod in mods:
        if mod.filename_patterns or mod.file_signatures:
            resolved_types.append(mod)
        # elif to prevent module being added twice
        elif mod.can_parse_dir:
            for fp in paths:
                if str(fp) != "-" and Path(fp).is_dir():
                    resolved_types.append(mod)
                    break

    if not resolved_types:
        log.error(
            f"None of the specified modules support parsing (modules: "
            f"{str([x.__name__ for x in mods]).strip('[]')})"
        )
        return None
    log.debug(
        f"Parsing using {len(resolved_types)} parse-capable modules: "
        f"{str([x.__name__ for x in resolved_types]).strip('[]')}"
    )

    # Disable automatic lookup of host information unless user has explicitly enabled it
    for key in ["RESOLVE_IP", "RESOLVE_MAC", "RESOLVE_HOSTNAME"]:
        if not config.non_default(key):
            log.trace(f"Setting default config '{key}' to False for parsing")
            setattr(config, key, False)

    # Should only specify a single device type for reading from stdin
    if len(resolved_types) > 1 and any(str(fp) == "-" for fp in paths):
        log.error(
            "You must specify a single device type for input from standard "
            "input (stdin). Add the '-d' flag, e.g. 'cat somefile | peat "
            "parse -d somemodule -'"
        )
        return None

    start_time = timeit.default_timer()
    parse_results = []
    parsed_devices = []

    # Devices that a successful parse of a file filled besides the device it returned
    # (e.g. one device per IED in an IEC 61850 SCD file): the devices it created, and
    # the existing devices the module lists in dev._cache["parse_devices"] (e.g. the
    # placeholder of a "hosts" entry of the PEAT config file that an IED reused).
    # They are pushed to Elasticsearch and are in the parse results as well. Devices
    # left behind by a failed parse are not: their files are not exported either.
    # (parse result of the file, devices filled by the parse)
    created: list[tuple[dict, list[DeviceData]]] = []

    def _parse_file(source: Path | str, dev_cls: type[DeviceModule]) -> None:
        before = list(datastore.objects)  # references keep their id() unique
        before_ids = {id(d) for d in before}
        dev = parse_data(source, dev_cls)
        filled = dev._cache.pop("parse_devices", []) if dev is not None else []

        parsed_devices.append(dev)
        result = {
            "name": source.name if isinstance(source, Path) else "stdin",
            "path": source.as_posix() if isinstance(source, Path) else "stdin",
            "module": dev_cls.__name__,
            "results": dev.elastic() if dev else {},
        }
        parse_results.append(result)
        if dev is not None:
            new = [d for d in datastore.objects if id(d) not in before_ids]
            new.extend(d for d in filled if id(d) in before_ids)  # existing devices
            created.append((result, new))

    # Iterate over the user-provided path arguments
    # TODO: breakup this logic a bit
    for path in paths:
        log.trace2(f"Parsing path: {path}")

        # Cases:
        # - single module + stdin (ex: 'cat set_all.txt | peat parse -d selrelay -')
        # - single module + single file (ex: 'peat parse -d selrelay ./set_all.txt')
        # - single module + directory input (ex: 'peat parse -d sage ./sage_files/')
        #
        # If a file AND single device module, don't try to use the file glob.
        #   Handles edge cases and custom names.
        # '-' -> read from standard input stream (file redirection or pipes)
        # NOTE: directories require a single module type (for now)
        if len(resolved_types) == 1 and (
            str(path) == "-"
            or Path(path).is_file()
            or (Path(path).is_dir() and resolved_types[0].can_parse_dir)
        ):
            _parse_file(path, resolved_types[0])

        # Cases:
        # - single module + directory + module isn't directory-aware
        # - multi-module + single file (ex: 'peat parse ./somefile.txt')
        # - multi-module + directory (ex: 'peat parse ./somedir/')
        else:
            # Procedure:
            # - Collect tree of files
            # - Run fingerprinters on all files
            # - For remaining files, match using filename patterns.
            #      -> make this behavior configurable, like a --only-fingerprints option

            # TODO: fingerprint to detect if directory of files matches, then parse the whole
            #   directory as one device.  file signatures may help, but not sufficient.
            # TODO: add something to API to specify a group of files should be passed?  similar
            #   to directory, though more targeted; possibly useful for data aggregation needs
            # TODO: during a pass of multiple files, group files by module
            #   pass the same dev object to multiple parses?
            #   or update devices' parse logic to do smarter lookups?

            all_files = sorted(utils.collect_files(Path(path), sub_dirs))

            for dev_cls in resolved_types:
                for file_path in find_parsable_files(all_files, dev_cls):
                    _parse_file(file_path, dev_cls)

    # * Deduplicate *
    before_dedupe = list(datastore.objects)  # references keep their id() unique
    datastore.deduplicate(prune_inactive=False)

    # Devices that successful parses filled besides the devices they returned and
    # that are still in the datastore (not merged into another device)
    current = {id(d) for d in datastore.objects}
    returned = [d for d in parsed_devices if d is not None]
    parse_ids = {id(d) for d in returned}  # devices of this parse
    other_devices: dict[int, list[DeviceData]] = {}  # id(parse result) -> devices
    for result, devices in created:
        for c_dev in devices:
            if id(c_dev) in current and id(c_dev) not in parse_ids:
                parse_ids.add(id(c_dev))  # each device once
                other_devices.setdefault(id(result), []).append(c_dev)

    # A device of this parse that de-duplication merged into another device (e.g. into
    # the placeholder of a "hosts" entry of the PEAT config file, with the label and
    # asset context of the entry) is replaced by the device that has its data now.
    # That device writes its files to the output directory of the merged device, which
    # has the earlier exports of the device, unless it has an output directory already.
    # The parse result of a merged device that a parse returned stays its state after
    # the file; a merged device that a parse created or filled is replaced in the
    # parse results too (each device once).
    of_parse = parse_ids | {id(d) for _, devices in created for d in devices}
    survivors: dict[int, DeviceData] = {}  # id(merged device) -> device it is in
    for m_dev in before_dedupe:
        if id(m_dev) in of_parse and id(m_dev) not in current:
            survivor = next((s for s in datastore.objects if s.is_duplicate(m_dev)), None)
            if survivor is not None:
                survivors[id(m_dev)] = survivor
                if not survivor._out_dir and m_dev._out_dir:
                    survivor._out_dir = m_dev._out_dir
    parse_ids.update(id(survivors[id(d)]) for d in returned if id(d) in survivors)
    for result, devices in created:
        for c_dev in devices:
            survivor = survivors.get(id(c_dev))
            if survivor is not None and id(survivor) not in parse_ids:
                parse_ids.add(id(survivor))
                other_devices.setdefault(id(result), []).append(survivor)

    # Devices that are not part of this parse (neither parsed nor filled by it) are
    # neither exported nor pushed
    parse_devices = [d for d in datastore.objects if id(d) in parse_ids]

    # * Export the final state of the devices to files *
    # DeviceModule.parse() exports a device after each file: the state after a later
    # file of the same device went to "device-data-full.json.1", ".2", ... Like pull
    # and scan, "device-data-full.json" gets the final (merged) state of each device.
    # Different devices can have the same output directory (IDs that differ only in
    # case or separators, or the same name, e.g. SEL event files of one relay): only
    # the first device overwrites its files, the others write numbered files.
    if config.DEVICE_DIR:
        written: dict[Path, DeviceData] = {}  # output directory -> first device
        for f_dev in parse_devices:
            out_dir = f_dev.get_out_dir()
            first = written.setdefault(out_dir, f_dev)
            if first is not f_dev:
                log.warning(
                    f"Devices {_dev_name(first)} and {_dev_name(f_dev)} have the same "
                    f"output directory '{out_dir.as_posix()}': the final state of the "
                    f"second device is in numbered files (device-data-full.json.<n>)"
                )
            f_dev.export_to_files(overwrite_existing=first is f_dev)

    # * Push results to Elasticsearch *
    if state.elastic:
        for d_dev in parse_devices:
            d_dev.export_to_elastic()

    # * Construct the parse results summary *
    parse_results.sort(key=itemgetter("module"))  # sort by device module
    files_parsed = [r["path"] for r in parse_results]

    parse_successes = []
    parse_failures = []
    for result in parse_results:
        if result["results"]:
            parse_successes.append(result)
            # one result per device: the other devices created by the parse of the
            # file (e.g. the other IEDs of an SCD file) follow the device it returned
            for o_dev in other_devices.get(id(result), []):
                o_results = o_dev.elastic()
                if o_results:
                    parse_successes.append({**result, "results": o_results})
        else:
            del result["results"]
            parse_failures.append(result)
    num_parse_successes = len(parse_results) - len(parse_failures)

    parse_duration = timeit.default_timer() - start_time

    parse_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "parse_duration": parse_duration,
        "parse_modules": module_api.lookup_names(device_types),
        "input_paths": filepaths,
        "files_parsed": files_parsed,
        "num_files_parsed": len(files_parsed),
        "num_parse_successes": num_parse_successes,
        "num_parse_failures": len(parse_failures),
        "parse_failures": parse_failures,
        "parse_results": parse_successes,
    }

    # * Save parse results summary to a file *
    utils.save_results_summary(parse_summary, "parse-summary")

    # * Push parse results summary to Elasticsearch *
    if state.elastic:
        log.info(
            f"Pushing parse result summary to {state.elastic.type} "
            f"(index basename: {config.ELASTIC_PARSE_INDEX})"
        )

        if not state.elastic.push(config.ELASTIC_PARSE_INDEX, parse_summary):
            log.error(f"Failed to push parse result summary to {state.elastic.type}")

    log.info(
        f"Completed parsing of {len(parse_results)} files in {utils.fmt_duration(parse_duration)}"
    )
    return parse_summary


def _dev_name(dev: DeviceData) -> str:
    """Device ID for log messages, with its ``id`` if that is different."""
    dev_id = dev.get_id()
    return f"'{dev_id}' (id '{dev.id}')" if dev.id and dev.id != dev_id else f"'{dev_id}'"


def parse_data(source: str | Path | TextIO, dev_cls: type[DeviceModule]) -> DeviceData | None:
    log.info(f"Parsing {dev_cls.__name__} file '{source}'")

    # Read data as bytes from stdin (CLI input, e.g. pipes or redirection)
    if isinstance(source, str) and source == "-":
        log.debug("Parse data is from standard input (stdin)")
        source = sys.stdin
    # source is assumed to be a filename, make it a Path for DeviceModule.parse()
    elif isinstance(source, str):
        source = Path(source)

    try:
        parsed_dev = dev_cls.parse(source)
    except Exception as ex:
        log.exception(f"Failed to parse '{source}' due to exception: {ex}")
        state.error = True
        return None

    if not parsed_dev:
        log.warning(f"Failed to parse data from '{source}' using {dev_cls.__name__}")
        state.error = True
        return None

    return parsed_dev


def find_parsable_files(files: list[str], dev_cls: type[DeviceModule]) -> list[Path]:
    """Find files that are parsable by a device type."""
    parsable_files = set()  # Prevent conflicts
    log.debug(f"Searching {len(files)} files for {dev_cls.__name__} files")

    def is_parsable(filename: str) -> None | str:
        # Favor fast matching first to limit overall delay and resource consumption
        if parsable_file_by_pattern(filename, dev_cls) or parsable_file_by_signature(
            filename, dev_cls
        ):
            return filename
        return None

    # Get configurable worker thread count
    max_workers: int | None = config.OVERRIDE_MAX_FILE_DISCOVERY_THREADS
    if max_workers is not None and max_workers > 0 and config.MAX_THREADS > 0:
        max_workers = min(max_workers, config.MAX_THREADS)  # maintains upper bound
    else:
        max_workers = None  # defaults ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(is_parsable, files)
        for result in results:
            if result is not None:
                parsable_files.add(result)

    if not parsable_files:
        log.debug(f"No parsable files found for {dev_cls.__name__}")
        return []

    sorted_files = sorted(parsable_files)  # convert set to list and sort
    log.trace2(f"Parsable files for {dev_cls.__name__}: {sorted_files}")
    sorted_paths = [Path(file).resolve() for file in sorted_files]
    return sorted_paths


def parsable_file_by_pattern(filename: str, dev_cls: type[DeviceModule]) -> bool:
    """Determine if file matches device type filename patterns."""
    for pattern in dev_cls.filename_patterns:
        if pattern[0] != "*":
            pattern = f"*{pattern}"

        log.trace3(f"Checking {dev_cls.__name__}'s pattern '{pattern}' against {filename}")
        if fnmatchcase(filename.lower(), pattern.lower()):
            log.debug(f"Pattern match ({pattern}) on {filename}")
            return True
    return False


def parsable_file_by_signature(filename: str, dev_cls: type[DeviceModule]) -> bool:
    """Determine if file matches device type file signatures."""
    for sig in dev_cls.file_signatures:
        log.trace3(f"Checking {dev_cls.__name__}'s signature '{sig}' against {filename}")
        if sig.matches(filename):
            log.debug(f"Signature match ({sig}) on {filename}")
            return True
    return False


__all__ = ["parse"]
