import os
import re
import shutil
import sys
import tempfile
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
from peat.api import disk_image_api


def parse(
    filepaths: str | Path | list[str | Path],
    device_types: list[type[DeviceModule] | str] | None = None,
    sub_dirs: bool | None = None,
    password_file: str | Path | None = None,
    copy_files: bool | None = None,
) -> dict[str, dict | list | str | float | int] | None:
    """
    Find and parse device and/or project files.

    Paths can be files, directories (including drives and mount points, such as
    ``C:\\`` or ``/mnt/disk``), or disk images (e.g. VMDK, VHDX, qcow2, raw, ISO,
    or DMG). Disk images are mounted read-only, the files to parse on each of their
    volumes are copied to :attr:`~peat.settings.Configuration.PARSE_FILES_DIR`, then
    the copies are parsed. A file with a disk image extension is only treated as a
    disk image if none of the device modules parse it.

    Files matching :attr:`~peat.settings.Configuration.COLLECT_FILE_PATTERNS` are
    copied to :attr:`~peat.settings.Configuration.PARSE_FILES_DIR` without parsing them.

    Args:
        filepaths: File, directory, or disk image paths to parse,
            or ``"-"`` to read from standard input (``stdin``).
        device_types: names, aliases, or classes of PEAT device modules to use.
            If :class:`None`, all currently imported modules are used.
        sub_dirs: If sub-directories of a directory path (or disk image volume)
            should be searched. If :obj:`None`, the value of
            :attr:`~peat.settings.Configuration.PARSE_RECURSIVE` is used.
        password_file: File with passwords to unlock encrypted disk images
            and volumes, one per line
        copy_files: Copy the files found in directories to
            :attr:`~peat.settings.Configuration.PARSE_FILES_DIR`. If :obj:`None`,
            the value of :attr:`~peat.settings.Configuration.PARSE_COPY_FILES` is used.
            Files found on disk images are always copied.

    Returns:
        :ref:`pull-summary` as a :class:`dict`, or :obj:`None` if an error occurred
    """
    if isinstance(filepaths, (str, Path)):
        filepaths = [filepaths]
    if sub_dirs is None:
        sub_dirs = config.PARSE_RECURSIVE
    if copy_files is None:
        copy_files = config.PARSE_COPY_FILES

    log.info(f"Parsing {len(filepaths)} filepaths")

    paths = []
    for fp in filepaths:
        checked = utils.check_file(fp)
        if not checked:
            return None
        if str(checked) != "-" and disk_image_api.is_disk_image(checked):
            # Not resolved, since that turns mapped network drives on Windows into
            # UNC paths, which may not be visible from an Administrator terminal
            checked = Path(os.path.abspath(os.path.expanduser(fp)))
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

    is_image = {
        str(path): str(path) != "-"
        and disk_image_api.is_disk_image(path)
        and not _is_parsable(Path(path), resolved_types)
        for path in paths
    }
    if password_file and not any(is_image.values()):
        log.warning("Ignoring the password file, since none of the paths are disk images")
    if copy_files and not config.PARSE_FILES_DIR:
        log.warning("Not copying the files that are found, since PARSE_FILES_DIR isn't set")

    start_time = timeit.default_timer()
    run = _ParseRun(resolved_types, sub_dirs, copy_files, collect_file_patterns())

    # Iterate over the user-provided path arguments
    for path in paths:
        log.trace2(f"Parsing path: {path}")

        if is_image[str(path)]:
            run.parse_disk_image(Path(path), password_file)
        else:
            run.parse_path(path)

    parse_results = run.parse_results
    parsed_devices = run.parsed_devices

    # * Deduplicate *
    datastore.deduplicate(prune_inactive=False)

    # * Push results to Elasticsearch *
    if state.elastic:
        for d_dev in datastore.objects:
            if d_dev not in parsed_devices:  # skip any not part of this parse
                log.trace(f"Skipping device not part of parse: {d_dev.get_id()}")
                continue
            d_dev.export_to_elastic()

    # * Construct the parse results summary *
    parse_results.sort(key=itemgetter("module"))  # sort by device module

    parse_successes = []
    parse_failures = []
    for result in parse_results:
        if result["results"]:
            parse_successes.append(result)
        else:
            del result["results"]
            parse_failures.append(result)

    parse_duration = timeit.default_timer() - start_time

    parse_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "parse_duration": parse_duration,
        "parse_modules": module_api.lookup_names(device_types),
        "input_paths": filepaths,
        "disk_images": run.disk_images,
        "files_parsed": [r["path"] for r in parse_results],
        "num_files_parsed": len(parse_results),
        "num_parse_successes": len(parse_successes),
        "num_parse_failures": len(parse_failures),
        "files_collected": run.collected_files,
        "num_files_collected": len(run.collected_files),
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


def pillage(source: str | Path, password_file: str | Path | None = None) -> bool:
    """
    Find and parse the files in a directory or disk image, and copy them
    to :attr:`~peat.settings.Configuration.PARSE_FILES_DIR`.

    .. deprecated:: 2026.10
       Use :func:`~peat.api.parse_api.parse` instead, which parses disk images.
       This calls it with ``copy_files=True``.

    Args:
        source: Path of a directory or disk image
        password_file: File with passwords to unlock encrypted disk images
            and volumes, one per line

    Returns:
        If the parse was successful
    """
    log.warning(
        "'peat pillage' is deprecated and will be removed in a future release. "
        "Use 'peat parse' instead, which parses disk images, e.g. "
        "'peat parse --copy-files disk.vmdk'."
    )
    summary = parse(source, password_file=password_file, copy_files=True)
    return summary is not None and not state.error


class _ParseRun:
    """The state of a call to :func:`parse`: its options, and the results so far."""

    def __init__(
        self,
        resolved_types: list[type[DeviceModule]],
        sub_dirs: bool,
        copy_files: bool,
        collect_patterns: list[str],
    ) -> None:
        self.resolved_types = resolved_types
        self.sub_dirs = sub_dirs
        self.copy_files = copy_files
        self.collect_patterns = collect_patterns
        self.parse_results: list[dict] = []
        self.parsed_devices: list[DeviceData | None] = []
        self.disk_images: list[str] = []
        self.collected_files: list[str] = []
        self._copy_dirs: dict[Path, Path] = {}

    def parse_path(self, path: str | Path) -> None:
        """Parse a file, directory, or ``"-"`` (stdin)."""
        # Cases:
        # - single module + stdin (ex: 'cat set_all.txt | peat parse -d selrelay -')
        # - single module + single file (ex: 'peat parse -d selrelay ./set_all.txt')
        # - single module + directory input (ex: 'peat parse -d sage ./sage_files/')
        #
        # If a file AND single device module, don't try to use the file glob.
        #   Handles edge cases and custom names.
        # '-' -> read from standard input stream (file redirection or pipes)
        # NOTE: directories require a single module type (for now)
        if len(self.resolved_types) == 1 and (
            str(path) == "-"
            or Path(path).is_file()
            or (Path(path).is_dir() and self.resolved_types[0].can_parse_dir)
        ):
            if self.copy_files and str(path) != "-":
                files = self._find_files(Path(path)) or []
                self._copy_tree(Path(path), [Path(f).resolve() for f in files])
            self._parse_file(path, self.resolved_types[0])
            return

        # Cases:
        # - single module + directory + module isn't directory-aware
        # - multi-module + single file (ex: 'peat parse ./somefile.txt')
        # - multi-module + directory (ex: 'peat parse ./somedir/')
        #
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
        path = Path(path)
        all_files = self._find_files(path)
        if all_files is None:
            state.error = True
            return

        matches = self._match_files(all_files)
        collected = self._match_collect_patterns(all_files, matches)

        if self.copy_files:
            self._copy_tree(path, [f for files in matches.values() for f in files])
        if collected:
            self._collect(path, collected)

        for dev_cls, files in matches.items():
            for file_path in files:
                self._parse_file(file_path, dev_cls)

    def parse_disk_image(self, image: Path, password_file: str | Path | None) -> None:
        """
        Mount a disk image, copy the files to parse on each of its volumes to
        :attr:`~peat.settings.Configuration.PARSE_FILES_DIR`, then parse the copies.
        """
        log.info(f"Parsing disk image '{image}'")
        self.disk_images.append(image.as_posix())

        temp_dir = None
        if config.PARSE_FILES_DIR:
            image_dir = self._copy_dir(image)
        else:
            # The files are still copied, since the image isn't mounted while they're parsed
            temp_dir = Path(tempfile.mkdtemp(prefix="peat_parse_files_"))
            image_dir = temp_dir / image.name
            log.warning(
                f"PARSE_FILES_DIR isn't set, so the files found on '{image.name}' are "
                f"copied to a temporary directory to parse them ('{temp_dir}'), "
                f"which is deleted after they're parsed"
            )

        volume_count = 0

        def _search_volume(volume: str) -> bool:
            nonlocal volume_count
            volume_count += 1
            volume_dir = image_dir / f"volume_{volume_count}"
            log.info(f"Copying files to parse from volume '{volume}' to '{volume_dir}'")

            files = disk_image_api.find_files(
                volume, exclude_system_dirs=True, recursive=self.sub_dirs, skip_dirs=_output_dirs()
            )
            if files is None:
                return False

            matches = self._match_files(files)
            collected = self._match_collect_patterns(files, matches)
            if collected and temp_dir:
                log.warning(
                    f"Not collecting {len(collected)} files matching COLLECT_FILE_PATTERNS, "
                    f"since PARSE_FILES_DIR isn't set"
                )
                collected = []

            # The image is untrusted, so symbolic links to files outside the
            # volume (e.g. to "/etc/shadow" on the host) are never followed
            root = Path(os.path.realpath(volume))
            to_copy = []
            for file in sorted({f for paths in matches.values() for f in paths} | set(collected)):
                if file.is_relative_to(root):
                    to_copy.append(file)
                else:
                    log.warning(f"Skipping '{file}', it's a link to a file outside the volume")

            copied = self._copy_files(Path(volume), to_copy, volume_dir)
            self.collected_files.extend(copied[f].as_posix() for f in collected if f in copied)
            log.info(f"Copied {len(copied)} files from volume '{volume}'")
            return True

        try:
            if not disk_image_api.search_image(image, _search_volume, password_file):
                log.error(f"Failed to search disk image '{image}'")
                state.error = True

            if image_dir.is_dir():
                # Collected files were already handled, don't count them again.
                # The copies are always searched recursively, since they're in
                # directories for each volume, even if the volumes weren't.
                options = (self.collect_patterns, self.copy_files, self.sub_dirs)
                self.collect_patterns, self.copy_files, self.sub_dirs = [], False, True
                try:
                    self.parse_path(image_dir)
                finally:
                    self.collect_patterns, self.copy_files, self.sub_dirs = options
            else:
                log.warning(f"No files to parse were found on disk image '{image}'")
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _parse_file(self, source: str | Path, dev_cls: type[DeviceModule]) -> None:
        dev = parse_data(source, dev_cls)

        self.parsed_devices.append(dev)
        self.parse_results.append(
            {
                "name": source.name if isinstance(source, Path) else "stdin",
                "path": source.as_posix() if isinstance(source, Path) else "stdin",
                "module": dev_cls.__name__,
                "results": dev.elastic() if dev else {},
            }
        )

    def _find_files(self, path: Path) -> list[str] | None:
        if path.is_dir():
            return disk_image_api.find_files(
                path, recursive=self.sub_dirs, skip_dirs=_output_dirs()
            )
        return [str(path)]

    def _match_files(self, files: list[str]) -> dict[type[DeviceModule], list[Path]]:
        """The files each device module can parse."""
        files = sorted(files)
        matches = {}
        for dev_cls in self.resolved_types:
            matches[dev_cls] = disk_image_api.remove_dataless_files(
                find_parsable_files(files, dev_cls)
            )
        return matches

    def _match_collect_patterns(
        self, files: list[str], matches: dict[type[DeviceModule], list[Path]]
    ) -> list[Path]:
        """Files that match the collect patterns, and aren't parsed by a device module."""
        if not self.collect_patterns:
            return []

        parsed = {f for paths in matches.values() for f in paths}
        collected = []
        for file in files:
            name = os.path.basename(file).lower()
            for pattern in self.collect_patterns:
                if fnmatchcase(name, pattern.lower()):
                    file_path = Path(file).resolve()
                    if file_path not in parsed:
                        log.debug(f"Collect pattern match ({pattern}) on {file}")
                        collected.append(file_path)
                    break

        return disk_image_api.remove_dataless_files(sorted(collected))

    def _collect(self, source: Path, files: list[Path]) -> None:
        if not config.PARSE_FILES_DIR:
            log.warning(
                f"Not collecting {len(files)} files matching COLLECT_FILE_PATTERNS, "
                f"since PARSE_FILES_DIR isn't set"
            )
            return

        log.info(f"Collecting {len(files)} files matching COLLECT_FILE_PATTERNS")
        copied = self._copy_tree(source, files)
        self.collected_files.extend(copied[f].as_posix() for f in files if f in copied)

    def _copy_tree(self, source: Path, files: list[Path]) -> dict[Path, Path]:
        """
        Copy files from a directory (or a single file) to
        :attr:`~peat.settings.Configuration.PARSE_FILES_DIR`.
        """
        if not config.PARSE_FILES_DIR or not files:
            return {}
        dest = self._copy_dir(source)
        if source.is_file():
            # Copied to the directory as the unique name of the file, e.g. "set_all.txt_2"
            return self._copy_files(source.parent, files, dest.parent, {source.name: dest.name})
        return self._copy_files(source, files, dest)

    def _copy_dir(self, source: Path) -> Path:
        """
        Directory in :attr:`~peat.settings.Configuration.PARSE_FILES_DIR` to copy the
        files found in a path to, named after it, and unique for this parse.
        """
        source = Path(os.path.abspath(source))
        if source in self._copy_dirs:
            return self._copy_dirs[source]

        # The root of a drive or filesystem doesn't have a name, e.g. "C:\\",
        # "\\\\server\\share", or "/", so it's named after the drive, if it has one
        name = source.name or re.sub(r"[\\/:]+", "_", source.drive).strip("_") or "root"
        dest = config.PARSE_FILES_DIR / name
        count = 1
        while dest in self._copy_dirs.values():
            count += 1
            dest = config.PARSE_FILES_DIR / f"{name}_{count}"
        self._copy_dirs[source] = dest
        return dest

    @staticmethod
    def _copy_files(
        source: Path, files: list[Path], dest: Path, renames: dict[str, str] | None = None
    ) -> dict[Path, Path]:
        """
        Copy files in a directory to another directory, keeping their paths
        relative to the source directory. Paths in ``renames`` (relative to
        the source directory) are copied to a different relative path.

        Returns:
            The path of each file that was copied, and where it was copied to
        """
        source = Path(os.path.realpath(source))
        copied = {}
        for file in files:
            try:
                relative = Path(file).relative_to(source)
            except ValueError:
                # e.g. it's a symbolic link to a file outside the directory
                relative = Path(Path(file).name)

            if renames and relative.as_posix() in renames:
                relative = Path(renames[relative.as_posix()])

            try:
                utils.copy_file(Path(file), dest / relative)
            except OSError as ex:
                # e.g. the file is locked by another program on Windows
                log.error(f"Failed to copy '{file}' to '{dest / relative}': {ex}")
                state.error = True
                continue

            copied[file] = dest / relative

        return copied


def collect_file_patterns() -> list[str]:
    """
    Filename patterns of files to copy without parsing them: the patterns in
    :attr:`~peat.settings.Configuration.COLLECT_FILE_PATTERNS`, and the
    ``filenames`` and ``extensions`` in the deprecated ``pillage`` configuration.
    """
    patterns = list(config.COLLECT_FILE_PATTERNS)

    if config.PILLAGE:
        log.warning(
            "The 'pillage' configuration section is deprecated, use "
            "'collect_file_patterns' instead. Its 'filenames' and 'extensions' are "
            "added to the collect patterns, and its other options are ignored."
        )
        sections = [config.PILLAGE.get("default") or {}]
        sections.extend((config.PILLAGE.get("brands") or {}).values())
        for section in sections:
            patterns.extend(section.get("filenames") or [])
            patterns.extend(f"*.{ext}" for ext in section.get("extensions") or [])

    # Remove duplicates, keeping the order
    return list(dict.fromkeys(patterns))


def _output_dirs() -> list[Path]:
    """
    PEAT's output directories, which aren't searched for files to parse, so that
    parsing a directory with the output of earlier runs in it (e.g. ``peat parse .``)
    doesn't parse and copy them again.
    """
    return [d for d in [config.OUT_DIR, config.RUN_DIR, config.PARSE_FILES_DIR] if d]


def _is_parsable(path: Path, dev_types: list[type[DeviceModule]]) -> bool:
    """If any of the device modules can parse a file, by its name or file signature."""
    return any(
        parsable_file_by_pattern(str(path), dev_cls)
        or parsable_file_by_signature(str(path), dev_cls)
        for dev_cls in dev_types
    )


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


__all__ = ["parse", "pillage"]
