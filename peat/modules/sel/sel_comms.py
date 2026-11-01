import timeit
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Final

from peat import DeviceData, DeviceError, PeatError, config, consts, log, utils
from peat.protocols import FTP

from .sel_files import SOURCE_DOWNLOAD, record_downloaded_file
from .sel_serial import SELSerial
from .sel_telnet import SELTelnet

#: Directories with the preferred copy of a file when files in different
#: directories have the same name. ``HISTORY.TXT`` and ``CHISTORY.TXT`` are
#: in both ``REPORTS`` and ``EVENTS`` on the 700G, and the SEL-351S and SEL-421
#: instruction manuals list them in both (Virtual File Interface sections).
#: The other report files (``SER.TXT``, ``CSER.TXT``, etc.) are in ``REPORTS``.
PREFERRED_DIRS: Final = ("REPORTS",)


def clean_filenames(filenames: list[bytes | str]) -> list[str]:
    """
    Some file listings contain embedded null bytes.
    """
    clean = []

    for filename in filenames:
        if isinstance(filename, bytes):
            filename = filename.decode()
        clean.append(filename.strip().replace("\x00", ""))

    return clean


def device_label(dev: DeviceData) -> str:
    """
    The device's address (``dev.address``) for messages, or its ID if it
    doesn't have an address (e.g. a relay behind a RTAC, refer to
    :mod:`peat.modules.sel.sel_gateway`).
    """
    try:
        return dev.address
    except PeatError:
        return dev.get_id(["id", "name"])


def _method_name(comms: FTP | SELTelnet | SELSerial) -> str:
    if isinstance(comms, FTP):
        return "FTP"
    elif getattr(comms, "transport_name", "") == "rtac_tunnel":
        return "RTAC tunnel"
    elif isinstance(comms, SELTelnet):
        return "Telnet"
    elif isinstance(comms, SELSerial):
        return "Serial"
    else:
        raise DeviceError(f"Invalid comms class: {comms.__class__.__name__}")


def _transfer_info(comms: FTP | SELTelnet | SELSerial) -> dict[str, str]:
    """
    How files are transferred by ``comms``, for ``File.extra``.

    .. note::
       Call this after a download. For serial, it uses the result of the
       ``FILE SHOW`` support check cached by the download, instead of
       sending a command to the relay to find out.
    """
    if isinstance(comms, FTP):
        return {"transport": "ftp", "file_transfer": "ftp"}

    if isinstance(comms, SELSerial):
        if comms.force_ymodem or getattr(comms, "_supports_show", None) is False:
            return {"transport": "serial", "file_transfer": "ymodem"}
        return {"transport": "serial", "file_transfer": "file_show"}

    # "rtac_tunnel" for a relay behind a RTAC (refer to sel_tunnel.py)
    return {
        "transport": getattr(comms, "transport_name", "") or "telnet",
        "file_transfer": "file_show",
    }


def download_files(
    files: list[str],
    comms: FTP | SELTelnet | SELSerial,
    save_dir: Path | None,
    handle_download_errors: bool = True,
    dev: DeviceData | None = None,
    directory: str | None = None,
) -> dict[str, dict[str, bytes | str | Path]]:
    """
    Download a selected list of files from a relay in a comms-agnostic manner.

    Each file is hashed, using the data as it was received (before ``.TXT``
    files are decoded). If ``dev`` is set, then each file is also recorded in
    ``dev.files`` using :func:`~peat.modules.sel.sel_files.record_downloaded_file`.

    .. code-block:: python

       {
           "filename": {
               "name": filename,
               "data": file_data,
               "raw_path": path,
               "device_path": PurePosixPath(...),
               "local_path": Path(...),
               "hash": {"md5": "...", "sha1": "...", ...},
               "size": 1234,
               "file": File(...),  # only if dev is set
           },
           ...
       }

    Args:
        files: Paths of the files to download, in the format used by ``comms``
            (``SETTINGS/SET_1.TXT`` for FTP, ``SETTINGS SET_1.TXT`` for Telnet/serial)
        comms: Communication method to use, as a class instance
        save_dir: Directory to save the files to, or :obj:`None` to not save them
        handle_download_errors: If errors should be logged instead of raised
        dev: Device to record the downloaded files for
        directory: Directory on the device the files are in, if it isn't
            part of the paths in ``files`` (e.g. older relays, where PEAT
            changes to the directory before downloading)
    """

    method = _method_name(comms)

    log.info(f"Retrieving {len(files)} files from {comms.address} via {method}")

    if isinstance(comms, SELTelnet) and not comms.can_download_files():
        raise DeviceError(
            f"{comms.address} is not capable of downloading files "
            f"via Telnet. Terminating Telnet download."
        )

    # filename: {path, data}
    all_file_data = {}

    for path in files:
        # path can be:
        # - "SET_P1.TXT"
        # - "SETTINGS SET_P1.TXT"
        # - "SETTINGS/SET_P1.TXT" (need to confirm)
        fmt_path = "/".join(path.replace("\\", "/").split())
        if directory and directory != "/" and "/" not in fmt_path.strip("/"):
            fmt_path = f"{directory}/{fmt_path}"
        if fmt_path[0] != "/":
            fmt_path = f"/{fmt_path}"
        path_obj = PurePosixPath(fmt_path)
        filename = path_obj.name

        log.info(f"Retrieving '{path}' from {comms.address} via {method}")

        try:
            raw_data = comms.download_binary(path, save_to_file=False)

            if raw_data is None:
                log.error(f"Failed to download {filename} from {comms.address} via {method}")
                continue

            file_data = raw_data
            if isinstance(raw_data, bytes) and path.upper().endswith(".TXT"):
                try:
                    file_data = raw_data.decode("utf-8")
                except UnicodeDecodeError:
                    # e.g. a degree sign (0xB0) in an event file. The saved
                    # file and the hashes are of the raw bytes either way.
                    log.warning(
                        f"{filename} from {comms.address} isn't valid UTF-8, decoding as Latin-1"
                    )
                    file_data = raw_data.decode("latin-1")

            # What's saved and hashed
            content = raw_data
            description = ""
            if isinstance(file_data, str) and file_data.strip() == "=>":
                log.warning(
                    f"File '{filename}' only has '=>' as contents, "
                    f"probably as a artifact of a Telnet mis-parse. "
                    f"Writing empty data instead."
                )
                content = ""
                description = "Only '=>' was received, probably a Telnet mis-parse"

            file_dict = {
                "name": filename,
                "data": file_data,  # bytes or str
                "raw_path": path,
                "device_path": path_obj,
                "local_path": "",
            }

            if save_dir:
                # utils.write_file() writes to "<name>.<num>" if the file exists.
                # Pick that name here, so local_path is the file that's written.
                local_path = save_dir / consts.sanitize_filename(filename)
                if local_path.exists():
                    local_path = utils.dup_path(local_path)
                if utils.write_file(content, local_path):
                    file_dict["local_path"] = local_path

            # Recording is a side effect: never drop a downloaded file because of it
            try:
                if dev is not None:
                    file_obj = record_downloaded_file(
                        dev=dev,
                        data=content,
                        name=filename,
                        device_path=path_obj,
                        local_path=file_dict["local_path"] or None,
                        source=SOURCE_DOWNLOAD,
                        peat_module="SELRelay",
                        description=description,
                        extra=_transfer_info(comms),
                    )
                    file_dict["file"] = file_obj
                    file_dict["hash"] = file_obj.hash.dict(exclude_none=True)
                    file_dict["size"] = file_obj.size
                else:
                    raw_content = content.encode("utf-8") if isinstance(content, str) else content
                    file_dict["hash"] = utils.gen_hashes(raw_content)
                    file_dict["size"] = len(raw_content)
            except Exception as rec_ex:
                log.warning(f"Failed to record hashes for '{path}' from {comms.address}: {rec_ex}")

            # Check for duplicates in the same directory. Files with the same
            # name in different directories (e.g. EVENTS/HISTORY.TXT and
            # REPORTS/HISTORY.TXT on the 700G) are handled by pull_files().
            if filename in all_file_data:
                ext_count = 1
                while f"{filename}.{ext_count}" in all_file_data:
                    ext_count += 1

                updated_filename = f"{filename}.{ext_count}"
                log.warning(
                    f"{filename} already exists in all_file_data! "
                    f"Saving to {updated_filename} instead."
                )
                filename = updated_filename

            all_file_data[filename] = file_dict

        except Exception as ex:
            if handle_download_errors:
                log.error(f"Failed to retrieve '{path}' from {comms.address} via {method}: {ex}")
            else:
                raise ex from None

    log.info(f"Retrieved {len(files)} files from {comms.address} via {method}")

    return all_file_data


def filter_names(
    paths: list[str],
    only: list[str] | None = None,
    never: list[str] | None = None,
) -> list[str]:
    if not only and not never:  # short-circuit common case
        return sorted(paths)

    if only is not None and not isinstance(only, list):
        raise DeviceError(
            f"'only' filters must be a list, not '{type(only).__name__}' "
            f"(value provided: {repr(only)})"
        )

    if never is not None and not isinstance(never, list):
        raise DeviceError(
            f"'never' filters must be a list, not '{type(never).__name__}'"
            f"(value provided: {repr(never)})"
        )

    filtered = set()

    for path in sorted(paths):
        if only:
            for allow_pattern in only:
                if path == allow_pattern or fnmatch(path.lower(), allow_pattern.lower()):
                    filtered.add(path)
                    break
        elif never:
            excluded = False
            for exclude_pattern in never:
                if path == exclude_pattern or fnmatch(path.lower(), exclude_pattern.lower()):
                    excluded = True
                    break
            if not excluded:
                filtered.add(path)

    return sorted(filtered)


def _in_preferred_dir(file_dict: dict) -> bool:
    return PurePosixPath(file_dict["device_path"]).parent.name.upper() in PREFERRED_DIRS


def _files_by_name(files_by_path: dict[str, dict], address: str) -> dict[str, dict]:
    """
    Key downloaded files by their name instead of their path on the device.

    If files in different directories have the same name, a file in one of
    :data:`PREFERRED_DIRS` is used. Otherwise, the file in the last directory
    (in sorted order) is used, which is the same as before files were keyed by path.
    """
    by_name = {}  # type: dict[str, dict]

    for file_dict in files_by_path.values():
        name = file_dict["name"]
        current = by_name.get(name)

        if current is None:
            by_name[name] = file_dict
            continue

        if _in_preferred_dir(file_dict) or not _in_preferred_dir(current):
            by_name[name] = file_dict

        log.info(
            f"'{name}' is in multiple directories on {address} "
            f"('{current['device_path']}' and '{file_dict['device_path']}'), "
            f"using '{by_name[name]['device_path']}'"
        )

    return by_name


def pull_files(
    dev: DeviceData, comms: FTP | SELTelnet | SELSerial
) -> dict[str, dict[str, bytes | str]]:
    """
    Recursively download all files from a relay in a comms-agnostic manner.

    Every file downloaded is hashed and recorded in ``dev.files`` (see
    :func:`~peat.modules.sel.sel_files.record_downloaded_file`).

    Args:
        dev: The device to pull from
        comms: Communication method to use, as a class instance. It must have
            the methods ``list_files()`` and ``download_binary``.

    Returns:
        The files downloaded, keyed by filename, with value being a dict including
        the file data, the device path, the local path (if it was saved locally),
        the hashes, and the :class:`~peat.data.models.File` in ``dev.files``.
        If files in different directories have the same name (e.g. ``EVENTS/HISTORY.TXT``
        and ``REPORTS/HISTORY.TXT``), only one is included. All of the files,
        keyed by their path on the device, are in ``dev._cache["all_files_by_path"]``.
    """
    method = _method_name(comms)
    start_time = timeit.default_timer()

    log.info(f"Pulling relay config files from {device_label(dev)} via {method}")

    # Directory to save raw files to
    # Format: peat_results/<run-dir>/devices/{address}/relay_files_{timestamp}/*
    configs_dir = None
    if config.DEVICE_DIR:
        configs_dir = dev.get_sub_dir("relay_files")

    # Determine files to download from root directory and any sub-directories
    populate_file_listing(dev, comms)

    log.trace(f"{method} file listing: {dev.extra['file_listing']}")

    to_download = filter_names(
        list(dev.extra["file_listing"].keys()),
        only=dev.options["sel"]["only_download_dirs"],
        never=dev.options["sel"]["never_download_dirs"],
    )

    log.info(f"Directories to download from {device_label(dev)} via {method}: {to_download}")

    # Raw and file paths contents of all files downloaded, keyed by device path
    files_by_path = {}  # type: dict[str, dict]

    # Download files from each directory
    for dirname in to_download:
        # Filter files to download based on config settings
        filenames = filter_names(
            dev.extra["file_listing"][dirname],
            dev.options["sel"]["only_download_files"],
            dev.options["sel"]["never_download_files"],
        )

        if not filenames:
            log.warning(
                f"Skipping directory {dirname} on {device_label(dev)}, "
                f"it's either empty or there are no files that "
                f"weren't filtered by the 'only_download_files' or "
                f"'never_download_files' options"
            )
            continue

        # Determine file path to use for download
        if dirname != "/" and not (dev.extra.get("sel_old_ftp") or dev.options["sel"]["old_ftp"]):
            # Telnet requires space between directory and file name
            # Technically you can get away with a slash, but some devices don't like this.
            sep = "/" if isinstance(comms, FTP) else " "
            paths = [f"{dirname}{sep}{file}" for file in filenames]
        else:
            paths = filenames

        # Save files to a sub-directory matching the structure on the device,
        # if file saving is enabled (if configs_dir != None).
        sub_dir = configs_dir
        if configs_dir and dirname != "/":
            sub_dir = configs_dir / dirname

        try:
            # Change directory if needed for older devices
            if (dev.extra.get("sel_old_ftp") or dev.options["sel"]["old_ftp"]) and isinstance(
                comms, FTP
            ):
                comms.cd(dirname)  # cd <dirname> => retr <file> => cd ..

            downloaded = download_files(
                files=paths,
                comms=comms,
                save_dir=sub_dir,
                handle_download_errors=dev.options["sel"].get("handle_download_errors", True),
                dev=dev,
                directory=dirname,
            )

            for file_dict in downloaded.values():
                files_by_path.setdefault(file_dict["device_path"].as_posix(), file_dict)

            # Restore directory location
            if (dev.extra.get("sel_old_ftp") or dev.options["sel"]["old_ftp"]) and isinstance(
                comms, FTP
            ):
                comms.cd("..")
        except Exception as ex:
            log.warning(
                f"Failed to retrieve files from {dirname} on {device_label(dev)} "
                f"via {method}: {ex}"
            )

    duration = timeit.default_timer() - start_time
    log.info(
        f"Pulled {len(files_by_path)} files from {device_label(dev)} via {method} "
        f"(duration: {utils.fmt_duration(duration)})"
    )
    log.debug(f"Files pulled from {device_label(dev)} via {method}: {', '.join(files_by_path)}")

    all_files = _files_by_name(files_by_path, device_label(dev))

    # NOTE: if SET_ALL.TXT isn't in the files, it's reconstructed from the
    # individual settings files (SET_*.TXT) in SELRelay.pull_configs()
    dev._cache["all_files"] = all_files
    dev._cache["all_files_by_path"] = files_by_path

    # Add files to related.files, in case they aren't already
    for file_dict in files_by_path.values():
        dev.related.files.add(file_dict["name"])

    return all_files


def populate_file_listing(dev: DeviceData, comms: FTP | SELTelnet | SELSerial) -> None:
    # ["DIAGNOSTICS", "EVENTS", "HMI", "REPORTS", "SER", "STATUS", "SETTINGS"]
    if not dev.extra.get("file_listing"):
        if isinstance(comms, FTP):
            slash_listing = comms.nlst_files()
        else:
            slash_listing = comms.list_files()
        dev.extra["file_listing"] = {"/": clean_filenames(slash_listing)}

    if not dev.extra.get("settings_root_directory"):
        if "SETTINGS" in dev.extra["file_listing"]["/"]:
            dev.extra["settings_root_directory"] = "SETTINGS"
        else:
            dev.extra["settings_root_directory"] = "/"
        log.debug(
            f"Settings root directory for {device_label(dev)}: "
            f"'{dev.extra['settings_root_directory']}'"
        )

    root_files = []
    files_on_dev = set()
    dirs_on_dev = set()

    for file in dev.extra["file_listing"]["/"]:
        # Process sub-directories
        # Note(cegoes): Files will always have "." as far as I know
        if "." not in file and file not in dev.extra["file_listing"]:
            if isinstance(comms, FTP):
                listing = clean_filenames(comms.nlst_files(file))
            else:
                listing = clean_filenames(comms.list_files(file))

            # Handle 351 and older devices that act in a weird way...
            # 'ls <directory>' doesn't work, you have to cd to the directory,
            # then run 'ls' to get a proper file listing.
            # cd <dirname> => ls => cd ..
            if file in listing and isinstance(comms, FTP):
                comms.cd(file)
                listing = clean_filenames(comms.nlst_files())
                comms.cd("..")
                dev.extra["sel_old_ftp"] = True

            log.trace(f"Files in '{file}' from {device_label(dev)}: {listing}")
            files_on_dev.update(listing)
            dirs_on_dev.add(file)

            # Sets the sub-directory to be a separate part of the file listing
            # dict from the files in the root directory, e.g.
            #   dev.extra["file_listing"]["/"] = ["CFG.XML", ...]
            #   dev.extra["file_listing"]["SETTINGS"] = ["SET_1.TXT", ...]
            dev.extra["file_listing"][file] = listing
        else:
            root_files.append(file)
            files_on_dev.add(file)

    dirs_on_dev.add("/")

    dev.extra["file_listing"]["/"] = root_files
    dev.extra["num_directories_on_device"] = len(dirs_on_dev)
    dev.extra["num_files_on_device"] = len(files_on_dev)
    dev.extra["all_dirs_on_device"] = sorted(dirs_on_dev)
    dev.extra["all_files_on_device"] = sorted(files_on_dev)

    dev.related.files.update(files_on_dev)
