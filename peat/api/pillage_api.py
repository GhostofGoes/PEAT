import hashlib
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePath, PurePosixPath
from typing import Final

# Allow module to be imported without errors
# on non-Linux systems (Windows and OSX).
try:
    import kmodpy

    KMODPY_INSTALLED = True
except (ImportError, OSError):
    KMODPY_INSTALLED = False

from peat import config, consts, log, utils
from peat.api import pillage_image

# Keep track if the nbd module was already loaded when pillage started
# don't remove it if it was.  Keep the system in the same state when done
# pillaging
NBD_ALREADY_LOADED = False

#: Ways disk images can be read, see :attr:`~peat.settings.Configuration.PILLAGE_BACKEND`
BACKENDS: Final = ("auto", "library", "mount")

#: Directories skipped at the top level of the source (case-insensitive)
EXCLUDED_ROOT_DIRS: Final = (
    "Windows",
    "System Volume Information",
    "PerfLogs",
    "MSOCache",
    "cygwin64",
    "Recovery",
    "Boot",
    "$Recycle.Bin",
    "bootmgr",
)

#: Default for the ``max_file_size`` Pillage option (bytes)
DEFAULT_MAX_FILE_SIZE: Final = 256 * 1024 * 1024

#: Default for the ``max_total_size`` Pillage option (bytes)
DEFAULT_MAX_TOTAL_SIZE: Final = 8 * 1024 * 1024 * 1024

#: Pillage stops copying files from a disk image if there would be
#: less free disk space than this (bytes)
MIN_FREE_SPACE: Final = 512 * 1024 * 1024

# Reparse tags with this bit are "name surrogates", that point at another file
# or directory (junctions and symbolic links). Other reparse points, e.g.
# OneDrive (cloud files) folders, hold their own files.
_REPARSE_TAG_NAME_SURROGATE: Final = 0x20000000

# TODO: integrate pillage with parse. Pillage results should go in peat_results.


def pillage(source: str | None = None) -> bool:
    """
    peat pillage.

    Search a directory or disk image for device files (configs, project files, etc.)
    and copy them to ``./pillage_results/``.

    How disk images are read is configured by
    :attr:`PILLAGE_BACKEND <peat.settings.Configuration.PILLAGE_BACKEND>`.

    Args:
        source: Path of the directory or disk image to pillage.
            Defaults to the current directory.

    Returns:
        If pillaging was successful
    """
    if not config.PILLAGE:
        log.error(
            "No Pillage config specified! Make sure the 'pillage' section "
            "is included in the peat config file!"
        )
        return False

    results_path = Path("pillage_results")
    if not results_path.exists():
        results_path.mkdir()

    source = source or "."  # The documented default (was a TypeError)
    log.info(f"Pillage source path: {source}")
    source_path = Path(source)

    # Validate source exists
    if source_path.exists():
        if source_path.is_dir():
            log.info(f"Pillaging directory {source}")
            return search(source_path, results_path)

        elif source_path.is_file():
            backend = select_backend(source_path)
            if backend == "library":
                try:
                    return search_image(source_path, results_path)
                except pillage_image.UnsupportedImageError as ex:
                    if _requested_backend() != "auto":
                        log.error(f"[Pillage] Can't pillage '{source_path.name}': {ex}")
                        return False
                    log.warning(f"[Pillage] {ex}. Trying to mount the image instead.")
                    backend = "mount" if can_mount_image(source_path) else None
                except pillage_image.PillageImageError as ex:
                    log.error(f"[Pillage] Failed to read image '{source_path}': {ex}")
                    return False
                except OSError as ex:
                    log.error(f"[Pillage] Failed to read image '{source_path}': {ex}")
                    return False

            if backend == "mount":
                log.info(f"Pillaging image {source}")

                # Create temporary directory to mount image to in current directory
                temp_path = Path("pillage_temp")
                if temp_path.exists():
                    try:
                        shutil.rmtree(temp_path)
                    except OSError:
                        unmount_image(temp_path)
                temp_path.mkdir()

                # Mount image
                log.debug(f"Mount image to {temp_path}")
                success = False
                if mount_image(source_path, temp_path):
                    try:
                        success = search(temp_path, results_path)
                    except (Exception, KeyboardInterrupt) as ex:
                        log.critical(f"Failed pillage search: {ex}")
                    # remove Mount
                    if unmount_image(temp_path):
                        log.debug(f"Unmout image from '{temp_path}'")
                else:
                    log.error("Failed to mount image")

                if temp_path.exists():
                    shutil.rmtree(temp_path)
                    log.debug(f"Deleted temp directory '{temp_path}'")

                return success
            return False
        else:
            log.error("Unsupported source type")
            return False

    log.error(f"Source ({source}) does not exist")
    return False


def validate_image_mounting() -> bool:
    """Ensure all the requirements needed to mount an image are satisfied.

    In order to mount an image and search, certain conditions must be met:

    - PEAT must be run as ``root``
    - PEAT must be run on a Linux system and not on Windows Subsystem for Linux (WSL)
    - ``kmodpy`` Python package must be installed
    - ``qemu-nbd`` must be installed and available in the system PATH

    Returns:
        If the requirements for mounting are met
    """
    if consts.WSL or not consts.LINUX:
        log.error(
            "To mount an image for searching, you must be running on Linux "
            "(Windows, WSL, or macOS are not supported at this time)"
        )
        return False
    elif os.geteuid() != 0:
        log.error("To mount an image for searching, you must be running as root")
    elif not KMODPY_INSTALLED:
        log.error("To mount an image for searching, you must have kmodpy installed")
    elif not shutil.which("qemu-nbd"):
        log.error(
            "Could not find 'qemu-nbd', which is required to mount a disk "
            "image. To fix this, install the 'qemu-utils' package: "
            "'sudo apt-get install qemu-utils'"
        )
    else:
        return True

    return False


def mount_image(source: Path, mount_point: Path) -> bool:
    global NBD_ALREADY_LOADED

    if "nbd" not in list_loaded_modules():
        try:
            # Equivalent of "modprobe nbd"
            kmodpy.Kmod().modprobe("nbd")
        except Exception as e:
            log.error(f"Failed to load 'nbd' kernel module: {e}")
            return False
    else:
        NBD_ALREADY_LOADED = True

    nbd_args = ["qemu-nbd", "-r", "-c", "/dev/nbd1", str(source)]
    nbd_result = subprocess.call(nbd_args)
    if nbd_result != 0:
        log.error(f"Failed to run '{' '.join(nbd_args)}' (return code: {nbd_result})")
        remove_nbd_module()
        return False

    # Give the system time to mount device before attempting to mount to folder
    time.sleep(0.5)

    mnt_args = ["mount", "-o", "ro", "/dev/nbd1p1", str(mount_point)]
    mnt_result = subprocess.call(mnt_args)
    if mnt_result != 0:
        log.error(f"Failed to run '{' '.join(mnt_args)}' (return code: {mnt_result})")
        remove_nbd_device()
        remove_nbd_module()
        return False

    return True


def unmount_image(mount_point: Path) -> bool:
    result = True

    umount_args = ["umount", str(mount_point)]
    retval = subprocess.call(umount_args)
    if retval != 0:
        log.error(f"Failed to run '{' '.join(umount_args)}' (return code: {retval})")
        result &= False

    result &= remove_nbd_device()
    result &= remove_nbd_module()

    return True


def remove_nbd_module() -> bool:
    if not NBD_ALREADY_LOADED:
        try:
            kmodpy.Kmod().rmmod("nbd")
        except Exception as e:
            log.error(f"Failed to remove 'nbd' module: {e}")
            return False

    return True


def remove_nbd_device() -> bool:
    nbd_args = ["qemu-nbd", "-d", "/dev/nbd1"]
    retval = subprocess.call(nbd_args)

    if retval != 0:
        log.error(f"Failed to run '{' '.join(nbd_args)}' (return code: {retval})")
        return False

    return True


def list_loaded_modules() -> list[str]:
    result = []
    km = kmodpy.Kmod()
    for mod in km.list():
        result.append(mod[0].decode("utf-8"))

    return result


def search(source: Path, results: Path) -> bool:
    if not source.is_dir():
        log.error(f"Failed pillage search: source path '{source}' is not a valid directory.")
        return False

    excluded = {d.lower() for d in EXCLUDED_ROOT_DIRS}
    exclude_counter = 0
    output_dirs = _output_dirs(results)

    for root, dirnames, filenames in os.walk(str(source), onerror=_log_walk_error):
        log.trace2(f"Searching in: {root}")

        # Never descend into links, or Windows junctions (os.walk follows those).
        # Don't search PEAT's output (e.g. when pillaging the current directory).
        kept = []
        for dirname in dirnames:
            dir_path = os.path.join(root, dirname)
            if _is_link_or_junction(dir_path):
                log.debug(f"[Pillage] Not following link or junction '{dir_path}'")
            elif _is_output_dir(dir_path, output_dirs):
                log.info(f"[Pillage] Not searching PEAT's output directory '{dir_path}'")
            else:
                kept.append(dirname)
        dirnames[:] = kept

        # Skip excluded directories at the top level of the source.
        # Case-insensitive, since NTFS and FAT are case-insensitive.
        if root == str(source):
            for dirname in [d for d in dirnames if d.lower() in excluded]:
                log.trace2(f"Skipping excluded dir '{os.path.join(root, dirname)}'")
                exclude_counter += 1
                dirnames.remove(dirname)

        for filename in filenames:
            src_file = Path(root) / filename
            is_valid, config_type = is_valid_file(src_file)

            if is_valid:
                dst_file = Path(results) / config_type / filename

                # If a file with that name already exists in the results folder
                # increment a counter and append that counter to the file name
                name_only = dst_file.stem
                ext_only = dst_file.suffix
                count = 1
                while dst_file.exists():
                    dst_file = Path(results) / config_type / f"{name_only}{ext_only}.{count}"
                    count += 1

                # Prompt user if they want to copy each file
                if not config.PILLAGE["auto_copy"]:
                    auto_copy = input(
                        f"Found {src_file}, do you want to copy it to {dst_file} (Y or N):"
                    )
                    print(auto_copy, file=sys.stderr, flush=True)  # noqa: T201

                    if auto_copy == "Y":
                        copy_file(src_file, dst_file)
                    else:
                        log.warning(
                            f"[Pillage] Declined to copy {src_file} to "
                            f"{dst_file} (auto_copy is false)"
                        )
                else:
                    copy_file(src_file, dst_file)

        if not config.PILLAGE["recursive"]:
            break

    if exclude_counter:
        log.info(f"Skipped {exclude_counter} excluded subdirectories")

    return True


# TODO: function not used yet, still need to decide how to search through specific locations
#   How to search through specific directories?  Only search those listed?
#   Search through all but only validate a file if its one of those specified?
#   How to handle if one brand says search through everything and ones
#       says only a specific directory?
#   Searching through everything and then validating at a file level
#       would be easiest to implement but not be the quickest way to search.
#       If only a single location is specified that search will take the same
#       amount of time as a search with all directories.
# def create_location_list():
#     locations = []
#     all_dirs = False
#     if 'brands' in config.PILLAGE:
#         for brand_data in config.PILLAGE['brands'].values():
#             if 'locations' in brand_data:
#                 if len(brand_data['locations']) > 0:
#                     locations.append(brand_data['locations'])
#                 else:
#                     # if there is a location entry but no locations defined then look
#                     # through all directories
#                     all_dirs = True
#     if 'default' in config.PILLAGE:
#         if 'locations' in config.PILLAGE['default']:
#             if len(config.PILLAGE['default']) > 0:
#                 locations.append(config.PILLAGE['default']['locations'])
#             else:
#                 # if there is a location entry but no locations defined then look
#                 # through all directories
#                 all_dirs = True
#     return all_dirs, locations


def copy_file(src: Path, dst: Path) -> bool:
    try:
        if not dst.parent.exists():
            dst.parent.mkdir(exist_ok=True, parents=True)

        shutil.copyfile(str(src), str(dst))
    except OSError as ex:
        # e.g. a file that's locked or can't be read on Windows, don't stop the search
        log.warning(f"[Pillage] Failed to copy {src} to {dst}: {ex}")
        return False

    log.info(f"[Pillage] Copied {src} to {dst}")
    return True


def is_valid_file(_file: PurePath):
    """
    Determine if a file is valid based on the search criteria
    in the Pillage configuration.
    """
    brand_list = []
    valid_file = False
    config_type = ""

    if "brands" in config.PILLAGE:
        for brand, brand_data in config.PILLAGE["brands"].items():
            valid_file, condition = check_file_conditions(_file, brand_data)
            if valid_file:
                brand_list.append((brand, condition))

        if len(brand_list) > 0:
            brand_str = ""
            for brand, condition in brand_list:
                brand_str += f"{brand} ({condition}), "

            log.info(
                f"[Pillage] {_file} is valid for the following "
                f"brands and conditions: {brand_str[:-2]}"
            )
            valid_file = True
            config_type = brand_list[0][0]
            if len(brand_list) > 1:
                config_type = "MULTIPLE"

    # If a valid file wasn't found using the specific brand conditions check for default files
    if not valid_file and "default" in config.PILLAGE:
        valid_file, condition = check_file_conditions(_file, config.PILLAGE["default"])
        if valid_file:
            log.info(f"[Pillage] {_file} is valid for DEFAULT condition {condition}")
            config_type = "DEFAULT"

    return valid_file, config_type


def check_file_conditions(_file: PurePath, conditions: dict[str, list]) -> tuple:
    found = False
    condition_type = ""

    if conditions.get("filenames"):
        for cond_fname in conditions["filenames"]:
            if _file.name.lower() == cond_fname.lower():
                condition_type = "FILENAME"
                found = True
                break

    if not found and conditions.get("extensions"):
        for cond_ext in conditions["extensions"]:
            if _file.suffix[1:].lower() == cond_ext.lower():
                condition_type = "EXTENSION"
                found = True
                break

    # TODO: Check for magic number

    return found, condition_type


def _log_walk_error(ex: OSError) -> None:
    """Log directories that can't be read (e.g. permissions on Windows)."""
    log.warning(f"[Pillage] Can't read '{ex.filename}': {ex.strerror or ex}")


def _is_link_or_junction(path: str) -> bool:
    """
    If a path is a symbolic link, or a Windows junction (or another
    reparse point that points somewhere else).

    :func:`os.walk` doesn't follow symbolic links, but it does
    follow Windows directory junctions (https://bugs.python.org/issue23407).
    Other reparse points, e.g. OneDrive folders, are not links.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False

    if stat.S_ISLNK(st.st_mode):
        return True

    # st_file_attributes and st_reparse_tag only exist on Windows
    if not getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    tag = getattr(st, "st_reparse_tag", 0)
    return not tag or bool(tag & _REPARSE_TAG_NAME_SURROGATE)


def _output_dirs(results: Path) -> dict[str, list[str]]:
    """
    PEAT's output directories, which aren't searched: the Pillage results,
    :attr:`OUT_DIR <peat.settings.Configuration.OUT_DIR>` and
    :attr:`RUN_DIR <peat.settings.Configuration.RUN_DIR>`.

    Returns:
        The absolute paths of the directories, by their lowercase name
    """
    dirs: dict[str, list[str]] = {}
    for pth in (results, config.OUT_DIR, config.RUN_DIR):
        if pth:
            abs_path = os.path.abspath(pth)
            dirs.setdefault(os.path.basename(abs_path).lower(), []).append(abs_path)
    return dirs


def _is_output_dir(path: str, output_dirs: dict[str, list[str]]) -> bool:
    """
    If a directory is one of PEAT's output directories. Paths are compared with
    :func:`os.path.samefile`, so case and symbolic links don't matter.
    """
    for out_dir in output_dirs.get(os.path.basename(path).lower(), []):
        try:
            if os.path.samefile(path, out_dir):
                return True
        except OSError:
            continue  # e.g. the output directory doesn't exist yet
    return False


def can_mount_image(source: Path) -> bool:
    """
    If a disk image can be pillaged with the ``mount`` backend (``qemu-nbd``).

    Logs the reason if it can't.
    """
    try:
        fmt = pillage_image.detect_image_format(source, config.PILLAGE.get("image_format"))
    except pillage_image.PillageImageError as ex:
        log.error(f"[Pillage] Can't mount '{source.name}': {ex}")
        return False

    if fmt == "split_raw":
        try:
            # A single ".001" file is a raw image, qemu-nbd can read that
            single_file = len(pillage_image.split_raw_parts(source)) == 1
        except pillage_image.PillageImageError as ex:
            log.error(f"[Pillage] Can't mount '{source.name}': {ex}")
            return False
    else:
        single_file = False

    if fmt == "ewf" or (fmt == "split_raw" and not single_file):
        log.error(
            f"[Pillage] {fmt} images can't be mounted with qemu-nbd. Read the image without "
            f'mounting it ("--pillage-backend library"), or mount it yourself '
            f"(e.g. with ewfmount for EWF) and pillage the mounted directory."
        )
        return False

    return validate_image_mounting()


def _requested_backend() -> str:
    return str(config.PILLAGE_BACKEND or "auto").strip().lower()


def select_backend(source: Path) -> str | None:
    """
    Choose how to read a disk image, based on the
    :attr:`PILLAGE_BACKEND <peat.settings.Configuration.PILLAGE_BACKEND>` option.

    - ``library``: read files from the image without mounting it (any OS, no root)
    - ``mount``: mount the image with ``qemu-nbd`` (Linux and root only)
    - ``auto``: ``library`` if it supports the image, otherwise ``mount``

    Returns:
        ``"library"``, ``"mount"``, or :obj:`None` if the image can't be read
        (the reason is logged)
    """
    requested = _requested_backend()

    if requested not in BACKENDS:
        log.error(
            f"[Pillage] Invalid PILLAGE_BACKEND '{config.PILLAGE_BACKEND}', "
            f"valid values are: {', '.join(BACKENDS)}"
        )
        return None

    if requested == "mount":
        return "mount" if can_mount_image(source) else None

    try:
        fmt = pillage_image.detect_image_format(source, config.PILLAGE.get("image_format"))
        pillage_image.check_library_support(fmt)
    except pillage_image.UnsupportedImageError as ex:
        if requested == "library":
            log.error(f"[Pillage] Can't read '{source.name}' without mounting it: {ex}")
            return None
        log.warning(
            f"[Pillage] Can't read '{source.name}' without mounting it ({ex}), "
            f"trying to mount it instead"
        )
        return "mount" if can_mount_image(source) else None
    except pillage_image.PillageImageError as ex:
        log.error(f"[Pillage] Failed to read image '{source}': {ex}")
        return None

    return "library"


def search_image(source: Path, results: Path) -> bool:
    """
    Search a disk image for files without mounting it (the ``library`` backend).

    This works on any OS and doesn't need root. All partitions with a
    supported filesystem are searched. A summary of the image and the copied
    files is saved to ``pillage-summary.json`` in
    :attr:`SUMMARIES_DIR <peat.settings.Configuration.SUMMARIES_DIR>`.

    Images are untrusted, so the output is limited: files larger than the
    ``max_file_size`` option are skipped, hard links to a file that was
    already copied aren't copied again, and copying stops if the total size
    of the copied files would be larger than the ``max_total_size`` option,
    or if there would be less than :data:`MIN_FREE_SPACE` free disk space.

    Args:
        source: Path of the disk image (for split images, the first file)
        results: Directory to copy the files to

    Returns:
        If the image was searched, :obj:`False` if copying was stopped early

    Raises:
        UnsupportedImageError: If the image can't be read without mounting it.
            Nothing was copied.
        PillageImageError: If the image is corrupt or can't be read
    """
    start_time = utils.utc_now()
    max_size = _max_size_option("max_file_size", DEFAULT_MAX_FILE_SIZE)
    max_total = _max_size_option("max_total_size", DEFAULT_MAX_TOTAL_SIZE)
    total_size = 0
    files_copied = []
    duplicates = []
    copied_data: dict[tuple[int, int], str] = {}  # (partition, data ID): destination
    num_skipped = 0
    num_errors = 0
    stop_reason = None

    log.info(f"Pillaging image {source} (without mounting it)")
    with pillage_image.DiskImage(source, config.PILLAGE.get("image_format")) as img:
        if img.info.get("hashes"):
            log.info(f"[Pillage] Hashes stored in the image: {img.info['hashes']}")

        recursive = config.PILLAGE.get("recursive", True)
        for img_file in img.iter_files(recursive, EXCLUDED_ROOT_DIRS):
            # "p1:/path/file.txt", so the logs say which partition it's in
            is_valid, brand = is_valid_file(PurePosixPath(str(img_file)))
            if not is_valid:
                continue

            if img_file.size > max_size:
                log.warning(
                    f"[Pillage] Skipping {img_file}: it's {utils.fmt_size(img_file.size)}, "
                    f"which is larger than the 'max_file_size' option "
                    f"({utils.fmt_size(max_size)})"
                )
                num_skipped += 1
                continue

            # Hard links (or cross-linked FAT files) to a file that was already
            # copied, e.g. a malicious image with many links to a large file
            data_key = None if img_file.data_id is None else (img_file.volume, img_file.data_id)
            if data_key in copied_data:
                log.info(
                    f"[Pillage] Not copying {img_file}: it's the same file as "
                    f"{copied_data[data_key]} (a hard link)"
                )
                duplicates.append({"source": str(img_file), "same_as": copied_data[data_key]})
                continue

            stop_reason = _output_limit_reason(results, img_file.size, total_size, max_total)
            if stop_reason:
                log.error(f"[Pillage] Stopped copying files at {img_file}: {stop_reason}")
                break

            dst = _unique_destination(results / brand, img_file.path.name)
            if not _confirm_copy(str(img_file), dst):
                num_skipped += 1
                continue

            sha256 = _copy_image_file(img_file, dst)
            if sha256 is None:
                num_errors += 1
                continue

            size = dst.stat().st_size
            total_size += size
            if data_key is not None:
                copied_data[data_key] = dst.as_posix()
            files_copied.append(
                {
                    "source": str(img_file),
                    "destination": dst.as_posix(),
                    "brand": brand,
                    "size": size,
                    "sha256": sha256,
                }
            )

        summary = {
            "source": str(source.resolve()),
            "source_type": "image",
            "backend": "library",
            **img.summary(),
            "files_copied": files_copied,
            "num_files_copied": len(files_copied),
            "total_size_copied": total_size,
            "duplicates": duplicates,
            "num_files_skipped": num_skipped,
            "num_errors": num_errors,
            "stopped_early": stop_reason,
            "start_time": start_time,
            "end_time": utils.utc_now(),
        }

    log.info(
        f"[Pillage] Copied {len(files_copied)} files ({utils.fmt_size(total_size)}) "
        f"from '{source.name}' ({num_skipped} skipped, {len(duplicates)} hard links "
        f"not copied again, {num_errors} errors)"
    )
    utils.save_results_summary(summary, "pillage-summary")

    return stop_reason is None


def _max_size_option(name: str, default: int) -> int:
    """A size limit Pillage option (e.g. ``max_file_size``), in bytes."""
    value = config.PILLAGE.get(name)
    if value is None:
        return default

    try:
        size = int(value)
        if size > 0:
            return size
    except (TypeError, ValueError):
        pass

    log.warning(
        f"[Pillage] Invalid '{name}' option '{value}' (must be a positive number "
        f"of bytes), using the default ({default})"
    )
    return default


def _output_limit_reason(results: Path, size: int, total_size: int, max_total: int) -> str | None:
    """
    Why a file of ``size`` bytes can't be copied to the results, if it can't:
    ``max_total_size`` would be exceeded, or the disk would be (almost) full.
    """
    if total_size + size > max_total:
        return (
            f"the total size of the copied files would be larger than the "
            f"'max_total_size' option ({utils.fmt_size(max_total)})"
        )

    try:
        free = shutil.disk_usage(results).free
    except OSError as ex:
        log.debug(f"[Pillage] Can't get the free disk space of '{results}': {ex}")
        return None

    if free - size < MIN_FREE_SPACE:
        return (
            f"not enough free disk space for the results ({utils.fmt_size(free)} free, "
            f"Pillage keeps at least {utils.fmt_size(MIN_FREE_SPACE)} free)"
        )
    return None


def _confirm_copy(src: str, dst: Path) -> bool:
    """Prompt the user if they want to copy a file, unless ``auto_copy`` is set."""
    if config.PILLAGE.get("auto_copy", True):
        return True

    answer = input(f"Found {src}, do you want to copy it to {dst} (Y or N):")
    print(answer, file=sys.stderr, flush=True)  # noqa: T201
    if answer == "Y":
        return True

    log.warning(f"[Pillage] Declined to copy {src} to {dst} (auto_copy is false)")
    return False


def _unique_destination(directory: Path, name: str) -> Path:
    """
    Path to copy a file from a disk image to, that doesn't exist yet.

    File names from images are untrusted: only the base name is used, and it's
    sanitized so it's valid on all platforms (e.g. ``:`` or ``CON`` on Windows).
    Duplicate names get a number added, e.g. ``set_all.txt.1``.
    """
    safe_name = consts.sanitize_filename(PurePath(name).name)
    if not safe_name or safe_name in (".", ".."):
        safe_name = "unnamed"

    dst = directory / safe_name
    count = 1
    while dst.exists() or dst.is_symlink():
        dst = directory / f"{safe_name}.{count}"
        count += 1

    return dst


def _copy_image_file(img_file: pillage_image.ImageFile, dst: Path) -> str | None:
    """
    Copy a file from a disk image.

    Returns:
        SHA256 hash of the file, or :obj:`None` if the copy failed (the error is logged)
    """
    sha256 = hashlib.sha256()
    created = False

    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        with dst.open("xb") as fp:  # Never overwrite or follow an existing file
            created = True
            for chunk in img_file.chunks():
                sha256.update(chunk)
                fp.write(chunk)
    except (OSError, pillage_image.PillageImageError) as ex:
        log.warning(f"[Pillage] Failed to copy {img_file} to {dst}: {ex}")
        if created:
            dst.unlink(missing_ok=True)
        return None

    log.info(f"[Pillage] Copied {img_file} to {dst}")
    return sha256.hexdigest()
