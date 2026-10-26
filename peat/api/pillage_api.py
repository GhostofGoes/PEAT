import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

# Allow module to be imported without errors
# on non-Linux systems (Windows and OSX).
try:
    import kmodpy

    KMODPY_INSTALLED = True
except (ImportError, OSError):
    KMODPY_INSTALLED = False

from peat import config, consts, log

# Keep track if the nbd module was already loaded when pillage started
# don't remove it if it was.  Keep the system in the same state when done
# pillaging
NBD_ALREADY_LOADED = False

#: Default for the ``max_file_size`` Pillage option: files larger than this
#: many bytes are skipped instead of copied (256 MiB)
DEFAULT_MAX_FILE_SIZE: Final[int] = 256 * 1024 * 1024

#: Flags used to open files being copied. O_NOFOLLOW refuses symbolic links and
#: O_NONBLOCK prevents blocking on a FIFO, in case a file is swapped after it's
#: checked. O_NOFOLLOW isn't available on Windows.
_COPY_OPEN_FLAGS: Final[int] = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)

#: Size of the chunks files are copied in (1 MiB)
_COPY_CHUNK_SIZE: Final[int] = 1024 * 1024


#: Disk image formats for the ``image_format`` Pillage option (``qemu-nbd -f``),
#: in addition to ``auto``. ``vpc`` is the VHD format.
IMAGE_FORMATS: Final[tuple[str, ...]] = ("raw", "qcow2", "vmdk", "vhdx", "vdi", "vpc")

#: Image format for file extensions, used if the ``image_format`` option is ``auto``
IMAGE_FORMAT_EXTENSIONS: Final[dict[str, str]] = {
    ".qcow2": "qcow2",
    ".qcow": "qcow2",
    ".vmdk": "vmdk",
    ".vhdx": "vhdx",
    ".vdi": "vdi",
    ".vhd": "vpc",
}

#: Seconds to wait for ``qemu-img info`` to check an image
QEMU_IMG_TIMEOUT: Final[float] = 60.0

#: Directory with the block devices of the system (Linux sysfs)
SYS_BLOCK_DIR: Final[Path] = Path("/sys/block")

# The Network Block Device (e.g. "/dev/nbd0") the image is connected to.
# NOTE: not Final, it's set by mount_image() and cleared by remove_nbd_device().
NBD_DEVICE: str | None = None

# TODO: integrate pillage with parse. Pillage results should go in peat_results.


def pillage(source: str, image_format: str | None = None) -> bool:
    """
    peat pillage.

    Args:
        source: Path of the directory or disk image to pillage
        image_format: Format of the disk image, overrides the ``image_format``
            Pillage option (refer to :func:`get_image_format`)

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

    log.info(f"Pillage source path: {source}")
    source_path = Path(source)

    # Validate source exists
    if source_path.exists():
        if source_path.is_dir():
            log.info(f"Pillaging directory {source}")
            return search(source_path, results_path)

        elif source_path.is_file():
            # TODO: build in support for images made of up smaller image files
            if validate_image_mounting():
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
                if mount_image(source_path, temp_path, image_format):
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
            "(Windows, WSL, or OSX are not supported at this time)"
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


def get_image_format(source: Path, image_format: str | None = None) -> str | None:
    """
    Get the format of a disk image from the ``image_format`` Pillage option.

    The format is never probed from the contents of the image, since a crafted
    raw image can pretend to be another format (e.g. qcow2) that references a
    "backing file" on the system running PEAT, which qemu would then open.
    If the option is ``auto`` (the default), the format is determined by the
    file extension (:data:`IMAGE_FORMAT_EXTENSIONS`, e.g. ``.qcow2``), and is
    ``raw`` for other extensions.

    Args:
        source: Path of the disk image
        image_format: Format to use instead of the ``image_format`` Pillage option

    Returns:
        The image format to pass to ``qemu-nbd -f``, or :obj:`None` if the option is invalid
    """
    if not image_format:
        image_format = config.PILLAGE.get("image_format") or "auto"
    image_format = str(image_format).strip().lower()

    if image_format == "auto":
        image_format = IMAGE_FORMAT_EXTENSIONS.get(source.suffix.lower(), "raw")
        log.info(f"Using image format '{image_format}' for '{source.name}' (from file extension)")

    if image_format not in IMAGE_FORMATS:
        log.error(
            f"Invalid 'image_format' Pillage option '{image_format}'. "
            f"Valid formats: auto, {', '.join(IMAGE_FORMATS)}"
        )
        return None

    return image_format


def _is_own_extent(source: Path, filename: str) -> bool:
    """
    If a VMDK extent file is part of the image: the image itself, or a file next
    to it named after it (e.g. ``disk-s001.vmdk`` or ``disk-flat.vmdk`` for a
    "split" ``disk.vmdk``) that is a regular file and not a symbolic link.
    """
    extent = Path(filename)
    if not extent.is_absolute():
        extent = source.parent / extent
    try:
        if extent.resolve() == source.resolve():
            return True
        return (
            extent.parent.resolve() == source.parent.resolve()
            and extent.name.startswith(f"{source.stem}-")
            and not extent.is_symlink()
            and extent.is_file()
        )
    except OSError:
        return False


def has_backing_file(source: Path, image_format: str) -> bool:
    """
    Check if a disk image references other files that qemu would open (e.g.
    files or devices on the system running PEAT), using ``qemu-img info``:
    a backing file, a qcow2 external data file (``data-file``), or VMDK
    extents that aren't part of the image (refer to :func:`_is_own_extent`).

    Raw images can't reference other files. If the image can't be checked,
    it's treated as if it references other files.
    """
    if image_format == "raw":
        return False

    info_args = ["qemu-img", "info", "--output=json", "-f", image_format, str(source)]
    try:
        info = json.loads(
            subprocess.check_output(info_args, stderr=subprocess.DEVNULL, timeout=QEMU_IMG_TIMEOUT)
        )
        format_specific = info.get("format-specific", {})
        data = format_specific.get("data", {})
        extents = data.get("extents", [])
        if not isinstance(extents, list):
            raise ValueError("invalid VMDK extents")
        extent_files = [str(e.get("filename") or "") for e in extents]
    except (
        OSError,
        ValueError,
        AttributeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as ex:
        log.error(f"Failed to check image '{source}' with '{' '.join(info_args)}': {ex}")
        return True

    if info.get("backing-filename") or info.get("full-backing-filename"):
        log.error(
            f"Refusing to mount image '{source}': it references a backing file "
            f"'{info.get('backing-filename')}', which could be a file on this system"
        )
        return True

    if data.get("data-file"):
        log.error(
            f"Refusing to mount image '{source}': it references an external data "
            f"file '{data.get('data-file')}', which could be a file on this system"
        )
        return True

    for extent_file in extent_files:
        if not extent_file or not _is_own_extent(source, extent_file):
            log.error(
                f"Refusing to mount image '{source}': it references an extent "
                f"file '{extent_file}', which could be a file on this system"
            )
            return True

    return False


def find_free_nbd_device() -> str | None:
    """
    Find a Network Block Device (``/dev/nbdN``) that isn't in use. The ``nbd``
    kernel module must be loaded. A device is in use if it has a ``pid`` file
    (the process serving it) or a non-zero size in ``/sys/block/nbdN``.

    Returns:
        The path of the device (e.g. ``/dev/nbd0``), or :obj:`None` if none are free
    """
    devices = []
    for path in SYS_BLOCK_DIR.glob("nbd*"):
        if match := re.fullmatch(r"nbd(\d+)", path.name):
            devices.append((int(match.group(1)), path))

    for _, path in sorted(devices):
        if (path / "pid").exists():
            continue
        try:
            if int((path / "size").read_text(encoding="utf-8").strip() or "0") != 0:
                continue
        except (OSError, ValueError):
            continue
        return f"/dev/{path.name}"

    return None


def mount_image(source: Path, mount_point: Path, image_format: str | None = None) -> bool:
    global NBD_ALREADY_LOADED, NBD_DEVICE

    image_format = get_image_format(source, image_format)
    if not image_format or has_backing_file(source, image_format):
        return False

    if "nbd" not in list_loaded_modules():
        try:
            # Equivalent of "modprobe nbd"
            kmodpy.Kmod().modprobe("nbd")
        except Exception as e:
            log.error(f"Failed to load 'nbd' kernel module: {e}")
            return False
    else:
        NBD_ALREADY_LOADED = True

    nbd_device = find_free_nbd_device()
    if not nbd_device:
        log.error("No free Network Block Devices (/dev/nbdN) to connect the image to")
        remove_nbd_module()
        return False

    # NOTE: the format is always given, so qemu doesn't probe it from the image
    nbd_args = ["qemu-nbd", "-r", "-f", image_format, "-c", nbd_device, str(source)]
    nbd_result = subprocess.call(nbd_args)
    if nbd_result != 0:
        log.error(f"Failed to run '{' '.join(nbd_args)}' (return code: {nbd_result})")
        remove_nbd_module()
        return False
    NBD_DEVICE = nbd_device

    # Give the system time to mount device before attempting to mount to folder
    time.sleep(0.5)

    # The image is untrusted: don't honor device files or setuid/setgid bits,
    # and don't allow anything on it to be executed.
    mnt_args = ["mount", "-o", "ro,nodev,nosuid,noexec", f"{nbd_device}p1", str(mount_point)]
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
    global NBD_DEVICE

    # Only disconnect the device PEAT connected, not one used by something else
    if not NBD_DEVICE:
        return True

    nbd_args = ["qemu-nbd", "-d", NBD_DEVICE]
    retval = subprocess.call(nbd_args)

    if retval != 0:
        log.error(f"Failed to run '{' '.join(nbd_args)}' (return code: {retval})")
        return False

    NBD_DEVICE = None
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

    excluded = [
        "Windows",
        "System Volume Information",
        "PerfLogs",
        "MSOCache",
        "cygwin64",
        "Recovery",
        "Boot",
        "$Recycle.Bin",
        "bootmgr",
    ]
    exclude_counter = 0
    max_file_size = config.PILLAGE.get("max_file_size", DEFAULT_MAX_FILE_SIZE)

    # NOTE: os.walk() doesn't follow symbolic links to directories by default
    for root, dirnames, filenames in os.walk(str(source)):
        log.trace2(f"Searching in: {root}")

        # Skip excluded directories at the top level of the source
        if root == str(source):
            for dirname in [d for d in dirnames if d in excluded]:
                log.trace2(f"Skipping excluded dir '{Path(root, dirname)}'")
                dirnames.remove(dirname)
                exclude_counter += 1

        for filename in filenames:
            src_file = Path(root) / filename

            # Only copy regular files. The source is untrusted, and symbolic
            # links or device files could be used to read files on the host.
            try:
                src_stat = os.lstat(src_file)
            except OSError as ex:
                log.warning(f"[Pillage] Failed to stat {src_file}: {ex}")
                continue

            if not stat.S_ISREG(src_stat.st_mode):
                log.debug(f"[Pillage] Skipping {src_file}: not a regular file")
                continue

            is_valid, config_type = is_valid_file(src_file)

            if is_valid and max_file_size and src_stat.st_size > max_file_size:
                log.warning(
                    f"[Pillage] Skipping {src_file}: size {src_stat.st_size} bytes "
                    f"is larger than the 'max_file_size' option ({max_file_size} bytes)"
                )
                continue

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
                        copy_file(src_file, dst_file, max_file_size, base=source)
                    else:
                        log.warning(
                            f"[Pillage] Declined to copy {src_file} to "
                            f"{dst_file} (auto_copy is false)"
                        )
                else:
                    copy_file(src_file, dst_file, max_file_size, base=source)

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


def _open_no_symlinks(src: Path, base: Path | None) -> int:
    """
    Open a file for copying. If ``base`` is set, each directory between ``base``
    and the file is opened relative to the previous one without following
    symbolic links, so a directory swapped for a link after it was checked
    can't be used to read a file outside of ``base``.
    """
    if base is None or os.open not in os.supports_dir_fd:  # e.g. Windows
        return os.open(src, _COPY_OPEN_FLAGS)

    parts = src.relative_to(base).parts
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, dir_flags, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        return os.open(parts[-1], _COPY_OPEN_FLAGS, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def copy_file(src: Path, dst: Path, max_size: int | None = None, base: Path | None = None) -> bool:
    """
    Copy a regular file, refusing to follow symbolic links or read special files.

    Args:
        src: File to copy
        dst: Path to copy the file to
        max_size: Stop copying and remove the partial copy if the file turns out
            to be larger than this many bytes (e.g. it grew after it was checked,
            or it's a pseudo-file that reports a size of 0). :obj:`None` or 0
            means there's no limit.
        base: Directory ``src`` was found in (e.g. the pillage source). If set,
            symbolic links in the directories between it and ``src`` aren't
            followed either.

    Returns:
        If the file was copied
    """
    try:
        fd = _open_no_symlinks(src, base)
    except (OSError, ValueError) as ex:
        log.warning(f"[Pillage] Failed to open {src}, skipping it: {ex}")
        return False

    with os.fdopen(fd, "rb") as fsrc:
        # Check what was actually opened, in case the file was swapped
        if not stat.S_ISREG(os.fstat(fsrc.fileno()).st_mode):
            log.warning(f"[Pillage] Skipping {src}: not a regular file")
            return False

        if not dst.parent.exists():
            dst.parent.mkdir(exist_ok=True, parents=True)

        copied = 0
        with dst.open("wb") as fdst:
            while chunk := fsrc.read(_COPY_CHUNK_SIZE):
                copied += len(chunk)
                if max_size and copied > max_size:
                    break
                fdst.write(chunk)

    if max_size and copied > max_size:
        dst.unlink(missing_ok=True)
        log.warning(
            f"[Pillage] Skipping {src}: it's larger than the 'max_file_size' "
            f"option ({max_size} bytes)"
        )
        return False

    log.info(f"[Pillage] Copied {src} to {dst}")
    return True


def is_valid_file(_file: Path):
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


def check_file_conditions(_file: Path, conditions: dict[str, list]) -> tuple:
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
