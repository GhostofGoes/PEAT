import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

# Allow module to be imported without errors
# on non-Linux systems (Windows and OSX).
# kmodpy is only used for mounting disk images on Linux.
try:
    import kmodpy

    KMODPY_INSTALLED = True
except (ImportError, OSError):
    KMODPY_INSTALLED = False

from peat import config, consts, log, utils

# Keep track if the nbd module was already loaded when pillage started
# don't remove it if it was.  Keep the system in the same state when done
# pillaging
NBD_ALREADY_LOADED = False

#: Disk image formats that Windows can mount natively (with ``Mount-DiskImage``).
#: Other formats are converted to VHDX with ``qemu-img`` before mounting.
WINDOWS_NATIVE_IMAGE_FORMATS = (".vhd", ".vhdx", ".iso")

#: Directories in the root of the source that are skipped when searching.
#: These are Windows system directories that won't have project files in them.
#: Names are compared case-insensitively, since Windows paths are case-insensitive.
EXCLUDED_DIRS = [
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

# Mounts the disk image read-only (unless it's already attached), waits for
# Windows to bring its volumes online, then prints the volumes as JSON.
# The image path is passed in an environment variable to avoid quoting issues.
_PS_MOUNT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$imagePath = $env:PEAT_PILLAGE_IMAGE
$alreadyAttached = (Get-DiskImage -ImagePath $imagePath).Attached
if (-not $alreadyAttached) {
    Mount-DiskImage -ImagePath $imagePath -Access ReadOnly | Out-Null
}
$volumes = @()
for ($i = 0; $i -lt 30; $i++) {
    $volumes = @(Get-DiskImage -ImagePath $imagePath | Get-Volume -ErrorAction SilentlyContinue)
    if ($volumes.Count -gt 0) { break }
    # ISO images only have one volume, but VHDs are disks with partitions.
    # Windows Server's default SAN policy leaves newly attached disks offline.
    $disk = Get-DiskImage -ImagePath $imagePath | Get-Disk -ErrorAction SilentlyContinue
    if ($disk) {
        if ($disk.IsOffline) {
            Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
        }
        $volumes = @($disk | Get-Partition -ErrorAction SilentlyContinue |
            Get-Volume -ErrorAction SilentlyContinue)
        if ($volumes.Count -gt 0) { break }
    }
    Start-Sleep -Milliseconds 500
}
$result = [PSCustomObject]@{
    already_attached = [bool]$alreadyAttached
    volumes = @($volumes | ForEach-Object {
        [PSCustomObject]@{
            drive_letter = if ($_.DriveLetter) { [string]$_.DriveLetter } else { '' }
            path = [string]$_.Path
            filesystem = [string]$_.FileSystemType
            label = [string]$_.FileSystemLabel
        }
    })
}
ConvertTo-Json -InputObject $result -Depth 3 -Compress
"""

_PS_UNMOUNT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Dismount-DiskImage -ImagePath $env:PEAT_PILLAGE_IMAGE | Out-Null
"""

# TODO: integrate pillage with parse. Pillage results should go in peat_results.


def pillage(source: str) -> bool:
    """
    peat pillage.

    Args:
        config_file: Path to pillage config file
        source: Path of directory to pillage

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
            log.info(f"Pillaging image {source}")
            if consts.WINDOWS:
                return pillage_image_windows(source_path, results_path)

            # TODO: build in support for images made of up smaller image files
            if not validate_image_mounting():
                return False

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
        else:
            log.error("Unsupported source type")
            return False

    log.error(f"Source ({source}) does not exist")
    return False


def validate_image_mounting() -> bool:
    """Ensure all the requirements needed to mount an image are satisfied.

    In order to mount an image and search, certain conditions must be met:

    - PEAT must be run as ``root``
    - PEAT must be run on a Linux system and not on Windows Subsystem for Linux (WSL).
      Windows is handled separately, by :func:`validate_image_mounting_windows`.
    - ``kmodpy`` Python package must be installed
    - ``qemu-nbd`` must be installed and available in the system PATH

    Returns:
        If the requirements for mounting are met
    """
    if consts.WSL or not consts.LINUX:
        log.error(
            "To mount an image for searching, you must be running on Linux "
            "or Windows (WSL and OSX are not supported at this time). If you "
            "are using WSL, run peat.exe on Windows instead."
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


def pillage_image_windows(source: Path, results: Path) -> bool:
    """
    Mount a disk image read-only on Windows, search its volumes, then unmount it.

    VHD, VHDX, and ISO images are mounted natively with ``Mount-DiskImage``.
    Other formats (raw, VMDK, qcow2, etc.) are first converted to a temporary
    VHDX file in ``pillage_temp`` using ``qemu-img``, which must be installed.
    """
    if not validate_image_mounting_windows(source):
        return False

    image = source.resolve()
    temp_path = None

    if image.suffix.lower() not in WINDOWS_NATIVE_IMAGE_FORMATS:
        temp_path = Path("pillage_temp")
        if temp_path.exists():
            shutil.rmtree(temp_path)
        temp_path.mkdir()

        converted = convert_image_windows(image, temp_path.resolve())
        if not converted:
            shutil.rmtree(temp_path, ignore_errors=True)
            return False
        image = converted

    success = False
    mount_info = mount_image_windows(image)

    if mount_info is None:
        log.error("Failed to mount image")
    else:
        try:
            success = search_volumes_windows(mount_info["volumes"], results)
        except (Exception, KeyboardInterrupt) as ex:
            log.critical(f"Failed pillage search: {ex}")

        # Leave the image attached if it was attached before pillage started
        if mount_info["already_attached"]:
            log.info(f"Leaving '{image}' attached, since it was attached before pillage started")
        elif unmount_image_windows(image):
            log.debug(f"Unmounted image '{image}'")

    if temp_path and temp_path.exists():
        shutil.rmtree(temp_path, ignore_errors=True)
        log.debug(f"Deleted temp directory '{temp_path}'")

    return success


def validate_image_mounting_windows(source: Path) -> bool:
    """
    Ensure all the requirements needed to mount an image on Windows are satisfied.

    - PowerShell (``powershell.exe``) must be available, for ``Mount-DiskImage``
    - PEAT must be run as Administrator, unless the image is an ISO
    - ``qemu-img`` must be installed and in the system PATH, unless
      the image is a VHD, VHDX, or ISO

    Returns:
        If the requirements for mounting are met
    """
    suffix = source.suffix.lower()

    if not shutil.which("powershell"):
        log.error(
            "Could not find 'powershell.exe', which is required to mount a disk image on Windows"
        )
    elif suffix != ".iso" and not utils.are_we_superuser():
        log.error(
            "To mount a disk image for searching on Windows, you must run PEAT "
            "as Administrator (ISO images are the exception). Re-run PEAT from "
            "an Administrator PowerShell or CMD terminal."
        )
    elif suffix not in WINDOWS_NATIVE_IMAGE_FORMATS and not shutil.which("qemu-img"):
        log.error(
            f"Windows can't mount '{suffix}' images natively, only VHD, VHDX, and ISO "
            f"images. Install QEMU (https://qemu.weilnetz.de/w64/) and add "
            f"'qemu-img.exe' to the PATH so PEAT can convert the image, convert it "
            f"to VHDX yourself ('qemu-img convert -O vhdx {source.name} image.vhdx'), "
            f"or mount it with another tool and pillage the drive letter instead."
        )
    else:
        return True

    return False


def convert_image_windows(source: Path, temp_dir: Path) -> Path | None:
    """
    Convert a disk image Windows can't mount natively to a VHDX file.

    Returns:
        Path to the converted VHDX image, or :obj:`None` if the conversion failed
    """
    dest = temp_dir / f"{source.stem}.vhdx"
    qemu_args = ["qemu-img", "convert", "-O", "vhdx", str(source), str(dest)]

    log.info(
        f"Converting '{source.name}' to VHDX so Windows can mount it. This makes "
        f"a temporary copy of the image in '{temp_dir}', which may take a while "
        f"and use a lot of disk space for large images."
    )
    log.debug(f"Running '{' '.join(qemu_args)}'")

    retval = subprocess.call(qemu_args)
    if retval != 0 or not dest.is_file():
        log.error(f"Failed to run '{' '.join(qemu_args)}' (return code: {retval})")
        return None

    return dest


def _run_powershell(script: str, image: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PEAT_PILLAGE_IMAGE"] = str(image)

    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def mount_image_windows(image: Path) -> dict | None:
    """
    Mount a VHD, VHDX, or ISO image read-only using ``Mount-DiskImage``.

    Returns:
        Dict with ``already_attached`` (if the image was already attached, in which
        case it isn't mounted again) and ``volumes`` (list of dicts describing each
        volume on the image), or :obj:`None` if mounting failed.
    """
    log.debug(f"Mounting image '{image}' (read-only)")
    proc = _run_powershell(_PS_MOUNT_SCRIPT, image)

    if proc.returncode != 0:
        log.error(
            f"Failed to mount '{image}' with Mount-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}"
        )
        return None

    try:
        info = json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        log.error(f"Failed to parse Mount-DiskImage output: {proc.stdout.strip()}")
        unmount_image_windows(image)
        return None

    # PowerShell 5.1 doesn't serialize empty arrays nested in objects consistently
    volumes = info.get("volumes") or []
    if isinstance(volumes, dict):
        volumes = [volumes]
    info["volumes"] = volumes

    log.debug(f"Mounted image '{image}' with {len(volumes)} volumes: {volumes}")
    return info


def unmount_image_windows(image: Path) -> bool:
    proc = _run_powershell(_PS_UNMOUNT_SCRIPT, image)

    if proc.returncode != 0:
        log.error(
            f"Failed to unmount '{image}' with Dismount-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}"
        )
        return False

    return True


def search_volumes_windows(volumes: list[dict], results: Path) -> bool:
    """
    Search the volumes of a mounted disk image.

    Volumes that were assigned a drive letter are searched using it
    (e.g. ``E:\\``), otherwise the volume GUID path is used
    (e.g. ``\\\\?\\Volume{...}\\``). Volumes with a filesystem Windows
    can't read (e.g. ext4) are skipped.

    Returns:
        If at least one volume was searched successfully
    """
    searched = 0

    for vol in volumes:
        fs = vol.get("filesystem", "")
        name = vol.get("label") or vol.get("path", "")

        if not fs or fs.lower() in ["unknown", "raw"]:
            log.warning(
                f"Skipping volume '{name}', its filesystem isn't readable by Windows. "
                f"To pillage it, run PEAT on Linux, which supports more filesystems."
            )
            continue

        if vol.get("drive_letter"):
            vol_path = f"{vol['drive_letter']}:\\"
        elif vol.get("path"):
            # Kept as a string, since pathlib drops the trailing backslash from
            # volume GUID paths, and without it they refer to the volume device
            # instead of the root directory of its filesystem.
            vol_path = vol["path"].rstrip("\\/") + os.sep
        else:
            log.warning(f"Skipping volume '{name}', it doesn't have a path")
            continue

        log.info(f"Pillaging volume '{vol_path}' ({fs}, label: '{vol.get('label', '')}')")
        if search(vol_path, results):
            searched += 1

    if not searched:
        log.error("No volumes on the image could be searched")
        return False

    return True


def _is_junction(path: str) -> bool:
    """
    If a path is a Windows directory junction (mount point reparse point).

    Junctions such as ``C:\\Documents and Settings`` point to other directories
    on the same system, and following them would search the same files twice.
    """
    try:
        return os.lstat(path).st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    except (AttributeError, OSError):
        return False


def search(source: Path | str, results: Path) -> bool:
    source = str(source)
    if not os.path.isdir(source):
        log.error(f"Failed pillage search: source path '{source}' is not a valid directory.")
        return False

    excluded = {name.lower() for name in EXCLUDED_DIRS}
    exclude_counter = 0

    def _walk_error(err: OSError) -> None:
        # Common on live Windows systems, e.g. for folders only SYSTEM can read
        log.debug(f"Failed to search '{err.filename}': {err.strerror}")

    for root, dirnames, filenames in os.walk(source, onerror=_walk_error):
        log.trace2(f"Searching in: {root}")

        # Prune excluded system directories in the root of the source,
        # and junctions, so os.walk doesn't descend into them.
        for dirname in list(dirnames):
            dir_path = os.path.join(root, dirname)
            if (root == source and dirname.lower() in excluded) or (
                consts.WINDOWS and _is_junction(dir_path)
            ):
                log.trace2(f"Skipping excluded dir '{dir_path}'")
                dirnames.remove(dirname)
                exclude_counter += 1

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


def copy_file(src: Path, dst: Path) -> None:
    if not dst.parent.exists():
        dst.parent.mkdir(exist_ok=True, parents=True)

    try:
        shutil.copyfile(str(src), str(dst))
    except OSError as ex:
        # e.g. the file is locked by another program on Windows
        log.error(f"[Pillage] Failed to copy {src} to {dst}: {ex}")
        return

    log.info(f"[Pillage] Copied {src} to {dst}")


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
