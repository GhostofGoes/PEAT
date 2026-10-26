"""
Mount disk images read-only and find the files on their volumes, for ``peat parse``.

Disk images are mounted with ``qemu-nbd`` on Linux, ``Mount-DiskImage`` on Windows,
and ``hdiutil`` on macOS.
"""

import contextlib
import errno
import getpass
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# Allow module to be imported without errors
# on non-Linux systems (Windows and macOS).
# kmodpy is only used for mounting disk images on Linux.
try:
    import kmodpy

    KMODPY_INSTALLED = True
except (ImportError, OSError):
    KMODPY_INSTALLED = False

from peat import consts, log, utils

# Keep track if the nbd module was already loaded before mounting an image,
# and don't remove it if it was. Keep the system in the same state when done.
NBD_ALREADY_LOADED = False

#: Disk image formats that Windows can mount natively (with ``Mount-DiskImage``).
#: Other formats are converted to VHDX with ``qemu-img`` before mounting.
WINDOWS_NATIVE_IMAGE_FORMATS: Final[tuple[str, ...]] = (".vhd", ".vhdx", ".iso")

#: Directories in the root of a drive, mount, or disk image that are skipped when searching.
#: These are Windows system directories that won't have project files in them.
#: Names are compared case-insensitively, since Windows paths are case-insensitive.
EXCLUDED_DIRS: Final[tuple[str, ...]] = (
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

#: OEM ID in the boot sector of a BitLocker encrypted volume, at offset 3
BITLOCKER_SIGNATURE: Final[bytes] = b"-FVE-FS-"

#: Magic bytes at the start of a LUKS (version 1 or 2) encrypted volume
LUKS_SIGNATURE: Final[bytes] = b"LUKS\xba\xbe"

#: Times to prompt for the password of a locked volume, if there isn't a password file
MAX_PASSWORD_PROMPTS: Final[int] = 3

#: Seconds to wait for a command used for mounting images to finish
COMMAND_TIMEOUT: Final[float] = 120.0

#: File extension of images converted with ``qemu-img``, by output format
CONVERTED_IMAGE_SUFFIXES: Final[dict[str, str]] = {"vhdx": ".vhdx", "raw": ".img"}

#: Paths (relative to the root) of macOS system directories that are skipped when
#: searching the root of a volume, along with :data:`EXCLUDED_DIRS`.
#: ``System`` includes ``System/Volumes/Data``, where the macOS Data volume is
#: mounted, since its contents are also in ``/`` through firmlinks (e.g. ``/Users``).
MACOS_EXCLUDED_DIRS: Final[tuple[str, ...]] = (
    "System",
    "cores",
    "private/var/vm",
    "private/var/db",
    "private/var/folders",
    ".Spotlight-V100",
    ".fseventsd",
    ".DocumentRevisions-V100",
    ".MobileBackups",
    ".Trashes",
    ".vol",
)

#: Directories in the root of a live macOS system (``/``) that other filesystems are
#: mounted on (other drives, disk images, network shares, and devices), which are
#: skipped when searching ``/``. To search them, parse them directly.
MACOS_ROOT_EXCLUDED_DIRS: Final[tuple[str, ...]] = ("Volumes", "dev", "Network", "net", "home")

#: Where the macOS Data volume is mounted, relative to ``/``. Everything on it is also
#: in ``/`` through firmlinks, so it's never searched as part of ``/``.
MACOS_DATA_VOLUME: Final[str] = "System/Volumes/Data"

#: File flag (``st_flags``) of a "dataless" file, a placeholder for a file in iCloud
#: Drive or another cloud storage provider that hasn't been downloaded.
#: ``stat.SF_DATALESS`` was added in Python 3.13.
SF_DATALESS: Final[int] = getattr(stat, "SF_DATALESS", 0x40000000)

#: Disk image formats that macOS attaches natively with ``hdiutil``, which detects
#: their format itself. Raw images are attached with ``hdiutil``'s raw disk image
#: class, and other formats are converted to raw images with ``qemu-img`` first.
MACOS_NATIVE_IMAGE_FORMATS: Final[tuple[str, ...]] = (
    ".dmg",
    ".sparseimage",
    ".sparsebundle",
    ".iso",
    ".cdr",
)

#: File extensions of raw disk images (e.g. from ``dd``). If ``qemu-img`` is
#: installed, it's used to check the format instead (e.g. a ``.img`` may be qcow2).
MACOS_RAW_IMAGE_FORMATS: Final[tuple[str, ...]] = (".img", ".raw", ".dd", ".bin")

#: Directory the temporary mount points for disk images are created in on macOS.
#: Mount point paths must be short, since macOS limits their length.
MACOS_MOUNT_ROOT_PARENT: Final[str] = "/tmp"

#: ``content-hint`` of entities on an attached disk image that aren't
#: volumes (e.g. partition maps), which are skipped without a warning
MACOS_NON_VOLUME_HINTS: Final[frozenset[str]] = frozenset(
    {
        "GUID_partition_scheme",
        "FDisk_partition_scheme",
        "Apple_partition_scheme",
        "Apple_partition_map",
        "Apple_Free",
        "Apple_Boot",
        "EFI",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",  # EFI system partition
        "426F6F74-0000-11AA-AA11-00306543ECAC",  # Apple_Boot
    }
)

#: ``content-hint`` of APFS physical stores, containers, and volumes on an
#: attached disk image, which are mounted (and unlocked) with ``diskutil apfs``
MACOS_APFS_HINTS: Final[frozenset[str]] = frozenset(
    {
        "Apple_APFS",
        "Apple_APFS_Container",
        "Apple_APFS_Volume",
        "7C3457EF-0000-11AA-AA11-00306543ECAC",  # Physical store partition
        "EF57347C-0000-11AA-AA11-00306543ECAC",  # Container
        "41504653-0000-11AA-AA11-00306543ECAC",  # Volume
    }
)

#: Roles of APFS volumes used to boot macOS, which won't have project files
#: on them, and aren't mounted unless macOS mounted them already
MACOS_SKIPPED_APFS_ROLES: Final[frozenset[str]] = frozenset(
    {"VM", "Preboot", "Recovery", "Update", "Hardware", "xART", "Baseband"}
)

#: Times to try to detach a disk image on macOS. The last try uses ``-force``.
MACOS_DETACH_ATTEMPTS: Final[int] = 5

#: Seconds to wait between tries to detach a disk image on macOS
MACOS_DETACH_RETRY_DELAY: Final[float] = 2.0

#: Seconds to wait for ``hdiutil attach`` to finish, which can be slow for large images
MACOS_ATTACH_TIMEOUT: Final[float] = 600.0

# Scripts for mounting disk images on Windows. The image path is passed in
# an environment variable, to avoid quoting issues and command injection.

_PS_ATTACHED_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
[bool](Get-DiskImage -ImagePath $env:PEAT_DISK_IMAGE).Attached
"""

# Mounts the disk image read-only (unless it's already attached), waits for
# Windows to bring all of its volumes online, then prints the volumes as JSON.
# Partitions on a disk come online one at a time, so it waits until the number
# of volumes stops changing, to avoid missing any.
_PS_MOUNT_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$imagePath = $env:PEAT_DISK_IMAGE
$alreadyAttached = (Get-DiskImage -ImagePath $imagePath).Attached
if (-not $alreadyAttached) {
    Mount-DiskImage -ImagePath $imagePath -Access ReadOnly | Out-Null
}
$volumes = @()
$previousCount = -1
for ($i = 0; $i -lt 30; $i++) {
    # ISO images are optical drives with one volume, VHDs are disks with partitions
    $disk = Get-DiskImage -ImagePath $imagePath | Get-Disk -ErrorAction SilentlyContinue
    if ($disk) {
        # Windows Server's default SAN policy leaves newly attached disks offline.
        # Disks that were already attached are left as they are.
        if ($disk.IsOffline -and -not $alreadyAttached) {
            Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
        }
        $volumes = @($disk | Get-Partition -ErrorAction SilentlyContinue |
            Get-Volume -ErrorAction SilentlyContinue)
    } else {
        $volumes = @(Get-DiskImage -ImagePath $imagePath |
            Get-Volume -ErrorAction SilentlyContinue)
    }
    if ($volumes.Count -gt 0 -and $volumes.Count -eq $previousCount) { break }
    $previousCount = $volumes.Count
    Start-Sleep -Milliseconds 500
}
# The lock status of volumes without a readable filesystem, if the BitLocker
# module is available (it isn't on Windows Server without the BitLocker feature)
$bitlocker = [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
$result = [PSCustomObject]@{
    volumes = @($volumes | ForEach-Object {
        $letter = if ($_.DriveLetter) { [string]$_.DriveLetter } else { '' }
        $fs = [string]$_.FileSystemType
        $lockStatus = ''
        if ($bitlocker -and (-not $fs -or $fs -eq 'Unknown' -or $fs -eq 'RAW')) {
            $mountPoint = if ($letter) { "$($letter):" } else { [string]$_.Path }
            try {
                $lockStatus = [string](Get-BitLockerVolume -MountPoint $mountPoint).LockStatus
            } catch { }
        }
        [PSCustomObject]@{
            drive_letter = $letter
            path = [string]$_.Path
            filesystem = $fs
            label = [string]$_.FileSystemLabel
            bitlocker = $lockStatus
        }
    })
}
ConvertTo-Json -InputObject $result -Depth 3 -Compress
"""

_PS_UNMOUNT_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
$imagePath = $env:PEAT_DISK_IMAGE
if ((Get-DiskImage -ImagePath $imagePath).Attached) {
    Dismount-DiskImage -ImagePath $imagePath | Out-Null
}
"""

#: Seconds to wait for a PowerShell command used for mounting images to finish
POWERSHELL_TIMEOUT: Final[float] = 120.0

#: Called with the path of each volume on a mounted disk image, to search it.
#: Returns if the volume was searched successfully.
VolumeHandler = Callable[[str], bool]

#: File extensions of disk images that ``peat parse`` mounts and searches, if no
#: device module parses the file. ``.bin`` isn't included, even though raw disk
#: images sometimes use it, since it's much more common for firmware.
DISK_IMAGE_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".img",
        ".raw",
        ".dd",
        ".vmdk",
        ".qcow2",
        ".qcow",
        ".vhd",
        ".vhdx",
        ".vdi",
        ".iso",
        ".dmg",
        ".sparseimage",
        ".sparsebundle",
        ".cdr",
    }
)


def is_disk_image(path: Path | str) -> bool:
    """
    If a path looks like a disk image that can be mounted, from its file extension.

    macOS sparse bundles (``.sparsebundle``) are directories, and are only
    treated as disk images on macOS, since they can only be mounted there.
    """
    path = Path(path)
    if path.suffix.lower() not in DISK_IMAGE_SUFFIXES:
        return False
    return path.is_file() or _is_image_bundle(path)


def search_image(
    source: Path | str, handler: VolumeHandler, password_file: Path | str | None = None
) -> bool:
    """
    Mount a disk image read-only, search each of its volumes, then unmount it.

    Images are mounted with ``qemu-nbd`` on Linux (as root), ``Mount-DiskImage``
    on Windows (as Administrator, except for ISO images), and ``hdiutil`` on macOS.
    Refer to the "Disk images" section of the parse documentation for details.

    Args:
        source: Path of the disk image to search
        handler: Called with the path of each mounted volume, to search it.
            The volume is only mounted until the handler returns.
        password_file: File with passwords to unlock encrypted disk images
            and volumes, one per line (see :class:`UnlockSecrets`)

    Returns:
        If at least one volume on the image was searched successfully
    """
    source_path = Path(source)
    if not is_disk_image(source_path):
        log.error(f"'{source}' isn't a disk image PEAT can mount, or doesn't exist")
        return False

    secrets = UnlockSecrets(password_file)
    if not secrets.load():
        return False

    if password_file and not consts.MACOS:
        log.warning(
            "Ignoring the password file, since unlocking encrypted volumes "
            "is only supported on macOS (encrypted DMG and APFS volumes)"
        )

    if consts.WINDOWS:
        return search_image_windows(source_path, handler)

    if consts.MACOS:
        return search_image_macos(source_path, handler, secrets)

    # TODO: build in support for images made of up smaller image files
    if not validate_image_mounting():
        return False

    log.info(f"Searching disk image {source}")

    # Temporary directory to mount the image to
    temp_path = Path(tempfile.mkdtemp(prefix="peat_image_"))

    # Mount image
    log.debug(f"Mount image to {temp_path}")
    success = False
    mounted = False
    try:
        mounted = mount_image(source_path, temp_path)
        if mounted:
            success = handler(str(temp_path))
        else:
            log.error("Failed to mount image")
    except Exception as ex:
        log.critical(f"Failed to search disk image: {ex}")
    finally:
        # Unmount, even if the search was interrupted (e.g. with Ctrl+C)
        if mounted and unmount_image(temp_path):
            log.debug(f"Unmounted image from '{temp_path}'")

        try:
            temp_path.rmdir()
            log.debug(f"Deleted temp directory '{temp_path}'")
        except OSError as ex:
            log.warning(f"Failed to delete temp directory '{temp_path}': {ex}")

    return success


def _is_image_bundle(path: Path) -> bool:
    """If a directory is a macOS disk image bundle (``.sparsebundle``)."""
    return consts.MACOS and path.suffix.lower() == ".sparsebundle" and path.is_dir()


class UnlockSecrets:
    """
    Passwords and BitLocker recovery passwords used to unlock encrypted volumes.

    Secrets are read from a password file, with one password or recovery password
    per line. Each line is used exactly as written, only the line ending is removed,
    and empty lines are ignored. If there isn't a password file and PEAT is running
    in an interactive terminal, the user is prompted for a password when a locked
    volume is found instead.

    Secrets are never logged, and are passed to other programs through
    stdin or environment variables, never as command line arguments.
    """

    def __init__(self, password_file: Path | str | None = None) -> None:
        self.password_file: Path | None = Path(password_file) if password_file else None
        self._secrets: list[str] = []

    def load(self) -> bool:
        """
        Read the password file, if there is one.

        Returns:
            If the password file was read successfully, or there isn't one
        """
        if not self.password_file:
            return True

        try:
            text = self.password_file.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as ex:
            log.error(f"Failed to read password file '{self.password_file}': {ex}")
            return False

        self._secrets = [line.rstrip("\r") for line in text.split("\n") if line.rstrip("\r")]
        if not self._secrets:
            log.error(f"Password file '{self.password_file}' doesn't have any passwords in it")
            return False

        log.info(
            f"Read {len(self._secrets)} passwords from '{self.password_file}', "
            f"to try on encrypted volumes"
        )
        return True

    @staticmethod
    def can_prompt() -> bool:
        """If PEAT is running in an interactive terminal, so the user can be prompted."""
        try:
            return bool(sys.stdin and sys.stdin.isatty())
        except (AttributeError, ValueError):
            return False

    def candidates(self, volume: str) -> Iterator[str]:
        """
        The secrets to try on a locked volume, in order.

        Secrets from the password file (and ones that unlocked other volumes)
        are tried first. Then, if there isn't a password file and PEAT is running
        in an interactive terminal, the user is prompted, up to
        :data:`MAX_PASSWORD_PROMPTS` times, or until they enter an empty password.
        """
        yield from list(self._secrets)

        if self.password_file or not self.can_prompt():
            return

        for _ in range(MAX_PASSWORD_PROMPTS):
            try:
                secret = getpass.getpass(f"Password for {volume} (leave empty to skip it): ")
            except EOFError:
                return
            if not secret:
                return
            yield secret

    def remember(self, secret: str) -> None:
        """Remember a secret that unlocked a volume, to try it first on other volumes."""
        if secret not in self._secrets:
            self._secrets.insert(0, secret)


def _locked_volume_message(name: str, label: str) -> str:
    return (
        f"Skipping volume {name}, it's encrypted with {label} and locked. To search "
        f"it, run parse with '--password-file FILE', where FILE has the password "
        f"or recovery password on a line, or run it in a terminal to be prompted "
        f"for the password."
    )


def _run_command(
    args: list[str], input_data: bytes = b"", timeout: float = COMMAND_TIMEOUT
) -> subprocess.CompletedProcess:
    """
    Run a command used to mount images, and capture its output.

    Secrets must only be passed in ``input_data`` (stdin), never in ``args``.
    Output is captured to temporary files instead of pipes, since commands that
    start a daemon (e.g. ``qemu-nbd -c``, or FUSE filesystems) may leave a pipe
    open after they exit, which would block reading it.
    """
    log.debug(f"Running '{' '.join(args)}'")

    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.run(
                args, input=input_data, stdout=out, stderr=err, timeout=timeout, check=False
            )
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            returncode = 1
            err.write(f"timed out after {timeout} seconds".encode())
        except OSError as ex:
            returncode = 1
            err.write(str(ex).encode())

        out.seek(0)
        err.seek(0)
        return subprocess.CompletedProcess(
            args,
            returncode,
            stdout=out.read().decode("utf-8", errors="replace"),
            stderr=err.read().decode("utf-8", errors="replace").strip(),
        )


def _run_failed(proc: subprocess.CompletedProcess) -> str:
    return f"Failed to run '{' '.join(proc.args)}' (return code: {proc.returncode})" + (
        f": {proc.stderr}" if proc.stderr else ""
    )


def validate_image_mounting() -> bool:
    """Ensure all the requirements needed to mount an image are satisfied.

    In order to mount an image and search, certain conditions must be met:

    - PEAT must be run as ``root``
    - PEAT must be run on a Linux system and not on Windows Subsystem for Linux (WSL).
      Windows and macOS are handled separately, by :func:`validate_image_mounting_windows`
      and :func:`validate_image_mounting_macos`.
    - ``kmodpy`` Python package must be installed
    - ``qemu-nbd`` must be installed and available in the system PATH

    Returns:
        If the requirements for mounting are met
    """
    if consts.WSL or not consts.LINUX:
        log.error(
            "To mount an image for searching, you must be running on Linux, "
            "Windows, or macOS (WSL is not supported at this time). If you "
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

    if is_bitlocker(read_volume_header("/dev/nbd1p1")):
        log.error(
            "The first partition of the image is encrypted with BitLocker, which "
            "PEAT can't search. To search it, unlock and mount it yourself "
            "(e.g. with 'cryptsetup open --type bitlk --readonly' or dislocker), "
            "then parse the mount point."
        )
        remove_nbd_device()
        remove_nbd_module()
        return False

    # The image's contents are untrusted: no device files, setuid, or executables
    mnt_args = ["mount", "-o", "ro,nodev,nosuid,noexec", "/dev/nbd1p1", str(mount_point)]
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


def search_image_windows(source: Path, handler: VolumeHandler) -> bool:
    """
    Mount a disk image read-only on Windows, search its volumes, then unmount it.

    VHD, VHDX, and ISO images are mounted natively with ``Mount-DiskImage``.
    Other formats (raw, VMDK, qcow2, etc.) are first converted to a temporary
    VHDX file in a ``peat_image_*`` directory using ``qemu-img``, which must
    be installed. Images that were attached before PEAT started are left
    attached and aren't modified.
    """
    if not validate_image_mounting_windows(source):
        return False

    log.info(f"Searching disk image {source}")

    # Not resolve(), which turns mapped network drives into UNC paths,
    # and those may not be visible from an Administrator terminal.
    image = Path(os.path.abspath(source))
    temp_path = None
    mount_attempted = False
    already_attached = False
    success = False

    try:
        if image.suffix.lower() not in WINDOWS_NATIVE_IMAGE_FORMATS:
            temp_path = Path(tempfile.mkdtemp(prefix="peat_image_", dir=os.getcwd()))
            converted = convert_image(image, temp_path, "vhdx")
            if not converted:
                return False
            image = converted

        already_attached = is_image_attached_windows(image)
        if already_attached is None:
            return False

        mount_attempted = True
        volumes = mount_image_windows(image)

        if volumes is None:
            log.error("Failed to mount image")
        else:
            try:
                success = search_volumes_windows(volumes, handler)
            except Exception as ex:
                log.critical(f"Failed to search disk image: {ex}")
    finally:
        # Leave the image attached if it was attached before PEAT started.
        # Otherwise, always unmount it, even if mounting failed part way.
        if mount_attempted and already_attached:
            log.info(f"Leaving '{image}' attached, since it was attached before PEAT started")
        elif mount_attempted and unmount_image_windows(image):
            log.debug(f"Unmounted image '{image}'")

        if temp_path:
            try:
                shutil.rmtree(temp_path)
                log.debug(f"Deleted temp directory '{temp_path}'")
            except OSError as ex:
                log.warning(
                    f"Failed to delete temp directory '{temp_path}', delete it "
                    f"manually (see 'Disk images' in the parse documentation): {ex}"
                )

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
            f"or mount it with another tool and parse the drive letter instead."
        )
    else:
        return True

    return False


def qemu_img_info(source: Path) -> dict | None:
    """
    Information about a disk image from ``qemu-img info``, such as its
    format (``format``), size (``virtual-size``), and the disk space it
    uses (``actual-size``).

    Returns:
        The information, or :obj:`None` if ``qemu-img`` isn't
        installed or couldn't read the image
    """
    if not shutil.which("qemu-img"):
        return None

    proc = _run_command(["qemu-img", "info", "--output=json", str(source)])
    if proc.returncode != 0:
        log.debug(_run_failed(proc))
        return None

    try:
        info = json.loads(proc.stdout)
    except json.JSONDecodeError:
        log.debug(f"Failed to parse 'qemu-img info' output: {proc.stdout.strip()}")
        return None

    return info if isinstance(info, dict) else None


def check_conversion_space(source: Path, temp_dir: Path, info: dict | None = None) -> bool:
    """
    Check there's enough free disk space in ``temp_dir`` to convert an image.

    The converted image needs at least as much space as the data in the image
    (``actual-size``). It may need up to the full size of the disk in the image
    (``virtual-size``), unless the filesystem supports sparse files (e.g. APFS
    or NTFS), so that only logs a warning.

    Returns:
        If there's enough space, or the space needed couldn't be determined
    """
    if info is None:
        info = qemu_img_info(source)
    if not info:
        return True

    try:
        free = shutil.disk_usage(temp_dir).free
    except OSError as ex:
        log.debug(f"Failed to get the free disk space in '{temp_dir}': {ex}")
        return True

    actual = int(info.get("actual-size") or 0)
    virtual = int(info.get("virtual-size") or 0)
    log.info(
        f"'{source.name}' is a {info.get('format', 'unknown')} image of a "
        f"{utils.fmt_size(virtual)} disk, with {utils.fmt_size(actual)} of data in it. "
        f"Free disk space in '{temp_dir.parent}': {utils.fmt_size(free)}"
    )

    if actual > free:
        log.error(
            f"Not enough free disk space in '{temp_dir.parent}' to convert '{source.name}', "
            f"which needs at least {utils.fmt_size(actual)}. Free up some space, or run "
            f"PEAT from a directory on a drive with more free space."
        )
        return False
    elif virtual > free:
        log.warning(
            f"The converted copy of '{source.name}' may need up to "
            f"{utils.fmt_size(virtual)} of disk space, which is more than is free in "
            f"'{temp_dir.parent}'. This is only a problem if the filesystem doesn't "
            f"support sparse files (APFS and NTFS do, HFS+, FAT, and exFAT don't)."
        )

    return True


def convert_image(source: Path, temp_dir: Path, output_format: str = "vhdx") -> Path | None:
    """
    Convert a disk image that can't be mounted natively with ``qemu-img``, to a
    VHDX image (``output_format`` is ``"vhdx"``) on Windows, or a raw disk image
    (``"raw"``) on macOS.

    Returns:
        Path to the converted image, or :obj:`None` if the conversion failed
    """
    dest = temp_dir / f"{source.stem}{CONVERTED_IMAGE_SUFFIXES[output_format]}"
    qemu_args = ["qemu-img", "convert", "-O", output_format, str(source), str(dest)]

    if not check_conversion_space(source, temp_dir):
        return None

    log.info(
        f"Converting '{source.name}' to {output_format.upper()} so it can be mounted. "
        f"This makes a temporary copy of the image in '{temp_dir}', which may take "
        f"a while and use a lot of disk space for large images."
    )
    log.debug(f"Running '{' '.join(qemu_args)}'")

    retval = subprocess.call(qemu_args)
    if retval != 0 or not dest.is_file():
        log.error(f"Failed to run '{' '.join(qemu_args)}' (return code: {retval})")
        return None

    return dest


def _run_powershell(script: str, image: Path) -> subprocess.CompletedProcess:
    # PowerShell 7 (pwsh) adds its own module directories to PSModulePath. If PEAT
    # is run from pwsh, Windows PowerShell inherits them and can fail to load its
    # own modules. Without PSModulePath, it uses its default module directories.
    # (os.environ keys are upper case on Windows, so compare case-insensitively)
    env = {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}
    env["PEAT_DISK_IMAGE"] = str(image)
    args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]

    try:
        return subprocess.run(
            args,
            env=env,
            capture_output=True,
            encoding="utf-8-sig",  # Strip the byte order mark, if there is one
            errors="replace",
            timeout=POWERSHELL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args, 1, stdout="", stderr=f"timed out after {POWERSHELL_TIMEOUT} seconds"
        )


def is_image_attached_windows(image: Path) -> bool | None:
    """
    If a disk image is already attached (mounted) on Windows.

    Returns:
        If the image is attached, or :obj:`None` if the check failed
        (e.g. the file isn't a valid disk image)
    """
    proc = _run_powershell(_PS_ATTACHED_SCRIPT, image)
    result = proc.stdout.strip()

    if proc.returncode != 0 or result not in ["True", "False"]:
        log.error(
            f"Failed to check if '{image}' is attached with Get-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}"
        )
        return None

    return result == "True"


def mount_image_windows(image: Path) -> list[dict] | None:
    """
    Mount a VHD, VHDX, or ISO image read-only using ``Mount-DiskImage``.

    If the image is already attached, it isn't mounted again. The caller is
    responsible for unmounting the image, even if this fails, since it may
    have failed after the image was mounted.

    Returns:
        List of dicts describing each volume on the image,
        or :obj:`None` if mounting failed.
    """
    log.debug(f"Mounting image '{image}' (read-only)")
    proc = _run_powershell(_PS_MOUNT_SCRIPT, image)

    if proc.returncode != 0:
        log.error(
            f"Failed to mount '{image}' with Mount-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}"
        )
        return None

    # The JSON is the last line, in case anything else was printed before it
    lines = proc.stdout.strip().splitlines()
    try:
        info = json.loads(lines[-1] if lines else "")
    except json.JSONDecodeError:
        log.error(f"Failed to parse Mount-DiskImage output: {proc.stdout.strip()}")
        return None

    # PowerShell 5.1 doesn't serialize empty arrays nested in objects consistently
    volumes = info.get("volumes") or []
    if isinstance(volumes, dict):
        volumes = [volumes]

    log.debug(f"Mounted image '{image}' with {len(volumes)} volumes: {volumes}")
    return volumes


def unmount_image_windows(image: Path) -> bool:
    proc = _run_powershell(_PS_UNMOUNT_SCRIPT, image)

    if proc.returncode != 0:
        log.error(
            f"Failed to unmount '{image}' with Dismount-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}. To unmount "
            f"it manually, run 'Dismount-DiskImage -ImagePath \"{image}\"' "
            f"from an Administrator PowerShell terminal."
        )
        return False

    return True


def search_volumes_windows(volumes: list[dict], handler: VolumeHandler) -> bool:
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

        if (not fs or fs.lower() in ["unknown", "raw"]) and vol.get("path"):
            # Locked BitLocker volumes don't have a readable filesystem. Reading the
            # volume header is a fallback, for when the BitLocker module is missing.
            if vol.get("bitlocker") == "Locked" or is_bitlocker(
                read_volume_header(vol["path"].rstrip("\\/"))
            ):
                log.warning(
                    f"Skipping volume '{name}', it's encrypted with BitLocker and "
                    f"locked. To search it, attach the image with Mount-DiskImage, "
                    f"unlock the volume (e.g. in File Explorer or with 'manage-bde "
                    f"-unlock'), then run parse again. Images that are already "
                    f"attached are searched as they are."
                )
                continue

        if not fs or fs.lower() in ["unknown", "raw"]:
            log.warning(
                f"Skipping volume '{name}', its filesystem isn't readable by Windows. "
                f"To search it, run PEAT on Linux, which supports more filesystems."
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

        log.info(f"Searching volume '{vol_path}' ({fs}, label: '{vol.get('label', '')}')")
        if handler(vol_path):
            searched += 1

    if not searched:
        log.error("No volumes on the image could be searched")
        return False

    return True


@dataclass
class _MacOSImage:
    """What was set up to search a disk image on macOS, so it can be cleaned up."""

    #: Whole disk device the image was attached as (e.g. ``/dev/disk4``), to detach.
    #: Empty if the image was attached before PEAT started, so it's left attached.
    device: str = ""
    #: Device and mount point of each volume to search
    mounts: list[tuple[str, str]] = field(default_factory=list)


def search_image_macos(
    source: Path, handler: VolumeHandler, secrets: UnlockSecrets | None = None
) -> bool:
    """
    Attach a disk image read-only on macOS, search its volumes, then detach it.

    DMG, sparse image and bundle, ISO, and raw images are attached natively with
    ``hdiutil``, which doesn't require root. Other formats (VMDK, VHD, VHDX,
    qcow2, etc.) are first converted to a temporary raw image in a
    ``peat_image_*`` directory using ``qemu-img``, which must be installed.
    Every volume macOS can read is searched, including all the volumes in APFS
    containers. Encrypted DMG images and locked APFS volumes are unlocked using
    the passwords in ``secrets``. BitLocker and LUKS encrypted volumes, and
    filesystems macOS can't read (e.g. ext4), are skipped. Images that were
    attached before PEAT started are searched as they are, and left attached.
    """
    if secrets is None:
        secrets = UnlockSecrets()

    kind = image_kind_macos(source)
    if not validate_image_mounting_macos(source, kind):
        return False

    log.info(f"Searching disk image {source}")

    image_path = Path(os.path.abspath(source))
    temp_path = None
    mount_root = None
    image = _MacOSImage()
    attach_attempted = False
    success = False

    try:
        if kind == "convert":
            temp_path = Path(tempfile.mkdtemp(prefix="peat_image_", dir=os.getcwd()))
            converted = convert_image(image_path, temp_path, "raw")
            if not converted:
                return False
            image_path, kind = converted, "raw"

        attached = attached_images_macos()
        if attached is None:
            return False

        already_attached = find_attached_image_macos(image_path, attached)
        if already_attached is not None:
            log.info(
                f"'{image_path}' was attached before PEAT started, so its mounted "
                f"volumes are searched as they are, and it's left attached"
            )
            for entity in already_attached.get("system-entities", []):
                if entity.get("mount-point"):
                    image.mounts.append((entity.get("dev-entry", ""), entity["mount-point"]))
        else:
            mount_root = Path(tempfile.mkdtemp(prefix="peat_image_", dir=_mount_root_parent()))
            attach_attempted = True
            entities = attach_image_macos(image_path, mount_root, kind == "raw", secrets, image)
            if entities is None:
                log.error("Failed to mount image")
                return False
            mount_volumes_macos(entities, mount_root, secrets, image)

        if not image.mounts:
            log.error("No volumes on the image could be mounted")
            return False

        searched = 0
        try:
            for device, mount_point in image.mounts:
                log.info(f"Searching volume '{device}' (mounted at '{mount_point}')")
                if handler(mount_point):
                    searched += 1
        except Exception as ex:
            log.critical(f"Failed to search disk image: {ex}")

        success = searched > 0
    finally:
        # If attaching was interrupted, the image may be attached without PEAT
        # knowing its device, so look for it, to always detach images PEAT attached
        if attach_attempted and not image.device:
            info = find_attached_image_macos(image_path, attached_images_macos() or [])
            if info:
                image.device = _whole_disk(info.get("system-entities", []))
        cleanup_image_macos(image, mount_root, temp_path)

    return success


def _mount_root_parent() -> str | None:
    """Short directory to create mount points in, or the default temp directory."""
    return MACOS_MOUNT_ROOT_PARENT if os.path.isdir(MACOS_MOUNT_ROOT_PARENT) else None


def image_kind_macos(source: Path) -> str:
    """
    How a disk image is attached on macOS.

    Returns:
        ``"native"`` if ``hdiutil`` can attach it as it is (e.g. a DMG or ISO),
        ``"raw"`` if it's a raw disk image, which ``hdiutil`` attaches with its raw
        disk image class, or ``"convert"`` if it must be converted to a raw image
        (e.g. VMDK or qcow2). The format is checked with ``qemu-img`` if it's
        installed, otherwise the file extension is used.
    """
    suffix = source.suffix.lower()
    if suffix in MACOS_NATIVE_IMAGE_FORMATS:
        return "native"

    info = qemu_img_info(source)
    image_format = info.get("format") if info else None
    if image_format == "raw":
        # Includes the "-flat.vmdk" extents of monolithicFlat VMDK disks
        return "raw"
    elif image_format == "dmg":
        return "native"
    elif image_format:
        return "convert"
    elif suffix in MACOS_RAW_IMAGE_FORMATS:
        return "raw"

    return "convert"


def validate_image_mounting_macos(source: Path, kind: str) -> bool:
    """
    Ensure all the requirements needed to mount an image on macOS are satisfied.

    - ``hdiutil`` must be available (it's part of macOS)
    - ``qemu-img`` must be installed and in the system PATH, if the
      image must be converted (see :func:`image_kind_macos`)

    Returns:
        If the requirements for mounting are met
    """
    if not shutil.which("hdiutil") or not shutil.which("diskutil"):
        log.error(
            "Could not find 'hdiutil' and 'diskutil', which are part of macOS "
            "and are required to mount a disk image on macOS"
        )
    elif kind == "convert" and not shutil.which("qemu-img"):
        log.error(
            f"macOS can't attach '{source.suffix}' images natively, only DMG, sparse "
            f"image, sparse bundle, ISO, and raw images. Install QEMU ('brew install "
            f"qemu') so PEAT can convert the image, convert it to a raw image yourself "
            f"('qemu-img convert -O raw {source.name} image.img'), or mount it with "
            f"another tool and parse the mount point instead."
        )
    else:
        return True

    return False


def _parse_plist(text: str) -> dict | None:
    """
    Parse the XML property list output of ``hdiutil`` or ``diskutil`` with ``-plist``.
    Anything printed before the property list is ignored.
    """
    start = text.find("<?xml")
    if start == -1:
        start = text.find("<plist")
    if start == -1:
        return None

    try:
        data = plistlib.loads(text[start:].encode("utf-8"))
    except Exception as ex:
        log.debug(f"Failed to parse property list: {ex}")
        return None

    return data if isinstance(data, dict) else None


def attached_images_macos() -> list[dict] | None:
    """
    Disk images that are attached, from ``hdiutil info``.

    Returns:
        List of dicts describing each attached image, including its ``image-path`` and
        ``system-entities``, or :obj:`None` if they couldn't be listed
    """
    proc = _run_command(["hdiutil", "info", "-plist"])
    info = _parse_plist(proc.stdout) if proc.returncode == 0 else None

    if info is None:
        log.error(f"Failed to list the attached disk images. {_run_failed(proc)}")
        return None

    return info.get("images", [])


def find_attached_image_macos(image: Path, attached: list[dict]) -> dict | None:
    """The attached image (from :func:`attached_images_macos`) that's ``image``, if any."""
    target = os.path.realpath(image)

    for info in attached:
        if info.get("image-path") and os.path.realpath(info["image-path"]) == target:
            return info

    return None


def is_image_encrypted_macos(image: Path) -> bool:
    """If a disk image (e.g. DMG or sparse bundle) is encrypted, from ``hdiutil isencrypted``."""
    proc = _run_command(["hdiutil", "isencrypted", "-plist", str(image)])
    info = _parse_plist(proc.stdout) if proc.returncode == 0 else None

    if info is None:
        log.debug(f"Failed to check if '{image}' is encrypted. {_run_failed(proc)}")
        return False

    return bool(info.get("encrypted"))


def _whole_disk(entities: list[dict]) -> str:
    """
    The whole disk device of an attached image (e.g. ``/dev/disk4``). APFS
    containers on the image are on their own synthesized disk (e.g. ``/dev/disk5``),
    which is created after the image's disk, so it has a higher number.
    """
    disks = [
        e["dev-entry"] for e in entities if re.fullmatch(r"/dev/disk\d+", e.get("dev-entry", ""))
    ]
    return min(disks, key=lambda d: int(d[len("/dev/disk") :]), default="")


def attach_image_macos(
    image_path: Path, mount_root: Path, raw: bool, secrets: UnlockSecrets, image: _MacOSImage
) -> list[dict] | None:
    """
    Attach a disk image read-only with ``hdiutil attach``, mounting the volumes macOS
    can read in ``mount_root``. Encrypted images are unlocked with a password from
    ``secrets``, which is passed to ``hdiutil`` through stdin (``-stdinpass``).

    Returns:
        List of dicts describing each disk, partition, and volume on the
        image (``system-entities``), or :obj:`None` if attaching failed
    """
    args = [
        "hdiutil",
        "attach",
        "-readonly",
        "-nobrowse",
        "-noautoopen",
        "-noverify",
        "-noautofsck",
        "-plist",
        "-mountrandom",
        str(mount_root),
    ]
    if raw:
        args.extend(["-imagekey", "diskimage-class=CRawDiskImage"])

    log.debug(f"Attaching image '{image_path}' (read-only)")

    if raw or not is_image_encrypted_macos(image_path):
        proc = _run_command([*args, str(image_path)], timeout=MACOS_ATTACH_TIMEOUT)
        if proc.returncode != 0:
            log.error(_run_failed(proc))
            return None
        return _attached_entities_macos(proc, image_path, image)

    tried = 0
    for secret in secrets.candidates(f"'{image_path.name}' (encrypted disk image)"):
        tried += 1
        # hdiutil reads a passphrase terminated by a null byte from stdin
        proc = _run_command(
            [*args, "-stdinpass", str(image_path)],
            input_data=secret.encode("utf-8") + b"\0",
            timeout=MACOS_ATTACH_TIMEOUT,
        )
        if proc.returncode == 0:
            secrets.remember(secret)
            log.info(f"Unlocked encrypted disk image '{image_path.name}'")
            return _attached_entities_macos(proc, image_path, image)
        log.warning(
            f"Failed to unlock encrypted disk image '{image_path.name}' with "
            f"password {tried}: {proc.stderr}"
        )

    if tried:
        log.error(
            f"Couldn't attach encrypted disk image '{image_path.name}', none of "
            f"the {tried} passwords tried unlocked it"
        )
    else:
        log.error(
            f"Couldn't attach disk image '{image_path.name}', it's encrypted. To search "
            f"it, run parse with '--password-file FILE', where FILE has the password "
            f"on a line, or run it in a terminal to be prompted for the password."
        )
    return None


def _attached_entities_macos(
    proc: subprocess.CompletedProcess, image_path: Path, image: _MacOSImage
) -> list[dict] | None:
    """The ``system-entities`` of an image attached by ``hdiutil attach``."""
    info = _parse_plist(proc.stdout)
    if info is None:
        # It was attached, so find it in the list of attached images to detach it
        log.warning(f"Failed to parse 'hdiutil attach' output: {proc.stdout.strip()}")
        info = find_attached_image_macos(image_path, attached_images_macos() or [])

    entities = info.get("system-entities", []) if info else []
    image.device = _whole_disk(entities)
    if not image.device:
        log.error(f"Couldn't find the disk device '{image_path}' was attached as")
        return None

    log.debug(f"Attached image '{image_path}' as '{image.device}': {entities}")
    return entities


def _mount_point_macos(device: str) -> str:
    """Where a volume is mounted (from ``diskutil info``), or an empty string if it isn't."""
    proc = _run_command(["diskutil", "info", "-plist", device])
    info = _parse_plist(proc.stdout) if proc.returncode == 0 else None
    return str(info.get("MountPoint") or "") if info else ""


def mount_volume_macos(device: str, mount_root: Path, image: _MacOSImage, name: str = "") -> bool:
    """Mount a volume read-only in its own directory in ``mount_root``, with ``diskutil``."""
    mount_point = mount_root / Path(device).name
    mount_point.mkdir(exist_ok=True)

    proc = _run_command(["diskutil", "mount", "readOnly", "-mountPoint", str(mount_point), device])
    if proc.returncode != 0:
        log.warning(
            f"Skipping volume '{name or device}', it couldn't be mounted. {_run_failed(proc)}"
        )
        with contextlib.suppress(OSError):
            mount_point.rmdir()
        return False

    image.mounts.append((device, str(mount_point)))
    log.info(f"Mounted volume '{name or device}' ({device}) read-only at '{mount_point}'")
    return True


def unlock_apfs_volume_macos(device: str, name: str, secrets: UnlockSecrets) -> bool:
    """
    Unlock an encrypted APFS volume, without mounting it, with ``diskutil apfs
    unlockVolume``. The password is passed to ``diskutil`` through stdin.

    Returns:
        If the volume was unlocked
    """
    tried = 0

    for secret in secrets.candidates(f"'{device}' (APFS volume '{name}')"):
        tried += 1
        proc = _run_command(
            ["diskutil", "apfs", "unlockVolume", device, "-stdinpassphrase", "-nomount"],
            input_data=secret.encode("utf-8"),
        )
        if proc.returncode == 0:
            secrets.remember(secret)
            log.info(f"Unlocked encrypted APFS volume '{name}' ({device})")
            return True
        log.warning(
            f"Failed to unlock APFS volume '{name}' ({device}) with password {tried}: "
            f"{proc.stderr or proc.stdout.strip()}"
        )

    if tried:
        log.error(
            f"Skipping APFS volume '{name}' ({device}), none of the {tried} "
            f"passwords tried unlocked it"
        )
    else:
        log.warning(_locked_volume_message(f"'{name}' ({device})", "APFS encryption"))
    return False


def mount_apfs_volumes_macos(
    mount_root: Path, secrets: UnlockSecrets, image: _MacOSImage
) -> set[str]:
    """
    Mount the volumes in the APFS containers on an attached image that macOS didn't
    mount, unlocking encrypted volumes first. They're found with ``diskutil apfs list``.

    Returns:
        The devices of the APFS physical stores and volumes on the image
    """
    proc = _run_command(["diskutil", "apfs", "list", "-plist"])
    info = _parse_plist(proc.stdout) if proc.returncode == 0 else None
    if info is None:
        log.warning(f"Failed to list APFS containers. {_run_failed(proc)}")
        return set()

    disk = Path(image.device).name
    mounted = {device for device, _ in image.mounts}
    handled: set[str] = set()

    for container in info.get("Containers", []):
        stores = [s.get("DeviceIdentifier", "") for s in container.get("PhysicalStores", [])]
        if container.get("DesignatedPhysicalStore"):
            stores.append(container["DesignatedPhysicalStore"])
        if not any(s == disk or s.startswith(f"{disk}s") for s in stores):
            continue

        handled.update(f"/dev/{s}" for s in stores)
        if container.get("ContainerReference"):
            handled.add(f"/dev/{container['ContainerReference']}")

        for vol in container.get("Volumes", []):
            device = f"/dev/{vol.get('DeviceIdentifier', '')}"
            name = vol.get("Name", "") or device
            handled.add(device)
            log.debug(
                f"APFS volume '{name}' in container '{container.get('ContainerReference')}': {vol}"
            )
            if device in mounted:
                continue

            mount_point = _mount_point_macos(device)
            if mount_point:
                image.mounts.append((device, mount_point))
                continue

            roles = set(vol.get("Roles", []))
            if roles & MACOS_SKIPPED_APFS_ROLES:
                log.info(
                    f"Skipping APFS volume '{name}' ({device}), it's a macOS "
                    f"{'/'.join(sorted(roles))} volume, which won't have project files on it"
                )
                continue

            # If diskutil doesn't say if it's locked, an encrypted volume
            # on an image that macOS didn't mount is assumed to be locked
            locked = vol.get("Locked", bool(vol.get("FileVault") or vol.get("Encryption")))
            if locked:
                if not unlock_apfs_volume_macos(device, name, secrets):
                    continue
                # Some versions of macOS may mount it anyway
                mount_point = _mount_point_macos(device)
                if mount_point:
                    image.mounts.append((device, mount_point))
                    continue

            mount_volume_macos(device, mount_root, image, name)

    return handled


def mount_volumes_macos(
    entities: list[dict], mount_root: Path, secrets: UnlockSecrets, image: _MacOSImage
) -> None:
    """
    Find the volumes on an attached image to search: the volumes ``hdiutil`` mounted,
    and the volumes in APFS containers (see :func:`mount_apfs_volumes_macos`). Volumes
    that can't be mounted are logged and skipped, including BitLocker and LUKS
    encrypted volumes, and filesystems macOS can't read (e.g. ext4).
    """
    for entity in entities:
        if entity.get("mount-point"):
            image.mounts.append((entity.get("dev-entry", ""), entity["mount-point"]))

    handled = mount_apfs_volumes_macos(mount_root, secrets, image)
    devices = [e.get("dev-entry", "") for e in entities]

    for entity in entities:
        device = entity.get("dev-entry", "")
        hint = entity.get("content-hint", "")
        if (
            not device
            or entity.get("mount-point")
            or device in handled
            or hint in MACOS_APFS_HINTS
            or hint in MACOS_NON_VOLUME_HINTS
            or any(d.startswith(f"{device}s") for d in devices)  # Disk with partitions
        ):
            continue

        # Read the raw (character) device, which bypasses the buffer cache
        header = read_volume_header(device.replace("/dev/disk", "/dev/rdisk", 1))
        if is_bitlocker(header):
            log.warning(
                f"Skipping volume '{device}', it's encrypted with BitLocker, which macOS "
                f"can't unlock. To search it, run PEAT on Linux or Windows instead."
            )
        elif is_luks(header):
            log.warning(
                f"Skipping volume '{device}', it's encrypted with LUKS, which macOS "
                f"can't unlock. To search it, run PEAT on Linux instead."
            )
        else:
            log.warning(
                f"Skipping volume '{device}' ({hint or 'unknown type'}), macOS can't mount "
                f"its filesystem (e.g. ext4, Btrfs, XFS, or swap). To search it, run "
                f"PEAT on Linux, which supports more filesystems."
            )


def detach_image_macos(device: str) -> bool:
    """
    Detach a disk image with ``hdiutil detach``, which also unmounts its volumes.
    Detaching can fail if a volume is briefly busy (e.g. Spotlight is reading it),
    so it's tried several times, and the last time it's forced.
    """
    proc = None

    for attempt in range(1, MACOS_DETACH_ATTEMPTS + 1):
        if hasattr(os, "sync"):
            os.sync()  # Avoids "Resource busy" errors
        args = ["hdiutil", "detach", device]
        if attempt == MACOS_DETACH_ATTEMPTS:
            args.append("-force")

        proc = _run_command(args)
        if proc.returncode == 0:
            log.debug(f"Detached '{device}'")
            return True
        if "No such file or directory" in proc.stderr:
            log.debug(f"'{device}' was already detached")
            return True

        log.debug(f"{_run_failed(proc)} (try {attempt} of {MACOS_DETACH_ATTEMPTS})")
        if attempt < MACOS_DETACH_ATTEMPTS:
            time.sleep(MACOS_DETACH_RETRY_DELAY)

    log.error(f"{_run_failed(proc)}. To detach it manually, run 'hdiutil detach {device} -force'")
    return False


def cleanup_image_macos(
    image: _MacOSImage, mount_root: Path | None, temp_path: Path | None
) -> bool:
    """
    Detach the disk image if PEAT attached it, and delete the temporary mount
    point and converted image directories. Each step is attempted, even if
    earlier ones fail.

    Returns:
        If everything was cleaned up
    """
    result = True

    if image.device:
        result = detach_image_macos(image.device)

    # Only delete the mount points if nothing is still mounted on them
    if mount_root and mount_root.is_dir():
        if any(os.path.ismount(p) for p in mount_root.iterdir()):
            result = False
        else:
            shutil.rmtree(mount_root, ignore_errors=True)
            log.debug(f"Deleted temp directory '{mount_root}'")

    if temp_path:
        try:
            shutil.rmtree(temp_path)
            log.debug(f"Deleted temp directory '{temp_path}'")
        except OSError as ex:
            log.warning(f"Failed to delete temp directory '{temp_path}': {ex}")
            result = False

    if not result:
        log.warning(
            "Failed to clean up after searching the image. Clean up manually "
            "(see 'Disk images' in the parse documentation)."
        )

    return result


def read_volume_header(path: str, size: int = 4096) -> bytes:
    """
    Read the first bytes of a volume (e.g. ``/dev/nbd1p1``, or
    ``\\\\?\\Volume{...}`` on Windows) to check what's on it.

    Returns:
        The bytes that were read, or empty bytes if it couldn't be read
    """
    try:
        with open(path, "rb", buffering=0) as fp:
            return fp.read(size)
    except OSError as ex:
        log.debug(f"Failed to read the header of volume '{path}': {ex}")
        return b""


def is_bitlocker(header: bytes) -> bool:
    """If the header (boot sector) of a volume is from a BitLocker encrypted volume."""
    return header[3:11] == BITLOCKER_SIGNATURE


def is_luks(header: bytes) -> bool:
    """If the header of a volume is from a LUKS (version 1 or 2) encrypted volume."""
    return header[:6] == LUKS_SIGNATURE


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


def _is_dataless(path: str | Path) -> bool:
    """
    If a file or directory on macOS is "dataless", a placeholder for something in
    iCloud Drive or another cloud storage provider (e.g. in ``~/Library/CloudStorage``)
    that hasn't been downloaded. Reading it would download it.
    """
    try:
        return bool(getattr(os.lstat(path), "st_flags", 0) & SF_DATALESS)
    except OSError:
        return False


def _is_macos_root(source: str) -> bool:
    """If the source is the root of a live macOS system (``/``)."""
    return consts.MACOS and os.path.realpath(source) == "/"


def _excluded_paths(source: str, exclude_system_dirs: bool) -> set[str]:
    """
    Paths of the directories to skip when searching a source, relative to the
    source, lowercase, and with ``/`` as the separator.
    """
    excluded = set()

    if exclude_system_dirs:
        excluded.update(EXCLUDED_DIRS)
        excluded.update(MACOS_EXCLUDED_DIRS)

    if _is_macos_root(source):
        # The Data volume is never searched as part of "/", since it would be searched
        # twice, through the firmlinks in "/" (e.g. "/Users") and in "/System/Volumes/Data"
        excluded.add(MACOS_DATA_VOLUME)
        if exclude_system_dirs:
            excluded.update(MACOS_ROOT_EXCLUDED_DIRS)

    return {path.lower() for path in excluded}


def _relative_dir(source: str, dir_path: str) -> str:
    """Path of a directory found by ``os.walk(source)``, relative to the source."""
    return dir_path[len(source) :].lstrip("\\/").replace("\\", "/").lower()


def _search_errors_hint(errors: list[OSError]) -> str:
    """How to fix the errors from searching directories PEAT can't read."""
    if consts.MACOS and any(err.errno == errno.EPERM for err in errors):
        # "Operation not permitted" means macOS privacy protections (TCC) blocked it
        return (
            "macOS privacy protections block access to some folders (e.g. Mail, "
            "Messages, Safari, and other users' Desktop and Documents), even for root. "
            "To search them, give the terminal app PEAT is running in Full Disk Access "
            "(System Settings > Privacy & Security > Full Disk Access), restart the "
            "terminal, and run PEAT again."
        )
    return "Run PEAT as Administrator or root to search them."


def find_files(
    source: Path | str,
    exclude_system_dirs: bool | None = None,
    recursive: bool = True,
    skip_dirs: Iterable[Path | str] = (),
) -> list[str] | None:
    """
    Find the files in a directory, such as a drive, mount point, or volume on a disk image.

    Directory junctions on Windows are skipped, so the same files aren't found twice.
    On macOS, directories that are placeholders for iCloud Drive or other cloud storage
    that haven't been downloaded are skipped, and when searching ``/``,
    ``/System/Volumes/Data`` is always skipped, since everything in it is also in
    ``/``, through firmlinks. Use :func:`remove_dataless_files` to skip files that
    haven't been downloaded, since reading them would download them.

    Args:
        source: Directory to search
        exclude_system_dirs: Skip system directories in the root of the source
            that won't have project files in them, e.g. ``Windows`` or ``System``
            (see :data:`EXCLUDED_DIRS` and :data:`MACOS_EXCLUDED_DIRS`), and on macOS,
            directories in ``/`` that other filesystems are mounted on
            (see :data:`MACOS_ROOT_EXCLUDED_DIRS`). By default, they're only skipped
            if the source is the root of a drive or mounted filesystem.
        recursive: Search sub-directories of the source
        skip_dirs: Directories to skip, e.g. PEAT's own output directory

    Returns:
        Paths of the regular files that were found (not FIFOs, devices, or sockets,
        which can't be parsed and may block when read), or :obj:`None` if the
        source couldn't be read
    """
    source = str(source)
    if not os.path.isdir(source):
        log.error(f"Failed to search '{source}': it's not a valid directory")
        return None

    if exclude_system_dirs is None:
        exclude_system_dirs = os.path.ismount(source)

    excluded = _excluded_paths(source, exclude_system_dirs)
    skipped = {os.path.normcase(os.path.abspath(d)) for d in skip_dirs}
    exclude_counter = 0
    junction_counter = 0
    dataless_counter = 0
    errors: list[OSError] = []
    files: list[str] = []

    def _walk_error(err: OSError) -> None:
        # Common on live Windows systems, e.g. for folders only SYSTEM can read,
        # and on macOS for folders protected by privacy protections (TCC)
        errors.append(err)
        log.debug(f"Failed to search '{err.filename}': {err.strerror}")

    for root, dirnames, filenames in os.walk(source, onerror=_walk_error):
        log.trace2(f"Searching in: {root}")

        # Prune excluded system directories, junctions, and dataless
        # directories on macOS, so os.walk doesn't descend into them.
        for dirname in list(dirnames):
            dir_path = os.path.join(root, dirname)
            if excluded and _relative_dir(source, dir_path) in excluded:
                log.trace2(f"Skipping excluded dir '{dir_path}'")
                dirnames.remove(dirname)
                exclude_counter += 1
            elif skipped and os.path.normcase(os.path.abspath(dir_path)) in skipped:
                log.debug(f"Skipping directory '{dir_path}'")
                dirnames.remove(dirname)
            elif consts.WINDOWS and _is_junction(dir_path):
                log.debug(f"Skipping directory junction '{dir_path}'")
                dirnames.remove(dirname)
                junction_counter += 1
            elif consts.MACOS and _is_dataless(dir_path):
                log.debug(f"Skipping dataless directory '{dir_path}' (not downloaded)")
                dirnames.remove(dirname)
                dataless_counter += 1

        for filename in filenames:
            file_path = os.path.join(root, filename)
            # Follows symbolic links, so links to regular files are kept
            if os.path.isfile(file_path):
                files.append(file_path)
            else:
                log.debug(f"Skipping '{file_path}', it's not a regular file")

        if not recursive:
            break

    if exclude_counter:
        log.info(f"Skipped {exclude_counter} excluded subdirectories")
    if junction_counter:
        log.info(
            f"Skipped {junction_counter} directory junctions, which point to other "
            f"directories. To search where a junction points, parse that directory."
        )
    if dataless_counter:
        log.info(
            f"Skipped {dataless_counter} directories in iCloud Drive or other "
            f"cloud storage that haven't been downloaded"
        )

    if errors and errors[0].filename == source:
        log.error(
            f"Failed to search '{source}': couldn't read it: {errors[0].strerror}"
            + (f". {_search_errors_hint(errors)}" if errors[0].errno == errno.EPERM else "")
        )
        return None
    elif errors:
        log.warning(
            f"Couldn't search {len(errors)} directories, e.g. '{errors[0].filename}' "
            f"({errors[0].strerror}). {_search_errors_hint(errors)}"
        )

    return files


def remove_dataless_files(files: list[Path]) -> list[Path]:
    """
    Remove files that are placeholders for files in iCloud Drive or other cloud
    storage that haven't been downloaded, since reading them would download them.
    This only applies to macOS, on other systems the files are returned as they are.
    """
    if not consts.MACOS:
        return files

    kept = []
    for file in files:
        if _is_dataless(file):
            log.warning(
                f"Skipping {file}, it's in iCloud Drive or another cloud storage "
                f"provider and hasn't been downloaded, and reading it would download "
                f"it. To parse it, download it (e.g. with 'Download Now' in Finder), "
                f"then run parse again."
            )
        else:
            kept.append(file)

    return kept


__all__ = ["DISK_IMAGE_SUFFIXES", "find_files", "is_disk_image", "search_image"]
