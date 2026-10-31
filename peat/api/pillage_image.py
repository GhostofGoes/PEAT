"""
Read files from disk images without mounting them.

This is the ``library`` backend of :ref:`peat pillage <pillage>`. It reads
EnCase/Expert Witness Format (EWF: ``.E01``, ``.Ex01``, ``.S01``), raw,
split raw (``.001``, ``.002``, ...), VMware VMDK, VHD, VHDX and qcow2 images,
finds their partitions (GPT, MBR with extended partitions, or none) and reads
files from NTFS, FAT12/16/32, exFAT and ext2/3/4 filesystems. It works the same
on Windows, macOS and Linux, and doesn't need root or Administrator permissions.

Images are read with the `libyal <https://github.com/libyal>`__ Python bindings
(``pyewf``, ``pyvmdk``, ``pyvhdi``, ``pyqcow``, ``pyfsntfs``, ``pyfsfat`` and
``pyfsext``, LGPL-3.0-or-later). They're imported when they're first needed,
so a missing or broken binding only affects this backend.

Disk images are untrusted input. This module:

- never resolves the targets of symbolic links, junctions or other reparse
  points inside an image (only files and directories in the image are read)
- never opens files outside of the image's own directory
  (EWF segments, split raw parts and VMDK extent files)
- keeps a limited number of files open, however many files an image has,
  and refuses a file that was replaced or changed when it's opened again
- refuses images that depend on a parent or backing file
  (differencing VHD/VHDX, VMDK snapshots, qcow2 backing files)
- bounds the partition table parsing (CRC checks, entry limits, loop guards)

This module doesn't use :mod:`peat.config`, the caller passes the options in.
"""

from __future__ import annotations

import bisect
import io
import os
import stat
import struct
import uuid
import zlib
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Final

from peat import log
from peat.consts import PeatError

__all__ = [
    "FORMATS",
    "DiskImage",
    "ImageFile",
    "PillageImageError",
    "UnsupportedImageError",
    "VolumeInfo",
    "check_library_support",
    "detect_image_format",
    "find_volumes",
    "split_raw_parts",
]


class PillageImageError(PeatError):
    """A disk image can't be read (corrupt, refused or an I/O error)."""


class UnsupportedImageError(PillageImageError):
    """
    The library backend can't read the image.

    For example, a Python module is missing, the image format is unsupported,
    or no supported filesystem was found. ``auto`` mode may fall back to mounting.
    """


#: Image formats the library backend can read
FORMATS: Final = ("raw", "split_raw", "ewf", "vmdk", "vhd", "vhdx", "qcow2")

#: Alternate names accepted for the ``image_format`` option
FORMAT_ALIASES: Final = {
    "auto": "auto",
    "e01": "ewf",
    "encase": "ewf",
    "vpc": "vhd",  # QEMU's name for VHD
    "qcow": "qcow2",
    "img": "raw",
    "dd": "raw",
}

#: Formats that QEMU (the "mount" backend) can read, but this backend can't
MOUNT_ONLY_FORMATS: Final = ("vdi", "qed", "dmg", "parallels", "bochs", "cloop", "luks")

#: Python module needed to read each format (:obj:`None`: pure Python)
FORMAT_MODULES: Final[dict[str, str | None]] = {
    "raw": None,
    "split_raw": None,
    "ewf": "pyewf",
    "vmdk": "pyvmdk",
    "vhd": "pyvhdi",
    "vhdx": "pyvhdi",
    "qcow2": "pyqcow",
}

#: Python module used to read each filesystem type
FS_MODULES: Final = {"ntfs": "pyfsntfs", "fat": "pyfsfat", "ext": "pyfsext"}

#: PyPI package that provides each Python module
PYPI_PACKAGES: Final = {
    "pyewf": "libewf-python",
    "pyvmdk": "libvmdk-python",
    "pyvhdi": "libvhdi-python",
    "pyqcow": "libqcow-python",
    "pyfsntfs": "libfsntfs-python",
    "pyfsfat": "libfsfat-python",
    "pyfsext": "libfsext-python",
}

EXTENSION_FORMATS: Final = {
    ".e01": "ewf",
    ".ex01": "ewf",
    ".s01": "ewf",
    ".vmdk": "vmdk",
    ".vhd": "vhd",
    ".vhdx": "vhdx",
    ".avhd": "vhd",
    ".avhdx": "vhdx",
    ".qcow2": "qcow2",
    ".qcow": "qcow2",
    ".000": "split_raw",
    ".001": "split_raw",
    ".vdi": "vdi",
}

#: Signature ("cookie") of a VHD footer
VHD_COOKIE: Final = b"conectix"  # codespell:ignore

# (offset, signature, format). Binary signatures only: text VMDK descriptors
# are only opened if the file has a ".vmdk" extension.
MAGICS: Final = (
    (0, b"EVF\x09\x0d\x0a\xff\x00", "ewf"),  # EWF-E01, EWF-S01
    (0, b"EVF2\r\n\x81\x00", "ewf"),  # EWF2-Ex01
    (0, b"LVF\x09\x0d\x0a\xff\x00", "l01"),  # EWF-L01 (logical evidence)
    (0, b"LEF2\r\n\x81\x00", "l01"),  # EWF2-Lx01 (logical evidence)
    (0, b"KDMV", "vmdk"),  # VMDK sparse extent
    (0, b"COWD", "vmdk"),  # VMware ESX sparse extent
    (0, b"vhdxfile", "vhdx"),
    (0, VHD_COOKIE, "vhd"),  # Dynamic VHD (copy of the footer)
    (0, b"QFI\xfb", "qcow2"),
    (64, b"\x7f\x10\xda\xbe", "vdi"),
)

# Boot sector (VBR) signatures, so a bare filesystem isn't mistaken for an MBR
_VBR_SIGS: Final = (
    (3, b"NTFS    "),
    (3, b"EXFAT   "),
    (3, b"-FVE-FS-"),  # BitLocker
    (3, b"ReFS"),
    (54, b"FAT1"),
    (54, b"FAT     "),
    (82, b"FAT32   "),
)

# Signatures of volumes this backend can't read, for clear messages.
# (offset, signature, name)
_UNSUPPORTED_FS: Final = (
    (3, b"-FVE-FS-", "BitLocker encrypted volume"),
    (3, b"ReFS", "ReFS"),
    (0, b"XFSB", "XFS"),
    (0, b"LUKS\xba\xbe", "LUKS encrypted volume"),
    (512, b"LABELONE", "LVM physical volume"),
    (32, b"NXSB", "APFS"),
    (1024, b"H+", "HFS+"),
    (1024, b"HX", "HFSX"),
    (0x10040, b"_BHRfS_M", "btrfs"),
)

# MBR partition types of extended partitions (EBR chains)
_MBR_EXTENDED: Final = (0x05, 0x0F, 0x85)
_MBR_PROTECTIVE: Final = 0xEE
_MAX_LOGICAL_PARTITIONS: Final = 128
_MAX_GPT_ENTRIES: Final = 4096
_MAX_GPT_TABLE_BYTES: Final = 1024 * 1024

#: Maximum directory depth that's searched in an image
MAX_DEPTH: Final = 256

#: Size of the chunks files are read in
CHUNK_SIZE: Final = 1024 * 1024

# Values from EWF headers are stored in the summary, limit their size
_MAX_INFO_VALUE_LEN: Final = 1024
_MAX_INFO_VALUES: Final = 64

# The libyal error messages are very long, limit them in logs
_MAX_ERROR_LEN: Final = 300

#: Maximum number of files of an image that are open at the same time
#: (EWF segments, split raw parts and VMDK extents). Images can have
#: more files than the open file limit (256 by default on macOS).
MAX_OPEN_FILES: Final = 32

# Maximum number of parts of a split raw image
_MAX_SPLIT_PARTS: Final = 100000


def _safe_text(value: Any, max_len: int = _MAX_ERROR_LEN) -> str:
    """
    Make untrusted text from an image (e.g. a parent file name) safe to log.

    Control characters (e.g. terminal escape sequences) are escaped,
    and long values are shortened.
    """
    text = "".join(
        f"\\x{ord(c):02x}" if ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F else c for c in str(value)
    )
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def _err(ex: BaseException) -> str:
    """Short, single-line version of an exception message, safe to log."""
    return _safe_text(" ".join(str(ex).split()) or ex.__class__.__name__)


def _quiet_close(obj: Any) -> None:
    """
    Close an object, ignoring errors.

    The libyal objects raise an error if they're closed before they were
    opened, which would hide the error that's being handled.
    """
    try:
        obj.close()
    except Exception as ex:
        log.trace2(f"[Pillage] Error closing {obj.__class__.__name__}: {_err(ex)}")


def _import(name: str) -> ModuleType:
    """
    Import a libyal Python module.

    The imports are explicit statements so PyInstaller bundles the modules.

    Raises:
        UnsupportedImageError: If the module can't be imported
    """
    try:
        if name == "pyewf":
            import pyewf as mod
        elif name == "pyvmdk":
            import pyvmdk as mod
        elif name == "pyvhdi":
            import pyvhdi as mod
        elif name == "pyqcow":
            import pyqcow as mod
        elif name == "pyfsntfs":
            import pyfsntfs as mod
        elif name == "pyfsfat":
            import pyfsfat as mod
        elif name == "pyfsext":
            import pyfsext as mod
        else:
            raise ValueError(f"unknown module '{name}'")
    except (ImportError, OSError) as ex:
        raise UnsupportedImageError(
            f"the Python module '{name}' is not available ({_err(ex)}). "
            f'Install it with "pip install {PYPI_PACKAGES[name]}"'
        ) from ex

    return mod


def normalize_format(image_format: str | None) -> str:
    """
    Normalize the name of an image format (e.g. ``"VPC"`` => ``"vhd"``).

    :obj:`None` and empty strings are ``"auto"``.
    """
    name = str(image_format or "auto").strip().lower()
    return FORMAT_ALIASES.get(name, name)


def detect_image_format(path: Path, requested: str | None = "auto") -> str:
    """
    Determine the format of a disk image.

    An explicitly requested format is used as-is. Otherwise, the format is
    determined from the file's signature ("magic"), then from the file
    extension. Files that don't match anything are treated as raw images.

    Args:
        path: Path of the image file
        requested: Format to use, or ``"auto"`` (or :obj:`None`) to detect it

    Returns:
        The image format, one of :data:`FORMATS` or :data:`MOUNT_ONLY_FORMATS`

    Raises:
        UnsupportedImageError: If the format is unknown, or the file is EWF
            logical evidence (L01/Lx01), which isn't a disk image
    """
    fmt = normalize_format(requested)

    if fmt != "auto":
        if fmt not in FORMATS and fmt not in MOUNT_ONLY_FORMATS:
            raise UnsupportedImageError(
                f"unknown image format '{requested}', valid formats are: "
                f"{', '.join((*FORMATS, *MOUNT_ONLY_FORMATS))}"
            )
        return fmt

    try:
        with path.open("rb") as fp:
            head = fp.read(1024)
            fp.seek(0, os.SEEK_END)
            size = fp.tell()
            tail = b""
            if size >= 512:
                fp.seek(size - 512)
                tail = fp.read(512)
    except OSError as ex:
        raise PillageImageError(f"can't read '{path.name}': {_err(ex)}") from ex

    for offset, sig, magic_fmt in MAGICS:
        if head[offset : offset + len(sig)] == sig:
            if magic_fmt == "l01":
                raise UnsupportedImageError(
                    f"'{path.name}' is EWF logical evidence (L01/Lx01), not a disk image"
                )
            return magic_fmt

    # Fixed size VHDs are a raw image with a footer at the end
    if tail[:8] == VHD_COOKIE:
        return "vhd"

    return EXTENSION_FORMATS.get(path.suffix.lower(), "raw")


def check_library_support(fmt: str) -> None:
    """
    Check that the library backend can read images of a format.

    Raises:
        UnsupportedImageError: If the format isn't supported, the Python
            module for the format can't be imported, or none of the
            filesystem modules can be imported
    """
    if fmt not in FORMATS:
        raise UnsupportedImageError(f"{fmt.upper()} images can't be read without mounting")

    module = FORMAT_MODULES[fmt]
    if module:
        _import(module)

    fs_errors = []
    for fs_module in FS_MODULES.values():
        try:
            _import(fs_module)
            return
        except UnsupportedImageError as ex:
            fs_errors.append(str(ex))

    raise UnsupportedImageError(f"no filesystem modules are available: {'; '.join(fs_errors)}")


# --- Containers (the virtual disk) ---


class _Media:
    """Random access to the virtual disk of an image."""

    def __init__(
        self,
        read_at: Callable[[int, int], bytes],
        size: int,
        close: Callable[[], None],
        info: dict[str, Any] | None = None,
    ) -> None:
        self._read_at = read_at
        self.size = size
        self._close = close
        self.info = info or {}

    def read_at(self, offset: int, size: int) -> bytes:
        """Read up to ``size`` bytes at ``offset`` (fewer at the end of the disk)."""
        if offset < 0 or size <= 0 or offset >= self.size:
            return b""
        size = min(size, self.size - offset)
        try:
            return self._read_at(offset, size)
        except OSError as ex:
            raise PillageImageError(f"failed to read the image: {_err(ex)}") from ex

    def close(self) -> None:
        try:
            self._close()
        except Exception as ex:
            log.debug(f"[Pillage] Error closing image: {_err(ex)}")


def _libyal_media(
    obj: Any, close: Callable[[], None], info: dict[str, Any] | None = None
) -> _Media:
    """
    Wrap an opened libyal image object (e.g. a pyewf handle).

    Raises:
        OSError: If the size of the image can't be read
    """

    def _read_at(offset: int, size: int) -> bytes:
        return obj.read_buffer_at_offset(size, offset)

    return _Media(_read_at, obj.get_media_size(), close, info)


def _file_identity(st: os.stat_result) -> tuple[int, int, int]:
    """
    What a file of an image must still match when it's opened again:
    its device, inode (the file ID on Windows) and size.

    The size is included since ``st_ino`` only identifies a file if it's
    not zero, which depends on the filesystem (e.g. WebDAV on Windows), and
    FAT file IDs on Windows come from the file's directory entry.
    """
    return (st.st_dev, st.st_ino, st.st_size)


class _FilePool:
    """
    Opens the files of an image when they're read, and keeps at most
    ``max_open`` of them open (the least recently used file is closed).

    A file that's opened again must be the same file (see :func:`_file_identity`),
    e.g. it wasn't replaced while it was closed. While a file is open it can't be
    replaced on Windows, and on other systems the open file is still read.
    """

    def __init__(self, max_open: int | None = None) -> None:
        self.max_open = max(1, max_open or MAX_OPEN_FILES)
        self._open: OrderedDict[_PooledFile, io.BufferedReader] = OrderedDict()

    @property
    def num_open(self) -> int:
        return len(self._open)

    def get(self, pooled: _PooledFile) -> io.BufferedReader:
        """
        The open file of a :class:`_PooledFile`, opening it if needed.

        Raises:
            OSError: If the file can't be opened, or it's not the same file anymore
        """
        fp = self._open.get(pooled)
        if fp is not None:
            self._open.move_to_end(pooled)
            return fp

        while len(self._open) >= self.max_open:
            _, oldest = self._open.popitem(last=False)
            oldest.close()

        fp = pooled.path.open("rb")
        try:
            st = os.fstat(fp.fileno())
            if _file_identity(st) != pooled.file_id or not stat.S_ISREG(st.st_mode):
                raise OSError(
                    f"'{pooled.name}' was replaced or changed while the image was being read"
                )
        except BaseException:
            fp.close()
            raise
        self._open[pooled] = fp
        return fp

    def release(self, pooled: _PooledFile) -> None:
        """Close the file of a :class:`_PooledFile`, if it's open."""
        fp = self._open.pop(pooled, None)
        if fp is not None:
            fp.close()

    def close(self) -> None:
        """Close all open files."""
        while self._open:
            _, fp = self._open.popitem()
            fp.close()


class _PooledFile:
    """
    Read-only file-like object for a file of an image (e.g. an EWF segment).

    The file is opened by a :class:`_FilePool` when it's read, so images can
    have more files than the open file limit. The libyal modules read the
    files of an image through these.
    """

    def __init__(self, pool: _FilePool, path: Path) -> None:
        # Only regular files are opened (e.g. opening a FIFO would block)
        if not stat.S_ISREG(path.stat().st_mode):
            raise OSError(f"'{path.name}' is not a regular file")

        # Identify the file the same way as when it's opened again. On Windows,
        # os.stat() and os.fstat() don't always get st_dev and st_ino the same way
        # (e.g. os.stat() uses GetFileInformationByName() in Python 3.12+).
        with path.open("rb") as fp:
            st = os.fstat(fp.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"'{path.name}' is not a regular file")

        self.path = path
        self.name = path.name
        self.size = st.st_size
        self.file_id = _file_identity(st)
        self._pool = pool
        self._pos = 0

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            size = self.size - self._pos
        size = min(size, self.size - self._pos)
        if size <= 0:
            return b""
        fp = self._pool.get(self)
        fp.seek(self._pos)
        data = fp.read(size)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            pos = offset
        elif whence == os.SEEK_CUR:
            pos = self._pos + offset
        elif whence == os.SEEK_END:
            pos = self.size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if pos < 0:
            raise OSError(f"invalid seek position: {pos}")
        self._pos = pos
        return pos

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self.size

    def close(self) -> None:
        self._pool.release(self)


class _FileReader:
    """Random access reads of one or more consecutive files (raw or split raw)."""

    def __init__(self, paths: list[Path]) -> None:
        self._pool = _FilePool()
        self._files = [_PooledFile(self._pool, pth) for pth in paths]
        self._starts: list[int] = []  # Offset of each file on the disk
        self.size = 0
        for part in self._files:
            self._starts.append(self.size)
            self.size += part.size

    def read_at(self, offset: int, size: int) -> bytes:
        chunks = []
        index = bisect.bisect_right(self._starts, offset) - 1
        while size > 0 and 0 <= index < len(self._files):
            part = self._files[index]
            local = offset - self._starts[index]
            wanted = min(size, part.size - local)
            if wanted > 0:
                part.seek(local)
                data = part.read(wanted)
                chunks.append(data)
                offset += len(data)
                size -= len(data)
                if len(data) < wanted:
                    break  # The file got shorter
            index += 1
        return b"".join(chunks)

    def close(self) -> None:
        self._pool.close()


def _regular_sibling(image: Path, name: str, what: str) -> Path:
    """
    Resolve a file referenced by an image, it must be in the image's directory.

    Raises:
        PillageImageError: If the reference isn't a plain file name in the
            image's directory, or isn't a regular file
    """
    if (
        not name
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or ":" in name
        or "\x00" in name
    ):
        raise PillageImageError(
            f"refusing {what} '{_safe_text(name)}' referenced by '{image.name}': "
            f"it must be a file in the same directory as the image"
        )

    if name == image.name:
        return image  # The image itself (chosen by the user), e.g. a sparse VMDK

    pth = image.parent / name
    try:
        st = os.lstat(pth)
    except OSError as ex:
        raise PillageImageError(f"{what} '{_safe_text(name)}' is missing: {_err(ex)}") from ex
    if not stat.S_ISREG(st.st_mode):
        raise PillageImageError(f"refusing {what} '{_safe_text(name)}': not a regular file")

    return pth


def split_raw_parts(first: Path) -> list[Path]:
    """
    Find the parts of a split raw image (``disk.001``, ``disk.002``, ...).

    Args:
        first: The first part of the image. It must have a numeric
            extension, e.g. ``disk.001`` (or ``disk.000``).

    Raises:
        UnsupportedImageError: If the file doesn't have a numeric extension
        PillageImageError: If a part is refused (e.g. it's a symbolic link)
    """
    number = first.suffix[1:]
    if not (number.isascii() and number.isdigit()):
        raise UnsupportedImageError(
            f"'{first.name}' can't be read as a split raw image, the first part "
            f"must have a numeric extension (e.g. 'disk.001')"
        )

    parts = [first]
    stem = first.name[: -len(first.suffix)]
    start = int(number)
    for num in range(start + 1, start + _MAX_SPLIT_PARTS):
        name = f"{stem}.{num:0{len(number)}d}"
        if not os.path.lexists(first.parent / name):
            break
        parts.append(_regular_sibling(first, name, "split image part"))
    return parts


def _open_ewf(path: Path) -> _Media:
    pyewf = _import("pyewf")

    try:
        segments = [Path(s) for s in pyewf.glob(str(path))]
    except OSError as ex:
        raise PillageImageError(f"can't find the EWF segment files: {_err(ex)}") from ex

    # pyewf.glob() derives the names from the first segment, check them anyway
    files = [_regular_sibling(path, seg.name, "EWF segment") for seg in segments]
    if not files:
        raise PillageImageError(f"no EWF segment files found for '{path.name}'")

    # The segments are opened by PEAT when they're read, instead of libewf
    # opening all of them at once (images can have hundreds of segments)
    pool = _FilePool()
    handle = pyewf.handle()

    def _close() -> None:
        _quiet_close(handle)
        pool.close()

    try:
        handle.open_file_objects([_PooledFile(pool, f) for f in files])

        # libewf doesn't check if segments are missing (pyewf.glob() stops at the
        # first missing segment), until the data in them is read
        media_size = handle.get_media_size()
        if media_size > 512:
            handle.read_buffer_at_offset(512, media_size - 512)

        info: dict[str, Any] = {"segments": [f.name for f in files]}
        for key, getter in (("hashes", "get_hash_values"), ("headers", "get_header_values")):
            try:
                values = getattr(handle, getter)() or {}
                info[key] = {
                    str(k)[:_MAX_INFO_VALUE_LEN]: str(v)[:_MAX_INFO_VALUE_LEN]
                    for k, v in list(values.items())[:_MAX_INFO_VALUES]
                }
            except Exception as ex:
                log.debug(f"[Pillage] Failed to read EWF {key}: {_err(ex)}")

        return _libyal_media(handle, _close, info)
    except OSError as ex:
        _close()
        raise PillageImageError(
            f"failed to open EWF image '{path.name}' (missing or corrupt segment?): {_err(ex)}"
        ) from ex
    except BaseException:
        _close()
        raise


def _vmdk_extent_names(handle: Any, path: Path) -> list[str]:
    types = _import("pyvmdk").extent_types
    # Not readable: raw device mappings (VMFS_RAW, VMFS_RDM) and ZERO extents
    readable = (types.FLAT, types.SPARSE, types.VMFS_FLAT, types.VMFS_SPARSE)
    names = []
    for i in range(handle.number_of_extents):
        extent = handle.get_extent_descriptor(i)
        if extent.type not in readable:
            raise UnsupportedImageError(
                f"VMDK '{path.name}' has an unsupported extent type ({extent.type}), "
                f"only flat and sparse extents can be read"
            )
        names.append(extent.filename)
    return names


def _open_vmdk(path: Path) -> _Media:
    pyvmdk = _import("pyvmdk")
    handle = pyvmdk.handle()
    pool = _FilePool()

    def _close() -> None:
        _quiet_close(handle)
        pool.close()

    try:
        handle.open(str(path))
        disk_types = pyvmdk.disk_types
        raw_types = [
            getattr(disk_types, name, None)
            for name in ("DEVICE", "DEVICE_PARITIONED", "VMFS_RAW", "VMFS_RDM", "VMFS_RDMP")
        ]
        if handle.disk_type in raw_types:
            raise UnsupportedImageError(
                f"VMDK '{path.name}' maps a physical device (raw device mapping), refusing it"
            )
        if handle.parent_content_identifier not in (None, 0xFFFFFFFF):
            raise UnsupportedImageError(
                f"VMDK '{path.name}' is a snapshot (it has a parent disk "
                f"'{_safe_text(handle.parent_filename)}'), use the parent disk or consolidate it"
            )

        names = _vmdk_extent_names(handle, path)
        with path.open("rb") as fp:
            is_sparse_file = fp.read(4) == b"KDMV"
        if (
            is_sparse_file
            and len(names) == 1
            and handle.disk_type in (disk_types.MONOLITHIC_SPARSE, disk_types.STREAM_OPTIMIZED)
        ):
            # The descriptor is embedded in the image and its only extent is the
            # image itself. The descriptor has the image's original file name,
            # which is wrong if it was renamed (it may even be another file).
            extent_paths = [path]
        else:
            extent_paths = [_regular_sibling(path, name, "VMDK extent") for name in names]

        # Open the extent files ourselves, so libvmdk can't open other files
        handle.open_extent_data_files_as_file_objects(
            [_PooledFile(pool, pth) for pth in extent_paths]
        )

        info = {"disk_type": handle.disk_type, "extents": [pth.name for pth in extent_paths]}
        return _libyal_media(handle, _close, info)
    except OSError as ex:
        _close()
        raise PillageImageError(f"failed to open VMDK image '{path.name}': {_err(ex)}") from ex
    except BaseException:
        _close()
        raise


def _open_vhdi(path: Path, fmt: str) -> _Media:
    pyvhdi = _import("pyvhdi")
    vhd = pyvhdi.file()
    try:
        vhd.open(str(path))
        if vhd.disk_type == pyvhdi.disk_types.DIFFERENTIAL:
            raise UnsupportedImageError(
                f"{fmt.upper()} '{path.name}' is a differencing disk (it has a parent disk "
                f"'{_safe_text(vhd.parent_filename)}'), merge it into its parent first"
            )
        return _libyal_media(vhd, vhd.close, {"disk_type": vhd.disk_type})
    except OSError as ex:
        _quiet_close(vhd)
        raise PillageImageError(
            f"failed to open {fmt.upper()} image '{path.name}': {_err(ex)}"
        ) from ex
    except BaseException:
        _quiet_close(vhd)
        raise


def _open_qcow(path: Path) -> _Media:
    pyqcow = _import("pyqcow")
    qcow = pyqcow.file()
    try:
        qcow.open(str(path))
        if qcow.backing_filename:
            raise UnsupportedImageError(
                f"qcow2 '{path.name}' has a backing file "
                f"('{_safe_text(qcow.backing_filename)}'), flatten it first "
                f'(e.g. "qemu-img convert -O qcow2 in.qcow2 out.qcow2")'
            )
        if qcow.is_locked():
            raise UnsupportedImageError(f"qcow2 '{path.name}' is encrypted")
        return _libyal_media(qcow, qcow.close)
    except OSError as ex:
        _quiet_close(qcow)
        raise PillageImageError(f"failed to open qcow2 image '{path.name}': {_err(ex)}") from ex
    except BaseException:
        _quiet_close(qcow)
        raise


def _open_media(path: Path, fmt: str) -> _Media:
    """Open the virtual disk of an image."""
    if fmt in ("raw", "split_raw"):
        parts = split_raw_parts(path) if fmt == "split_raw" else [path]
        try:
            reader = _FileReader(parts)
        except OSError as ex:
            raise PillageImageError(f"can't read '{path.name}': {_err(ex)}") from ex
        info = {"parts": [p.name for p in parts]} if fmt == "split_raw" else {}
        return _Media(reader.read_at, reader.size, reader.close, info)
    elif fmt == "ewf":
        return _open_ewf(path)
    elif fmt == "vmdk":
        return _open_vmdk(path)
    elif fmt in ("vhd", "vhdx"):
        return _open_vhdi(path, fmt)
    elif fmt == "qcow2":
        return _open_qcow(path)

    raise UnsupportedImageError(f"{fmt.upper()} images can't be read without mounting")


class RangeReader(io.RawIOBase):
    """
    Read-only, seekable file-like view of a byte range (a partition) of a disk.

    The libyal filesystem modules read volumes through this.
    """

    def __init__(self, media: _Media, offset: int, size: int) -> None:
        super().__init__()
        self._media = media
        self._offset = offset
        self._size = max(0, min(size, media.size - offset))
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self._size

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            pos = offset
        elif whence == os.SEEK_CUR:
            pos = self._pos + offset
        elif whence == os.SEEK_END:
            pos = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if pos < 0:
            raise OSError(f"invalid seek position: {pos}")
        self._pos = pos
        return pos

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            size = self._size - self._pos
        size = min(size, self._size - self._pos)
        if size <= 0:
            return b""
        data = self._media.read_at(self._offset + self._pos, size)
        self._pos += len(data)
        return data

    def readinto(self, buffer: Any) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


# --- Partitions ---


@dataclass
class VolumeInfo:
    """A partition (or the whole disk, if there's no partition table)."""

    #: Partition number. MBR: 1-4 primary, 5+ logical. GPT: entry number.
    #: 0: no partition table, the filesystem starts at the beginning of the disk.
    index: int
    #: Partition table: ``"gpt"``, ``"mbr"`` or ``"none"``
    scheme: str
    #: Offset of the partition on the disk, in bytes
    offset: int
    #: Size of the partition, in bytes
    size: int
    #: MBR partition type (e.g. ``"0x07"``) or GPT partition type GUID
    type_id: str = ""
    #: GPT partition name
    name: str = ""
    #: Filesystem that was found (``"ntfs"``, ``"fat"`` or ``"ext"``)
    filesystem: str | None = None
    #: Why the filesystem couldn't be read
    error: str | None = None

    def describe(self) -> str:
        desc = f"partition {self.index} ({self.scheme}"
        if self.type_id:
            desc += f" {self.type_id}"
        return f"{desc}, offset {self.offset}, size {self.size})"


def _looks_like_vbr(sector: bytes) -> bool:
    return any(sector[off : off + len(sig)] == sig for off, sig in _VBR_SIGS)


def _gpt_guid(data: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(data)))


def _parse_gpt(media: _Media) -> list[VolumeInfo] | None:
    """Parse a GUID Partition Table (GPT), with 512 or 4096 byte sectors."""
    for sector_size in (512, 4096):
        hdr = media.read_at(sector_size, 512)
        if hdr[:8] != b"EFI PART":
            continue

        hsize, hcrc = struct.unpack_from("<II", hdr, 12)
        if not 92 <= hsize <= len(hdr):
            log.warning(f"[Pillage] Invalid GPT header size {hsize}, ignoring the GPT")
            return None
        if zlib.crc32(hdr[:16] + b"\x00" * 4 + hdr[20:hsize]) != hcrc:
            log.warning("[Pillage] GPT header checksum mismatch, ignoring the GPT")
            return None

        entries_lba, num_entries, entry_size, entries_crc = struct.unpack_from("<QIII", hdr, 72)
        table_size = num_entries * entry_size
        if (
            num_entries > _MAX_GPT_ENTRIES
            or not 128 <= entry_size <= 4096
            or entry_size % 8
            or table_size > _MAX_GPT_TABLE_BYTES
        ):
            log.warning(
                f"[Pillage] Invalid GPT entries ({num_entries} x {entry_size} bytes), "
                f"ignoring the GPT"
            )
            return None

        table = media.read_at(entries_lba * sector_size, table_size)
        if len(table) != table_size or zlib.crc32(table) != entries_crc:
            log.warning("[Pillage] GPT partition entries checksum mismatch, ignoring the GPT")
            return None

        volumes = []
        for i in range(num_entries):
            entry = table[i * entry_size : (i + 1) * entry_size]
            if entry[:16] == b"\x00" * 16:
                continue
            first, last = struct.unpack_from("<QQ", entry, 32)
            offset = first * sector_size
            if last < first or offset >= media.size:
                log.warning(f"[Pillage] Skipping invalid GPT partition {i + 1}")
                continue
            size = min((last - first + 1) * sector_size, media.size - offset)
            name = entry[56:128].decode("utf-16-le", errors="replace").split("\x00")[0]
            volumes.append(
                VolumeInfo(
                    index=i + 1,
                    scheme="gpt",
                    offset=offset,
                    size=size,
                    type_id=_gpt_guid(entry[:16]),
                    name=name[:36],
                )
            )
        return volumes

    return None


def _mbr_entries(sector: bytes) -> list[tuple[int, int, int]] | None:
    """The (type, start LBA, sectors) of the 4 entries, or None if it's not an MBR."""
    if len(sector) < 512 or sector[510:512] != b"\x55\xaa" or _looks_like_vbr(sector):
        return None

    entries = []
    for i in range(4):
        boot, ptype, start, count = struct.unpack_from("<B3xB3xII", sector, 446 + i * 16)
        if boot not in (0x00, 0x80):
            return None
        entries.append((ptype, start, count))
    return entries


def _parse_mbr(media: _Media) -> list[VolumeInfo] | None:
    """Parse a Master Boot Record (MBR) partition table, including logical partitions."""
    entries = _mbr_entries(media.read_at(0, 512))
    if entries is None:
        return None

    volumes = []
    logical = 5  # Logical partitions are numbered from 5

    def _add(index: int, ptype: int, start_lba: int, count: int) -> None:
        offset = start_lba * 512
        if offset >= media.size:
            log.warning(f"[Pillage] Skipping MBR partition {index}: starts after the end of disk")
            return
        size = min(count * 512, media.size - offset)
        volumes.append(VolumeInfo(index, "mbr", offset, size, f"0x{ptype:02x}"))

    for i, (ptype, start, count) in enumerate(entries):
        if ptype == _MBR_PROTECTIVE:
            # GPT disk, but the GPT was invalid or not found
            log.warning("[Pillage] Disk has a protective MBR but no valid GPT")
            return []
        if ptype == 0 or count == 0:
            continue
        if ptype not in _MBR_EXTENDED:
            _add(i + 1, ptype, start, count)
            continue

        # Extended partition: follow the chain of extended boot records (EBR)
        ext_base = start
        ebr_lba = start
        seen: set[int] = set()
        while ebr_lba not in seen and len(seen) < _MAX_LOGICAL_PARTITIONS:
            seen.add(ebr_lba)
            ebr = _mbr_entries(media.read_at(ebr_lba * 512, 512))
            if ebr is None:
                break
            l_type, l_start, l_count = ebr[0]
            if l_type and l_count:
                _add(logical, l_type, ebr_lba + l_start, l_count)
                logical += 1
            n_type, n_start, _ = ebr[1]
            if n_type not in _MBR_EXTENDED or not n_start:
                break
            ebr_lba = ext_base + n_start
        else:
            log.warning("[Pillage] Stopped following a looping or very long EBR chain")

    return volumes


def find_volumes(media: _Media) -> list[VolumeInfo]:
    """
    Find the partitions on a disk: GPT, then MBR, then none.

    If there's no partition table, the disk is treated as a single
    filesystem starting at offset 0 (e.g. a CF card or partition image).
    """
    for parse in (_parse_gpt, _parse_mbr):
        volumes = parse(media)
        if volumes is not None:
            return volumes

    return [VolumeInfo(0, "none", 0, media.size)]


# --- Filesystems ---


@dataclass(frozen=True)
class ImageFile:
    """A regular file in a filesystem in a disk image."""

    #: Partition number (:attr:`VolumeInfo.index`)
    volume: int
    #: Path of the file in the filesystem
    path: PurePosixPath
    #: Size of the file, in bytes (as stored in the filesystem)
    size: int
    _entry: Any = field(repr=False, compare=False)
    #: Identifies the file's data in the partition: the NTFS MFT entry, the ext
    #: inode, or the first FAT cluster. Hard links (and cross-linked FAT files)
    #: have the same ID. :obj:`None` if unknown.
    data_id: int | None = None

    def __str__(self) -> str:
        return f"p{self.volume}:{self.path}"

    def chunks(self, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
        """
        Read the file's data.

        Raises:
            OSError: If the data can't be read
        """
        offset = 0
        while offset < self.size:
            data = self._entry.read_buffer_at_offset(min(chunk_size, self.size - offset), offset)
            if not data:
                break
            offset += len(data)
            yield data


class _FsAdapter:
    """Differences between the libyal filesystem modules."""

    name = ""

    def kind(self, entry: Any) -> str:
        """``"dir"``, ``"file"`` or ``"other"`` (links, devices, etc., which are skipped)."""
        raise NotImplementedError

    def key(self, entry: Any) -> int | None:  # noqa: ARG002
        """Unique ID of an entry, to detect directory loops."""
        return None

    def data_id(self, entry: Any) -> int | None:
        """ID of a file's data, the same for all hard links to the file."""
        return self.key(entry)

    def skip(self, entry: Any) -> bool:  # noqa: ARG002
        """If an entry should be ignored."""
        return False


class _NtfsAdapter(_FsAdapter):
    name = "ntfs"

    def kind(self, entry: Any) -> str:
        if entry.has_directory_entries_index():
            # Directories with a reparse point are searched too, only their own
            # index is read and the reparse point is never resolved. Junctions
            # and symbolic links have an empty index, while e.g. OneDrive
            # (cloud files) folders have the files that are on the disk.
            return "dir"
        # Symbolic links, etc. have no data. Only the default data stream is read.
        return "file" if entry.has_default_data_stream() else "other"

    def key(self, entry: Any) -> int | None:
        return entry.file_reference & 0xFFFFFFFFFFFF

    def skip(self, entry: Any) -> bool:
        # MFT entries 0-23 are NTFS metadata files ($MFT, $Extend, etc.)
        return (entry.file_reference & 0xFFFFFFFFFFFF) < 24


class _FatAdapter(_FsAdapter):
    name = "fat"

    def kind(self, entry: Any) -> str:
        flags = entry.file_attribute_flags
        if flags & 0x08:  # Volume label
            return "other"
        return "dir" if flags & 0x10 else "file"

    def key(self, entry: Any) -> int | None:
        return entry.identifier

    def data_id(self, entry: Any) -> int | None:
        # FAT has no hard links, but a corrupt or malicious FAT can have
        # many entries pointing at the same clusters
        if not entry.number_of_extents:
            return None
        return int(entry.get_extent(0)[0])

    def skip(self, entry: Any) -> bool:
        return bool(entry.file_attribute_flags & 0x08)


class _ExtAdapter(_FsAdapter):
    name = "ext"

    def kind(self, entry: Any) -> str:
        mode = entry.file_mode
        if stat.S_ISDIR(mode):
            return "dir"
        # Symbolic links, devices, FIFOs and sockets are skipped
        return "file" if stat.S_ISREG(mode) else "other"

    def key(self, entry: Any) -> int | None:
        return entry.inode_number


_ADAPTERS: Final = {"ntfs": _NtfsAdapter, "fat": _FatAdapter, "ext": _ExtAdapter}


def _identify_unsupported(view: RangeReader, encrypted_only: bool = False) -> str | None:
    for offset, sig, name in _UNSUPPORTED_FS:
        if encrypted_only and "encrypted" not in name:
            continue
        view.seek(offset)
        if view.read(len(sig)) == sig:
            return name
    return None


def _open_filesystem(view: RangeReader) -> tuple[_FsAdapter, Any]:
    """
    Open the filesystem in a partition.

    Raises:
        PillageImageError: If the filesystem isn't supported or can't be opened
    """
    # BitLocker volumes look like FAT volumes, check for encryption first
    encrypted = _identify_unsupported(view, encrypted_only=True)
    if encrypted:
        raise UnsupportedImageError(f"unsupported volume type: {encrypted}")

    missing = []
    for fs_type, module in FS_MODULES.items():
        try:
            mod = _import(module)
        except UnsupportedImageError as ex:
            missing.append(str(ex))
            continue

        try:
            view.seek(0)
            matched = mod.check_volume_signature_file_object(view)
        except OSError:
            matched = False  # e.g. the partition is too small
        if not matched:
            continue

        try:
            view.seek(0)
            volume = mod.volume()
            volume.open_file_object(view)
        except OSError as ex:
            raise PillageImageError(f"failed to open {fs_type} filesystem: {_err(ex)}") from ex

        return _ADAPTERS[fs_type](), volume

    unsupported = _identify_unsupported(view)
    if unsupported:
        raise UnsupportedImageError(f"unsupported volume type: {unsupported}")
    if missing:
        raise UnsupportedImageError(f"no supported filesystem found ({'; '.join(missing)})")
    raise UnsupportedImageError("no supported filesystem found")


def _safe_name(name: Any) -> str:
    """
    Names from an image are untrusted: make them a single path component,
    without control characters (e.g. terminal escape sequences in the logs).
    """
    return "".join(
        "_" if c == "/" or ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F else c for c in str(name or "")
    )


def walk_filesystem(
    adapter: _FsAdapter,
    fs_volume: Any,
    vol_index: int,
    recursive: bool = True,
    excluded_root_dirs: Iterable[str] = (),
) -> Iterator[ImageFile]:
    """
    Find the regular files in a filesystem.

    The targets of links, junctions and reparse points are never followed.
    Directories in ``excluded_root_dirs`` are skipped if they're at the root of
    the filesystem (case-insensitive). Directories that can't be read are
    logged and skipped.
    """
    excluded = {d.lower() for d in excluded_root_dirs}
    stack = [(PurePosixPath("/"), fs_volume.get_root_directory(), 0)]
    seen: set[int] = set()
    num_entries = 0

    while stack:
        path, directory, depth = stack.pop()
        try:
            key = adapter.key(directory)
            if key is not None:
                if key in seen:
                    log.warning(f"[Pillage] Directory loop at p{vol_index}:{path}, skipping")
                    continue
                seen.add(key)
            entries = list(directory.sub_file_entries)
        except OSError as ex:
            log.warning(f"[Pillage] Failed to list p{vol_index}:{path}: {_err(ex)}")
            continue

        subdirs = []
        for entry in entries:
            try:
                name = _safe_name(entry.name)
                if not name or name in (".", "..") or adapter.skip(entry):
                    continue
                kind = adapter.kind(entry)
                size = int(entry.size or 0) if kind == "file" else 0
                data_id = adapter.data_id(entry) if kind == "file" else None
            except (OSError, ValueError, TypeError) as ex:
                log.warning(
                    f"[Pillage] Failed to read an entry in p{vol_index}:{path}: {_err(ex)}"
                )
                continue

            num_entries += 1
            if num_entries % 10000 == 0:
                log.info(f"[Pillage] Searched {num_entries} entries in partition {vol_index}")

            if kind == "dir":
                if depth == 0 and name.lower() in excluded:
                    log.debug(f"[Pillage] Skipping excluded directory p{vol_index}:/{name}")
                    continue
                if not recursive:
                    continue
                if depth + 1 > MAX_DEPTH:
                    log.warning(f"[Pillage] Too deep, skipping p{vol_index}:{path / name}")
                    continue
                subdirs.append((path / name, entry, depth + 1))
            elif kind == "file":
                yield ImageFile(vol_index, path / name, size, entry, data_id)
            else:
                log.trace2(f"[Pillage] Skipping p{vol_index}:{path / name} (not a regular file)")

        # Reverse, so directories are searched in the order they're listed
        stack.extend(reversed(subdirs))


class DiskImage:
    """
    A disk image, opened for reading files.

    .. code-block:: python

       with DiskImage(Path("disk.E01")) as img:
           for image_file in img.iter_files():
               print(image_file, image_file.size)

    Raises:
        UnsupportedImageError: If the library backend can't read the image,
            for example the format is unsupported or no supported filesystem was found
        PillageImageError: If the image is corrupt, refused, or can't be read
    """

    def __init__(self, path: Path, image_format: str | None = "auto") -> None:
        self.path = Path(path)
        self.requested_format = image_format
        self.format = ""
        self.volumes: list[VolumeInfo] = []
        self._media: _Media | None = None
        self._filesystems: list[tuple[VolumeInfo, _FsAdapter, Any]] = []

    def __enter__(self) -> DiskImage:
        self.open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def media_size(self) -> int:
        return self._media.size if self._media else 0

    @property
    def info(self) -> dict[str, Any]:
        """Metadata about the image, e.g. EWF headers and stored hashes."""
        return self._media.info if self._media else {}

    def open(self) -> None:
        self.format = detect_image_format(self.path, self.requested_format)
        check_library_support(self.format)
        log.info(f"[Pillage] Reading '{self.path.name}' as a {self.format} image")

        self._media = _open_media(self.path, self.format)
        try:
            self.volumes = find_volumes(self._media)
            for vol in self.volumes:
                try:
                    adapter, fs_volume = _open_filesystem(
                        RangeReader(self._media, vol.offset, vol.size)
                    )
                except PillageImageError as ex:
                    vol.error = str(ex)
                    log.warning(f"[Pillage] Skipping {vol.describe()}: {ex}")
                    continue
                vol.filesystem = adapter.name
                self._filesystems.append((vol, adapter, fs_volume))
                log.info(f"[Pillage] Found {adapter.name} filesystem in {vol.describe()}")

            if not self._filesystems:
                errors = "; ".join(f"partition {v.index}: {v.error}" for v in self.volumes)
                raise UnsupportedImageError(
                    f"no supported filesystems found in '{self.path.name}'"
                    + (f" ({errors})" if errors else " (no partitions)")
                )
        except BaseException:
            self.close()
            raise

    def iter_files(
        self, recursive: bool = True, excluded_root_dirs: Iterable[str] = ()
    ) -> Iterator[ImageFile]:
        """Find the regular files in all readable partitions of the image."""
        excluded = tuple(excluded_root_dirs)
        for vol, adapter, fs_volume in self._filesystems:
            try:
                yield from walk_filesystem(adapter, fs_volume, vol.index, recursive, excluded)
            except (OSError, PillageImageError) as ex:
                vol.error = _err(ex)
                log.warning(f"[Pillage] Failed to search {vol.describe()}: {vol.error}")

    def summary(self) -> dict[str, Any]:
        """Summary of the image, for the results summary file."""
        return {
            "image_format": self.format,
            "media_size": self.media_size,
            "image_info": self.info,
            "volumes": [asdict(v) for v in self.volumes],
        }

    def close(self) -> None:
        """Close the image. Never raises."""
        for _, _, fs_volume in self._filesystems:
            try:
                fs_volume.close()
            except Exception as ex:
                log.debug(f"[Pillage] Error closing filesystem: {_err(ex)}")
        self._filesystems = []
        if self._media:
            self._media.close()
            self._media = None
