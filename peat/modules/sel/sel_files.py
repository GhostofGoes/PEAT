"""
Hash and record the files that PEAT downloads from SEL devices or derives from them.

Every file is recorded as a :class:`~peat.data.models.File` in ``dev.files``,
with the hashes of its contents, and the hashes are added to ``dev.related.hash``.
The hashes are calculated from the data in memory, so files are recorded even
when device file output is disabled (``DEVICE_DIR`` is unset).

These helpers are in their own module (instead of ``sel_comms``) so that
``relay_parse`` can use them without a circular import. ``sel_comms``
re-exports :func:`record_downloaded_file`.

``File.extra`` keys set by these helpers:

- ``transport``: how the data was transferred, e.g. ``ftp``, ``telnet``,
  ``serial``, ``http``, or ``https``. Not set for files PEAT created.
- ``source``: what the file is, one of the ``SOURCE_*`` values in this module.
- ``derived_from``: names of the files a derived file was created from.
"""

import copy
import json
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, Final

from peat import DeviceData, File, Hash, config, consts, log, utils
from peat.data.data_utils import merge_models

#: File downloaded from the device's file system (FTP, ``FILE SHOW``, or YMODEM)
SOURCE_DOWNLOAD: Final = "download"

#: Page downloaded from the device's web interface
SOURCE_WEB_PAGE: Final = "web_page"

#: File downloaded from the device's web interface, e.g. ``soe.csv``
SOURCE_WEB_DOWNLOAD: Final = "web_download"

#: Output of commands run on the device, saved to a file by PEAT
SOURCE_COMMAND_OUTPUT: Final = "command_output"

#: File created by PEAT from other files, e.g. a reconstructed ``SET_ALL.TXT``
SOURCE_DERIVED: Final = "derived"

#: Stream in a SEL QuickSet database (``*.rdb``)
SOURCE_RDB_STREAM: Final = "rdb_stream"

#: File that was parsed with ``peat parse`` (or ``DeviceModule.parse()``)
SOURCE_PARSE_INPUT: Final = "parse_input"

#: Settings file PEAT prepared to push (upload) to the device with ``peat push``
SOURCE_PUSH: Final = "push"


def _to_bytes(data: bytes | bytearray | str) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def _serialize(data: Any, filename: str) -> bytes:
    """
    The bytes :func:`peat.utils.write_file` writes for ``data``, so the hash
    is the same whether or not device file output is enabled.
    """
    if ".json" in PurePosixPath(filename).suffixes:
        return json.dumps(consts.convert(data), indent=4).encode("utf-8")

    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)

    return str(data).encode("utf-8")


def _checked_local_path(local_path: Path | str | None, raw: bytes, name: str) -> Path | None:
    """
    Only record a local path if it's a file with the same contents as the
    data that was hashed. :meth:`~peat.data.models.DeviceData.write_file`
    returns the intended path, which isn't always the path that was written
    (e.g. ``NAME.1`` if ``NAME`` exists), and it returns the bare filename
    when device file output is disabled.
    """
    if not local_path:
        return None

    local_path = Path(local_path)
    if not local_path.is_absolute() or not local_path.is_file():
        return None

    local_path = local_path.resolve()

    try:
        same = local_path.stat().st_size == len(raw) and local_path.read_bytes() == raw
    except OSError as ex:
        log.debug(f"Failed to read {local_path} to check its contents: {ex}")
        same = False

    if not same:
        log.warning(
            f"Not recording local path '{local_path}' for '{name}': "
            f"the file's contents differ from the data that was hashed"
        )
        return None

    return local_path


def record_downloaded_file(
    dev: DeviceData,
    data: bytes | bytearray | str,
    name: str,
    device_path: PurePath | str | None = None,
    local_path: Path | str | None = None,
    transport: str = "",
    source: str = SOURCE_DOWNLOAD,
    peat_module: str = "",
    description: str = "",
    extra: dict | None = None,
) -> File:
    """
    Hash a file that was downloaded from a device (or derived from one) and
    record it in ``dev.files``. The hashes are added to ``dev.related.hash``.

    The hashes are of ``data``, the bytes as they were received, before any
    decoding (:class:`str` is encoded as UTF-8). This works when device file
    output is disabled.

    Recording the same file again (same local path, or the same name, device
    path, and hashes if there's no local path) updates the existing entry
    instead of adding a new one. Files with the same name but different
    contents (e.g. ``EVENTS/HISTORY.TXT`` and ``REPORTS/HISTORY.TXT``)
    are separate entries.

    Args:
        dev: Device the file is from
        data: Raw contents of the file
        name: Name of the file, e.g. ``SET_1.TXT``
        device_path: Path of the file on the device, e.g. ``/SETTINGS/SET_1.TXT``.
            :class:`str` values are converted to :class:`~pathlib.PurePosixPath`.
            Leave unset for files that aren't on the device (e.g. derived files).
        local_path: Path of the file saved by PEAT, if any. It's only recorded
            if the file exists and has the same contents as ``data``.
        transport: How the file was transferred (``ftp``, ``telnet``,
            ``serial``, ``http``, ``https``). Saved in ``File.extra``.
        source: What the file is, one of the ``SOURCE_*`` values in this
            module. Saved in ``File.extra``.
        peat_module: Name of the PEAT module, e.g. ``SELRelay``.
            Defaults to the device's module, if it's set.
        description: Human-readable description of the file
        extra: Additional values for ``File.extra``

    Returns:
        The :class:`~peat.data.models.File` in ``dev.files``
    """
    raw = _to_bytes(data)
    hashes = utils.gen_hashes(raw)

    if device_path is not None and not isinstance(device_path, PurePath):
        device_path = PurePosixPath(str(device_path).replace("\\", "/"))

    if not peat_module and dev._module:
        peat_module = dev._module.__name__

    file_extra = {}
    if transport:
        file_extra["transport"] = transport
    if source:
        file_extra["source"] = source
    if extra:
        file_extra.update(copy.deepcopy(extra))

    file_obj = File(
        name=name,
        local_path=_checked_local_path(local_path, raw, name),
        size=len(raw),
        hash=Hash.parse_obj(hashes),
        type="file",
        peat_module=peat_module,
        description=description,
        extra=file_extra,
    )
    if device_path is not None:
        file_obj.path = device_path

    existing = _find_recorded(dev, file_obj)
    if existing is None:
        dev.store("files", file_obj, append=True)
        return file_obj

    merge_models(existing, file_obj)
    existing.annotate(dev)
    return existing


def _find_recorded(dev: DeviceData, file_obj: File) -> File | None:
    """
    Find a recorded file that's the same as ``file_obj``: the same local path,
    or if there isn't a local path, the same name, path, and hashes.

    .. note::
       This compares attributes directly instead of using the ``lookup``
       argument to :meth:`~peat.data.models.DeviceData.store`, which converts
       every file in ``dev.files`` to a :class:`dict` for each lookup and is
       slow for relays with hundreds of files.
    """
    for existing in dev.files:
        if file_obj.local_path:
            if existing.local_path == file_obj.local_path:
                return existing
        elif (
            not existing.local_path
            and existing.name == file_obj.name
            and existing.path == file_obj.path
            and existing.hash == file_obj.hash
            and all(
                existing.extra.get(key) == file_obj.extra.get(key)
                for key in ("source", "transport", "file_transfer")
            )
        ):
            return existing

    return None


def write_and_record_file(
    dev: DeviceData,
    data: Any,
    filename: str,
    out_dir: Path | None = None,
    name: str = "",
    device_path: PurePath | str | None = None,
    transport: str = "",
    source: str = SOURCE_DERIVED,
    peat_module: str = "",
    description: str = "",
    extra: dict | None = None,
) -> File:
    """
    Write data to a file in the device's output directory (like
    :meth:`~peat.data.models.DeviceData.write_file`), then hash and record
    it with :func:`record_downloaded_file`.

    The recorded local path is the file that was actually written: if a file
    with the name already exists, the ``<name>.<num>`` name that
    :func:`peat.utils.write_file` would use is chosen before writing.
    Nothing is written if device file output is disabled, but the
    file is still hashed and recorded.

    Args:
        dev: Device the file is for
        data: Data to write. If ``filename`` ends in ``.json``, it's
            serialized to JSON, like :func:`peat.utils.write_file` does.
        filename: Name of the file to write, which may include sub-directories
        out_dir: Directory to write to. Defaults to ``dev.get_out_dir()``.
        name: Name to record for the file. Defaults to the name of ``filename``.
        device_path: Path of the file on the device, if it's from the device
        transport: How the data was transferred, if it's from the device
        source: What the file is, one of the ``SOURCE_*`` values in this module
        peat_module: Name of the PEAT module, e.g. ``SELRelay``
        description: Human-readable description of the file
        extra: Additional values for ``File.extra``

    Returns:
        The :class:`~peat.data.models.File` in ``dev.files``, or :obj:`None`
        if the data couldn't be hashed and recorded (this never raises,
        a failure is logged as a warning)
    """
    filename = consts.sanitize_filepath(filename)
    try:
        content = _serialize(data, filename)
    except Exception as ex:
        # utils.write_file() handles (and logs) serialization errors itself
        log.warning(f"Failed to serialize {filename} for hashing: {ex}")
        content = None

    local_path = None
    if dev._out_dir or config.DEVICE_DIR:
        target = (out_dir if out_dir else dev.get_out_dir()) / filename
        if target.exists():
            target = utils.dup_path(target)

        if utils.write_file(data, target):
            local_path = target
    else:
        log.debug(f"Device file output is disabled, skipping write to file {filename}")

    if content is None:
        if local_path is None:
            return None
        content = local_path.read_bytes()

    try:
        return record_downloaded_file(
            dev=dev,
            data=content,
            name=name if name else PurePosixPath(filename).name,
            device_path=device_path,
            local_path=local_path,
            transport=transport,
            source=source,
            peat_module=peat_module,
            description=description,
            extra=extra,
        )
    except Exception as ex:
        log.warning(f"Failed to record hashes for {filename}: {ex}")
        return None


def annotate_settings_classes(classes: dict, files: list[File]) -> None:
    """
    Add the settings class from the ``[CLASSES]`` section of ``CFG.TXT``
    to the recorded settings files it's for, in ``File.extra["settings_class"]``.

    The ``[CLASSES]`` lines on some relays include a hex value for each
    class, e.g. ``1,"Group 1","\\SETTINGS\\SET_1.TXT","a9dd3ac2"``. It's
    probably a checksum of the class's settings, but the algorithm isn't
    documented, so it's recorded as-is (``checksum``) and not verified.

    Args:
        classes: The parsed ``[CLASSES]`` section, from
            :func:`~peat.modules.sel.relay_parse.parse_cfg_txt`
        files: The recorded files to annotate
    """
    if not isinstance(classes, dict):
        return

    for cls_info in classes.values():
        if not isinstance(cls_info, dict) or not cls_info.get("class"):
            continue

        # "\SETTINGS\SET_1.TXT" or "SET_1.TXT". The file for class "P1"
        # is "SET_P1.TXT" if the file isn't listed.
        if cls_info.get("file"):
            filename = PurePosixPath(cls_info["file"]).name
        else:
            filename = f"SET_{cls_info['class']}.TXT"

        settings_class = {"class": cls_info["class"], "name": cls_info.get("name", "")}
        if cls_info.get("hex_id"):
            settings_class["checksum"] = cls_info["hex_id"]

        for file_obj in files:
            if file_obj.name.upper() == filename.upper():
                file_obj.extra["settings_class"] = settings_class


__all__ = [
    "SOURCE_COMMAND_OUTPUT",
    "SOURCE_DERIVED",
    "SOURCE_DOWNLOAD",
    "SOURCE_PARSE_INPUT",
    "SOURCE_PUSH",
    "SOURCE_RDB_STREAM",
    "SOURCE_WEB_DOWNLOAD",
    "SOURCE_WEB_PAGE",
    "annotate_settings_classes",
    "record_downloaded_file",
    "write_and_record_file",
]
