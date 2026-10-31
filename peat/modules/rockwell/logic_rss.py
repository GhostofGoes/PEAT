"""
PEAT module to parse Rockwell RSLogix 500 project files (``.RSS``).

RSLogix 500 (and RSLogix Micro) is the engineering software for the
Allen-Bradley SLC 500 and MicroLogix PLCs. The project file format is
undocumented, see :mod:`peat.modules.rockwell.rss_parse` for what is known
about it and how confident we are in each part.

What's extracted:

- Every stream in the file, decompressed, with an inventory (always, even
  if decoding of a section fails).
- Processor and project metadata: processor name and type code, RSLinx
  driver, last communication path (which names the engineering
  workstation), RSLogix version, and the OLE SummaryInformation timestamps.
- Ladder logic of every program file, rendered as mnemonic text such as
  ``SOR XIC I:1/0 OTE O:0/2 EOR``.
- Address descriptions (as tags) and rung comments.
- If the online image differs from the offline project, and if the
  project contains VBA code modules.

Usage:

.. code-block:: bash

    peat parse -d RSLogix500 -- project.RSS
    peat parse ./directory_with_rss_files/

Files are detected by their contents, not their extension, so renamed files
and backups (``*_BAK000.RSS``) are found, and RSS news feeds aren't.

The device is identified by the processor name, or by the file name
(``rss_<file name>``) if the processor isn't named. A project and its
backups have the same processor name, so they're the same device. The
device's logic, tags and metadata come from the project file that was saved
last. Every project file is listed in ``extra.rslogix500.project_files``,
and the output files of each one are in its own directory,
``rss/<file name>_<first 8 characters of the file's SHA-256>/``.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import olefile

from peat import DeviceData, DeviceModule, Logic, ParseError, Tag, datastore, utils
from peat.file_signature import FileSignature

from .rss_const import SKIP_DEFAULT_STATUS_DESCRIPTIONS
from .rss_parse import (
    RssContainer,
    address_type_name,
    is_default_processor_name,
    is_default_status_address,
    is_rslogix500_project,
    parse_rss,
    read_rss,
    render_ladder_text,
)

#: Characters allowed in the names of extracted files
_SAFE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-")
#: Longest part of a stream path used in the name of an extracted stream file.
#: Names are kept short so paths stay below the Windows limit of 260
#: characters. The full path of each stream is in the inventory.
_MAX_STREAM_NAME = 48
#: Longest part of the project file name used in the output directory name
_MAX_STEM = 32


def _safe_name(text: str) -> str:
    """Remove or replace anything in (untrusted) text that isn't safe in a file name."""
    cleaned = "".join(c if c in _SAFE_CHARS else "_" for c in text if c.isprintable())
    return cleaned.strip(" .") or "_"


def _stream_filename(index: int, path: str, extension: str) -> str:
    """
    Convert a stream path from the (untrusted) file into a short, safe file name.

    The name is the index of the stream, then the stream path with path
    separators changed to ``__``, for example ``012_PROGRAM FILES__ObjectData.bin``.
    Anything that isn't a letter, digit, space, dot, underscore or dash is
    removed or replaced. Long paths are shortened by replacing the middle
    with ``~``. The index keeps the names unique.
    """
    name = "__".join(_safe_name(part) for part in path.split("/"))
    if len(name) > _MAX_STREAM_NAME:
        # Keep the start and the end, which is the most specific part
        name = f"{name[:16].rstrip(' .')}~{name[17 - _MAX_STREAM_NAME :].strip(' .')}"
    return f"{index:03d}_{name}{extension}"


def _artifact_dir(file: Path, sha256: str) -> str:
    """Directory (relative to the device's directory) for the output files of a project file."""
    return f"rss/{_safe_name(file.stem)[:_MAX_STEM].rstrip(' .')}_{sha256[:8]}"


def _processor_name(parsed: dict[str, Any]) -> str:
    """Processor name from the PROCESSOR storage, or the SummaryInformation."""
    name = parsed["processor"].get("processor_name") or parsed["summary_info"].get(
        "processor_name"
    )
    if not isinstance(name, str):
        return ""
    return "".join(c for c in name if c.isprintable())[:64].strip()


class RSLogix500(DeviceModule):
    """
    Parse RSLogix 500 / RSLogix Micro project files (``.RSS``) for
    SLC 500 and MicroLogix PLCs.
    """

    device_type = "PLC"
    vendor_id = "Rockwell"  # Allen-Bradley is a brand name, not a vendor
    vendor_name = "Rockwell Automation/Allen-Bradley"
    supported_models = [
        "SLC 500",
        "MicroLogix 1000",
        "MicroLogix 1100",
        "MicroLogix 1200",
        "MicroLogix 1400",
        "MicroLogix 1500",
    ]
    # NOTE: there are deliberately no filename patterns. "*.rss" would also
    # match RSS news feeds (e.g. from browser caches found by pillage), which
    # would all fail to parse. Detection by content finds renamed files too.
    filename_patterns = []
    file_signatures = [
        FileSignature(
            default_filename="rslogix500_project.rss",
            custom_check=is_rslogix500_project,
        ),
    ]
    module_aliases = ["rss", "rslogix500", "rslogix_500", "logic_rss", "rockwell_rss"]
    default_options = {}

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """
        Parse a RSLogix 500 project file.

        Usage:
            ``peat parse -d RSLogix500 -- project_file.RSS``
        """
        with file.open("rb") as fp:
            magic = fp.read(len(olefile.MAGIC))
        if magic != olefile.MAGIC:
            cls.log.error(
                f"'{file.name}' isn't a RSLogix 500 project file "
                f"(RSS project files are OLE compound files)"
            )
            return None

        try:
            container = read_rss(file)
        except ParseError as ex:
            cls.log.error(f"Failed to read RSLogix 500 project file: {ex}")
            return None

        parsed = parse_rss(container)
        name = _processor_name(parsed)

        if dev is None:
            if not is_default_processor_name(name):
                dev = datastore.get(name, "name")
            else:
                tmp_id = f"rss_{file.stem.lower()}"
                cls.log.info(
                    f"Processor in '{file.name}' isn't named, using '{tmp_id}' as the device ID"
                )
                dev = datastore.get(tmp_id, "id")

        sha256 = utils.calc_hash(file, "sha256").lower()
        out_dir = _artifact_dir(file, sha256)

        # The streams are written first, so they're kept even if something fails later
        cls._write_streams(dev, container, out_dir)

        newest = cls._is_newest(dev, file, parsed)
        if newest:
            cls._populate(dev, file, parsed)
        cls._add_project_file(dev, file, sha256, parsed, out_dir, newest)
        cls._write_results(dev, parsed, out_dir, render_ladder_text(parsed))

        for msg in parsed["warnings"]:
            cls.log.debug(f"{file.name}: {msg}")
        if parsed["warnings"]:
            cls.log.info(
                f"{len(parsed['warnings'])} warnings while decoding '{file.name}', "
                f"see '{out_dir}/parsed.json' for details"
            )
        for msg in parsed["errors"]:
            cls.log.warning(f"{file.name}: {msg}")

        cls.update_dev(dev)

        return dev

    @classmethod
    def _is_newest(cls, dev: DeviceData, file: Path, parsed: dict[str, Any]) -> bool:
        """
        If a project file should be used for the device's data.

        A project and its backups have the same processor name, so they're
        the same device. The data comes from the one that was saved last.
        """
        previous = dev.logic.file.local_path
        project_files = dev.extra.get("rslogix500", {}).get("project_files", [])
        if (
            not previous
            or Path(previous) == file
            or not any(p["path"] == str(previous) for p in project_files)
        ):
            # No logic yet, the same file again, or logic that isn't from a project file
            return True

        saved = parsed["summary_info"].get("last_saved_time")
        current = dev.logic.last_updated
        try:
            older = bool(saved and current and saved < current)
        except TypeError:  # Naive and aware datetimes
            older = False

        if older:
            cls.log.info(
                f"'{file.name}' was saved before '{Path(previous).name}', so the device's "
                f"logic is from '{Path(previous).name}'"
            )
        else:
            cls.log.info(
                f"'{file.name}' replaces the logic from '{Path(previous).name}' "
                f"(it was saved after it, or the save times are unknown)"
            )
        return not older

    @staticmethod
    def _add_project_file(
        dev: DeviceData, file: Path, sha256: str, parsed: dict, out_dir: str, newest: bool
    ) -> None:
        """List a project file in ``dev.extra["rslogix500"]["project_files"]``."""
        extra = dev.extra.setdefault("rslogix500", {})
        project_files = [
            p
            for p in extra.get("project_files", [])
            if (p["path"], p["sha256"]) != (str(file), sha256)
        ]
        if newest:
            for item in project_files:
                item["used_for_device"] = False

        saved = parsed["summary_info"].get("last_saved_time")
        project_files.append(
            {
                "name": file.name,
                "path": str(file),
                "sha256": sha256,
                "processor_name": _processor_name(parsed),
                "last_saved_time": saved.isoformat() if isinstance(saved, datetime) else "",
                "output_directory": out_dir,
                "used_for_device": newest,
            }
        )
        extra["project_files"] = project_files

    @classmethod
    def _populate(cls, dev: DeviceData, file: Path, parsed: dict[str, Any]) -> None:
        """Map the parsed project into the PEAT data model."""
        summary = parsed["summary_info"]
        name = _processor_name(parsed)

        dev.type = "PLC"
        if not is_default_processor_name(name):
            dev.name = name

        # Logic. Start from scratch if the device has logic from another
        # project file (e.g. a backup), so the hash and file information
        # are for this file.
        if dev.logic.file.local_path:
            dev.logic = Logic()
        dev.logic.name = name if not is_default_processor_name(name) else file.stem
        dev.logic.file.local_path = file
        # Prevent the ".rss" extension being guessed as a RSS news feed
        if not dev.logic.file.mime_type:
            dev.logic.file.mime_type = "application/x-ole-storage"
        if isinstance(summary.get("create_time"), datetime):
            dev.logic.created = summary["create_time"]
        if isinstance(summary.get("last_saved_time"), datetime):
            dev.logic.last_updated = summary["last_saved_time"]
        author = summary.get("author") or summary.get("last_saved_by")
        if isinstance(author, str) and author:
            dev.logic.author = author
        dev.logic.parsed = render_ladder_text(parsed)
        # The raw decoded instructions, as compact JSON (same approach as the
        # ControlLogix module). This makes "logic.hash" a hash of the logic
        # itself, independent of the rest of the project file.
        dev.logic.original = json.dumps(
            [
                {
                    "number": pfile["number"],
                    "name": pfile["name"],
                    "type": pfile["type"],
                    "rungs": [
                        [
                            [tok["opcode"], tok["flag"], tok["operands"], tok["compiled_hex"]]
                            for tok in rung["tokens"]
                        ]
                        for rung in pfile["rungs"]
                    ],
                }
                for pfile in parsed["program_files"]
            ],
            separators=(",", ":"),
        )

        program_text: dict[str, str] = {}
        for pfile in parsed["program_files"]:
            if pfile["type_name"] != "ladder" and not pfile["rungs"]:
                continue
            key = f"{pfile['number']}:{pfile['name']}" if pfile["name"] else str(pfile["number"])
            program_text[key] = "\n".join(rung["text"] for rung in pfile["rungs"])
        if program_text:
            dev.logic.formats["program_files"] = program_text

        # Tags, from the documented addresses
        for entry in parsed["documentation"]:
            if entry["kind"] != "data":
                continue
            if SKIP_DEFAULT_STATUS_DESCRIPTIONS and is_default_status_address(
                entry["address_raw"]
            ):
                continue
            description = " ".join(line.strip() for line in entry["description_lines"] if line)
            if not description and not entry["symbol"]:
                continue
            tag = Tag(
                address=entry["address"],
                name=entry["symbol"],
                description=description,
                type=address_type_name(entry["address_raw"]),
            )
            dev.store("tag", tag, lookup="address")

        project_files = dev.extra.get("rslogix500", {}).get("project_files", [])
        dev.extra["rslogix500"] = {**cls._extra(parsed), "project_files": project_files}

    @staticmethod
    def _extra(parsed: dict[str, Any]) -> dict[str, Any]:
        """Summary of the project for ``dev.extra``."""
        summary = parsed["summary_info"]
        processor = parsed["processor"]
        type_code = processor.get("processor_type_code")
        fmt_version = parsed["file_format_version"]

        summary_extra = {
            key: value.isoformat() if hasattr(value, "isoformat") else value
            for key, value in summary.items()
            if key in ("revision_number", "total_edit_time_seconds", "last_printed")
            or key == "other_properties"
        }

        return {
            "file_format_version": f"{fmt_version:#x}" if fmt_version is not None else "",
            "rslogix_version": parsed["version"].get("rslogix_version", ""),
            "processor_type_code": type_code,
            "processor_type_code_hex": f"{type_code:#06x}" if type_code is not None else "",
            "comms_driver": processor.get("comms_driver", ""),
            "last_comms_path": processor.get("last_comms_path", ""),
            "engineering_workstation": processor.get("engineering_workstation", ""),
            "summary_info": summary_extra,
            "num_program_files": parsed["program_files_declared"],
            "num_data_files": parsed["num_data_files"],
            "program_files": [
                {
                    "number": pfile["number"],
                    "name": pfile["name"],
                    "type": pfile["type_name"],
                    "rungs": len(pfile["rungs"]),
                }
                for pfile in parsed["program_files"]
            ],
            "referenced_data_files": parsed["referenced_data_files"],
            "num_documented_addresses": len(parsed["documentation"]),
            "rung_comment_count": len(parsed["rung_comments"]),
            "online_image_differs": parsed["online_image_differs"],
            "vba": {
                "present": parsed["vba"]["present"],
                "modules": [m["name"] for m in parsed["vba"]["modules"]],
            },
            "warnings": parsed["warnings"],
            "errors": parsed["errors"],
        }

    @staticmethod
    def _write_streams(dev: DeviceData, container: RssContainer, out_dir: str) -> None:
        """Write the extracted streams and their inventory to ``out_dir``."""
        for index, path in enumerate(sorted(container.streams)):
            stream = container.streams[path]
            if stream.payload is not None:
                data, ext = stream.payload, ".bin"
            else:
                data, ext = stream.raw, ".raw"
            name = f"{out_dir}/streams/{_stream_filename(index, path, ext)}"
            stream.info["output_file"] = name
            # The directory is unique to the file's contents, so files
            # that already exist are from parsing the same file again
            dev.write_file(data, name, overwrite_existing=True)

        dev.write_file(
            container.inventory, f"{out_dir}/stream-inventory.json", overwrite_existing=True
        )

    @staticmethod
    def _write_results(dev: DeviceData, parsed: dict, out_dir: str, ladder: str) -> None:
        """Write the decoded results and the ladder logic text to ``out_dir``."""
        dev.write_file(parsed, f"{out_dir}/parsed.json", overwrite_existing=True)
        dev.write_file(ladder, f"{out_dir}/ladder.txt", overwrite_existing=True)

        if (
            parsed["online_image_differs"].get("PROGRAM FILES")
            and parsed["online_image_program_files"]
        ):
            # The rung comments are keyed by the offline rung numbers, which
            # can differ in the online image, so they aren't included
            text = render_ladder_text(parsed, parsed["online_image_program_files"])
            dev.write_file(text, f"{out_dir}/ladder-onlineimage.txt", overwrite_existing=True)


__all__ = ["RSLogix500"]
