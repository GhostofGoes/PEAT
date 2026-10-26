"""
Siemens SIMATIC S7 PLCs (S7-300, S7-400, S7-1200, and S7-1500).

S7 PLCs are programmed with Siemens engineering software: STEP 7 V5.x
("SIMATIC Manager") for the S7-300/400, and TIA Portal (STEP 7 Basic and
Professional) for the S7-1200/1500 and newer S7-300/400 projects. This
module parses the project and program files those tools produce, and
identifies and pulls basic information from PLCs over the network.

Services

- ISO-on-TCP with S7comm and S7comm-plus (TCP 102)
- HTTP and HTTPS web server, if enabled (TCP 80 and 443)
- SNMP (UDP 161), on PROFINET CPUs and CPs
- PROFINET DCP discovery (Ethernet, ethertype 0x8892)
- OPC UA (TCP 4840), on S7-1500 if enabled

Scanning and pulling use read-only S7comm functions: reading System Status
Lists (SZL) for the order number, firmware version, serial number, and
PLC name, the operating mode, and the number of blocks of each type.

Parsing supports:

- STEP 7 V5.x projects: ``.s7p`` files, project directories, and ``.zip``
  project archives
- TIA Portal projects: ``.apNN`` files, project directories, and ``.zapNN``
  project archives (metadata only, the project data format is undocumented)
- TIA Portal Openness XML (SimaticML) exports of blocks and tag tables
- STL (``.awl``) and SCL (``.scl``) source files
- STEP 7 symbol table exports (``.asc`` and ``.sdf``)

Authors

- Christopher Goes
"""

import json
import struct
import zipfile
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from peat import (
    CommError,
    DeviceData,
    DeviceModule,
    Event,
    File,
    IPMethod,
    ParseError,
    Service,
    Tag,
    datastore,
)
from peat.file_signature import FileSignature

from . import s7_parse
from .s7comm import (
    CONNECTION_TYPES,
    S7CommClient,
    parse_szl_001c,
    parse_szl_0011,
    parse_szl_0424,
)


def _is_step7_archive(data: BinaryIO) -> bool:
    return s7_parse.is_step7_archive(data)  # type: ignore[arg-type]


def _is_tia_archive(data: BinaryIO) -> bool:
    return s7_parse.is_tia_archive(data)  # type: ignore[arg-type]


def _decode_text(raw: bytes) -> str:
    # TIA Portal writes UTF-8, STEP 7 V5.x writes the Windows ANSI code page
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def _json_default(obj: object) -> str:
    return obj.isoformat() if isinstance(obj, datetime) else str(obj)


class S7(DeviceModule):
    """
    Siemens SIMATIC S7 PLC (S7-300, S7-400, S7-1200, S7-1500) and
    STEP 7/TIA Portal project files.
    """

    device_type = "PLC"
    vendor_id = "Siemens"
    vendor_name = "Siemens AG"
    brand = "SIMATIC"
    supported_models = ["S7-300", "S7-400", "S7-1200", "S7-1500"]
    module_aliases = ["s7", "simatic", "siemens_s7", "step7", "tia_portal"]
    filename_patterns = [
        "*.s7p",
        "*.ap[0-9][0-9]",
        "*.zap[0-9][0-9]",
        "*.awl",
        "*.scl",
    ]
    file_signatures = [
        FileSignature(
            default_filename="step7_project.zip",
            magic_number="504B0304",
            custom_check=_is_step7_archive,
        ),
        FileSignature(
            default_filename="tia_project.zap",
            magic_number="504B0304",
            custom_check=_is_tia_archive,
        ),
        FileSignature(
            default_filename="simaticml.xml",
            xml_tags=("Document", "Engineering"),
        ),
        FileSignature(
            default_filename="symbols.asc",
            magic_number="3132362C",  # "126,"
        ),
    ]
    can_parse_dir = True
    default_options = {
        "s7": {
            # Rack and slot combinations to try when connecting to the CPU.
            # S7-300 CPUs are usually in slot 2, S7-1200/1500 CPUs in slot 0 or 1,
            # and S7-400 CPUs vary, commonly slot 2 or 3.
            "rack_slots": [[0, 2], [0, 0], [0, 1], [0, 3]],
            # Connection resource type: "pg" (programming device),
            # "op" (operator panel), or "basic"
            "connection_type": "pg",
            # Read the number of blocks of each type that are loaded on the PLC
            "list_blocks": True,
        },
    }

    # --- Scan ---

    @classmethod
    def _connect(cls, dev: DeviceData) -> S7CommClient:
        """
        Connect to the PLC, trying each configured rack and slot.

        The rack and slot that worked are cached for later connections.

        Raises:
            CommError: If no rack/slot combination worked
        """
        port = dev.options["s7comm"]["port"]
        timeout = dev.options["s7comm"]["timeout"]
        conn_name = str(dev.options["s7"]["connection_type"]).lower()
        if conn_name not in CONNECTION_TYPES:
            raise CommError(
                f"Invalid S7 'connection_type' option '{conn_name}', "
                f"must be one of {', '.join(CONNECTION_TYPES)}"
            )
        conn_type = CONNECTION_TYPES[conn_name]

        try:
            rack_slots = [(int(rack), int(slot)) for rack, slot in dev.options["s7"]["rack_slots"]]
        except (TypeError, ValueError):
            raise CommError(
                f"Invalid S7 'rack_slots' option {dev.options['s7']['rack_slots']!r}, "
                f"must be a list of [rack, slot] pairs"
            ) from None
        if dev._cache.get("s7_rack_slot") in rack_slots:
            rack_slots.remove(dev._cache["s7_rack_slot"])
            rack_slots.insert(0, dev._cache["s7_rack_slot"])

        errors = []
        for rack, slot in rack_slots:
            client = S7CommClient(
                dev.ip, port, timeout, rack=rack, slot=slot, connection_type=conn_type
            )
            try:
                client.connect()
                dev._cache["s7_rack_slot"] = (rack, slot)
                return client
            except (CommError, OSError) as ex:
                errors.append(f"rack {rack} slot {slot}: {ex}")
                # A TCP connection failure (closed or filtered port) won't work for
                # other slots either. Handshake failures are raised as CommError.
                if not isinstance(ex, CommError):
                    break

        raise CommError(f"S7comm connection to {dev.ip}:{port} failed ({'; '.join(errors)})")

    @classmethod
    def _verify_s7comm(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a S7 PLC by connecting with S7comm (ISO-on-TCP,
        TCP 102) and reading the module identification (SZL ``0x0011``),
        which contains the Siemens order number of the CPU.
        """
        port = dev.options["s7comm"]["port"]
        log = cls.log.bind(target=f"{dev.ip}:{port}")

        try:
            with cls._connect(dev) as client:
                identity = parse_szl_0011(client.read_szl(0x0011))
        except (CommError, OSError) as ex:
            log.trace(f"S7comm verification failed: {ex}")
            return False

        order_number = identity.get("module", {}).get("order_number", "")
        if not order_number:
            log.debug("S7comm connection succeeded, but no order number was returned")
            return False

        log.debug(f"Verified S7 PLC with order number '{order_number}'")
        cls._process_identity(dev, identity, {})
        dev.store(
            "service",
            Service(protocol="s7comm", port=port, transport="tcp", status="verified"),
            lookup="protocol",
        )
        return True

    # --- Pull ---

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        results: dict = {}
        try:
            with cls._connect(dev) as client:
                results["rack_slot"] = list(dev._cache.get("s7_rack_slot", ()))
                results["pdu_size"] = client.pdu_size
                results["module_identification"] = parse_szl_0011(client.read_szl(0x0011))

                # The remaining reads aren't supported by all CPUs and emulators
                optional_reads = [
                    ("component_identification", lambda: parse_szl_001c(client.read_szl(0x001C))),
                    ("operating_mode", lambda: parse_szl_0424(client.read_szl(0x0424))),
                ]
                if dev.options["s7"]["list_blocks"]:
                    optional_reads.append(("block_counts", client.list_blocks))

                for key, read_func in optional_reads:
                    try:
                        results[key] = read_func()
                    except CommError as ex:
                        cls.log.warning(f"Failed to read {key.replace('_', ' ')}: {ex}")
                    except OSError as ex:
                        # The connection is gone, keep what was already read
                        cls.log.warning(
                            f"Failed to read {key.replace('_', ' ')}, "
                            f"skipping the remaining reads: {ex!r}"
                        )
                        break
        except (CommError, OSError) as ex:
            cls.log.error(f"Failed to pull from {dev.ip} using S7comm: {ex}")
            return False

        dev.write_file(results, "s7comm-pull.json")
        cls._process_identity(
            dev,
            results["module_identification"],
            results.get("component_identification", {}),
        )
        if results.get("operating_mode"):
            dev.run_mode = results["operating_mode"]
            dev.status = "running" if dev.run_mode.startswith("RUN") else "stopped"
        if "block_counts" in results:
            dev.extra["block_counts"] = results["block_counts"]
        dev.extra["s7comm"] = {"rack_slot": results["rack_slot"], "pdu_size": results["pdu_size"]}

        dev.store(
            "service",
            Service(
                protocol="s7comm",
                port=dev.options["s7comm"]["port"],
                transport="tcp",
                status="verified",
            ),
            lookup="protocol",
        )
        dev.successful_pulls["s7comm"] = True
        return True

    @classmethod
    def _process_identity(cls, dev: DeviceData, modules: dict, components: dict) -> None:
        """Populate device fields from parsed SZL 0x0011 and 0x001C data."""
        module = modules.get("module", {})
        if module.get("order_number"):
            dev.part_number = module["order_number"]
        if modules.get("hardware", {}).get("version"):
            dev.hardware.version = modules["hardware"]["version"]
        if modules.get("firmware", {}).get("version"):
            dev.firmware.version = modules["firmware"]["version"]
        if modules.get("boot_loader", {}).get("version"):
            dev.boot_firmware.version = modules["boot_loader"]["version"]

        if components.get("module_type_name"):
            dev.description.model = components["module_type_name"]
        if components.get("plc_name"):
            dev.name = components["plc_name"]
        if components.get("serial_number"):
            dev.serial_number = components["serial_number"]

        extra = {k: v for k, v in components.items() if k not in ("serial_number", "plc_name")}
        if extra:
            dev.extra["component_identification"] = extra
        if modules:
            dev.extra["module_identification"] = modules

    # --- Parse ---

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        """
        Parse a STEP 7 or TIA Portal project, project archive, SimaticML XML
        export, STL/SCL source, or symbol table.

        Usage:
            ``peat parse -d S7 -- project.zip``
        """
        file_type = s7_parse.detect_file_type(file)
        cls.log.debug(f"Detected file type of '{file.name}' as '{file_type}'")

        if not file_type and file.is_dir():
            return cls._parse_directory(file, dev)

        try:
            return cls._parse_file(file, file_type, dev)
        except (
            ParseError,
            OSError,
            ValueError,
            OverflowError,
            RecursionError,
            RuntimeError,  # e.g. encrypted zip archive members
            struct.error,
            zipfile.BadZipFile,
        ) as ex:
            cls.log.error(f"Failed to parse '{file.name}' ({file_type or 'unknown'}): {ex!r}")
            return None

    @classmethod
    def _parse_file(cls, file: Path, file_type: str, dev: DeviceData | None) -> DeviceData | None:
        if file_type == "step7_project":
            return cls._parse_step7_project(file, dev)
        if file_type == "tia_project":
            return cls._parse_tia_project(file, dev)
        if not file_type or not file.is_file():
            cls.log.error(f"Unable to parse '{file.name}': unknown or unsupported file type")
            return None

        raw = file.read_bytes()
        if file_type == "simaticml":
            # The XML parser handles the encoding from the XML declaration
            return cls._parse_simaticml(file, raw, dev)

        text = _decode_text(raw)
        if file_type == "symbol_table":
            return cls._parse_symbol_table(file, text, dev)
        return cls._parse_source(file, text, dev)

    @classmethod
    def _parse_directory(cls, directory: Path, dev: DeviceData | None) -> DeviceData | None:
        """
        Parse a directory of exported files, such as SimaticML XML exports,
        STL/SCL sources, and symbol tables, into a single device.
        """
        parsed = None
        for pth in sorted(directory.rglob("*")):
            if not pth.is_file():
                continue
            file_type = s7_parse.detect_file_type(pth)
            if not file_type:
                continue
            if dev is None:
                dev = datastore.get(directory.name, "id")
            result = cls._parse(pth, dev)
            parsed = result or parsed

        if parsed is None:
            cls.log.error(f"No STEP 7 or TIA Portal files found in directory '{directory}'")
        return parsed

    @classmethod
    def _get_dev(cls, dev: DeviceData | None, name: str, file: Path) -> DeviceData:
        if dev is not None:
            return dev
        if not name:
            name = file.stem
            cls.log.warning(f"No project name found in '{file.name}', using '{name}'")
        return datastore.get(name, "id")

    @classmethod
    def _parse_step7_project(cls, file: Path, dev: DeviceData | None) -> DeviceData | None:
        try:
            project = s7_parse.parse_step7_project(file)
        except (ParseError, OSError) as ex:
            cls.log.error(f"Failed to parse STEP 7 project '{file.name}': {ex}")
            return None

        dev = cls._get_dev(dev, project["name"], file)
        dev.logic.name = project["name"]
        cls._store_project_file(dev, file, "STEP 7 V5 project")
        if project.get("guid"):
            dev.logic.id = project["guid"]

        programs = project["programs"]
        if programs:
            created = [p["created"] for p in programs if p["created"]]
            modified = [p["last_modified"] for p in programs if p["last_modified"]]
            if created:
                dev.logic.created = min(created)
            if modified:
                dev.logic.last_updated = max(modified)
            authors = sorted({p["author"] for p in programs if p["author"]})
            if authors:
                dev.logic.author = ", ".join(authors)
            dev.logic.description = ", ".join(f"{p['name']} ({p['type']})" for p in programs)

        for table in project["symbol_tables"]:
            for symbol in table["symbols"]:
                cls._store_symbol(dev, symbol)

        for entry in project["change_log"]:
            dev.store(
                "event",
                Event(
                    action="project_change",
                    category={"configuration"},
                    created=entry["timestamp"],
                    dataset="step7_change_log",
                    id=str(entry["id"]),
                    kind={"event"},
                    message=" ".join(
                        filter(None, [entry["object_path"], entry["event"], entry["cause"]])
                    ),
                    provider="SIMATIC Manager",
                    type={"change"},
                    extra={
                        "computer": entry["computer"],
                        "user": entry["user"],
                        "action_code": entry["action"],
                    },
                ),
            )
            if entry["computer"]:
                dev.related.hosts.add(entry["computer"])

        dev.extra["step7_project"] = json.loads(json.dumps(project, default=_json_default))
        dev.write_file(project, "step7-project.json")
        return dev

    @classmethod
    def _parse_tia_project(cls, file: Path, dev: DeviceData | None) -> DeviceData | None:
        try:
            project = s7_parse.parse_tia_archive(file)
        except (ParseError, OSError) as ex:
            cls.log.error(f"Failed to parse TIA Portal project '{file.name}': {ex}")
            return None

        dev = cls._get_dev(dev, project.get("name", ""), file)
        dev.logic.name = project.get("name", "")
        cls._store_project_file(dev, file, "TIA Portal project")
        if project.get("tia_portal_version"):
            dev.logic.description = f"TIA Portal {project['tia_portal_version']} project"

        # Values extracted from the binary project data are best-effort,
        # so they're only used for the device when they're unambiguous.
        if len(project.get("cpu_names", [])) == 1 and not dev.description.model:
            dev.description.model = project["cpu_names"][0]

        dev.extra["tia_project"] = project
        dev.write_file(project, "tia-project.json")
        return dev

    @classmethod
    def _parse_simaticml(cls, file: Path, raw: bytes, dev: DeviceData | None) -> DeviceData | None:
        try:
            export = s7_parse.parse_simaticml(raw)
        except ParseError as ex:
            cls.log.error(f"Failed to parse SimaticML file '{file.name}': {ex}")
            return None

        names = [b["name"] for b in export["blocks"] + export["types"] + export["tag_tables"]]
        dev = cls._get_dev(dev, names[0] if names else "", file)
        cls._set_logic_from_blocks(dev, export["blocks"], file)
        dev.logic.original = _decode_text(raw)
        if export.get("created"):
            dev.logic.created = export["created"]

        for table in export["tag_tables"]:
            for tag in table["tags"]:
                cls._store_symbol(dev, tag)

        dev.extra["simaticml"] = json.loads(json.dumps(export, default=_json_default))
        return dev

    @classmethod
    def _parse_source(cls, file: Path, text: str, dev: DeviceData | None) -> DeviceData | None:
        try:
            source = s7_parse.parse_s7_source(text, file.name)
        except ParseError as ex:
            cls.log.error(f"Failed to parse S7 source file '{file.name}': {ex}")
            return None

        # Block names like "OB1" are common to most programs, use the file name
        dev = dev if dev is not None else datastore.get(file.stem, "id")
        cls._set_logic_from_blocks(dev, source["blocks"], file)
        dev.logic.original = text
        language = source["format"].split(" ")[0].lower()
        if language in ("stl", "scl"):
            dev.logic.formats[language] = text

        dev.extra["s7_source"] = source
        return dev

    @classmethod
    def _parse_symbol_table(
        cls, file: Path, text: str, dev: DeviceData | None
    ) -> DeviceData | None:
        try:
            symbols = s7_parse.parse_symbol_table(text, file.name)
        except ParseError as ex:
            cls.log.error(f"Failed to parse symbol table '{file.name}': {ex}")
            return None

        # Symbol tables don't contain a project name
        dev = dev if dev is not None else datastore.get(file.stem, "id")
        for symbol in symbols:
            cls._store_symbol(dev, symbol)
        cls._store_project_file(dev, file, "STEP 7 symbol table")
        return dev

    @classmethod
    def _store_project_file(cls, dev: DeviceData, file: Path, description: str) -> None:
        """
        Record a parsed file that isn't logic text, such as a project archive.
        These aren't set as ``logic.file``, since that's expected to be text.
        """
        dev.store(
            "files",
            File(
                local_path=file, description=description, type="dir" if file.is_dir() else "file"
            ),
        )

    @classmethod
    def _set_logic_from_blocks(cls, dev: DeviceData, blocks: list[dict], file: Path) -> None:
        dev.logic.file.local_path = file
        if not blocks:
            return
        dev.logic.name = blocks[0]["name"]
        for key in ("author", "header_author"):
            if blocks[0].get(key):
                dev.logic.author = blocks[0][key]
        titles = blocks[0].get("title")
        if isinstance(titles, dict):  # SimaticML has a title per language
            titles = next(iter(titles.values()), "")
        if titles:
            dev.logic.description = titles

        sources = [
            f"// {block['name']}, network {i + 1}\n{net['source']}"
            for block in blocks
            for i, net in enumerate(block.get("networks", []))
            if net.get("source")
        ]
        if sources:
            language = blocks[0].get("language", "source").lower()
            dev.logic.formats[language] = "\n\n".join(sources)

    @classmethod
    def _store_symbol(cls, dev: DeviceData, symbol: dict) -> None:
        dev.store(
            "tag",
            Tag(
                name=symbol["name"],
                address=symbol.get("address", ""),
                type=symbol.get("data_type", ""),
                description=symbol.get("comment", ""),
            ),
            append=True,
        )


S7.ip_methods = [
    IPMethod(
        name="S7 S7comm SZL module identification",
        description=str(S7._verify_s7comm.__doc__).strip(),
        type="unicast_ip",
        identify_function=S7._verify_s7comm,
        reliability=8,
        protocol="s7comm",
        transport="tcp",
        default_port=102,
    ),
]


__all__ = ["S7"]
