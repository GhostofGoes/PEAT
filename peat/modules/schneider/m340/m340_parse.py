"""
Parsing and extraction of configuration and logic for Schneider Modicon PLCs.

Authors

- Mark Woodard
- Christopher Goes
"""

import re
import struct
import zlib
from pprint import pformat
from typing import Final
from xml.etree import ElementTree
from xml.etree.ElementTree import SubElement

from peat import log, utils
from peat.parsing.plc_open.core_modules.definitions import TypeHierarchy_list
from peat.parsing.tc6 import TC6

ChunksType = dict[int, dict[str, int | str | bytes | bool | None]]
# IEC 61131-3 types
ALLOWED_TYPES: Final[set[str]] = {type_pair[0] for type_pair in TypeHierarchy_list}

# APX file format details (header, section and RTE header layouts, compression
# formats, CRC16, SD section) are based on apxutil by finngineering (MIT License),
# https://github.com/finngineering/apxutil
APX_HEADER_SIZE: Final[int] = 32
# Section header size, by section type
SECTION_HEADER_SIZES: Final[dict[int, int]] = {0: 8, 1: 16, 2: 16, 3: 24, 4: 24}
DEFAULT_RTE_TYPE: Final[int] = 2
DEFAULT_RTE_SIZE: Final[int] = 16
# The "SD" section (memory layout) and the "RT" section, whose CRC covers more
# than its data. apxutil's README lists these the other way around, but in real
# APX files the data of section 0x01 starts with "SD" and 0x11 with "RT".
SD_SECTION_NUMBER: Final[int] = 0x01
RT_SECTION_NUMBER: Final[int] = 0x11
RTE_ATTR_COMPRESSED: Final[int] = 1 << 13  # Section data is compressed
RTE_ATTR_NO_DATA: Final[int] = 1 << 28  # Section has no data in the file
PK_HEADER_SIZE: Final[int] = 0x2E
ZLIB_HEADER_SIZE: Final[int] = 16

# TODO: process FBD blocks to TC6
# TODO: process LD blocks to TC6


def extract_logic_blocks(logic_blob: bytes) -> dict[str, dict | list]:
    """
    Extracts the process logic blocks from a Schneider M340 APX project file blob.

    Args:
        logic_blob: Logic blob pulled from the PLC

    Returns:
        Logic blocks extracted from the blob
    """
    # This will decompress and extract portions of
    # the project file that are zlib-compressed.
    project_blocks = chunkify(bytes(logic_blob))
    extracted_blocks = {"ST": [], "FBD": [], "LD": [], "vars": {}}

    # TODO: need some comments explaining what's going on here
    for key, block in project_blocks.items():
        if not block:
            log.warning("Empty logic block")
            continue

        if block["tag"] == "2":
            if block["type"] == b"\x03\x24\xcf\xe0":
                ext_vars = extract_variables(block["data"])
                extracted_blocks["vars"].update(ext_vars)
            elif block["type"] == b"\x00\x80\x8f\xe0":
                init = extract_initial_values(block["data"])
                init_vals = set_init_vals(extracted_blocks["vars"], init)
                extracted_blocks["vars"].update(init_vals)
            elif block["type"] == b"\x03\x20\xcf\xe0":
                if b"STExchangeFile" in block["data"]:
                    st = strip_xml(block["data"])
                    # Clean up the ST code portion
                    st[0] = bytes(st[0]).replace(b"\r", b"")
                    extracted_blocks["ST"].append(st)
                elif b"FBDExchangeFile" in block["data"]:
                    fbd = strip_xml(block["data"])
                    extracted_blocks["FBD"].append(fbd)
                elif b"LDExchangeFile" in block["data"]:
                    ll = strip_xml(block["data"])
                    extracted_blocks["LD"].append(ll)
                else:
                    extracted_blocks[key] = block
        else:
            extracted_blocks[key] = block

    return extracted_blocks


def strip_xml(data: bytes) -> list[bytes]:
    """
    Strips unnecessary XML data and extracts field elements from a data blob.
    """
    index = data.find(b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    stripped_xml = []

    while index < len(data):
        try:
            # Fields longer than 0x7F
            if (data[index - 1] & 0x80) == 0x80:
                f_len = int(data[index - 1] & 0x0F) * 256 + int(data[index])
                index += 1
            # Fields Shorter than 0x7F
            else:
                f_len = int(data[index - 1])

            stripped_xml.append(bytes(data[index : index + f_len]))
        except Exception as ex:
            log.error(f"Error stripping data: {ex}")
            return []

        index = index + f_len + 1

    # Remove the XML header
    if b"<?xml" in stripped_xml[0]:
        del stripped_xml[0]

    return stripped_xml


def _make_crc16_kermit_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC16_KERMIT_TABLE: Final[tuple[int, ...]] = _make_crc16_kermit_table()


def crc16_kermit(data: bytes, init: int = 0xFFFF) -> int:
    """
    CRC16/Kermit (reflected polynomial 0x8408) of ``data``.

    APX files store this checksum of each section's data in the section's
    RTE header, computed with an initial value of ``0xFFFF``.
    Algorithm from apxutil (MIT License).

    Args:
        data: Bytes to compute the checksum of
        init: Initial CRC value

    Returns:
        The 16-bit CRC
    """
    crc = init
    for b in data:
        crc = (crc >> 8) ^ _CRC16_KERMIT_TABLE[(b ^ crc) & 0xFF]
    return crc & 0xFFFF


def _parse_rte(rte: bytes, rte_type: int) -> dict[str, int | bool | None]:
    """
    Parse the RTE header that follows each APX section header.

    Only the layout for RTE type 2 is known (from apxutil). For other
    types, or if the RTE header is too short, all values are :obj:`None`.
    """
    info = dict.fromkeys(
        [
            "block_count",
            "size_minus1",
            "attributes",
            "crc16",
            "mem_area",
            "mem_folio",
            "compressed",
        ]
    )

    if rte_type != 2 or len(rte) < 15:
        return info

    block_count, size_minus1, attributes, crc16, membyte = struct.unpack_from("<IIIHB", rte)
    info.update(
        {
            "block_count": block_count,
            "size_minus1": size_minus1,
            "attributes": attributes,
            "crc16": crc16,
            "mem_area": membyte >> 3,
            "mem_folio": membyte & 0x07,
            "compressed": bool(attributes & RTE_ATTR_COMPRESSED),
        }
    )
    return info


def chunkify(blob: bytes) -> ChunksType:
    """
    Processes a raw APX file and extracts distinct chunks.

    Format details are based on apxutil by finngineering (MIT License),
    https://github.com/finngineering/apxutil

    The file starts with a 32 byte header ("APX" chunk), which defines the
    RTE type (byte 6) and the RTE header size (byte 10, 16 for RTE type 2).
    The rest of the file is sections, each made of a section header,
    an RTE header (RTE size bytes) and the section data. The section type
    is the first 2 bytes of the section header (the chunk's "tag"):

        APX:    32 byte header      Project header
        0:      8 byte header       No data
        1:      16 byte header      No data
        2:      16 byte header      Contains data (ST logic, module configs, etc.)
        3, 4:   24 byte header      No data (not observed in practice)

    The RTE header fields (attributes, crc16, mem_area, mem_folio, etc.) are
    added to section chunks, as well as whether the data is compressed and
    whether the CRC16 of the section data is valid (``crc_valid``). These
    values are :obj:`None` if unknown (e.g. RTE types other than 2) or not
    checked. The "type" of a type 2 chunk is the raw bytes of the RTE attributes.
    The "number" of a section chunk is the 4 bytes at offset 4 of its header,
    while "section_number" is the actual (2 byte) section number.

    Args:
        blob: The blob to decompress portions of

    Returns:
        The extracted chunks
    """
    chunks = {}
    i = 0
    rte_type = DEFAULT_RTE_TYPE
    rte_size = DEFAULT_RTE_SIZE

    if not isinstance(blob, bytes):
        log.warning(f"chunkify got a non-bytes blob with type {type(blob).__name__}")
        blob = bytes(blob)

    while i < len(blob):
        chunks[i] = {}

        if blob[i : i + 3] == b"APX":
            head = blob[i : i + APX_HEADER_SIZE]
            chunks[i]["tag"] = "APX"
            chunks[i]["number"] = 0
            chunks[i]["type"] = ""
            chunks[i]["head"] = head

            if len(head) >= 11:
                rte_type = head[6]
                chunks[i]["version"] = int.from_bytes(head[4:6], "little")
                chunks[i]["rte_type"] = rte_type
                chunks[i]["rte_size"] = head[10]

                if head[10] == 0:
                    log.warning(
                        f"APX header has an RTE size of 0, using the default "
                        f"of {DEFAULT_RTE_SIZE} bytes instead"
                    )
                else:
                    rte_size = head[10]

                if rte_type != 2:
                    log.warning(
                        f"APX file has RTE type {rte_type}, only type 2 is fully "
                        f"supported. Parsing may be incomplete."
                    )

            i += APX_HEADER_SIZE
            continue

        section_type = int.from_bytes(blob[i : i + 2], "little")
        if len(blob[i : i + 2]) < 2 or section_type not in SECTION_HEADER_SIZES:
            log.warning(f"Unknown chunk tag at index {i}. Terminating chunkify early.")
            break  # Quit, since we don't know what to increment by

        header_size = SECTION_HEADER_SIZES[section_type]
        rte = blob[i + header_size : i + header_size + rte_size]
        chunk = chunks[i]
        chunk["tag"] = str(section_type)
        # NOTE: "number" is kept as the 4 bytes at offset 4 for compatibility,
        # but the section number is only the first 2 bytes ("section_number")
        chunk["number"] = int.from_bytes(blob[i + 4 : i + 8], "little")
        chunk["section_number"] = int.from_bytes(blob[i + 4 : i + 6], "little")
        chunk["type"] = ""
        chunk["head"] = blob[i : i + header_size + rte_size]
        chunk.update(_parse_rte(rte, rte_type))
        chunk["crc_valid"] = None

        if section_type != 2:
            if section_type in (3, 4):
                log.debug(f"Skipping section type {section_type} at index {i}")
            i += header_size + rte_size
            continue

        length = int.from_bytes(blob[i + 10 : i + 14], "little")
        attributes = chunk["attributes"]
        if attributes is not None and attributes & RTE_ATTR_NO_DATA:
            # Per apxutil, the data size is forced to 0 if this attribute is set
            length = 0

        chunk["length"] = length
        # For RTE type 2, these are the bytes of the RTE attributes
        chunk["type"] = blob[i + header_size + 8 : i + header_size + 12]

        data_start = i + header_size + rte_size
        data = blob[data_start : data_start + length]
        if len(data) < length:
            log.warning(
                f"Section {chunk['section_number']:#06x} at index {i} is truncated "
                f"(expected {length} bytes of data, got {len(data)})"
            )

        # The CRC of the RT section covers more than its data, so it isn't checked.
        # A stored CRC of 0 means the CRC wasn't set (seen in real Quantum projects).
        if chunk["crc16"] and data and chunk["section_number"] != RT_SECTION_NUMBER:
            computed = crc16_kermit(data)
            chunk["crc_valid"] = computed == chunk["crc16"]

            if not chunk["crc_valid"]:
                log.warning(
                    f"CRC16 mismatch for section {chunk['section_number']:#06x} at "
                    f"index {i} (stored: {chunk['crc16']:#06x}, computed: "
                    f"{computed:#06x}). The section may be corrupted or modified."
                )

        chunk["data"] = extract_chunk(data, compressed=chunk["compressed"])
        i = data_start + length

    return chunks


def extract_chunk(data: bytes, compressed: bool | None = None) -> bytes:
    """
    Extract and decompress data from a chunk.

    Args:
        data: Raw section data
        compressed: If the section data is compressed, as determined by the
            RTE attributes. If :obj:`None` (unknown), the data is scanned for
            zlib and zip signatures and anything found is decompressed.
            If decompression fails when :obj:`True`, scanning is used as a fallback.

    Returns:
        The extracted data
    """
    if compressed is None:
        return _scan_decompress(data)

    if not compressed:
        if data[:4] in (b"PK\x01\x02", b"ZLIB"):
            log.debug("Uncompressed section data starts with a compression signature")
        return bytes(data)

    try:
        extracted = _decompress_section(data)
    except zlib.error as ex:
        log.debug(f"Failed to decompress section data, falling back to scanning: {ex}")
        extracted = None

    if extracted is None:
        return _scan_decompress(data)

    return extracted


def _decompress_section(data: bytes) -> bytes | None:
    """
    Decompress section data that is flagged as compressed in the RTE attributes.

    Compression formats are from apxutil (MIT License).

    Returns:
        The decompressed data, or :obj:`None` if the format isn't recognized

    Raises:
        zlib.error: If the data is malformed
    """
    # Zip/"pk": raw deflate following a zip central directory style header
    if data[:4] == b"PK\x01\x02":
        return zlib.decompressobj(-15).decompress(data[PK_HEADER_SIZE:])

    # zlib stream following a 16 byte header
    if data[:4] == b"ZLIB":
        return zlib.decompressobj().decompress(data[ZLIB_HEADER_SIZE:])

    # One or more consecutive zlib streams
    if data[:1] == b"\x78":
        extracted = bytearray()
        remaining = bytes(data)

        while remaining:
            zo = zlib.decompressobj()
            extracted.extend(zo.decompress(remaining))
            if not zo.eof:  # Truncated stream
                break
            remaining = zo.unused_data

        return bytes(extracted)

    return None


def _scan_decompress(data: bytes) -> bytes:
    """
    Extract and decompress data by scanning it for zlib and zip signatures.
    """
    extracted = bytearray()
    z_header_len = 46  # Zip header length
    i = 0

    # TODO: still needs work but it does the job
    while i < len(data):
        # Decompress zlib fields
        if b"\x78\xda" == data[i : i + 2] or b"\x78\x9c" in data[i : i + 2]:
            try:
                zo = zlib.decompressobj()
                extracted.extend(zo.decompress(data[i:]))

                if len(zo.unused_data) == 0:
                    break

                i = data.find(zo.unused_data)
            except zlib.error:
                extracted.append(data[i])
                i += 1
        # Decompress zip fields
        elif data[i : i + 4] == b"PK\x01\x02":  # PK-zip header
            i += z_header_len
            zo = zlib.decompressobj(-15)
            decomp = bytearray()
            last = -1
            end = -1

            while i < len(data):
                try:
                    decomp.extend(zo.decompress(bytes([data[i]])))
                    if data[i] == decomp[-1:]:
                        if last != i - 1:
                            end = i
                        last = i
                    i += 1
                except zlib.error:
                    break

            if len(decomp[end:]) != 0 and end != last:
                decomp = decomp[: decomp.rfind(data[end:])]
                i = end - 1

            extracted.extend(decomp)
        else:
            extracted.append(data[i])
            i += 1

    return bytes(extracted)  # bytearray -> bytes


def parse_sd_section(data: bytes) -> dict[str, int | list] | None:
    """
    Decode the memory layout from the data of the APX "SD" section (section 0x01).

    The layout is based on apxutil (MIT License) and is only partially understood.

    Args:
        data: Data of the SD section

    Returns:
        The memory layout, or :obj:`None` if it couldn't be decoded
    """
    if data[:2] != b"SD":
        log.debug("SD section data doesn't start with 'SD', skipping memory layout decode")
        return None

    try:
        mem_header_offset = struct.unpack_from("<H", data, 4)[0]
        mem_header_size, mem_area_size, mem_folio_size, mem_area_count = struct.unpack_from(
            "<HHHB", data, mem_header_offset
        )

        # Area and folio entries must at least hold the fields read from them
        if mem_area_size < 7 or mem_folio_size < 13:
            log.warning(
                f"Unexpected memory area or folio entry size in APX SD section "
                f"(area: {mem_area_size}, folio: {mem_folio_size})"
            )
            return None

        layout = {
            "data_size": struct.unpack_from("<H", data, 6)[0],
            "data_flag": struct.unpack_from("<H", data, 12)[0],
            "mem_area_count": mem_area_count,
            "mem_areas": [],
        }

        offset = mem_header_offset + mem_header_size
        for _ in range(mem_area_count):
            area_num, folio_count, area_type, area_address = struct.unpack_from(
                "<BBBI", data, offset
            )
            offset += mem_area_size

            folios = []
            for _ in range(folio_count):
                folio_num, folio_size, folio_attributes = struct.unpack_from("<BIH", data, offset)
                folios.append(
                    {
                        "folio_num": folio_num,
                        "folio_size": folio_size,
                        "folio_attributes": folio_attributes,
                        "folio_size2": struct.unpack_from("<I", data, offset + 9)[0],
                    }
                )
                offset += mem_folio_size

            layout["mem_areas"].append(
                {
                    "area_num": area_num,
                    "area_type": area_type,
                    "area_address": area_address,
                    "folio_count": folio_count,
                    "folios": folios,
                }
            )
    except struct.error as ex:
        log.warning(f"Failed to decode memory layout from APX SD section: {ex}")
        return None

    return layout


def extract_variables(chunk: bytes) -> dict[str, dict[str, int | str | bytes]]:
    """
    Extracts variables and their metadata from a chunk.
    """
    var = {}
    variables = re.finditer(
        pattern=b"\x06\x00"
        b"(?P<var_name>[\x01-\xff]+)\x00"
        b"(?P<var_type>[\x01-\xff]+)\x00\x00"
        b"(\x30\x00(?P<unk1>[\x01-\xff]{1})\x00)"
        b"(\x31\x00(?P<var_loc>[\x00-\xff]{3})\x00)?"
        b"(\x03\x00(?P<var_address>[\x20-\xff]+)\x00)?"
        b"(\x02\x00(?P<var_comment>[\x20-\xff]+)\x00)?"
        b"(\x71\x00(?P<var_custom>[\x20-\xff]+)\x00)?"
        b"((?P<unk2>[^\x06]+))?",
        string=chunk,
    )

    for v in variables:
        contents = v.groupdict()
        vals = {}

        for key, val in contents.items():
            if key == "var_loc":
                if val is None:
                    vals["location"] = 0
                else:
                    vals["location"] = int(val[::-1].hex(), 16)
            elif key == "var_name":
                pass  # We're using this for var index
            else:
                key = key.split("_")[-1]

                if val is None:
                    vals[key] = ""
                elif "unk" in key:
                    vals[key] = val
                else:
                    vals[key] = val.decode()

        var[str(contents["var_name"].decode())] = vals

    return var


def extract_initial_values(chunk: bytes) -> dict[int, int]:
    """
    Extracts variable initial values from a chunk.

    Two types of variables: coils 01, registers 00.
    Each entry can set consecutive variables in
    memory starting from the memory location.
    """
    init = {}
    i = 0

    while i < len(chunk):
        if chunk[i : i + 6] == b"\x00" * 6:
            break

        if chunk[i : i + 1] == b"\x01":
            num_coil = int(chunk[i + 1])
            loc = int(chunk[i + 2 : i + 5][::-1].hex(), 16)

            for j in range(num_coil):
                init[loc + j] = int(chunk[i + 6 + j])

            i += 6 + num_coil
        elif chunk[i : i + 1] == b"\x00":
            num_reg = int(chunk[i + 1])
            loc = int(chunk[i + 2 : i + 5][::-1].hex(), 16)

            for j in range(0, num_reg, 2):
                init[loc + j] = int(chunk[i + 6 + j : i + 6 + j + 2][::-1].hex(), 16)

            i += 6 + num_reg
        else:
            log.warning(f"Unknown initial value variable tag at index {i}")
            break

    return init


def set_init_vals(var: dict[str, dict], init: dict) -> dict[str, dict]:
    """
    Sets the initial values of extracted variables using extracted initial values.

    Args:
        var: Variables to annotate with initial values
        init: Extracted initial values to annotate variables with

    Returns:
        Variables updated to include initial values
    """
    for v in var.keys():  # noqa: PLC0206
        if var[v]["location"] in init.keys():
            if "%I" not in var[v]["address"] and "%q" not in var[v]["address"]:
                var[v]["value"] = init[var[v]["location"]]

    return var


def parse_config_to_dict(config_blob: bytes) -> dict[str, str | dict]:
    """
    Extracts configuration information from a M340 APX project file blob.

    This will return less information than pull_config does, as it does not include
    information pulled directly over the network.
    Essentially, this function is the components of pull_config
    that do not involve network access.

    Args:
        config_blob: Schneider project file

    Returns:
        A dictionary containing information parsed from the project file
    """
    log.info(f"Parsing configuration from the project file (size: {len(config_blob)} bytes)")
    device_info = {
        "status_info": {},
        "module_names": [],
    }

    project_blocks = chunkify(config_blob)
    if project_blocks in ({}, {0: {}}):
        log.error("No chunks were returned from chunkify. Config was not parsed.")
        return device_info

    for block in project_blocks.values():
        if not block:
            log.warning("Empty block")
            continue

        # Memory layout of the PLC, from the "SD" section
        if block["tag"] == "2" and block.get("section_number") == SD_SECTION_NUMBER:
            memory_layout = parse_sd_section(block["data"])
            if memory_layout:
                device_info["memory_layout"] = memory_layout

        # Get project file metadata (Name, Unity version, etc.)
        if block["type"] == b"\x00\x00\x8f\xe0" and block["number"] == 20:
            offset = 255  # Project name offset
            # Project description follows project_name, separated by a nul
            # There are then 7 nuls following before unity_version
            # name => (nul + description + 7nul) => unity_ver
            # name => (9 nul) => unity_ver
            project_metadata = re.match(
                b"\x00+(?P<project_name>[^\x00]+)"
                b"(\x00{9}|\x00(?P<project_description>[^\x00]+)\x00{7})"
                b"(?P<unity_version>[^\x00]+)\x00+"
                b"(?P<user_name>[^\x00]+)"
                b"(\x00{1,3}(?P<file_path>[^\x00]+)|\x00{3,})",
                bytes(block["data"][offset:]),
            )

            if project_metadata:
                meta = {
                    k: v.decode().strip()
                    for k, v in project_metadata.groupdict().items()
                    if isinstance(v, bytes)
                }
                device_info["project_file_metadata"] = meta
            else:
                log.warning("Could not find the project file's metadata")

        # Get status information from the project file
        # TODO: find better tag names than address and value
        if block["type"] == b"\x08\x00\x83\xe0":
            index = 4
            status = {}

            while index < len(block["data"]):
                name_len = int(block["data"][index])
                name = str(block["data"][index + 2 : index + 2 + name_len], "utf-8")
                index += 2 + name_len
                address_len = int(block["data"][index])

                if address_len != 0:
                    address = str(block["data"][index + 2 : index + 2 + address_len], "utf-8")
                else:
                    address = ""

                index += 2 + address_len + 2
                value = "0x" + bytes(block["data"][index : index + 2]).hex().upper()
                index += 2
                status[name] = {"address": address, "value": value}

                if value == b"0xFFFF":
                    break

            device_info["status_info"].update(status)

        elif block["type"] == b"\x00\x20\x8f\xe0":
            # We don't care about attributes of Diagnostic,
            # Global, Bus, or Drop elements.
            # Therefore, we skip straight to Rack element using iterfind().
            # There should only be one rack, so getting the first
            # element of the iterfind() results using next() will suffice.
            index = block["data"].find(b'<?xml version="1.0"?>')
            if index == -1:
                log.error(
                    f"Could not find XML in rack config block, skipping "
                    f"the block. Block dump:\n{pformat(block)}"
                )
                continue  # Skip to the next block

            root = ElementTree.fromstring(block["data"][index:].decode())
            # TODO: generalize to multiple racks
            rack = next(root.iterfind(".//Rack"))

            # Rack metadata
            rack_info = {}
            for k, value in rack.items():
                name = utils.convert_to_snake_case(k)
                try:
                    rack_info[name] = int(value)
                except ValueError:
                    rack_info[name] = value
            device_info["rack"] = rack_info

            # Devices (modules) in the Rack
            #   Multiple racks on a single bus (slaved to the same CPU module)
            for device in rack:
                # Determine name used as key in device_info, using rack slot #
                # Get the slot number ('Pos' in the data)
                slot = str(device.get("Pos"))
                module_name = f"module_{slot}"  # module_<slot #>

                if module_name in device_info:  # Canary if duplicates show up
                    log.warning(f"Duplicate module in rack: {module_name}")
                else:
                    device_info["module_names"].append(module_name)

                module_info = {"slot": int(slot)}

                # Device metadata
                for k, value in device.items():
                    if k == "IPAddress":
                        module_info["ipv4_address"] = str(value)
                    elif k == "Ref":
                        module_info["model_name"] = str(value)
                    elif k == "Pos":
                        pass  # Skip slot #, already set
                    elif k == "Size":
                        module_info["size"] = int(value)
                    else:
                        module_info[k.lower()] = str(value)

                # IOGroups
                io_groups = []
                for group in device:
                    # Grab all the IOGroup attributes as a dict
                    group_dict = {}
                    for k, value in dict(group.attrib).items():
                        if k in ["channel", "repeat", "size"]:
                            group_dict[k] = int(value)
                        else:
                            group_dict[k] = str(value)
                    io_groups.append(group_dict)

                module_info["io_groups"] = io_groups
                device_info[module_name] = module_info

        elif block["type"] == b"\x03\x24\xcf\xe0" and b"COMExchangeFile" in block["data"]:
            # "Communication Exchange File"
            # Basically, it is the configuration of
            # the communication modules (e.g Ethernet).
            # TODO: see what multiple modules looks like
            com_block = strip_xml(block["data"])
            device_info["network_configurations"] = {}
            parsed_network = {
                "name": com_block[0],
                "network_family_cat_key": com_block[1],
                "network_cat_key": com_block[2],
                "ntp_srv": int(com_block[4]),
                "ip_config": {
                    "ethernet_configuration": int(com_block[5]),
                    "network_configuration": int(com_block[6]),
                },
            }

            # Get IP addresses
            offset = 7
            ips = [[], [], [], [], []]

            for _ in range(4):  # Octet 1 - 4 in IP address
                for i in range(5):
                    ips[i].append(com_block[offset + i])
                offset += 5

            for i in range(5):
                ips[i] = ".".join(ips[i])

            for i, name in enumerate(["IPNetwork", "mask", "gateway"]):
                parsed_network["ip_config"][name] = ips[i]

            parsed_network["messaging_config"] = {
                "nb_line": int(com_block[offset]),
                "ctrl_ip_address": int(com_block[offset + 1]),
                "access_control": int(com_block[offset + 2]),
            }
            offset += 3

            parsed_network["snmp_config"] = {
                "IPAddressMgr1": ips[3],
                "IPAddressMgr2": ips[4],
                # Community string
                "set": com_block[offset],
                # Community string
                "get": com_block[offset + 1],
                # Community string
                "trap": com_block[offset + 2],
                # Flag (is it a manager)
                "manager": int(com_block[offset + 3]),
                # Flag (is there auth)
                "authentication": int(com_block[offset + 4]),
            }
            offset += 5

            parsed_network["bandwidth_config"] = {
                "global_data_estimation": int(com_block[offset]),
                "messaging_estimation": int(com_block[offset + 1]),
                "ethernet_env": int(com_block[offset + 2]),
            }
            offset += 3

            # TODO: see what multiple network modules looks like
            device_info["network_configurations"][parsed_network["name"]] = parsed_network

    log.debug("Finished parsing configuration from the project file")
    return device_info


def add_logic_to_tc6(logic_blocks: dict, tc6: TC6, sceptre: bool = False) -> None:
    """
    Adds the M340-specific logic portions to a TC6 instance.

    Currently, this is the variables and Structured Text.

    Args:
        logic_blocks: Logic and variables
        tc6: TC6 class instance (NOTE: this will be modified!)
        sceptre: Make the resulting logic compatible with OpenPLC/SCEPTRE PLC
    """
    # TODO: this function needs some cleanup work, lots of duplicate logic
    log.info("Adding logic and variables to TC6 tree...")

    interface = tc6.main_pou.find("interface")
    # Note: All variables must be treated as locals for OpenPLC/SCEPTRE PLC
    io_vars = SubElement(interface, "localVars")
    local_vars = SubElement(interface, "localVars")
    w_addr = 0
    x_addr = 1

    # TODO: combine data type processing logic for local and I/O variables
    if not logic_blocks["vars"]:
        log.warning("Couldn't find variables in the decompressed logic")

    for var_name, var_values in logic_blocks["vars"].items():
        var_name = str(var_name)
        is_array = False
        arr_start = 0
        arr_end = 0

        # Local variables
        if var_values["address"] == "" or "%M" in var_values["address"]:
            if "ARRAY" in var_values["type"]:
                m = re.match(r"ARRAY\[(\d+)\.\.(\d+)] OF (\w+)", var_values["type"])

                if not m:
                    log.warning(
                        f"ARRAY regex failed for local variable {var_name}, '{var_values['type']}'"
                    )
                    continue

                res = m.groups()
                arr_start = int(res[0])
                arr_end = int(res[1])

                var = SubElement(local_vars, "variable", {"name": var_name})
                var_type = SubElement(var, "type")
                arr_type = SubElement(var_type, "array")
                SubElement(arr_type, "dimension", {"lower": res[0], "upper": res[1]})
                base_type = SubElement(arr_type, "baseType")
                SubElement(base_type, get_type_string(res[2], sceptre))
                is_array = True
            else:
                type_str = get_type_string(var_values["type"], sceptre)

                if not type_str:
                    log.warning(
                        f"Skipping local variable {var_name} with "
                        f"unimplemented type '{var_values['type']}'"
                    )
                    continue

                var = SubElement(local_vars, "variable", {"name": var_name})
                var_type = SubElement(var, "type")
                SubElement(var_type, type_str)

        # I/O variables
        # TODO: implement for all IEC 61131-3 types
        # TODO: implement ARRAY types
        else:
            if var_values["type"] == "INT":
                new_addr = f"%MD{w_addr}"
                type_str = var_values["type"]

                if sceptre:
                    # OpenPLC can only use REALs
                    type_str = "REAL"

                w_addr += 1
            elif var_values["type"] in ["EBOOL", "BOOL"]:
                # NOTE: EBOOL is a Schneider custom type
                # not supported by TC6 or IEC 61131-3.
                new_addr = f"%QX0.{x_addr}"
                type_str = "BOOL"
                x_addr += 1
            else:
                log.warning(
                    f"Skipping I/O variable {var_name} with "
                    f"unimplemented type '{var_values['type']}'"
                )
                continue

            var = SubElement(io_vars, "variable", {"name": var_name, "address": new_addr})
            var_type = SubElement(var, "type")
            SubElement(var_type, type_str)

        if "value" in var_values:
            # NOTE(cegoes): XML attributes must be strings
            init_val = str(var_values["value"])

            if sceptre and var_values["type"] == "INT":
                # INTs are REALs in OpenPLC-land
                init_val = str(float(init_val))

            var_init = SubElement(var, "initialValue")
            if is_array:
                arr_val = SubElement(var_init, "arrayValue")
                for _ in range(arr_start, arr_end + 1):
                    aval_ele = SubElement(arr_val, "value")
                    SubElement(aval_ele, "simpleValue", {"value": init_val})
            else:
                SubElement(var_init, "simpleValue", {"value": init_val})

    # Add the Structured Text to the tree
    try:
        tc6.add_st_content_to_pou(tc6.main_pou, logic_blocks["ST"][0][0])
    except IndexError:
        log.warning("Couldn't find Structured Text in the decompressed logic")

    log.debug("Finished adding logic and variables to TC6 tree")


def get_type_string(var_type: str, sceptre: bool) -> str:
    if sceptre and var_type == "INT":
        # OpenPLC can only use REALs
        return "REAL"
    elif var_type in ["EBOOL", "BOOL"]:
        # NOTE: EBOOL is a Schneider custom type
        # not supported by TC6 or IEC 61131-3.
        return "BOOL"
    # Types that directly map to types usable by OpenPLC
    elif var_type in ALLOWED_TYPES:
        return var_type
    else:
        return ""
