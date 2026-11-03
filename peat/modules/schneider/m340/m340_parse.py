"""
Parsing and extraction of configuration and logic for Schneider Modicon PLCs.

Authors

- Mark Woodard
- Christopher Goes
"""

import ipaddress
import re
import zlib
from pprint import pformat
from typing import Any, Final
from xml.etree import ElementTree
from xml.etree.ElementTree import SubElement

from peat import DeviceData, log, utils
from peat.data.models import (
    ConnectionStatistics,
    Indicator,
    NetworkStatistics,
    NetworkTraffic,
    Relationship,
    RelationshipEndpoint,
    Service,
    ServiceSecurity,
    TimeSource,
)
from peat.parsing.plc_open.core_modules.definitions import TypeHierarchy_list
from peat.parsing.tc6 import TC6

ChunksType = dict[int, dict[str, int | str | bytes]]
# IEC 61131-3 types
ALLOWED_TYPES: Final[set[str]] = {type_pair[0] for type_pair in TypeHierarchy_list}

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


def chunkify(blob: bytes) -> ChunksType:
    """
    Processes a raw APX file and extracts distinct chunks.

    There are four types of chunks: APX, 0000, 0100, 0200

        APX:    Fixed length       Project header
        0000:   Fixed length       Unknown purpose
        0100:   Fixed length       Unknown purpose
        0200:   Variable length    Contains data blocks (ST logic, module configs, etc.)

    Args:
        blob: The blob to decompress portions of

    Returns:
        The extracted chunks
    """
    chunks = {}
    i = 0

    if not isinstance(blob, bytes):
        log.warning(f"chunkify got a non-bytes blob with type {type(blob).__name__}")
        blob = bytes(blob)

    while i < len(blob):
        chunks[i] = {}

        if blob[i : i + 3] == b"APX":
            chunks[i]["tag"] = "APX"
            chunks[i]["number"] = 0
            chunks[i]["type"] = ""
            chunks[i]["head"] = blob[i : i + 32]
            i += 32
        elif blob[i : i + 2] == b"\x00\x00":
            chunks[i]["tag"] = str(0)
            chunks[i]["number"] = int(blob[i + 4 : i + 8][::-1].hex(), 16)
            chunks[i]["type"] = ""
            chunks[i]["head"] = blob[i : i + 24]
            i += 24
        elif blob[i : i + 2] == b"\x01\x00":
            chunks[i]["tag"] = str(1)
            chunks[i]["number"] = int(blob[i + 4 : i + 8][::-1].hex(), 16)
            chunks[i]["type"] = ""
            chunks[i]["head"] = blob[i : i + 32]
            i += 32
        elif blob[i : i + 2] == b"\x02\x00":
            chunks[i]["tag"] = str(2)
            chunks[i]["number"] = int(blob[i + 4 : i + 8][::-1].hex(), 16)
            length = int(blob[i + 10 : i + 14][::-1].hex(), 16)
            chunks[i]["length"] = length
            chunks[i]["type"] = blob[i + 24 : i + 28]
            head = blob[i : i + 32]
            chunks[i]["head"] = head
            data = blob[i + 32 : i + 32 + length]
            chunks[i]["data"] = extract_chunk(data)
            i += 32 + length
        else:
            log.warning(f"Unknown chunk tag at index {i}. Terminating chunkify early.")
            break  # Quit, since we don't know what to increment by

    return chunks


def extract_chunk(data: bytes) -> bytes:
    """
    Extract and decompress data from a chunk.
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
            # NOTE: decode the fields, joining bytes octets into an IP string failed
            com_block = [
                x.decode("utf-8", errors="replace") if isinstance(x, bytes) else str(x)
                for x in strip_xml(block["data"])
            ]
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


# --------------------------------------------------------------------------- #
# Processing of network-pulled and project file data into the data model
# --------------------------------------------------------------------------- #

# Documented factory SNMP communities (never stored, only compared)
DEFAULT_SNMP_COMMUNITIES: Final[frozenset[str]] = frozenset({"public", "private"})

# Keys of the SNMP/FTP module dicts (m340_pull) that move to the data model
_MOVED_MODULE_KEYS: Final[tuple[str, ...]] = (
    "module_status",
    "mac_address",
    "fw_id",
    "hardware_id",
    "port_502",
    "web_server",
    "smtp_server",
)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip() if value is not None else ""


def _valid_unicast_ip(value: Any) -> str:
    """The IPv4 address as a string if it is a usable host address, else ``""``."""
    text = _text(value)
    if not text or not utils.is_ip(text):
        return ""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if addr.is_unspecified or addr.is_multicast or text == "255.255.255.255":
        return ""
    return text


def _int(value: Any) -> int | None:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def led_indicators(module_info: dict, timestamp=None) -> list[Indicator]:
    """
    LED states from the Schneider TFE MIB LED table (``led_<i>`` keys of a SNMP
    module dict from ``m340_pull._get_snmp_metadata()``) as live LED
    :class:`~peat.data.models.Indicator` readings.

    The LED state enumeration is not documented publicly, so the raw state value is
    kept in ``value`` (``state`` stays empty).
    """
    timestamp = timestamp or utils.utc_now()
    indicators = []

    for key in sorted(k for k in module_info if re.fullmatch(r"led_\d+", str(k))):
        led = module_info[key]
        if not isinstance(led, dict):
            continue
        index = int(key.partition("_")[2])
        name = _text(led.get("description", "")) or _text(led.get("name", ""))
        if not name:
            name = key
        ind = Indicator(
            type="led",
            name=name,
            position=key,
            timestamp=timestamp,
            extra={"oid_index": index},
        )
        if led.get("name") is not None and _text(led["name"]) != name:
            ind.label = _text(led["name"])
        if led.get("state") is not None:
            ind.value = _text(led["state"])
        indicators.append(ind)

    return indicators


def port_502_service(port_502: dict, timestamp=None) -> Service:
    """Port 502 messaging (Modbus/TCP) service with its SNMP counters."""
    svc = Service(protocol="modbus_tcp", port=502, transport="tcp")
    if port_502.get("service_status"):
        svc.enabled = port_502["service_status"] == "operational"
        svc.extra["service_status"] = port_502["service_status"]
    if port_502.get("supported_protocol"):
        svc.extra["supported_protocol"] = port_502["supported_protocol"]
    if port_502.get("port_security"):
        # IP access control ("enabled"/"disabled") of the Port 502 service
        svc.security.extra["access_control"] = port_502["port_security"]

    stats = NetworkStatistics(
        ingress=NetworkTraffic(messages=_int(port_502.get("total_messages_received"))),
        egress=NetworkTraffic(
            messages=_int(port_502.get("total_messages_sent")),
            errors=_int(port_502.get("total_errors_sent")),
        ),
        connections=ConnectionStatistics(max=_int(port_502.get("max_connections"))),
    )
    if stats.dict(exclude_defaults=True):
        stats.timestamp = timestamp or utils.utc_now()
        svc.statistics = stats
    return svc


def web_service(web: dict, timestamp=None) -> Service:
    """Web server (HTTP) service with its login counters and password setting."""
    svc = Service(protocol="http", port=80, transport="tcp")
    if web.get("service_status"):
        svc.enabled = web["service_status"] == "operational"
        svc.extra["service_status"] = web["service_status"]
    if web.get("password_status") == "enabled":
        svc.security.authentication_required = True
    elif web.get("password_status") == "disabled":
        svc.security.authentication_required = False

    stats = NetworkStatistics(
        connections=ConnectionStatistics(
            authentication_successes=_int(web.get("successful_attempts")),
            authentication_failures=_int(web.get("failed_attempts")),
        )
    )
    if stats.dict(exclude_defaults=True):
        stats.timestamp = timestamp or utils.utc_now()
        svc.statistics = stats
    return svc


def smtp_service(smtp: dict, timestamp=None) -> tuple[Service, Relationship | None]:
    """SMTP (e-mail) client service with its counters, and the configured mail server."""
    svc = Service(protocol="smtp", port=25, transport="tcp", role="client")
    status = smtp.get("service_status", "")
    if status:
        svc.enabled = status != "no configuration"
        svc.extra["service_status"] = status
    for key in ("last_error", "last_mail_elapsed_time", "link_service_status"):
        if smtp.get(key) not in (None, ""):
            svc.extra[key] = smtp[key]

    stats = NetworkStatistics(
        egress=NetworkTraffic(
            messages=_int(smtp.get("mail_sent_count")), errors=_int(smtp.get("error_count"))
        ),
    )
    if _int(smtp.get("server_check_fail_count")) is not None:
        # Number of times the link to the SMTP server was detected down
        stats.extra["server_check_fail_count"] = _int(smtp["server_check_fail_count"])
    if stats.dict(exclude_defaults=True):
        stats.timestamp = timestamp or utils.utc_now()
        svc.statistics = stats

    rel = None
    server = _valid_unicast_ip(smtp.get("ipv4_address"))
    if server:
        rel = Relationship(
            type="communicates_with",
            protocol="smtp",
            transport="tcp",
            direction="egress",
            local=RelationshipEndpoint(role="client"),
            remote=RelationshipEndpoint(ip=server, port=25, role="server"),
            evidence={"config"},
        )
        if smtp.get("link_service_status"):
            rel.extra["link_service_status"] = smtp["link_service_status"]
    return svc, rel


def _find_module(dev: DeviceData, module_info: dict) -> DeviceData | None:
    slot = module_info.get("slot")
    if slot is not None and str(slot) != "":
        for mod in dev.module:
            if mod.slot == str(slot):
                return mod
    product = _text(module_info.get("device", "")) or _text(module_info.get("model_name", ""))
    if product:
        for mod in dev.module:
            if mod.description.product and mod.description.product == product:
                return mod
    return None


def process_network_config(dev: DeviceData, net_config: dict) -> dict:
    """
    Process the configuration and status pulled over the network
    (``m340_pull.pull_network_config()``: SNMP, FTP ``DINF``, Modbus/TCP)
    into the data model.

    - Port 502 (Modbus/TCP), web (HTTP) and SMTP counters -> ``Service.statistics``
    - LED table -> live LED :class:`~peat.data.models.Indicator` on the module
    - module status/MAC/firmware (SNMP, ``DINF``) -> ``dev.module[slot]``

    Returns:
        The data that was not mapped, to be merged into ``dev.extra``
    """
    if not net_config:
        return {}

    timestamp = utils.utc_now()
    remaining = {}

    for key, value in net_config.items():
        if key == "firmware_version":
            continue  # in dev.firmware.version (and the SNMP module's firmware)
        if not isinstance(value, dict) or not (
            key.startswith("module_") or key.startswith("device_")
        ):
            remaining[key] = value
            continue

        module_info = dict(value)
        # module_<slot> comes from SNMP (the module running the SNMP agent)
        is_snmp_module = key.startswith("module_") and "slot" in module_info

        if module_info.get("port_502"):
            dev.store(
                "service",
                port_502_service(module_info["port_502"], timestamp),
                interface_lookup={"ip": dev.ip} if dev.ip else None,
            )
        if module_info.get("web_server"):
            dev.store(
                "service",
                web_service(module_info["web_server"], timestamp),
                interface_lookup={"ip": dev.ip} if dev.ip else None,
            )
        if module_info.get("smtp_server"):
            svc, rel = smtp_service(module_info["smtp_server"], timestamp)
            dev.store("service", svc, interface_lookup={"ip": dev.ip} if dev.ip else None)
            if rel:
                dev.store("relationships", rel)

        module = _find_module(dev, module_info)
        new_module = module is None
        if new_module:
            module = DeviceData()
            if module_info.get("slot") is not None:
                module.slot = str(module_info["slot"])
            if module_info.get("device"):
                module.description.product = _text(module_info["device"])

        if module_info.get("module_status") in ("ok", "nok"):
            module.status = module_info["module_status"]
            module.health = "normal" if module_info["module_status"] == "ok" else "failure"
        if module_info.get("mac_address") and utils.is_mac(module_info["mac_address"]):
            module.mac = module_info["mac_address"].upper()
            ip = module_info.get("configured_ipv4_address") or module.ip
            iface = dev.retrieve("interface", {"ip": ip}) if ip else None
            if iface is not None and not iface.mac:
                iface.mac = module.mac
        if module_info.get("fw_id"):
            module.firmware.id = _text(module_info["fw_id"])
        if module_info.get("hardware_id"):
            module.hardware.id = _text(module_info["hardware_id"])
        if is_snmp_module and net_config.get("firmware_version"):
            module.firmware.version = _text(net_config["firmware_version"])

        for indicator in led_indicators(module_info, timestamp):
            module.store("indicators", indicator)

        unmapped = {
            k: v
            for k, v in module_info.items()
            if k not in _MOVED_MODULE_KEYS and not re.fullmatch(r"led_\d+", str(k))
        }
        if new_module and (module.slot or module.description.product):
            dev.store("module", module, lookup="slot" if module.slot else None)
        if unmapped:
            remaining[key] = unmapped

    return remaining


def redact_snmp_communities(device_info: dict) -> None:
    """
    Remove the SNMP community strings (secrets) from the ``snmp_config`` of
    ``network_configurations`` in parsed project file data (modified in-place).
    """
    for net_conf in (device_info.get("network_configurations") or {}).values():
        if isinstance(net_conf, dict) and isinstance(net_conf.get("snmp_config"), dict):
            for community in ("set", "get", "trap"):
                net_conf["snmp_config"].pop(community, None)


# Keys of a "snmp_config" that process_project_network_config() maps to the data
# model (SNMP service security, manager relationships) or that are secrets
# (the community strings)
MAPPED_SNMP_CONFIG_KEYS: Final[tuple[str, ...]] = (
    "IPAddressMgr1",
    "IPAddressMgr2",
    "authentication",
    "get",
    "set",
    "trap",
)


def without_mapped_network_config(device_info: dict) -> dict:
    """
    Copy of parsed project file data for ``dev.extra``, without the parts of
    ``network_configurations`` that :func:`process_project_network_config` maps
    to the data model: the ``snmp_config`` keys in :data:`MAPPED_SNMP_CONFIG_KEYS`
    (SNMP service security and manager relationships) and a non-zero
    ``ntp_srv`` (``clock.sources`` or ``clock.extra``). The other settings,
    e.g. the SNMP ``manager`` flag, stay.
    """
    net_confs = device_info.get("network_configurations")
    if not isinstance(net_confs, dict):
        return device_info
    stripped = {}
    for name, net_conf in net_confs.items():
        if isinstance(net_conf, dict):
            remaining = {k: v for k, v in net_conf.items() if k not in ("snmp_config", "ntp_srv")}
            snmp = net_conf.get("snmp_config")
            if isinstance(snmp, dict):
                snmp = {k: v for k, v in snmp.items() if k not in MAPPED_SNMP_CONFIG_KEYS}
            if snmp:
                remaining["snmp_config"] = snmp
            if "ntp_srv" in net_conf and not _int(net_conf["ntp_srv"]):
                remaining["ntp_srv"] = net_conf["ntp_srv"]  # not mapped (no server)
            net_conf = remaining
        stripped[name] = net_conf
    return {**device_info, "network_configurations": stripped}


def process_project_network_config(dev: DeviceData, network_configurations: dict) -> None:
    """
    Process the communication module configuration from the project file
    (``COMExchangeFile``, ``device_info["network_configurations"]``): SNMP
    security and trap receivers, and the NTP server.

    The SNMP community strings are only compared with the documented factory
    communities, never stored.
    """
    for net_conf in (network_configurations or {}).values():
        if not isinstance(net_conf, dict):
            continue

        snmp = net_conf.get("snmp_config")
        if isinstance(snmp, dict):
            communities = [_text(snmp.get(c, "")) for c in ("get", "set")]
            security = ServiceSecurity(security_mode="v1")
            if any(c in DEFAULT_SNMP_COMMUNITIES for c in communities):
                security.default_credentials = True
            elif all(communities):
                security.default_credentials = False
            if snmp.get("authentication") is not None:
                security.extra["authentication_flag"] = _int(snmp["authentication"])

            dev.store(
                "service",
                Service(protocol="snmp", port=161, transport="udp", security=security),
                interface_lookup={"ip": dev.ip} if dev.ip else None,
            )

            # SNMP managers, which receive traps
            for mgr_key in ("IPAddressMgr1", "IPAddressMgr2"):
                manager = _valid_unicast_ip(snmp.get(mgr_key))
                if not manager:
                    continue
                dev.store(
                    "relationships",
                    Relationship(
                        type="communicates_with",
                        protocol="snmp",
                        transport="udp",
                        direction="egress",
                        remote=RelationshipEndpoint(ip=manager, port=162, role="snmp_manager"),
                        evidence={"config"},
                        extra={"setting": mgr_key},
                    ),
                )

        # "ntp_srv" is an integer: an IPv4 address in integer form when it is
        # >= 2**24 (first octet non-zero), otherwise a flag/index (kept in extra).
        ntp_srv = _int(net_conf.get("ntp_srv"))
        if ntp_srv:
            if 2**24 <= ntp_srv < 2**32:
                address = str(ipaddress.IPv4Address(ntp_srv))
                if _valid_unicast_ip(address) and not any(
                    s.protocol == "ntp" and s.address == address for s in dev.clock.sources
                ):
                    dev.clock.sources.append(TimeSource(protocol="ntp", address=address))
            else:
                dev.clock.extra["ntp_srv"] = ntp_srv
