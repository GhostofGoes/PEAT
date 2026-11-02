"""
Parsing of files from Sage RTUs.

Works with 2400 and 3030M models, and should work with others.

Authors

- Christopher Goes
- Ryan Vrecenar
"""

import re
import tarfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path, PurePath, PurePosixPath
from typing import IO, Any, Final

from peat import DeviceData, log, utils
from peat.data.models import (
    Event,
    File,
    Indicator,
    Interface,
    Package,
    Relationship,
    RelationshipEndpoint,
    Route,
    Service,
    TimeSource,
    User,
)

ElasticType = None | int | bool | str | float


def _convert_to_elastic(_input: str) -> ElasticType:
    """
    Cast input to inferred type (int, bool, None) for Elasticsearch.
    """
    try:
        return int(_input)
    except Exception:
        try:
            return float(_input)
        except Exception:
            if _input == "N":
                return False
            elif _input == "Y":
                return True
            elif _input.upper() == "NONE":
                return None
            else:
                return _input


def _store_dict_items(elem_tree: ET.Element, element_dict: dict[str, ElasticType]) -> None:
    for item in elem_tree.items():
        try:
            element_dict[item[0]] = int(item[1])
        except Exception:
            if item[1] == "N":
                element_dict[item[0]] = False
            elif item[1] == "Y":
                element_dict[item[0]] = True
            else:
                element_dict[item[0]] = item[1]


def _is_placeholder(text: str | None) -> bool:
    """
    If a configuration value is the factory placeholder (``ChangeMe``) that
    should have been replaced when the RTU was commissioned.
    """
    return bool(text) and text.strip().lower() == "changeme"


def _parse_element_into_dict(element: ET.Element, info: dict, key_map: dict) -> None:
    if element.tag in key_map and element.text and not _is_placeholder(element.text):
        info[key_map[element.tag]] = element.text.strip()


def parse_access_xml(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse users and access permissions out of ``ACCESS.XML``.
    """
    access_info = {}

    root = ET.fromstring(f_handle.read())

    access_info["users"] = []
    for user in root:
        user_info: dict[str, Any] = {
            "id": user.get("ID", ""),
        }

        if user.get("SESTIMEOUT"):
            user_info["session_timeout"] = int(user.attrib["SESTIMEOUT"])

        for elem in user:
            if elem.tag == "DESC" and elem.text:
                user_info["description"] = elem.text
            elif elem.tag == "PASSWORD" and elem.text:
                user_info["password"] = elem.text
            elif elem.tag == "ACCESS":
                user_info["permissions"] = {}
                _store_dict_items(elem, user_info["permissions"])

        access_info["users"].append(user_info)

    if not access_info["users"]:
        return

    device_info["access_info"] = access_info


def process_access_xml(dev: DeviceData, info: dict) -> None:
    """
    Process data extracted from ``ACCESS.XML`` into the PEAT device data model.
    """
    users = info["users"]
    for user_info in users:
        user = User(
            description=user_info.get("description", ""),
            id=user_info.get("id", ""),
            name=user_info.get("id", ""),
        )

        if user_info.get("session_timeout"):
            user.extra["session_timeout"] = user_info["session_timeout"]

        if user_info.get("permissions"):
            user.extra["sage_permissions"] = user_info["permissions"]
            # Add any permissions that are enabled to set of permissions for user
            # e.g. if FTP="Y", then "FTP" would be added to user.permissions
            for perm_key, perm_value in user_info["permissions"].items():
                if perm_value is True:
                    user.permissions.add(perm_key)

        dev.store("users", user)


def redact_access_info(info: dict) -> dict:
    """
    Copy of the ``ACCESS.XML`` data without the account passwords
    (``password_set`` says if one was configured).
    """
    redacted = {**info, "users": []}
    for user_info in info.get("users", []):
        user_copy = {k: v for k, v in user_info.items() if k != "password"}
        if "password" in user_info:
            user_copy["password_set"] = bool(user_info["password"])
        redacted["users"].append(user_copy)
    return redacted


def parse_rtu_setup(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``rtusetup.xml``.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    info = {}
    # Names of fields still set to the "ChangeMe" placeholder
    placeholders = []

    root = ET.fromstring(f_handle.read())

    cpu = root.findall("CPU")
    if not cpu:
        log.warning("No 'CPU' element found in rtusetup.xml")
        return
    cpu = cpu[0]

    rtu_key_map = {
        "NAME": "name",
        "APPFILE": "app_file",
        "PARTNO": "part_number",
        "HWVER": "hw_ver",
        "USERID": "user_id",
        "SERIALNUM": "serial_number",
        "MFGNAME": "manufacturer_name",
        "RUNMODE": "run_mode",
        "TYPE": "model",
    }

    rtu = cpu.findall("RTU")
    if not rtu:
        log.warning("No 'RTU' element found in rtusetup.xml")
    else:
        rtu = rtu[0]

        for elem in rtu:
            if _is_placeholder(elem.text):
                placeholders.append(f"RTU/{elem.tag}")
            _parse_element_into_dict(elem, info, rtu_key_map)

        vxworks = rtu.findall("VXWORKS")
        if not vxworks:
            log.warning("No 'VXWORKS' element found in rtusetup.xml")
        else:
            for elem in vxworks[0]:
                if _is_placeholder(elem.text):
                    placeholders.append(f"RTU/VXWORKS/{elem.tag}")
                    continue
                if not elem.text:
                    continue

                if elem.tag == "VXCREATED":
                    os_date = datetime.strptime(elem.text, "%b %d %Y")
                    info["vx_created"] = os_date.isoformat(sep="-")
                elif elem.tag == "VXVERSION":
                    info["vx_version"] = elem.text.strip()

    config_tree = cpu.findall("CONFIG")
    if not config_tree:
        log.warning("No 'CONFIG' element found in rtusetup.xml")
    else:
        for elem in config_tree[0]:
            if _is_placeholder(elem.text):
                placeholders.append(f"CONFIG/{elem.tag}")
                continue
            if not elem.text:
                continue

            if elem.tag == "NAME":
                info["config_version"] = elem.text
            elif elem.tag == "LASTDATE":
                try:
                    fw_date = datetime.strptime(elem.text, "%m-%d-%y")
                except ValueError:
                    # Date can be '19' or '2019', must handle both accordingly
                    fw_date = datetime.strptime(elem.text, "%m-%d-%Y")
                info["config_timestamp"] = fw_date.isoformat(sep="-")
            elif elem.tag == "REVISION":
                info["config_revision"] = elem.text

    if placeholders:
        info["placeholders"] = sorted(set(placeholders))

    device_info["rtusetup_info"] = info


def process_rtusetup_info(dev: DeviceData, info: dict) -> None:
    """
    Process data extracted from ``rtusetup.xml`` into the PEAT device data model.
    """
    if info.get("name"):
        dev.description.description = info["name"]
    if info.get("app_file"):
        dev.related.files.add(info["app_file"])
    if info.get("part_number") and not dev.part_number:
        dev.part_number = info["part_number"]
    if info.get("user_id"):
        dev.related.user.add(info["user_id"])
    if info.get("serial_number") and not dev.serial_number:
        dev.serial_number = info["serial_number"]
    if info.get("run_mode") and not dev.run_mode:
        dev.run_mode = info["run_mode"]
    if info.get("model") and not dev.description.model:
        dev.description.model = info["model"]
    if info.get("vx_created") and not dev.os.timestamp:
        dev.os.timestamp = utils.parse_date(info["vx_created"])


def parse_tte(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``tte.xml`` to find time trigger ethernet settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    tte_settings = {}
    root = ET.fromstring(f_handle.read())
    entry = 0

    for tte_elem in root:
        entry_iter = f"entry_{entry}"
        tte_settings[entry_iter] = {}
        for tte_item in tte_elem.items():
            if tte_item[1] != "":
                tte_settings[entry_iter][tte_item[0]] = _convert_to_elastic(tte_item[1])
        entry += 1

    tte_settings["note"] = "Time Triggered Ethernet"
    device_info["tte"] = tte_settings


def parse_time_elements(_time: ET.Element, device_info: dict) -> None:
    """
    From TIME branch in ElementTree in time, parse out version
    and date of update for OS.
    """
    time_settings = {}

    for item in _time.items():
        time_settings[item[0]] = _convert_to_elastic(item[1])

    for element in _time:
        time_settings[element.tag] = {}
        for item in element.items():
            time_settings[element.tag][item[0]] = _convert_to_elastic(item[1])

    device_info["time_settings"] = time_settings


def parse_gblfrz_elements(gblfrz: ET.Element, device_info: dict) -> None:
    """
    From GBLFRZ branch in ElementTree in time, parse out version
    and date of update for OS.
    """
    gblfrz_settings = {}

    _store_dict_items(gblfrz, gblfrz_settings)

    device_info["gblfrz_settings"] = gblfrz_settings


def parse_gps_elements(gps: ET.Element, device_info: dict) -> None:
    """
    From GPS branch in ElementTree in time, parse out version
    and date of update for OS.
    """
    gps_settings = {}

    for item in gps.items():
        gps_settings[item[0]] = _convert_to_elastic(item[1])

    device_info["gps_settings"] = gps_settings


def parse_time(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse xml tree from ``time.xml`` to find ``time``, ``gblfrz``, and ``gps`` settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    root = ET.fromstring(f_handle.read())

    _time = root.findall("TIME")[0]
    parse_time_elements(_time, device_info)

    gblfrz = root.findall("GBLFRZ")[0]
    parse_gblfrz_elements(gblfrz, device_info)

    gps = root.findall("GPS")[0]
    parse_gps_elements(gps, device_info)


def bootline_parse(bootline: str | dict) -> dict[str, str]:
    """
    Parse useful information out of vxworks bootline string,
    which is embedded in ``bootline.xml``.
    """
    if isinstance(bootline, str):
        bootline_dict = {}
        cleaned = bootline.strip().replace(",0)", ",0) ").replace("host:", "host=")
        sections = [x.strip() for x in cleaned.split(" ") if x.strip()]

        for section in sections:
            parts = section.split("=")
            bootline_dict[parts[0]] = parts[1]
    else:
        bootline_dict = bootline

    # e: ethernet ip
    # b: blackplane IP (optional)
    # h: host IP
    # g: gateway IP
    # f: flags
    # tn: target name
    # s: startup script (optional)
    # o: other
    _key_map = {
        "e": "ethernet_ip",
        "b": "backplane_ip",
        "h": "host_ip",
        "g": "gateway_ip",
        "f": "flags",
        "tn": "target_name",
        "s": "startup_script",
        "o": "other",
    }

    info = {}

    for key, value in bootline_dict.items():
        if key in _key_map:
            key = _key_map[key]
        info[key] = _convert_to_elastic(value)

    # Handle if in format "192.0.2.1:ffffff00"
    for e_key in ["ethernet", "backplane", "host", "gateway"]:
        if ":" in info.get(f"{e_key}_ip", ""):
            ip, subnet_mask = _parse_eth_str(info[f"{e_key}_ip"])
            info[f"{e_key}_ip"] = ip
            info[f"{e_key}_subnet_mask"] = subnet_mask

    return info


def _parse_eth_str(eth_val: str) -> tuple[str, str]:
    """
    Parse string format "IP:Subnet", with the subnet being hex-encoded.
    Example: ``"192.0.2.1:ffffff00"``
    """
    ip = eth_val[: eth_val.index(":")]

    h_subnet = eth_val[eth_val.index(":") + 1 :]
    subnet_bytes = (h_subnet[0:2], h_subnet[2:4], h_subnet[4:6], h_subnet[6:8])
    subnet_mask = ".".join([f"{int(n, 16)}" for n in subnet_bytes])

    return ip, subnet_mask


def parse_bootline_xml(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``bootline.xml`` to find boot options including default
    IP address, location of operating system, hostname, username and password.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    root = ET.fromstring(f_handle.read())
    bootline = root.findall("BOOTLINE")[0]
    device_info["bootline_from_xml"] = bootline_parse(bootline.attrib)


def process_bootline(dev: DeviceData, data: dict[str, str]) -> None:
    """
    Process data extracted from VxWorks bootline into the PEAT device data model.
    """
    boot_file = data.get("file")
    if not boot_file and data.get("host") and "/" in data["host"]:
        boot_file = data["host"]

    if boot_file:
        b_path = PurePosixPath(boot_file)
        dev.related.files.add(str(b_path))
        dev.firmware.file.path = b_path
        dev.firmware.file.directory = str(b_path.parent)
        dev.firmware.file.name = b_path.name
        dev.firmware.file.type = "file"

    if data.get("ethernet_ip") and utils.is_ip(data["ethernet_ip"]):
        dev.related.ip.add(data["ethernet_ip"])

        iface = dev.retrieve("interface", {"ip": data["ethernet_ip"]})

        if not iface:
            iface = Interface(
                ip=data["ethernet_ip"],
                subnet_mask=data.get("ethernet_subnet_mask", ""),
                gateway=data.get("gateway_ip", ""),
                type="ethernet",
            )
            dev.store("interface", iface, lookup="ip")
        else:
            if not iface.subnet_mask and data.get("ethernet_subnet_mask"):
                iface.subnet_mask = data["ethernet_subnet_mask"]
            if not iface.gateway and data.get("gateway_ip") and utils.is_ip(data["gateway_ip"]):
                iface.gateway = data["gateway_ip"]

    if data.get("backplane_ip"):
        dev.related.ip.add(data["backplane_ip"])

    if data.get("host_ip") and utils.is_ip(data["host_ip"]):
        dev.related.ip.add(data["host_ip"])

    if data.get("gateway_ip") and utils.is_ip(data["gateway_ip"]):
        dev.related.ip.add(data["gateway_ip"])
        # The boot line gateway ("g=") is the default gateway of the network stack
        dev.store(
            "routes",
            Route(
                destination="0.0.0.0/0",
                gateway=data["gateway_ip"],
                type="static",
                description="VxWorks boot line gateway (g=)",
            ),
        )

    if data.get("raw_bootline"):
        dev.firmware.extra["bootline"] = data["raw_bootline"]


def parse_ether(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``ethernet.xml`` to find route settings and
    ethernet port settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    ether_settings = {}
    root = ET.fromstring(f_handle.read())

    for entry, ether_elem in enumerate(root):
        ether_iter = f"entry_{entry}"
        ether_settings[ether_iter] = {}

        # Save ethernet parameters including ID, Name, etc. Never the password
        # (a secret): only if one is set.
        for item in ether_elem.items():
            if item[0].lower() == "password":
                ether_settings[ether_iter]["password_set"] = bool(item[1])
                continue
            ether_settings[ether_iter][item[0]] = item[1]

        # Save Routes
        routes_elem = ether_elem.findall("ROUTES")
        if not routes_elem:
            log.warning("Failed to find 'ROUTES' element in ether_elem")
            continue

        for route in routes_elem[0]:
            route_fields = route.items()
            if not route_fields:
                continue

            # Route_ID uses first route field which is value of ID
            route_id = route_fields[0][1]

            # One dict per route (a single shared dict made every
            # route a copy of the last one)
            routes_settings = {}
            for field in route_fields[1:]:
                routes_settings[field[0]] = _convert_to_elastic(field[1])

            ether_settings[ether_iter][f"route_{route_id}"] = routes_settings

    device_info["ethernet"] = ether_settings


def parse_firewall_rule(firewall_line: str, firewall_rule: dict) -> None:
    delimiters = "block in ", "from ", " to ", " port = "
    regex_pattern = "|".join(map(re.escape, delimiters))

    # Split on grammar, drop null first byte
    firewall_syntax = re.split(regex_pattern, firewall_line)[1:]
    proto = firewall_syntax[0].rstrip() if not firewall_syntax[0] == "" else None

    firewall_rule["protocol"] = proto
    firewall_rule["from_cdir"] = firewall_syntax[1]
    firewall_rule["to_cdir"] = firewall_syntax[2]

    # Hard coded assumption, port = is last term
    if "port = " in firewall_line:
        firewall_rule["port"] = firewall_syntax[-1]


def parse_firewall(f_handle: IO[bytes], device_info: dict) -> None:
    firewall_rules = {}
    lines = f_handle.read().decode("utf-8")

    i = 0
    for line in lines.split("\n"):
        # Remove comments from firewall rules
        if len(line.lstrip()) > 1 and line.lstrip()[0] != "#" and line.lstrip()[0:2] != "//":
            i += 1
            firewall_rules[f"entry_{i}"] = {}
            firewall_entry = firewall_rules[f"entry_{i}"]
            firewall_entry["original_rule"] = line
            firewall_entry["semantic_rule"] = {}
            parse_firewall_rule(line, firewall_entry["semantic_rule"])
        else:
            continue

    device_info["firewall_settings"] = firewall_rules


def parse_isagraf(f_handle: IO[bytes], device_info: dict) -> None:
    isagraf_data = f_handle.read().decode("utf-8")
    isagraf_version = isagraf_data.split(" ")[1]

    device_info["isagraf"] = {}
    device_info["isagraf"]["version"] = isagraf_version.rstrip()
    device_info["isagraf"]["note"] = "Soft Logic Controller, including runtime, and dev tools"


def parse_startup_script(f_handle: IO[bytes], device_info: dict) -> None:
    script_data = f_handle.read().decode("utf-8")
    device_info["startup_script"] = script_data


def parse_vxworks_script(f_handle: IO[bytes], device_info: dict) -> None:
    script_data = f_handle.read().decode("utf-8")
    device_info["vxworks_script"] = script_data


def parse_private_key(f_handle: IO[bytes], device_info: dict) -> None:
    key_data = f_handle.read().decode("utf-8")
    device_info["server_private_key"] = key_data


def parse_certificate(f_handle: IO[bytes], device_info: dict) -> None:
    cert_data = f_handle.read().decode("utf-8")
    device_info["server_certificate"] = cert_data


def parse_ike_config(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ike_data = ""
    lines = f_handle.read().decode("utf-8")

    for line in lines.split("\n"):
        # Remove comments from firewall rules
        if len(line.lstrip()) > 0 and not line.lstrip()[0] == "#":
            ike_data += line

    device_info["ike"]["config"] = ike_data


def parse_ike_ca(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ca_data = f_handle.read().decode("utf-8")
    device_info["ike"]["telvent_cert_auth"] = ca_data


def parse_ike_privkey(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ca_data = f_handle.read().decode("utf-8")
    device_info["ike"]["privkey"] = ca_data


def parse_ike_cert(f_handle: IO[bytes], device_info: dict) -> None:
    if "ike" not in device_info:
        device_info["ike"] = {}

    ca_data = f_handle.read().decode("utf-8")
    device_info["ike"]["cert"] = ca_data


def parse_port_comm_settings(proto: ET.Element, port_settings: dict[str, ElasticType]) -> None:
    comms = proto.findall("COMM")[0]
    comm_settings = {}

    _store_dict_items(comms, comm_settings)

    port_settings["comm_settings"] = comm_settings


def parse_port_proto_settings(
    proto_name: str, proto: ET.Element, port_settings: dict[str, ElasticType]
) -> None:
    protocol_field = proto.findall(proto_name)[0]
    _store_dict_items(protocol_field, port_settings["protocol"])

    for child in protocol_field:
        _store_dict_items(child, port_settings["protocol"])

    # TODO
    """
    protocol_params = protocol_field.findall('AO_MAP')[0]
    store_dict_items(protocol_params, port_settings['protocol'])

    protocol_params = protocol_field.findall('AI_MAP')[0]
    store_dict_items(protocol_params, port_settings['protocol'])
    """


def parse_port(f_handle: IO[bytes], device_info: dict) -> None:
    if "ports" not in device_info:
        device_info["ports"] = {}

    port_settings = {}

    port = ET.fromstring(f_handle.read())
    proto = port.findall("PROTOCOL")[0]

    for item in port.items():
        if not item[0] == "VER" and not item[0] == "PNT":
            port_settings[item[0]] = item[1]
        elif item[0] == "PNT":
            port_name = item[1]

    for item in proto.items():
        if item[0] == "TYPE":
            if not item[1] == "NONE":
                port_settings["protocol"] = {}
                port_settings["protocol"]["name"] = item[1]
                parse_port_comm_settings(proto, port_settings)
                parse_port_proto_settings(item[1], proto, port_settings)
            else:
                port_settings["protocol"] = None

    device_info["ports"][f"port_{port_name}"] = port_settings


def parse_features(f_handle: IO[bytes], device_info: dict) -> None:
    features = ET.fromstring(f_handle.read())
    protocols = features.findall("PROTOCOLS")[0]

    device_info["feature_protocols"] = {}
    for proto in protocols:
        device_info["feature_protocols"][proto.text] = {}
        for item in proto.items():
            device_info["feature_protocols"][proto.text][item[0]] = _convert_to_elastic(item[1])


def parse_3835(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    c3835 = root.findall("C3835")
    cards = {}

    for i in c3835:
        # Set key for cards dict
        devid = ""
        card = {}

        for item in i.items():
            if item[0] == "DEVID":
                devid = item[1]
            else:
                card[item[0]] = _convert_to_elastic(item[1])

        cards[devid] = card

    device_info["c3835"] = cards


def parse_dcana(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    dcana_settings = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            grandchild_dict = {}
            for item in grandchild.items():
                if item[0] == "PNT":
                    key = item[1]
                else:
                    grandchild_dict[item[0]] = _convert_to_elastic(item[1])
                child_dict[key] = grandchild_dict

        dcana_settings[child.tag] = child_dict

    device_info["dcana_settings"] = dcana_settings


def parse_calc(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    calc = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

            for grand_child in child:
                grand_child_dict = {}

                # Traverse children scope and append to dictionary
                key = ""
                for item in grand_child.items():
                    if item[0] == "PN":
                        key = item[1]
                    else:
                        grand_child_dict[item[0]] = _convert_to_elastic(item[1])
                    if key != "":
                        child_dict[key] = grand_child_dict

        calc[child.tag] = child_dict

    device_info["calc"] = calc


def parse_rtu_sts(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    rtu_settings = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

            for grand_child in child:
                grand_child_dict = {}
                for item in grand_child.items():
                    if item[0] == "PNT":
                        key = item[1]
                    else:
                        grand_child_dict[item[0]] = _convert_to_elastic(item[1])
                    child_dict[key] = grand_child_dict

        rtu_settings[child.tag] = child_dict

    device_info["rtu_settings"] = rtu_settings


def parse_timing(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    timing_settings = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        timing_settings[child.tag] = child_dict

    device_info["timing_parameters"] = timing_settings


def parse_sfb(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    sfb_cards = {}

    for child in root:
        devid = child.items()[0]
        sfb_type = child.items()[1]

        child_dict = {}
        child_dict[sfb_type[0]] = _convert_to_elastic(sfb_type[1])
        sfb_cards[devid[1]] = child_dict

    device_info["sfb_cards"] = sfb_cards


def parse_acc_rate(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    acc_param = root.findall("ACC_PARAM")

    acc_rate = {}
    for device in acc_param:
        device_acc_param = {}
        for item in device.items():
            if item[0] == "DEVID":
                key = f"DevID_{item[1]}"
            else:
                device_acc_param[item[0]] = _convert_to_elastic(item[1])
        acc_rate[key] = device_acc_param

    device_info["acc_param"] = acc_rate


def parse_alarming(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    alarm_child = root.findall("ALARMS")[0]

    alarms = {}
    for item in alarm_child.items():
        alarms[item[0]] = _convert_to_elastic(item[1])

    for map_child in alarm_child:
        for item in map_child.items():
            alarms[f"{map_child.tag}_{item[0]}"] = _convert_to_elastic(item[1])

    device_info["alarming"] = alarms


def parse_alarms(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    alarm_child = root.findall("ALARMS")[0]

    alarms = {}
    for device in alarm_child:
        alarm_pnt = {}
        for item in device.items():
            if item[0] == "PNT":
                key = item[1]
            else:
                alarm_pnt[item[0]] = _convert_to_elastic(item[1])
        alarms[key] = alarm_pnt

    device_info["alarms"] = alarms


def parse_almdev(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    dev_attrb = root.findall("DEVICE_ATTRIBUTES")[0]
    almdev = {}

    for child in dev_attrb:
        attribute = {}
        for item in child.items():
            attribute[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            for item in grandchild.items():
                attribute[item[0]] = _convert_to_elastic(item[1])

        almdev[child.tag] = attribute

    device_info["almdev"] = almdev


def parse_bbdi(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    bbdi = {}

    for item in root.items():
        bbdi[item[0]] = _convert_to_elastic(item[1])

    points = root.findall("POINTS")[0]

    for child in points:
        point = {}
        point_items = child.items()
        key = ""

        for item in point_items:
            if item[0] == "PNT":
                key = item[1]

        for item in point_items:
            if item[0] != "PNT":
                point[item[0]] = _convert_to_elastic(item[1])

        bbdi[key] = point

    device_info["bbdi"] = bbdi


def parse_cbc(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    cbc = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            grandchild_dict = {}
            for item in grandchild.items():
                if item[0] == "PNT" or item[0] == "NUM":
                    key = item[1]
                else:
                    grandchild_dict[item[0]] = _convert_to_elastic(item[1])
                child_dict[key] = grandchild_dict

        cbc[child.tag] = child_dict

    device_info["cbc_config"] = cbc


def parse_ast(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    ast = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            grandchild_dict = {}

            for item in grandchild.items():
                if item[0] == "PNT" or item[0] == "NUM":
                    key = item[1]
                else:
                    grandchild_dict[item[0]] = _convert_to_elastic(item[1])
                child_dict[key] = grandchild_dict

            for ggchild in grandchild:
                ggchild_dict = {}
                for item in ggchild.items():
                    if item[0] == "PNT" or item[0] == "NUM":
                        gkey = item[1]
                    else:
                        ggchild_dict[item[0]] = _convert_to_elastic(item[1])
                    child_dict[f"{grandchild.tag}_{gkey}"] = ggchild_dict

        ast[child.tag] = child_dict

    device_info["ast_config"] = ast


def parse_anunctor(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    annunciator = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            gchild_items = grandchild.items()
            child_dict[gchild_items[0][1]] = _convert_to_elastic(gchild_items[1][1])
        annunciator[child.tag] = child_dict

    device_info["annunciator"] = annunciator


def parse_com_assignments(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    com_assignments = {}

    for port in root:
        port_items = port.items()
        # First entry is Num
        key = port_items[0][1]

        child_dict = {}
        for item in port_items[1:]:
            child_dict[item[0]] = _convert_to_elastic(item[1])
        com_assignments[f"port_{key}"] = child_dict

    device_info["com_assignments"] = com_assignments


def parse_sprcodes(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    spr_codes = {}

    for spr_code in root:
        spr_items = spr_code.items()

        # First entry is PNT
        key = spr_items[0][1]
        spr_codes[key] = _convert_to_elastic(spr_items[1][1])

    device_info["spr_code_map"] = spr_codes


def parse_leds(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    leds = {}

    for child in root:
        led_dict = {}

        for grandchild in child:
            gchild_items = grandchild.items()
            key = gchild_items[0][1]
            led_dict[key] = {}
            for item in gchild_items[1:]:
                led_dict[key][item[0]] = _convert_to_elastic(item[1])
        leds[child.tag] = led_dict

    device_info["leds"] = leds


def parse_relays(f_handle: IO[bytes], device_info: dict) -> None:
    # TODO: may be losing items from Relay tree, double check from config again
    root = ET.fromstring(f_handle.read())
    relay_tree = root.findall("RELAYS")[0]
    relays = {}

    for child in relay_tree:
        relay_dict = {}
        child_items = child.items()
        key = child_items[0][1]

        for item in child_items[1:]:
            relay_dict[item[0]] = _convert_to_elastic(item[1])

        relays[key] = relay_dict

    device_info["relays"] = relays


def parse_nrgcalc(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())

    nrgcalc_tree = root.findall("NRGCALC_PARAM")[0]
    nrgcalcs = {}
    nrgcalcs["note"] = "Energy Calc Parameters"

    # Set top level fields
    for item in nrgcalc_tree.items():
        nrgcalcs[item[0]] = _convert_to_elastic(item[1])

    for child in nrgcalc_tree:
        child_dict = {}
        child_items = child.items()

        if child.tag == "DI_LIST":
            for grandchild in child:
                gc_dict = {}
                gc_items = grandchild.items()
                key = gc_items[0][1]

                for item in gc_items[1:]:
                    gc_dict[item[0]] = _convert_to_elastic(item[1])

                nrgcalcs[f"di_list_{key}"] = gc_dict
        else:
            key = child_items[0][1]
            for item in child_items[1:]:
                child_dict[item[0]] = _convert_to_elastic(item[1])

            ais = []
            for grandchild in child:
                gc_dict = {}
                gc_items = grandchild.items()

                for item in gc_items:
                    gc_dict[item[0]] = _convert_to_elastic(item[1])

                ais.append(gc_dict)

            child_dict["ais"] = ais
            nrgcalcs[key] = child_dict

    device_info["nrgcalc_settings"] = nrgcalcs


def parse_bbrelay(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for grandchild in child:
            gchild_dict = {}
            gchild_items = grandchild.items()
            key = gchild_items[0][1]

            for item in gchild_items[1:]:
                gchild_dict[item[0]] = _convert_to_elastic(item[1])

            child_dict[f"bb_{key}"] = gchild_dict

    device_info["bb_relays"] = child_dict


def parse_btstconf(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    btests = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for gchild in child:
            gchild_dict = {}
            for element in gchild:
                elem_dict = {}
                items = element.items()
                key = items[0][1]

                for item in items[1:]:
                    elem_dict[item[0]] = _convert_to_elastic(item[1])
                gchild_dict[key] = elem_dict

            child_dict[gchild.tag] = gchild_dict

        btests[child.tag] = child_dict

    device_info["btest_config"] = btests


def parse_aci(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())

    fmr = root.findall("FMR")[0]
    fmr_dict = {}
    fmr_dict["note"] = "Oracle/Cisco ATG Customer Intellegence?"

    for item in fmr.items():
        fmr_dict[item[0]] = _convert_to_elastic(item[1])

    device_info["aci_db"] = fmr_dict


def parse_aci1250(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    aci = {}

    for child in root:
        child_dict = {}
        for item in child.items():
            child_dict[item[0]] = _convert_to_elastic(item[1])

        for gchild in child:
            gchild_dict = {}

            for item in gchild.items():
                gchild_dict[item[0]] = _convert_to_elastic(item[1])

            for element in gchild:
                items = element.items()
                for item in items:
                    gchild_dict[item[0]] = _convert_to_elastic(item[1])

                if element.tag == "SENSOR":
                    for sensor in element:
                        elem_dict = {}

                        sensor_items = sensor.items()
                        skey = sensor_items[0][1]

                        for item in sensor_items[1:]:
                            elem_dict[item[0]] = _convert_to_elastic(item[1])

                        gchild_dict[f"sensor {skey}"] = elem_dict

            child_dict[gchild.tag] = gchild_dict

        aci[child.tag] = child_dict

    device_info["aci1250_config"] = aci


def parse_userlog_settings_xml(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse XML tree from ``userlog.xml`` to find logging settings.

    Args:
        f_handle: file handler to read data from and parse xml
        device_info: dictionary of keys and values for target device
    """
    userlog_settings = {}
    root = ET.fromstring(f_handle.read())

    userlog = root.findall("USRLOG_PARAM")[0]
    for item in userlog.items():
        if item[0] == "TASK_ENABLED":
            userlog_settings["userlog_enabled"] = _convert_to_elastic(item[1])
        elif item[0] == "NUM_EVENTS":
            userlog_settings["userlog_num_events"] = _convert_to_elastic(item[1])

    device_info["userlog_settings"] = userlog_settings


def parse_cmdlog_settings_xml(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    cmdlog_settings = {}

    for child in root:
        for item in child.items():
            cmdlog_settings[item[0]] = _convert_to_elastic(item[1])

    device_info["cmdlog_settings"] = cmdlog_settings


def parse_soelog_settings_xml(f_handle: IO[bytes], device_info: dict) -> None:
    root = ET.fromstring(f_handle.read())
    soelog_settings = {}

    for child in root:
        for item in child.items():
            soelog_settings[item[0]] = _convert_to_elastic(item[1])

    device_info["soelog_settings"] = soelog_settings


def parse_ipcom_syslog(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse ``syslog`` and ``syslog.0`` files from ``ipcom/`` directory on the Sage.
    """
    # TODO: unit test
    data = f_handle.read().decode()
    events = []
    lines = [x.strip() for x in data.strip().splitlines() if x.strip()]

    for line in lines:
        parts = [x.strip() for x in line.split(": ") if x.strip()]

        event = {
            "timestamp": parts[0],
            "raw_task": parts[1],
            # "iptelnets" which is actually "ipcom_telnetspawn" in task list
            # However, the Task ID here actually resolves to ipcom_telnetd
            "short_task_name": parts[1].split("[")[0],
            "task_id": parts[1].split("[")[1].split("]")[0],
            "level": parts[2],
            "service_name": parts[3].replace(":", "").strip(),
            "message": ": ".join(parts[4:]),
            "original": line,
        }

        events.append(event)

    if not device_info.get("ipcom_syslog_events"):
        device_info["ipcom_syslog_events"] = []

    device_info["ipcom_syslog_events"].extend(events)


def process_ipcom_syslog(dev: DeviceData, events: list[dict]) -> None:
    """
    Process parsed ``ipcom/syslog`` events into the PEAT device data model.
    """
    for e_dict in events:
        event = Event(
            category={"network", "process", "session"},
            created=utils.parse_date(e_dict["timestamp"]),
            dataset="ipcom_syslog",
            kind={"event"},
            message=e_dict["message"],
            module="Sage",
            original=e_dict["original"],
            outcome="failure" if "error" in e_dict["level"].lower() else "unknown",
            provider=dev.ip,
            type={"connection"},
            log_level=e_dict["level"].lower(),
            extra={
                "raw_task": e_dict["raw_task"],
                "short_task_name": e_dict["short_task_name"],
                "task_id": e_dict["task_id"],
                "service_name": e_dict["service_name"],
            },
        )

        if "error" in e_dict["level"].lower():
            event.type.add("error")
        if "ipcom_accept" in event.message:
            event.type.add("access")

        dev.store("event", event)


def parse_logfiles(f_handle: IO[bytes], device_info: dict) -> None:
    """
    Parse the contents of ``SYSLOG.LOG``, ``USERLOG.LOG``, and ``soelog.txt``.

    This creates a list of dicts with structured event information.

    Known locations of logfiles:

    - ``/ata0a/Webfiles/LOGS/SYSLOG.LOG``
    - ``/ata0a/Webfiles/LOGS/USERLOG.LOG``
    - ``/ramDrv/soelog.txt``
    """
    data = f_handle.read().decode()

    # Replace NUL characters with spaces
    data = re.sub("[\x00]", " ", data)

    lines = [x.strip() for x in data.strip().splitlines() if x.strip()]

    # First line with "NextSlot" can be ignored.
    if "NextSlot" in lines[0]:
        lines = lines[1:]

    # SYSLOG.LOG has events across two separate lines
    if "DT=" not in data:
        lines = ["\n".join(x) for x in zip(lines[0::2], lines[1::2], strict=False)]

    events = []

    for raw_line in lines:
        # USERLOG.LOG, soelog.txt
        if raw_line.startswith("<REC"):
            # ID: identifier? NOTE: these are NOT sequential by time
            # DT: date. Ex: 01/01/2025
            # TM: time. Ex: 00:00:00.000

            # USERLOG.LOG: ID, DT, TM, TYPE, TXT
            #   TYPE: "Logged Out"
            #   TXT: "192.0.2.20-FTP, Admin"

            # soelog.txt: ID, DT, TM, VAL, PN, DN
            #   VAL: "0" or "1"
            #   PN: "MAX LOGIN FAILURES EXCEEDED"
            #   DN: "RTU Internal Status"

            line_tag = ET.fromstring(raw_line)
            pairs = {k.strip(): v.strip() for k, v in line_tag.attrib.items()}

            event = {
                "timestamp": f"{pairs['DT']} {pairs['TM']}",
                # NOTE: the events in the file are not listed in order of sequence!
                # HOWEVER, the ID= field is an integer that IS a proper ordered sequence.
                "id": int(pairs["ID"]),
                "original": raw_line,
                "extra": {},
            }

            # USERLOG.LOG
            if pairs.get("TYPE"):
                event["message"] = f"{pairs['TYPE']} {pairs['TXT']}"
                event["log_type"] = pairs["TYPE"]
                event["reason"] = pairs.get("TXT", "")

                # logged in => 192.0.2.1-TSHELL, Admin, LCL_DB
                # logged out => 192.0.2.1-TSHELL, Admin
                # logged in => 192.0.2.1-FTP, Admin, LCL_DB
                # logged out => 192.0.2.1-FTP, Admin
                if "logged" in pairs["TYPE"].lower() and pairs["TXT"].count(".") >= 3:
                    dash_parts = pairs["TXT"].partition("-")
                    event["extra"]["ip"] = dash_parts[0].strip()
                    comma_parts = dash_parts[2].split(",")
                    event["extra"]["service"] = comma_parts[0].strip()
                    if event["extra"]["service"] == "TSHELL":
                        event["extra"]["service"] = "Telnet"
                    event["extra"]["user"] = comma_parts[1].strip()
                # Power Up => RTU Started Up, Mode: NORMAL
                elif "Mode:" in pairs["TXT"]:
                    event["extra"]["mode"] = pairs["TXT"].split("Mode:")[1].strip()

            # soelog.txt
            if pairs.get("VAL"):
                event["extra"]["VAL"] = int(pairs["VAL"])
                event["message"] = pairs["PN"]
                # Point name of the status point that changed state
                event["reason"] = pairs["PN"]
                # 1 = point set (asserted), 0 = point cleared
                if event["extra"]["VAL"] == 1:
                    event["action"] = "set"
                elif event["extra"]["VAL"] == 0:
                    event["action"] = "clear"
                # This seems to always be "RTU Internal Status"
                event["extra"]["DN"] = pairs["DN"]
                if pairs["DN"] != "RTU Internal Status":
                    event["message"] += " " + pairs["DN"]

        # SYSLOG.LOG
        else:
            line = re.sub(r" {2,}", " ", raw_line).strip()

            chunks = line.split("\n")
            m_parts = chunks[0].strip().split(" ")

            event = {
                "id": int(m_parts[0]),
                "timestamp": " ".join(m_parts[1:2]),
                "message": chunks[1].strip(),
                "original": raw_line,
                "extra": {
                    # This seems to always be "startup"
                    "stage": m_parts[3],
                    # "GPST task"
                    # "m1_uif"
                    # "startup"
                    # "inCrashMode"
                    "task": " ".join(m_parts[4:]),
                },
            }

        events.append(event)

    # TODO: return a list instead of mutating device_info
    if not device_info.get("raw_events"):
        device_info["raw_events"] = []

    device_info["raw_events"].extend(events)


def process_logfile_events(dev: DeviceData, events: list[dict]) -> None:
    for e_dict in events:
        event = Event(
            action=e_dict.get("action", ""),
            created=utils.parse_date(e_dict["timestamp"]),
            dataset="logfiles",
            kind={"event"},
            message=e_dict["message"],
            module="Sage",
            original=e_dict["original"],
            provider=dev.ip,
            reason=e_dict.get("reason", ""),
            sequence=e_dict["id"],
            extra={**e_dict["extra"]},
        )

        if e_dict.get("log_type"):  # USERLOG.LOG
            event.dataset = "userlog"
        elif event.extra.get("DN"):  # soelog.txt
            event.dataset = "soelog"
        elif event.extra.get("stage"):  # SYSLOG.LOG
            event.dataset = "syslog_file"
        else:  # shouldn't ever hit this branch
            event.dataset = "unknown_log_file"

        lower_msg = event.original.lower()

        if e_dict.get("log_type"):
            e_type = e_dict["log_type"].lower()

            event.action = e_type.replace(" ", "-")

            if "power" in e_type:
                event.category.add("host")
                event.type.add("start")

            elif e_type.startswith("logged"):
                event.category.add("authentication")
                event.category.add("session")
                event.outcome = "success"
                event.type.add("access")

                if "logged in" in e_type:
                    event.type.add("start")
                elif "logged out" in e_type:
                    event.type.add("end")

        # NOTE: rtu_sts.xml lists the possible event strings for soelog.txt

        if "logged in" in lower_msg:
            event.outcome = "success"

        if "login" in lower_msg or "logged in" in lower_msg:
            event.category.add("authentication")
            event.type.add("access")

        if "login failure" in lower_msg:
            event.type.add("denied")

        # "LOGIN FAILURE"
        # "TIME SRC FAIL"
        if "failure" in lower_msg or "fail " in lower_msg:
            event.outcome = "failure"

        if "startup" in event.original.lower() or "started up" in event.original.lower():
            event.type.add("start")

        if event.extra.get("ip"):
            dev.related.ip.add(event.extra["ip"])
            dev.related.user.add(event.extra["user"])
            event.category.add("network")
            event.type.add("access")
            event.type.add("connection")

        dev.store("event", event)


# --------------------------------------------------------------------------- #
# Processing of parsed configuration into the data model
#
# NOTE: there are no public samples of the Sage XML configuration files. The
# attribute names of routes (ethernet.xml), time settings (time.xml), LEDs
# (leds.xml) and serial ports (xml/port*.xml) are matched by label (substring
# of the attribute name), and values are validated before use. Attributes that
# are not recognized are kept in the "extra" fields, and the full parsed data
# stays in "parsed-config.json".
# --------------------------------------------------------------------------- #


def _find_attr(
    attrs: dict, needles: tuple[str, ...], exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    """
    Find the first attribute whose (uppercase) name contains one of ``needles``
    and none of ``exclude``, with a non-empty value.

    Returns:
        Tuple of ``(attribute name, value)``, or ``("", None)`` if not found
    """
    for key, value in attrs.items():
        u_key = str(key).upper()
        if any(n in u_key for n in needles) and not any(x in u_key for x in exclude):
            if value is not None and value != "" and not isinstance(value, dict):
                return key, value
    return "", None


def _flag(value: Any) -> bool | None:
    """Convert a parsed flag (``True``/``False``, ``Y``/``N``, ``1``/``0``) to a bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().upper() in ("Y", "YES", "TRUE", "ON", "ENABLED"):
        return True
    if isinstance(value, str) and value.strip().upper() in ("N", "NO", "FALSE", "OFF", "DISABLED"):
        return False
    return None


def routes_from_ethernet(ether_settings: dict) -> list[Route]:
    """
    Convert the routes parsed from ``ethernet.xml`` (``device_info["ethernet"]``,
    see :func:`parse_ether`) into :class:`~peat.data.models.Route` objects.

    Routes without a recognizable destination are skipped.
    """
    routes = []

    for entry in ether_settings.values():
        if not isinstance(entry, dict):
            continue

        for key, attrs in entry.items():
            if not key.startswith("route_") or not isinstance(attrs, dict):
                continue

            used = set()
            dest_key, dest = _find_attr(
                attrs, ("DEST", "NET", "TARGET", "ADDR"), ("MASK", "GATE", "GW", "HOP")
            )
            mask_key, mask = _find_attr(attrs, ("MASK",))
            gw_key, gateway = _find_attr(attrs, ("GATE", "GW", "ROUTER", "HOP"))
            metric_key, metric = _find_attr(attrs, ("METRIC", "COST"))
            enabled_key, enabled = _find_attr(attrs, ("ENAB", "ACTIVE"))

            if dest is None or not utils.is_ip(str(dest).split("/")[0]):
                log.debug(f"Skipping Sage route {key} without a destination: {attrs}")
                continue

            destination = str(dest)
            used.add(dest_key)
            if mask is not None and "/" not in destination and utils.is_ip(str(mask)):
                destination = f"{destination} {mask}"
                used.add(mask_key)

            route = Route(destination=destination, type="static")

            if gateway is not None and utils.is_ip(str(gateway)):
                route.gateway = str(gateway)
                used.add(gw_key)
            if isinstance(metric, int) and metric >= 0:
                route.metric = metric
                used.add(metric_key)
            if _flag(enabled) is not None:
                route.enabled = _flag(enabled)
                used.add(enabled_key)

            route.extra["route_id"] = key.partition("_")[2]
            for a_key, a_value in attrs.items():
                if a_key not in used and a_value not in (None, ""):
                    route.extra[a_key] = a_value

            routes.append(route)

    return routes


# Time source protocol names (time.xml labels) -> TimeSource.protocol
_TIME_PROTOCOLS: Final[dict[str, str]] = {
    "SNTP": "sntp",
    "NTP": "ntp",
    "GPS": "gps",
    "IRIG": "irig_b",
    "PTP": "ptp",
    "1588": "ptp",
}


def _time_protocol(label: str) -> str:
    u_label = str(label).upper()
    for needle, proto in _TIME_PROTOCOLS.items():
        if needle in u_label:
            return proto
    return ""


def _walk_leaves(data: dict, path: tuple[str, ...] = ()):
    for key, value in data.items():
        if isinstance(value, dict):
            yield from _walk_leaves(value, (*path, str(key)))
        else:
            yield (*path, str(key)), value


def clock_from_time_settings(
    time_settings: dict | None, gps_settings: dict | None
) -> dict[str, Any]:
    """
    Extract time synchronization settings from ``time.xml``
    (``device_info["time_settings"]`` and ``device_info["gps_settings"]``).

    Returns:
        dict with ``sources`` (list of :class:`~peat.data.models.TimeSource`),
        and optionally ``source`` (active source protocol) and ``utc_offset``
    """
    results: dict[str, Any] = {"sources": []}
    time_settings = time_settings or {}
    gps_settings = gps_settings or {}

    # Network time servers: IP addresses under a SNTP/NTP label,
    # in configuration order (first = priority 1)
    servers = [
        ("/".join(path), str(value))
        for path, value in _walk_leaves(time_settings)
        if utils.is_ip(str(value))
        and _time_protocol("/".join(path)) in ("sntp", "ntp")
        and str(value) not in ("0.0.0.0", "255.255.255.255")  # unset server
    ]
    for priority, (label, address) in enumerate(servers, start=1):
        results["sources"].append(
            TimeSource(
                protocol=_time_protocol(label),
                address=address,
                priority=priority,
                extra={"setting": label},
            )
        )

    # Hardware sources with an enable flag (GPS receiver, IRIG-B input)
    for path, value in _walk_leaves(time_settings):
        label = "/".join(path)
        proto = _time_protocol(label)
        if proto in ("gps", "irig_b", "ptp") and "ENAB" in label.upper():
            if _flag(value) is not None:
                results["sources"].append(
                    TimeSource(protocol=proto, enabled=_flag(value), extra={"setting": label})
                )

    if gps_settings and not any(src.protocol == "gps" for src in results["sources"]):
        gps = TimeSource(protocol="gps")
        _, enabled = _find_attr(gps_settings, ("ENAB",))
        if _flag(enabled) is not None:
            gps.enabled = _flag(enabled)
        results["sources"].append(gps)

    # Active/selected time source, e.g. SOURCE="GPS"
    _, source = _find_attr(time_settings, ("SOURCE", "SRC"))
    if isinstance(source, str):
        proto = _time_protocol(source)
        if proto:
            results["source"] = proto
        elif source.strip().upper() in ("INTERNAL", "LOCAL", "NONE", "RTC"):
            results["source"] = "internal"

    # UTC offset, only if already in "+HH:MM" form (units of numeric values are unknown)
    _, offset = _find_attr(time_settings, ("UTC", "OFFSET", "TZ"))
    if isinstance(offset, str) and re.fullmatch(r"[+-]\d{2}:\d{2}", offset.strip()):
        results["utc_offset"] = offset.strip()

    return results


def process_time_settings(dev: DeviceData, device_info: dict) -> None:
    """
    Store the time settings from ``time.xml`` in
    :attr:`DeviceData.clock <peat.data.models.DeviceData.clock>`.
    """
    clock_info = clock_from_time_settings(
        device_info.get("time_settings"), device_info.get("gps_settings")
    )

    for src in clock_info["sources"]:
        existing = next(
            (
                s
                for s in dev.clock.sources
                if (s.protocol, s.address, s.port) == (src.protocol, src.address, src.port)
            ),
            None,
        )
        if existing is None:
            dev.clock.sources.append(src)

    if clock_info.get("source") and not dev.clock.source:
        dev.clock.source = clock_info["source"]
    if clock_info.get("utc_offset") and not dev.clock.utc_offset:
        dev.clock.utc_offset = clock_info["utc_offset"]


def indicators_from_leds(leds: dict) -> list[Indicator]:
    """
    Convert the LED configuration from ``leds.xml`` (``device_info["leds"]``,
    see :func:`parse_leds`) into LED :class:`~peat.data.models.Indicator`
    definitions (configuration only, no live state).
    """
    indicators = []

    for group, group_leds in leds.items():
        if not isinstance(group_leds, dict):
            continue

        for key, attrs in group_leds.items():
            if not isinstance(attrs, dict):
                continue

            used = set()
            ind = Indicator(type="led", name=str(key))
            if str(key).isdigit():
                ind.position = str(key)

            label_key, label = _find_attr(attrs, ("DESC", "LABEL", "TEXT", "NAME"))
            if label is not None:
                ind.label = str(label)
                used.add(label_key)

            # Point or logic driving the LED
            eq_key, equation = _find_attr(attrs, ("PNT", "POINT", "LOGIC", "EQU", "SOURCE"))
            if equation is not None:
                ind.equation = str(equation)
                used.add(eq_key)

            color_key, color = _find_attr(attrs, ("COLOR", "COLOUR"))
            if isinstance(color, str):
                ind.color = color
                used.add(color_key)

            cat_key, category = _find_attr(attrs, ("CATEGORY", "FUNC", "TYPE"))
            if isinstance(category, str):
                ind.category = category
                used.add(cat_key)

            if group.upper() not in ("LEDS", "LED"):
                ind.extra["group"] = group
            for a_key, a_value in attrs.items():
                if a_key not in used and a_value not in (None, ""):
                    ind.extra[a_key] = a_value

            indicators.append(ind)

    return indicators


def canonical_port_protocol(name: str) -> str:
    """
    Canonical (PEAT) protocol name for a Sage serial port protocol type,
    e.g. ``DNP3`` -> ``dnp3``, ``MODBUS`` -> ``modbus_rtu`` (serial).
    """
    u_name = str(name).strip().upper()
    if "DNP" in u_name:
        return "dnp3"
    if "MODBUS" in u_name or "MBUS" in u_name:
        return "modbus_rtu"
    if "IEC" in u_name and "101" in u_name:
        return "iec101"
    if "IEC" in u_name and "103" in u_name:
        return "iec103"
    return re.sub(r"[^a-z0-9]+", "_", u_name.lower()).strip("_")


# Per-protocol roles (docs/data_model.rst): (local master side, local slave side)
_PROTOCOL_ROLES: Final[dict[str, tuple[str, str]]] = {
    "dnp3": ("master", "outstation"),
    "modbus_rtu": ("client", "server"),
    "iec101": ("controlling_station", "controlled_station"),
    "iec103": ("controlling_station", "controlled_station"),
}


def _port_roles(proto_name: str, protocol: dict, canonical: str) -> tuple[str, str]:
    """``(local role, remote role)`` from the protocol type or a MODE/ROLE attribute."""
    _, mode = _find_attr(protocol, ("MODE", "ROLE"), ("BAUD",))
    text = f"{proto_name} {mode if isinstance(mode, str) else ''}".upper()
    master_role, slave_role = _PROTOCOL_ROLES.get(canonical, ("master", "slave"))

    if re.search(r"MASTER|CLIENT|(?:^|[_\s])M(?:$|[_\s])", text):
        return master_role, slave_role
    if re.search(r"SLAVE|OUTSTATION|SERVER|(?:^|[_\s])S(?:$|[_\s])", text):
        return slave_role, master_role
    return "", ""


def process_ports(dev: DeviceData, ports: dict) -> None:
    """
    Process serial port configurations from ``xml/port*.xml``
    (``device_info["ports"]``, see :func:`parse_port`) into serial
    :class:`~peat.data.models.Interface`, :class:`~peat.data.models.Service`
    and configured :class:`~peat.data.models.Relationship` objects.
    """
    for port_key, settings in ports.items():
        if not isinstance(settings, dict):
            continue

        port_name = port_key.partition("_")[2] or port_key
        iface = Interface(name=port_name, type="serial")

        comm = settings.get("comm_settings") or {}
        used = set()
        baud_key, baud = _find_attr(comm, ("BAUD",))
        if isinstance(baud, int) and baud > 0:
            iface.baudrate = baud
            used.add(baud_key)

        parity_key, parity = _find_attr(comm, ("PARITY",))
        parity_map = {"N": "none", "NONE": "none", "E": "even", "EVEN": "even"}
        parity_map.update({"O": "odd", "ODD": "odd"})
        if parity is False:  # "N" is converted to False by the parser
            iface.parity = "none"
            used.add(parity_key)
        elif isinstance(parity, str) and parity.strip().upper() in parity_map:
            iface.parity = parity_map[parity.strip().upper()]
            used.add(parity_key)

        data_key, data_bits = _find_attr(comm, ("DATA",), ("STOP",))
        if isinstance(data_bits, int) and 4 <= data_bits <= 9:
            iface.data_bits = data_bits
            used.add(data_key)

        stop_key, stop_bits = _find_attr(comm, ("STOP",))
        if isinstance(stop_bits, int) and 0 <= stop_bits <= 2:
            iface.stop_bits = stop_bits
            used.add(stop_key)

        unused_comm = {k: v for k, v in comm.items() if k not in used}
        if unused_comm:
            iface.extra["comm_settings"] = unused_comm
        for key, value in settings.items():
            if key not in ("protocol", "comm_settings") and value not in (None, ""):
                iface.extra[key] = value

        protocol = settings.get("protocol")
        if not isinstance(protocol, dict) or not protocol.get("name"):
            dev.store("interface", iface, lookup="name")
            continue

        proto_name = str(protocol["name"])
        canonical = canonical_port_protocol(proto_name)
        local_role, remote_role = _port_roles(proto_name, protocol, canonical)
        iface.application = canonical
        dev.store("interface", iface, lookup="name")

        svc = Service(
            protocol=canonical,
            role=local_role,
            listen_interface=port_name,
            extra={k: v for k, v in protocol.items() if k != "name"},
        )
        svc.extra["protocol_type"] = proto_name
        dev.store(
            "service",
            svc,
            lookup={"protocol": canonical, "listen_interface": port_name},
            interface_lookup={"name": port_name},
        )

        # Configured peer: protocol address of the other end of the link
        if remote_role in ("master", "client", "controlling_station"):
            remote_needles: tuple[str, ...] = ("MASTER", "REMOTE", "DEST")
            local_needles: tuple[str, ...] = ("SLAVE", "LOCAL", "OWN", "RTU", "STATION")
        else:
            remote_needles = ("SLAVE", "REMOTE", "DEST", "OUTSTATION")
            local_needles = ("MASTER", "LOCAL", "OWN", "RTU", "SOURCE", "SRC")

        address_needles = ("ADDR", "ADR")
        remote_addr = next(
            (
                v
                for k, v in protocol.items()
                if any(n in k.upper() for n in remote_needles)
                and any(a in k.upper() for a in address_needles)
                and isinstance(v, (int, str))
                and not isinstance(v, bool)
                and str(v) != ""
            ),
            None,
        )
        if remote_addr is None:
            continue

        local_addr = next(
            (
                v
                for k, v in protocol.items()
                if any(n in k.upper() for n in local_needles)
                and any(a in k.upper() for a in address_needles)
                and isinstance(v, (int, str))
                and not isinstance(v, bool)
                and str(v) != ""
            ),
            None,
        )

        dev.store(
            "relationships",
            Relationship(
                type="communicates_with",
                protocol=canonical,
                medium="serial",
                local=RelationshipEndpoint(
                    serial_port=port_name,
                    role=local_role,
                    protocol_address=str(local_addr) if local_addr is not None else "",
                ),
                remote=RelationshipEndpoint(
                    protocol_address=str(remote_addr),
                    role=remote_role,
                ),
                evidence={"config"},
            ),
        )


def netstat_has_task_ids(output: str) -> bool:
    """
    If ``netstat`` output has the columns parsed by
    :class:`~peat.parsing.command_parsers.NetstatSocketsVxWorksParser`
    (``Prot Recv-Q Send-Q Local Address Foreign Address (state) TID``),
    i.e. the header names the owning task ID column.
    """
    for line in (output or "").splitlines():
        cols = line.upper().split()
        if "RECV-Q" in cols and "SEND-Q" in cols:
            return "TID" in cols
    return False


def isagraf_package(isagraf: dict) -> Package | None:
    """ISaGRAF runtime version (``ISaGRAF.TXT``) as a software package."""
    if not isagraf or not isagraf.get("version"):
        return None
    return Package(
        name="ISaGRAF",
        version=str(isagraf["version"]),
        category="plc_runtime",
        description=isagraf.get("note", ""),
    )


def file_categories(path: str | PurePath) -> set[str]:
    """
    Categories (:attr:`File.category <peat.data.models.File.category>`)
    of a file on a Sage, based on its path.
    """
    p_str = PurePosixPath(str(path).replace("\\", "/")).as_posix().lower()
    name = p_str.rsplit("/", 1)[-1]

    if name.endswith(".scp") or "/scripts/" in f"/{p_str}":
        return {"script"}
    if name in ("syslog.log", "userlog.log", "soelog.txt") or re.fullmatch(
        r"syslog(\.\d+)?", name
    ):
        return {"log"}
    if name.endswith((".crt", ".cer", ".pem")):
        return {"certificate"}
    if name.endswith(".key"):
        return {"key"}
    if name == "vxworks":
        return {"firmware"}
    if name.endswith((".tar.gz", ".tgz")) and "config" in name:
        return {"configuration", "backup"}
    if name.endswith((".xml", ".cfg", ".conf")) or name == "isagraf.txt":
        return {"configuration"}
    return set()


def _mode_from_permissions(perms: str) -> str:
    """``rwxr-xr--`` or ``-rwxr-xr--`` -> ``0754`` (empty string if unparsable)."""
    perms = str(perms).strip()
    if len(perms) == 10:
        perms = perms[1:]
    if len(perms) != 9 or any(c not in "rwxsStT-" for c in perms):
        return ""
    value = 0
    for i, char in enumerate(perms):
        if char != "-" and char not in "ST":
            value |= 1 << (8 - i)
    return f"{value:04o}"


def listing_to_files(
    listing: list[dict], local_dir: Path | None = None, downloaded: set[str] | None = None
) -> list[File]:
    """
    Convert a FTP file listing (:meth:`~peat.protocols.FTP.rdir` metadata)
    into :class:`~peat.data.models.File` objects.

    Args:
        listing: file metadata dicts (``type``, ``permissions``, ``size``,
            ``modified``, ``name``, ``path``)
        local_dir: directory the files were downloaded to (``local_dir/<path>``)
        downloaded: device paths of files that were downloaded
    """
    files = []

    for entry in listing:
        if not entry.get("path"):
            continue
        f_type = entry.get("type", "")
        file = File(
            path=PurePosixPath(entry["path"]),
            name=entry.get("name", ""),
            type=f_type if f_type in ("file", "dir", "symlink") else "",
            peat_module="Sage",
            category=file_categories(entry["path"]) if f_type != "dir" else set(),
        )
        if isinstance(entry.get("size"), int) and f_type != "dir":
            file.size = entry["size"]
        if isinstance(entry.get("modified"), datetime):
            file.mtime = entry["modified"]  # device-local time (naive)
        mode = _mode_from_permissions(entry.get("permissions", ""))
        if mode:
            file.mode = mode
        if local_dir is not None and downloaded and entry["path"] in downloaded:
            local_path = Path(local_dir, entry["path"].lstrip("/"))
            if local_path.is_file():
                file.local_path = local_path
        files.append(file)

    return files


def sftp_attrs_to_file(folder: str, attrs: Any, local_dir: Path | None = None) -> File:
    """
    Convert a :class:`paramiko.SFTPAttributes` (from
    ``sftp_recursive_file_walk()``) into a :class:`~peat.data.models.File`.
    """
    path = f"{folder}/{attrs.filename}"
    file = File(
        path=PurePosixPath(path),
        name=attrs.filename,
        type="file",
        peat_module="Sage",
        category=file_categories(path),
    )
    if getattr(attrs, "st_size", None) is not None:
        file.size = attrs.st_size
    if getattr(attrs, "st_mtime", None) is not None:
        file.mtime = datetime.fromtimestamp(attrs.st_mtime, tz=UTC)
    longname = getattr(attrs, "longname", "") or ""
    mode = _mode_from_permissions(longname.split()[0] if longname.split() else "")
    if mode:
        file.mode = mode
    if local_dir is not None:
        local_path = Path(local_dir, path.lstrip("/"))
        if local_path.is_file():
            file.local_path = local_path
    return file


def tar_member_to_file(member: tarfile.TarInfo, archive_name: str) -> File:
    """A member of a Sage configuration/firmware archive as a :class:`~peat.data.models.File`."""
    if member.isdir():
        f_type = "dir"
    elif member.issym():
        f_type = "symlink"
    else:
        f_type = "file"

    file = File(
        path=PurePosixPath(member.name),
        name=PurePosixPath(member.name).name,
        type=f_type,
        peat_module="Sage",
        mode=f"{member.mode & 0o7777:04o}",
        category=file_categories(member.name) if f_type == "file" else set(),
        extra={"archive": archive_name},
    )
    if f_type == "file":
        file.size = member.size
    if member.mtime:
        file.mtime = datetime.fromtimestamp(member.mtime, tz=UTC)
    if f_type == "symlink" and member.linkname:
        file.target_path = PurePosixPath(member.linkname)
    return file


def parse_file(path: PurePath, f_handle: IO[bytes], device_info: dict) -> bool:
    """
    Parse a Sage file using the appropriate parsing function, and update
    the ``device_info`` dict with extracted data from that file.

    Returns:
        Bool indicating if a parsing function was found for the file.
    """
    f_name_lower = path.name.lower()

    # TODO: return dicts from functions instead of mutating device_info inside functions

    if f_name_lower in FILE_PROCESSING_MAP:
        FILE_PROCESSING_MAP[f_name_lower](f_handle, device_info)
    else:
        path_str = path.as_posix()

        if re.match(r"firewall/.*\.cfg", path_str, re.IGNORECASE):
            parse_firewall(f_handle, device_info)
        elif re.match(r"xml/port.*\.xml", path_str, re.IGNORECASE):
            parse_port(f_handle, device_info)
        # syslog or syslog.{x} (where x=an integer, e.g. "syslog.0")
        elif path.name.startswith("syslog") and len(path.name) in [6, 8]:
            parse_ipcom_syslog(f_handle, device_info)
        else:
            # File is not one of interest, continue
            log.trace2(f"Skipping file '{path}' (no parser for it)")
            return False

    return True


# tar => FTP:
#   xml/* => /ata0a/Webfiles/xml/*
#   ethernet.xml => /ata0a/ethernet.xml
#   bootline.xml => /ata0a/bootline.xml
#   isagraf/ISaGRAF.TXT => /ata0a/Webfiles/ISaGRAF/ISaGRAF.TXT
#   scripts/* => /ata0a/scripts/*
#   server.key => /ata0a/ssl/private/server.key
#   server.crt => /ata0a/ssl/cert/server.crt
#   ike/* => /ata0a/ike/*


# Dynamic function dispatch to the appropriate parser based on the input file
# NOTE: keys must be lowercase to ensure filenames match properly in all cases
FILE_PROCESSING_MAP: Final[dict[str, Callable]] = {
    "syslog.log": parse_logfiles,
    "userlog.log": parse_logfiles,
    "soelog.txt": parse_logfiles,
    "syslog": parse_ipcom_syslog,
    "syslog.0": parse_ipcom_syslog,
    "access.xml": parse_access_xml,
    "rtusetup.xml": parse_rtu_setup,
    "tte.xml": parse_tte,
    "userlog.xml": parse_userlog_settings_xml,
    "time.xml": parse_time,
    "ethernet.xml": parse_ether,
    "bootline.xml": parse_bootline_xml,
    "isagraf.txt": parse_isagraf,
    "startup.scp": parse_startup_script,
    "vxworks_start.scp": parse_vxworks_script,
    "server.key": parse_private_key,
    "server.crt": parse_certificate,
    "ike.cfg": parse_ike_config,
    # "ike/ca_store/telvent_ca.cer": parse_ike_ca,
    "telvent_ca.cer": parse_ike_ca,
    # "ike/private/priv0.key": parse_ike_privkey,
    "priv0.key": parse_ike_privkey,
    # "ike/cert/cert0.cer": parse_ike_cert,
    "cert0.cer": parse_ike_cert,
    "features.xml": parse_features,
    "c3835.xml": parse_3835,
    "dcana.xml": parse_dcana,
    "timing.xml": parse_timing,
    "calc.xml": parse_calc,
    "rtu_sts.xml": parse_rtu_sts,
    "sfb.xml": parse_sfb,
    "acc_rate.xml": parse_acc_rate,
    "alarms.xml": parse_alarms,
    "alarming.xml": parse_alarming,
    "almdev.xml": parse_almdev,
    "bbdi.xml": parse_bbdi,
    "cbcconf.xml": parse_cbc,
    "astconf.xml": parse_ast,
    "anunctor.xml": parse_anunctor,
    "cmdlog.xml": parse_cmdlog_settings_xml,
    "comasign.xml": parse_com_assignments,
    "sprcodes.xml": parse_sprcodes,
    "soelog.xml": parse_soelog_settings_xml,
    "leds.xml": parse_leds,
    "relays.xml": parse_relays,
    "nrgcalc.xml": parse_nrgcalc,
    "bbrelay.xml": parse_bbrelay,
    "btstconf.xml": parse_btstconf,
    "aci.xml": parse_aci,
    "aci1250.xml": parse_aci1250,
}
