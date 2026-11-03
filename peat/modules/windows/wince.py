"""
PEAT module for Windows CE embedded devices.

Authors

- Jacob Rahimi
- Christopher Goes
"""

import json
import re
from pathlib import Path, PureWindowsPath

from peat import DeviceData, DeviceModule, Interface, Service, datastore, utils
from peat.data.models import File, Hash, HostProcess, Relationship, RelationshipEndpoint
from peat.parsing.command_parsers import store_relationships
from peat.protocols.enip import VENDOR_NAMES
from peat.protocols.enip.enip_packets import PRODUCT_TYPES

# Possible key names in the pillage results (first one present is used)
_PID_KEYS = ("PID", "Process ID", "ProcessID", "pid")
_EXECUTABLE_KEYS = ("Executable", "Path", "Process Path", "Image Path")
_LOCAL_IP_KEYS = ("Local Address", "Local IP", "local_address")
_REMOTE_IP_KEYS = ("Remote Address", "Remote IP", "Foreign Address", "remote_address")
_REMOTE_PORT_KEYS = ("Remote Port", "Foreign Port", "remote_port")


def _first(data: dict, keys: tuple[str, ...]) -> object:
    for key in keys:
        if data.get(key) not in (None, ""):
            return data[key]
    return None


def _extra_key(key: object) -> str:
    """
    snake_case ``extra`` key for a key of the pillage results, which are
    words separated by spaces (e.g. ``Base Address`` -> ``base_address``).
    """
    words = [utils.convert_to_snake_case(w) for w in re.split(r"[^0-9A-Za-z]+", str(key))]
    return "_".join(w for w in words if w) or str(key)


def _to_port(value: object) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def process_from_pillage(proc_info: dict) -> HostProcess | None:
    """
    Convert a ``process_list`` entry of the pillage results
    (``{"Process Name": ..., "modules": [{"Module Name": ...}, ...], ...}``)
    to a :class:`~peat.data.models.HostProcess`. The loaded modules (DLLs)
    and other keys are kept in ``extra``.
    """
    name = str(proc_info.get("Process Name") or "").strip()
    pid = _first(proc_info, _PID_KEYS)
    executable = _first(proc_info, _EXECUTABLE_KEYS)
    if not name and pid is None and not executable:
        return None

    proc = HostProcess(type="process", name=name)

    try:
        if pid is not None:
            proc.pid = int(str(pid), 0)
    except ValueError:
        proc.extra["pid_raw"] = str(pid)

    if executable:
        proc.executable = str(executable)

    used_keys = {"Process Name", *_PID_KEYS, *_EXECUTABLE_KEYS}
    for key, value in proc_info.items():
        if key not in used_keys and value not in (None, "", []):
            proc.extra[_extra_key(key)] = value

    return proc


def file_from_pillage(file_info: dict, device_id: str = "") -> File | None:
    """
    Convert a ``file_list`` entry of the pillage results
    (``{"Name": "\\Windows\\app.exe", "Type": "File", "SHA256": ...}``)
    to a :class:`~peat.data.models.File`.
    """
    raw_name = str(file_info.get("Name") or "").strip()
    if not raw_name:
        return None

    path = PureWindowsPath(raw_name)
    raw_type = str(file_info.get("Type") or "").strip().lower()
    f_type = "dir" if raw_type in ("directory", "dir", "folder") else "file"

    file_obj = File(
        device=device_id,
        path=path,
        name=path.name or raw_name,
        directory=str(path.parent) if path.name else "",
        type=f_type,
    )
    if f_type == "file" and path.suffix:
        file_obj.extension = path.suffix.lstrip(".")

    sha256 = str(file_info.get("SHA256") or "").strip()
    if len(sha256) == 64:
        file_obj.hash = Hash(sha256=sha256)

    for key, value in file_info.items():
        if key not in ("Name", "Type", "SHA256") and value not in (None, ""):
            file_obj.extra[_extra_key(key)] = value

    return file_obj


def connection_from_socket(socket: dict, transport: str) -> Relationship | None:
    """
    A non-listening socket of the pillage results -> :class:`~peat.data.models.Relationship`
    (``evidence={"netstat"}``). Only keys present in the data are used; the
    direction and protocol are inferred by ``Relationship.annotate()``.
    """
    remote_ip = str(_first(socket, _REMOTE_IP_KEYS) or "").strip()
    if not utils.is_ip(remote_ip) or remote_ip in ("0.0.0.0", "::"):
        return None

    local_ip = str(_first(socket, _LOCAL_IP_KEYS) or "").strip()
    return Relationship(
        transport=transport,
        local=RelationshipEndpoint(
            ip=local_ip if utils.is_ip(local_ip) and local_ip not in ("0.0.0.0", "::") else "",
            port=_to_port(socket.get("Local Port")),
        ),
        remote=RelationshipEndpoint(
            ip=remote_ip,
            port=_to_port(_first(socket, _REMOTE_PORT_KEYS)),
        ),
        state=str(socket.get("state") or "").strip().lower(),
        evidence={"netstat"},
    )


class WindowsCE(DeviceModule):
    """
    PEAT module for Windows CE embedded devices.

    Usage:
        ``peat parse -d WindowsCE -- pillage-system_info.json``

    Supported devices:

    - Siemens TP700 Comfort HMI Panel
    - Rockwell PanelView Plus 7 Standard HMI
    """

    device_type = "HMI"

    # The name and/or file extensions this module is able to parse.
    filename_patterns = [
        "pillage-results.json",
        "pillage-system_info.json",
        "wince_pillage*.json",
    ]

    module_aliases = ["wince", "TP700", "SiemensComfort"]

    @classmethod
    def _parse(cls, file: Path, dev: DeviceData | None = None) -> DeviceData | None:
        # Read the JSON config data from the file
        raw_data = file.read_text(encoding="utf-8")

        # Convert the raw JSON text to a Python dictionary ("dict")
        data = json.loads(raw_data)  # type: dict

        # Create a DeviceData object using the IP address read from the file
        # This object stores data associated with a particular device.
        dev = datastore.get(data["ip"], "ip")  # type: DeviceData

        # NOTE: data.get(key, "") is used instead of data[key] to handle potential
        # cases where a field wasn't able to be retrieved.

        # Operating System (OS) information
        # This is a Windows system, so we can hardcode most of this
        dev.architecture = data.get("Processor Type", "").lower()
        dev.os.family = "windows"
        dev.os.vendor.name = "Microsoft Corporation"
        dev.os.vendor.id = "Microsoft"
        dev.os.full = f"Windows Embedded CE {data.get('OS Version', '')}".strip()
        dev.os.name = "Windows Embedded CE"
        dev.os.version = data.get("OS Version", "")

        # Populate information about network interfaces
        for interface in data["network_interfaces"]:
            iface_object = Interface(
                type="ethernet",
                ip=interface["ip"],
                mac=interface["mac"],
                name=interface["name"],
                subnet_mask=interface["subnet_mask"],
                gateway=interface["gateway"],
            )

            if interface.get("description"):
                iface_object.description.description = interface["description"]

            dev.store("interface", iface_object, lookup="name")

        # Populate information about Indicators of Compromise (IOCs)
        if "ioc_results" in data:
            dev.extra["ioc_results"] = data["ioc_results"]

        # Populate information about files
        if "file_list" in data:
            for file_info in data["file_list"]:
                if file_info.get("SHA256") and len(file_info["SHA256"]) == 64:
                    dev.related.hash.add(file_info["SHA256"])

                if file_info.get("Type", "") == "File" and file_info.get("Name"):
                    dev.related.files.add(file_info["Name"])

                file_obj = file_from_pillage(file_info, dev.get_comm_id())
                if file_obj:
                    dev.store("files", file_obj)

        # Populate information about network sockets
        if "network_sockets" in data:
            _protocol_lookups = {
                21: "ftp",
                23: "telnet",
                68: "bootp",
                80: "http",
                161: "snmp",
                2221: "enip_secure",
                2222: "enip",
                44818: "cip",
            }

            # TCP sockets. Sockets in LISTEN state are services, other
            # sockets (connections) are relationships.
            connections = []  # type: list[Relationship]
            # Sockets (or their columns) that are not mapped to services or
            # relationships are kept in dev.extra["network_sockets"]
            unmapped = {"TCP Sockets": [], "UDP Sockets": []}
            for t_skt in data["network_sockets"].get("TCP Sockets", []):
                if t_skt.get("state") != "LISTEN":
                    rel = connection_from_socket(t_skt, "tcp")
                    if rel:
                        connections.append(rel)
                    else:
                        unmapped["TCP Sockets"].append(t_skt)
                    continue

                if set(t_skt) - {"state", "Local Port"}:
                    unmapped["TCP Sockets"].append(t_skt)
                t_port = t_skt["Local Port"]  # type: int
                dev.related.ports.add(t_port)

                svc = Service(
                    port=t_port,
                    protocol=_protocol_lookups.get(t_port, ""),
                    transport="tcp",
                    status="open",
                )

                dev.store("service", svc, lookup="port")

            # UDP sockets. Save all ports to related, but only
            # save low ports as services (port < 10000).
            for u_skt in data["network_sockets"].get("UDP Sockets", []):
                if (
                    not u_skt.get("Local Port")
                    or u_skt["Local Port"] >= 10000
                    or set(u_skt) - {"Local Port"}
                ):
                    unmapped["UDP Sockets"].append(u_skt)
                if u_skt.get("Local Port"):
                    u_port = u_skt["Local Port"]  # type: int
                    dev.related.ports.add(u_port)

                    # Only add lower UDP ports as services
                    if u_port < 10000:
                        svc = Service(
                            port=u_port,
                            protocol=_protocol_lookups.get(u_port, ""),
                            transport="udp",
                            status="open",
                        )

                        dev.store("service", svc, lookup="port")

            # After the services, so the direction is inferred from listening ports
            store_relationships(dev, connections)

            unmapped = {k: v for k, v in unmapped.items() if v}
            if unmapped:
                dev.extra["network_sockets"] = unmapped

        # Populate information about processes
        if "process_list" in data:
            for proc_info in data["process_list"]:
                # Add process name to related.process
                if proc_info.get("Process Name"):
                    dev.related.process.add(proc_info["Process Name"])

                # Module name is file name, save to related.files
                for mod_info in proc_info.get("modules", []):
                    if "." in mod_info.get("Module Name", ""):
                        dev.related.files.add(mod_info["Module Name"])

                proc = process_from_pillage(proc_info)
                if proc:
                    dev.store("processes", proc)

        # Populate information about Windows Registry keys
        # HKEY_LOCAL_MACHINE is the most interesting of these.
        # The other three have some information, but are less useful.
        #
        # Reference for registry types:
        # https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
        #
        # TODO: flatten these into dicts to make it easier to parse and read
        if "HKEY_LOCAL_MACHINE" in data:
            dev.extra["HKEY_LOCAL_MACHINE"] = data["HKEY_LOCAL_MACHINE"]

            for reg_key in data["HKEY_LOCAL_MACHINE"]:
                k_name = reg_key["Key Name"]  # type: str

                # TODO: "Key Name": "\\HKLM\\SOFTWARE\\ROCKWELL SOFTWARE\\RSLINXNG\\Last Version",
                #   "Value Name": "Base Version"
                #   "Value Data": "5.90.00.000"

                # Need to combine multiple key values together,
                # so do this outside normal loop.
                if k_name.endswith("CIP Identity"):
                    cip_info = {}

                    for k_val in reg_key["Key Values"]:
                        cip_info[k_val["Value Name"]] = str(k_val["Value Data"])

                    dev.serial_number = cip_info.get("SerialNumber", "")
                    dev.firmware.version = cip_info.get("MajorRevision", "")
                    dev.firmware.revision = cip_info.get("MinorRevision", "")

                    # "PanelView Plus_7 Standard 700"
                    if cip_info.get("ProductName"):
                        prod_name = cip_info["ProductName"].replace("_", " ").strip()
                        dev.description.model = prod_name

                        if "PanelView" in prod_name:
                            dev.description.brand = "PanelView"
                            dev.type = "HMI"
                        elif "ArmorView" in prod_name:
                            dev.description.brand = "ArmorView"
                            dev.type = "HMI"

                    # Lookup CIP vendor ID. This is probably always going to be
                    # Rockwell, but doesn't hurt.
                    if cip_info.get("Vendor"):
                        vendor_id = int(cip_info["Vendor"])
                        try:
                            dev.description.vendor.name = VENDOR_NAMES[vendor_id]
                            if "Rockwell" in dev.description.vendor.name:
                                dev.description.vendor.id = "Rockwell"
                        except Exception:
                            cls.log.warning(
                                f"Unknown vendor ID for device {dev.get_id()}: {vendor_id}"
                            )

                    if cip_info.get("ProductType"):
                        type_id = int(cip_info["ProductType"])
                        try:
                            prod_type = PRODUCT_TYPES[type_id]
                            if prod_type != "Human-Machine Interface":
                                dev.type = prod_type
                            else:
                                dev.type = "HMI"  # be consistent with siemens
                            dev.extra["product_type_from_cip"] = prod_type
                        except Exception:
                            cls.log.warning(
                                f"Unknown product type for device {dev.get_id()}: {type_id}"
                            )

                    continue

                for k_val in reg_key["Key Values"]:
                    v_name = k_val["Value Name"]  # type: str
                    v_data = k_val["Value Data"]

                    # If no data, don't bother
                    if not v_data:
                        continue

                    # Don't care about any non-str values at the moment
                    if not isinstance(v_data, str):
                        continue

                    if "TP700" in v_data and ("Siemens" in v_data or "SIEMENS" in k_name):
                        dev.type = "HMI"
                        dev.description.vendor.id = "Siemens"
                        dev.description.vendor.name = "Siemens AG"
                        dev.description.brand = "SIMATIC"
                        dev.description.model = "TP700 Comfort"

                    if v_name == "sysDescr":
                        descr = str(v_data)
                        dev.extra["snmp_sysDescr"] = descr
                        if "Siemens" in descr and "TP700" in descr:
                            parts = descr.split(", ")
                            dev.part_number = parts[3].replace(" ", "")
                    elif v_name == "sysContact":
                        dev.extra["snmp_sysContact"] = str(v_data)
                    elif v_name == "sysLocation":
                        dev.geo.name = str(v_data)
                    elif v_name == "ImageVersion" and "SIEMENS" in k_name:
                        dev.extra["ImageVersion"] = str(v_data).strip()
                        if not dev.firmware.version:
                            dev.firmware.version = str(v_data).strip().lstrip("V")
                    elif v_name == "Username" and "Ident" in k_name:
                        dev.related.user.add(str(v_data).strip())

            # Try to determine vendor via other methods
            if not dev.description.vendor.name:
                for reg_key in data["HKEY_LOCAL_MACHINE"]:
                    k_name = reg_key["Key Name"]  # type: str

                    if "SIEMENS" in k_name or "\\PROFINET\\" in k_name:
                        dev.description.vendor.id = "Siemens"
                        dev.description.vendor.name = "Siemens AG"
                        break

                    if "ROCKWELL" in k_name:
                        dev.description.vendor.id = "Rockwell"
                        dev.description.vendor.name = "Rockwell Automation"
                        break

        # Save the other registry info into dev.extra
        if "HKEY_CURRENT_USER" in data:
            dev.extra["HKEY_CURRENT_USER"] = data["HKEY_CURRENT_USER"]
        if "HKEY_CLASSES_ROOT" in data:
            dev.extra["HKEY_CLASSES_ROOT"] = data["HKEY_CLASSES_ROOT"]
        if "HKEY_USERS" in data:
            dev.extra["HKEY_USERS"] = data["HKEY_USERS"]

        # Populate information about system info
        if "system_info" in data:
            sys_info = data["system_info"]
            dev.extra["system_info"] = sys_info

            dev.hardware.cpu.vendor.name = sys_info.get("Processor Type", "")

            # We're assuming these values are in bytes
            if "Program RAM Available" in sys_info:
                dev.hardware.memory_available = sys_info["Program RAM Available"]
                dev.hardware.memory_type = "ram"

            if "Total Program RAM" in sys_info:
                dev.hardware.memory_total = sys_info["Total Program RAM"]
                dev.hardware.memory_type = "ram"

            if sys_info.get("Username"):
                dev.related.user.add(sys_info["Username"].strip())

        return dev


__all__ = ["WindowsCE"]
