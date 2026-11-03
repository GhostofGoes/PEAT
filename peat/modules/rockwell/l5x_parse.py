"""
Functionality for pulling some interesting fields out of RSLogix L5X files.

Uses the ``l5x`` library for parsing, most functions return data structured
for PEAT.

Authors

- John Mulder
- Jennifer Trasti
- Christopher Goes
"""

import math
import xml.etree.ElementTree as ET
from datetime import timedelta
from typing import Final

import l5x

from peat import LogicTask, Relationship, RelationshipEndpoint, log, utils

# L5X <Task Type="..."> -> LogicTask.type
TASK_TYPES: Final[dict[str, str]] = {
    "CONTINUOUS": "continuous",
    "PERIODIC": "periodic",
    "EVENT": "event",
}

# TODO: cleanup this code to build PEAT data models directly, instead
# of returning dicts that then get used to build model objects...


def get_ip_address(project: l5x.Project) -> str:
    """
    Takes a ``l5x.Project`` object.
    Returns a string of the IP communication path.
    """
    comm_path = project.controller.comm_path

    if comm_path:
        ip_addr = comm_path.split("\\")[1]
    else:
        ip_addr = ""

    return ip_addr


def get_logic(project: l5x.Project) -> dict:
    """
    Return a logic dict created from the project object.
    """
    logic = {}

    logic["id"] = project.controller.element.attrib.get("ProjectSN", "")
    logic["author"] = project.doc.attrib.get("Owner", "")

    logic["created_date"] = project.controller.element.attrib.get("ProjectCreationDate", "")
    logic["last_modified_date"] = project.controller.element.attrib.get("LastModifiedDate", "")

    logic["major_rev"] = project.controller.element.attrib.get("MajorRev", "")
    logic["minor_rev"] = project.controller.element.attrib.get("MinorRev", "")

    logic["software_revision"] = project.doc.attrib.get("SoftwareRevision", "")
    logic["export_date"] = project.doc.attrib.get("ExportDate", "")

    programs = {}
    try:
        for name in project.programs.names:
            programs[name] = []
            routines_iter = project.programs[name].element.iter("Routine")

            for routine in routines_iter:
                xml_str = ET.tostring(routine, encoding="utf-8", method="xml")  # type: bytes

                # Remove the initial xml tag that ElementTree tacks on the beginning
                # start_index = xml_str.find(b"\n")  # + 1

                # Convert to proper string
                decoded_str = xml_str.decode("utf-8").strip()

                # programs[name].append(xml_str[start_index:])
                programs[name].append(decoded_str)
        logic["formats"] = {"routines": programs}
    except Exception as ex:
        log.warning(f"Failed to extract logic routines: {ex}")

    return logic


def get_modules_data(project: l5x.Project) -> list[dict]:
    """
    Gets module device data from an L5X project.
    """
    modules_data = []

    try:
        for name in project.modules.names:
            # look up the module in the l5x.Project structure
            module = project.modules[name]
            module_dict = {}
            module_dict["name"] = name
            module_dict["vendor"] = module.element.attrib.get("Vendor", "")
            module_dict["product_type"] = module.element.attrib.get("ProductType", "")
            module_dict["product_code"] = module.element.attrib.get("ProductCode", "")
            module_dict["part_number"] = module.element.attrib.get("CatalogNumber", "")
            module_dict["major"] = module.element.attrib.get("Major", "")
            module_dict["minor"] = module.element.attrib.get("Minor", "")
            module_dict["parent_module"] = module.element.attrib.get("ParentModule", "")
            module_dict["parent_mod_port_id"] = module.element.attrib.get("ParentModPortId", "")
            # Configuration properties, not live state:
            # Inhibited = the connection to the module is inhibited,
            # MajorFault = major fault the controller if the connection fails
            module_dict["inhibited"] = module.element.attrib.get("Inhibited", "")
            module_dict["major_fault"] = module.element.attrib.get("MajorFault", "")

            ports = []
            for port_num in module.ports.names:
                port_obj = module.ports[port_num]
                ports.append(
                    {
                        "id": port_num,
                        "type": port_obj.type,
                        "address": port_obj.address,
                        "upstream": port_obj.element.get("Upstream", ""),
                        "slot": port_obj.element.get("Slot", ""),
                    }
                )
            module_dict["ports"] = ports

            modules_data.append(module_dict)
    except Exception as ex:
        log.warning(f"Failed to extract modules: {ex}")

    return modules_data


def _l5x_bool(value: str | None) -> bool | None:
    """L5X boolean attribute (``"true"``/``"false"``), or :obj:`None` if not set."""
    if value is None or not str(value).strip():
        return None
    return str(value).strip().lower() == "true"


def _milliseconds(value: str | None) -> timedelta | None:
    """
    L5X time attribute in milliseconds (e.g. ``Rate="10"``, ``Watchdog="500"``),
    or :obj:`None` if it is not set, not a number, negative, not finite (e.g.
    ``inf``) or too large for a :class:`~datetime.timedelta` (e.g. ``1e20``).
    """
    try:
        milliseconds = float(value)
        if not math.isfinite(milliseconds) or milliseconds < 0:
            return None
        return timedelta(milliseconds=milliseconds)
    except (TypeError, ValueError, OverflowError):
        return None


def _description(element: ET.Element) -> str:
    """Text of the ``<Description>`` child element (CDATA content), if any."""
    desc = element.find("Description")
    if desc is None:
        return ""
    return "".join(desc.itertext()).strip()


def get_tasks(project: l5x.Project) -> list[LogicTask]:
    """
    Takes a ``l5x.Project`` object.
    Returns the controller's tasks (``<Tasks>/<Task>``) as
    :class:`~peat.data.models.LogicTask` objects.

    .. code-block:: xml

       <Task Name="MainTask" Type="CONTINUOUS" Priority="10" Watchdog="500"
             DisableUpdateOutputs="false" InhibitTask="false">
         <ScheduledPrograms>
           <ScheduledProgram Name="MainProgram"/>
         </ScheduledPrograms>
       </Task>

    ``Rate`` (period of ``PERIODIC`` tasks) and ``Watchdog`` are in milliseconds.
    """
    tasks_element = project.controller.element.find("Tasks")
    if tasks_element is None:
        return []

    tasks = []
    for element in tasks_element.findall("Task"):
        attrs = element.attrib
        vendor_type = attrs.get("Type", "").strip()
        extra = {"vendor_type": vendor_type} if vendor_type else {}

        disable_update_outputs = _l5x_bool(attrs.get("DisableUpdateOutputs"))
        if disable_update_outputs is not None:
            extra["disable_update_outputs"] = disable_update_outputs

        interval = None
        if vendor_type.upper() == "PERIODIC":
            interval = _milliseconds(attrs.get("Rate"))
        elif attrs.get("Rate"):
            # e.g. the timeout of EVENT tasks
            extra["rate_ms"] = attrs["Rate"]

        event_info = element.find("EventInfo")
        if event_info is not None:
            for attr, key in (("EventTrigger", "event_trigger"), ("EventTag", "event_tag")):
                if event_info.get(attr):
                    extra[key] = event_info.get(attr)

        priority = None
        try:
            priority = int(attrs["Priority"])
        except (KeyError, ValueError):
            pass

        inhibited = _l5x_bool(attrs.get("InhibitTask"))

        tasks.append(
            LogicTask(
                name=attrs.get("Name", ""),
                type=TASK_TYPES.get(vendor_type.upper(), ""),
                priority=priority,
                watchdog=_milliseconds(attrs.get("Watchdog")),
                interval=interval,
                enabled=None if inhibited is None else not inhibited,
                programs=[
                    sp.get("Name", "")
                    for sp in element.iter("ScheduledProgram")
                    if sp.get("Name", "").strip()
                ],
                description=_description(element),
                extra=extra,
            )
        )

    return tasks


def _module_port(module_dict: dict, port_id: str) -> dict | None:
    for port in module_dict.get("ports", []):
        if str(port.get("id", "")) == str(port_id):
            return port
    return None


def _is_ethernet(port: dict | None) -> bool:
    return port is not None and str(port.get("type", "")).lower() == "ethernet"


def _upstream_ethernet_port(module_dict: dict) -> dict | None:
    """The module's Ethernet port that connects it to its parent, if any."""
    for port in module_dict.get("ports", []):
        if _is_ethernet(port) and str(port.get("upstream", "")).lower() == "true":
            return port
    return None


def get_local_module_names(modules_data: list[dict]) -> set[str]:
    """
    Names of the modules in the controller's local chassis (from
    :func:`get_modules_data`): the controller and the modules reached from it
    without crossing an Ethernet network (backplane ports).

    A module is remote if its parent port (``ParentModule`` + ``ParentModPortId``)
    is an Ethernet port, or if it has an upstream Ethernet port, or if its parent
    is remote or unknown.
    """
    by_name = {m["name"]: m for m in modules_data}
    results = {}  # type: dict[str, bool]

    def is_local(name: str, seen: frozenset) -> bool:
        if name in results:
            return results[name]
        mod = by_name.get(name)
        if mod is None or name in seen:
            return False

        parent = mod.get("parent_module", "")
        if not parent or parent == name:  # the controller ("Local") is its own parent
            local = True
        elif _upstream_ethernet_port(mod) is not None:
            local = False
        elif parent not in by_name:
            local = False
        elif _is_ethernet(_module_port(by_name[parent], mod.get("parent_mod_port_id", ""))):
            local = False
        else:
            local = is_local(parent, seen | {name})

        results[name] = local
        return local

    return {name for name in by_name if is_local(name, frozenset())}


def get_io_relationships(
    modules_data: list[dict], local_modules: set[str] | None = None
) -> list[Relationship]:
    """
    Build the controller's I/O connections from the I/O tree of the project
    (:func:`get_modules_data`): one :class:`~peat.data.models.Relationship` per
    module that is connected to its parent over Ethernet (adapters, remote
    communication modules, drives, ...), with the module's IP address
    (``Port@Address`` of its upstream Ethernet port).

    The controller is the CIP ``scanner`` (originator of the I/O connections),
    the module the ``adapter``. If the parent is a local Ethernet module, its
    IP address is used as ``local.ip``.

    Args:
        modules_data: modules from :func:`get_modules_data`
        local_modules: names of the local chassis modules
            (:func:`get_local_module_names`), computed if not given

    Returns:
        The relationships
    """
    if local_modules is None:
        local_modules = get_local_module_names(modules_data)
    by_name = {m["name"]: m for m in modules_data}
    relationships = []

    for mod in modules_data:
        upstream = _upstream_ethernet_port(mod)
        if upstream is None:
            continue

        remote = RelationshipEndpoint(name=mod["name"], role="adapter")
        address = str(upstream.get("address", "") or "").strip()
        if utils.is_ip(address):
            remote.ip = address
        elif address:
            remote.hostname = address

        local = RelationshipEndpoint(role="scanner")
        parent = by_name.get(mod.get("parent_module", ""))
        if parent is not None and parent["name"] in local_modules:
            parent_port = _module_port(parent, mod.get("parent_mod_port_id", ""))
            parent_address = str((parent_port or {}).get("address", "") or "").strip()
            if _is_ethernet(parent_port) and utils.is_ip(parent_address):
                local.ip = parent_address

        extra = {
            "catalog_number": mod.get("part_number", ""),
            "parent_module": mod.get("parent_module", ""),
        }
        for key, attr in (("inhibited", "inhibited"), ("major_fault_on_failure", "major_fault")):
            value = _l5x_bool(mod.get(attr))
            if value is not None:
                extra[key] = value

        relationships.append(
            Relationship(
                type="communicates_with",
                protocol="cip",
                direction="egress",
                local=local,
                remote=remote,
                evidence={"config"},
                extra={k: v for k, v in extra.items() if v != ""},
            )
        )

    return relationships


def get_programs(project: l5x.Project) -> dict:
    """
    Takes a ``l5x.Project`` object.
    Returns dict of programs where key is the program name and value is
    a dict of some known interesting attributes of the program.
    """
    programs = {}

    for program_name in project.programs.names:
        program = project.programs[program_name]
        if "MainRoutineName" in program.element.attrib:
            main_routine_name = program.element.attrib["MainRoutineName"]
            programs[program_name] = {"MainRoutineName": main_routine_name}

    return programs


def get_tags(project: l5x.Project) -> dict:
    """
    Takes a ``l5x.Project`` object.
    Returns dict of tags where key is the tag name and value is
    a dict of attributes of the tag
    """
    # TODO: Extract values from the raw ElemenTree object... the l5x library is messing these up.
    tags = {}
    controller = project.controller.element

    for tags_element in controller.iter("Tags"):
        for tag_element in tags_element.iter("Tag"):
            tag = {}
            tag["name"] = tag_element.attrib.get("Name", "")
            tag["tag_type"] = tag_element.attrib.get("TagType", "")
            tag["data_type"] = tag_element.attrib.get("DataType", "")
            tag["radix"] = tag_element.attrib.get("Radix", "")
            for description_element in tag_element.iter("Description"):
                for cdata_content_element in description_element.iter("CDATAContent"):
                    tag["description"] = cdata_content_element.text
            tags[tag["name"]] = tag

    return tags


def get_comm_ports(project: l5x.Project) -> list[dict]:
    comm_ports = []

    for comm_ports_tag in project.controller.element.iter("CommPorts"):
        for comm_port_tag in comm_ports_tag.iter("SerialPort"):
            comm_port_dict = {}
            comm_port_dict["baudrate"] = comm_port_tag.attrib.get("BaudRate", "")
            comm_port_dict["parity"] = comm_port_tag.attrib.get("Parity", "")
            comm_port_dict["stop_bits"] = comm_port_tag.attrib.get("StopBits", "")
            comm_port_dict["id"] = comm_port_tag.attrib.get("Channel", "")
            comm_port_dict["data_bits"] = comm_port_tag.attrib.get("DataBits", "")
            comm_port_dict["application"] = comm_port_tag.attrib.get("ComDriverId", "")
            comm_ports.append(comm_port_dict)

    return comm_ports


def get_project_description(project: l5x.Project) -> str:
    ele = project.controller.element.find("Description")
    if ele is None or not len(ele):
        return ""

    return next(iter(ele)).text.strip()
