"""
SEL RTAC parsing functions.

These functions parse the XML files that ACSELERATOR RTAC (SEL-5033) writes
when a project is exported ("Export" in the project tree). Each item in the
project tree is exported as its own XML file, for example
``SEL_RTAC/System/Main Controller.xml`` or ``SEL_RTAC/Devices/Relay1.xml``.

Every file has a ``<RTACModule>`` root element with exactly one child. The
tag of the child is the type of the item, for example ``Device``,
``TagProcessor`` or ``POU``. Most children have an ``<ExportSource>``
element with the ``Schema`` version of the export and the ``DeviceMOT``
(model option table, the part number or model) of the RTAC.

Each parser takes the parsed root element and a ``device_info`` dict, and adds
its results to ``device_info`` under a key for that item type.
"""

import math
import re
import xml.etree.ElementTree as ET
from typing import Final

ElasticType = None | int | bool | str | float

#: Columns of a setting page that is a list of single settings, with one
#: setting per row (instead of a table of tags with one tag per row).
KEY_VALUE_COLUMNS: Final[frozenset[str]] = frozenset({"Setting", "Value"})

#: Setting pages that only describe the pins of the function block
#: the editor generates for an item. They don't have configuration data.
IGNORED_PAGES: Final[frozenset[str]] = frozenset({"POU Pin Settings"})

#: Columns used to name the rows of a table of tags, in order of preference.
ROW_KEY_COLUMNS: Final[tuple[str, ...]] = (
    "Tag Name",
    "Channel Name",
    "Station Name",
    "Poll Number",
    "PMU Reference",
    "GocbRef",
)

#: Columns with names or other identifiers. The values of these columns are
#: kept as text, so that e.g. a tag named ``Y`` doesn't become ``True``.
#: Columns that end with one of :data:`TEXT_COLUMN_SUFFIXES` are also kept as text.
TEXT_COLUMNS: Final[frozenset[str]] = frozenset(
    {"GocbRef", "GoID", "DatSet", "Dest Addr", "Category", "Variation"}
)
TEXT_COLUMN_SUFFIXES: Final[tuple[str, ...]] = (
    "Name",
    "Alias",
    "Comment",
    "Desc",
    "Path",
    "Reference",
    "Message",
)

#: ``END_*`` keyword for each type of IEC 61131-3 POU declaration.
POU_END_KEYWORDS: Final[dict[str, str]] = {
    "PROGRAM": "END_PROGRAM",
    "FUNCTION_BLOCK": "END_FUNCTION_BLOCK",
    "FUNCTION": "END_FUNCTION",
    "INTERFACE": "END_INTERFACE",
}


def convert_to_elastic(_input: str) -> ElasticType:
    """Cast input to inferred type (int, bool, None) for elasticDB."""
    try:
        return int(_input)
    except Exception:
        try:
            value = float(_input)
            # NaN and infinity can't be stored in Elasticsearch or JSON
            if math.isfinite(value):
                return value
        except Exception:
            pass

        if _input in {"N", "False"}:
            return False
        elif _input in {"Y", "True"}:
            return True
        elif _input in {"None", "NONE"}:
            return None
        else:
            if (
                isinstance(_input, str)
                and len(_input) > 1
                and _input[0] == "'"
                and _input[-1] == "'"
            ):
                _input = _input[1:-1]
            return _input


def snake_case(name: str) -> str:
    """Convert a page name such as ``"Binary Inputs"`` to ``"binary_inputs"``."""
    return re.sub(r"[^0-9a-zA-Z]+", "_", name).strip("_").lower()


def convert_cell(column: str, value: str | None) -> ElasticType:
    """
    Convert the value of a setting page cell with :func:`convert_to_elastic`,
    unless the column has names or identifiers (:data:`TEXT_COLUMNS`).
    """
    if column in TEXT_COLUMNS or column.endswith(TEXT_COLUMN_SUFFIXES):
        return value.strip() if value else value
    return convert_to_elastic(value)


def get_text(element: ET.Element | None, path: str, default: str = "") -> str:
    """Text of the child at ``path``, stripped, or ``default`` if it is missing or empty."""
    if element is None:
        return default
    text = element.findtext(path)
    if text is None or not text.strip():
        return default
    return text.strip()


def get_code(element: ET.Element | None, path: str) -> str:
    """Text of the child at ``path`` with whitespace kept (e.g. Structured Text code)."""
    if element is None:
        return ""
    text = element.findtext(path)
    return text if text else ""


def get_item(xml_root: ET.Element) -> ET.Element:
    """
    The item element in a RTAC XML file (the only child of ``<RTACModule>``).
    """
    if not len(xml_root):
        raise ValueError(f"No item element under the '{xml_root.tag}' root element")
    return xml_root[0]


def parse_export_source(item: ET.Element) -> dict[str, ElasticType]:
    """
    Parse the ``<ExportSource>`` element of an item.

    Returns:
        Dict with the ``"Schema"`` and ``"DeviceMOT"`` values that are present
    """
    results = {}
    source = item.find("ExportSource")
    if source is None:
        return results

    schema = get_text(source, "Schema")
    if schema:
        results["Schema"] = convert_to_elastic(schema)
    mot = get_text(source, "DeviceMOT")
    if mot:
        results["DeviceMOT"] = mot

    return results


def row_to_dict(row: ET.Element) -> dict[str, str | None]:
    """
    Get the values of the cells in a setting page ``<Row>``, keyed by column name.

    .. note::
       The ``enabled="false"`` attribute on a ``<Setting>`` means the cell
       is read-only in the editor. It does NOT mean that the setting is
       disabled, so these cells are included.
    """
    cells = {}
    for setting in row.findall("Setting"):
        column = get_text(setting, "Column")
        if column:
            cells[column] = setting.findtext("Value")
    return cells


def parse_setting_page(page: ET.Element, strip_prefix: str = "") -> dict:
    """
    Parse one ``<SettingPage>``.

    There are two forms of setting page:

    - A list of single settings, with ``Setting``, ``Value`` and ``Comment``
      columns. This returns a dict of setting name to value.
    - A table, for example of tags, with one tag per row. This returns a dict
      of row name (e.g. the tag name) to a dict of the cell values in that row.
      Empty cells are not included.

    Args:
        page: The ``<SettingPage>`` element
        strip_prefix: Prefix to remove from row names, e.g. ``"SystemTags."``

    Returns:
        The page data, or an empty dict if the page has no rows
    """
    rows = [row_to_dict(row) for row in page.findall("Row")]
    rows = [row for row in rows if row]
    if not rows:
        return {}

    if all(KEY_VALUE_COLUMNS.issubset(row) for row in rows):
        return {
            row["Setting"].strip(): convert_to_elastic(row["Value"])
            for row in rows
            if row["Setting"] and row["Setting"].strip()
        }

    table = {}
    for index, row in enumerate(rows):
        cells = {
            column: convert_cell(column, value)
            for column, value in row.items()
            if value is not None and value.strip()
        }
        if not cells:
            continue

        key = ""
        for column in ROW_KEY_COLUMNS:
            if row.get(column) and row[column].strip():
                key = row[column].strip()
                break
        if strip_prefix and key.startswith(strip_prefix):
            key = key[len(strip_prefix) :]
        if not key:
            key = f"row_{index}"
        # Don't overwrite rows that have the same name
        if key in table:
            key = f"{key}_row_{index}"

        table[key] = cells

    return table


def parse_setting_pages(container: ET.Element | None, strip_prefix: str = "") -> dict[str, dict]:
    """
    Parse all of the ``<SettingPage>`` elements under ``container/SettingPages``.

    Returns:
        Dict of page name to the results of :func:`parse_setting_page`.
        Pages in :data:`IGNORED_PAGES` and empty pages are not included.
    """
    results = {}
    if container is None:
        return results

    for index, page in enumerate(container.findall("./SettingPages/SettingPage")):
        name = get_text(page, "Name", f"page_{index}")
        if name in IGNORED_PAGES:
            continue
        data = parse_setting_page(page, strip_prefix)
        if data:
            results[name] = data

    return results


def parse_settings(start_element: ET.Element | None) -> dict:
    """
    Parse the single settings on the ``"Settings"`` page under ``start_element``,
    for example the IP address and port of a remote device.
    """
    return parse_setting_pages(start_element).get("Settings", {})


def parse_accesspointrouters(router: ET.Element, device_info: dict) -> None:
    item = get_item(router)
    name = get_text(item, "Name", "unknown")
    source = item.find("Source")
    dest = item.find("Destination")

    results = {}
    for label, endpoint in [("Source", source), ("Destination", dest)]:
        results[label] = {
            "device_name": convert_to_elastic(get_text(endpoint, "DeviceName")),
            "device_protocol": convert_to_elastic(get_text(endpoint, "DeviceProtocol")),
            "type": convert_to_elastic(get_text(endpoint, "type")),
        }

    results["Settings"] = parse_settings(item)

    device_info.setdefault("AccessPointRouters", {})[name] = results


def parse_devices(device: ET.Element, device_info: dict) -> None:
    """
    Parse a ``Device``: a connection to a remote device, or a server
    on the RTAC, e.g. ``ModbusClient``, ``DNPServer`` or ``AccessPointServer``.

    The single settings are under ``"Settings"``. The other setting pages, such
    as tag lists, register maps and polls, are under the snake case name of
    the page, e.g. ``"binary_inputs"`` or ``"holding_registers"``.
    """
    item = get_item(device)
    name = get_text(item, "Name", "unknown")
    connection = item.find("Connection")

    results = {
        "Manufacturer": get_text(item, "Manufacturer"),
        "Model": get_text(item, "Model"),
        "Protocol": get_text(connection, "Protocol"),
        "Connection Type": get_text(connection, "ConnectionType"),
    }

    pages = parse_setting_pages(connection)
    results["Settings"] = pages.pop("Settings", {})
    for page_name, page_data in pages.items():
        results[snake_case(page_name)] = page_data

    # The channels of each PMU of a C37.118 client
    pmus = {}
    for index, pmu in enumerate(item.findall("./Connection/PMUs/PMU")):
        pmu_data = pmu.find("ClientPMUData")
        pmu_name = get_text(pmu_data, "Name", f"PMU_{index}")
        pmu_results = {"Type": get_text(pmu, "ClientPMUType")}
        for page_name, page_data in parse_setting_pages(pmu_data).items():
            pmu_results[snake_case(page_name)] = page_data
        pmus[pmu_name] = {k: v for k, v in pmu_results.items() if v}
    results["pmus"] = pmus

    # remove empty values
    for key in list(results.keys()):
        if not results[key]:
            results.pop(key)

    device_info.setdefault("Devices", {})[name] = results


def parse_goose_devices(goose: ET.Element, device_info: dict) -> None:
    """
    Parse a ``GooseDevice``: an IEC 61850 GOOSE message the RTAC
    subscribes to (``GooseRx``) or publishes (``GooseTx``).
    """
    item = get_item(goose)
    ied_name = get_text(item, "IEDName")
    ld_inst = get_text(item, "LDInst")
    cb_name = get_text(item, "CBName")
    connection = item.find("Connection")

    results = {
        "IED Name": ied_name,
        "LD Inst": ld_inst,
        "CB Name": cb_name,
        "Protocol": get_text(connection, "Protocol"),
        "Connection Type": get_text(connection, "ConnectionType"),
    }

    pages = parse_setting_pages(connection)
    results["Settings"] = pages.pop("Settings", {})
    # The "Message" page has one row, the GOOSE control block
    message = pages.pop("Message", {})
    if message:
        results["Message"] = next(iter(message.values()))
    for page_name, page_data in pages.items():
        results[snake_case(page_name)] = page_data

    for key in list(results.keys()):
        if not results[key]:
            results.pop(key)

    name = "_".join(n for n in [ied_name, ld_inst, cb_name] if n) or "unknown"
    device_info.setdefault("GooseDevices", {})[name] = results


def parse_tag_lists(tag_list: ET.Element, device_info: dict) -> None:
    """
    Parse a ``TagList``, e.g. a list of virtual tags
    (``Virtual``) or a C37.118 data stream (``C37118``).
    """
    item = get_item(tag_list)
    name = get_text(item, "Name", "unknown")

    results = {"Type": get_text(item, "TagListType")}
    pages = parse_setting_pages(item)
    results["Settings"] = pages.pop("Settings", {})
    for page_name, page_data in pages.items():
        results[snake_case(page_name)] = page_data

    for key in list(results.keys()):
        if not results[key]:
            results.pop(key)

    device_info.setdefault("TagLists", {})[name] = results


def parse_maincontroller(maincontroller: ET.Element, device_info: dict) -> None:
    """
    Parse the ``MainController``: the cycle and watchdog times of
    the main task and of the other tasks (e.g. ``Automation``).
    """
    item = get_item(maincontroller)
    results = {}

    task_index = 0
    for task in item:
        if task.tag == "MainTask":
            name = task.tag
        elif task.tag == "Task":
            name = get_text(task, "Name", f"Task_{task_index}")
            task_index += 1
        else:
            continue

        task_results = {}
        for line in task:
            if line.tag == "POUs":
                # The programs the task runs, in the order they run
                task_results["POUs"] = [
                    {
                        "Name": get_text(pou_item, "Name"),
                        "Enabled": convert_to_elastic(get_text(pou_item, "Enabled").title()),
                    }
                    for pou_item in line.findall("Item")
                    if get_text(pou_item, "Name")
                ]
            elif not len(line):
                task_results[line.tag] = convert_to_elastic(get_text(line, "."))
        results[name] = task_results

    device_info["MainController"] = results


def parse_contact_ios(contact: ET.Element, device_info: dict) -> None:
    """Parse ``ContactIO``: the physical contact inputs and outputs of the RTAC."""
    device_info["ContactIO"] = parse_setting_pages(get_item(contact))


def tagname_from_ET(row: ET.Element, identifier: str) -> str:
    """Value of the cell in column ``identifier`` of a setting page ``<Row>``."""
    value = row_to_dict(row).get(identifier)
    return value.strip() if value else ""


def parse_tagprocessor(tag: ET.Element, device_info: dict) -> None:
    """
    Parse the ``TagProcessor``: the tag mappings from sources to
    destinations, e.g. from a relay's tags to a DNP3 server's tags.

    Rows are named ``SolveOrder_<n>`` using the ``SolveOrder`` column.
    """
    results = {}

    item = get_item(tag)
    for page_index, page in enumerate(item.findall("./SettingPages/SettingPage")):
        page_name = get_text(page, "Name", f"page_{page_index}")
        page_results = {}

        for row_index, row in enumerate(page.findall("Row")):
            cells = {
                column: convert_cell(column, value)
                for column, value in row_to_dict(row).items()
                if value is not None and value.strip()
            }
            if not cells:
                continue

            solve_order = tagname_from_ET(row, "SolveOrder")
            key = f"SolveOrder_{solve_order}" if solve_order else f"row_{row_index}"
            if key in page_results:
                key = f"{key}_row_{row_index}"
            page_results[key] = cells

        if page_results:
            results[page_name] = page_results

    device_info["TagProcessor"] = results


def parse_systemtags(tag: ET.Element, device_info: dict) -> None:
    """Parse ``SystemTags``: the tags the RTAC provides, e.g. for alarms and status."""
    device_info["SystemTags"] = parse_setting_pages(get_item(tag), strip_prefix="SystemTags.")


def parse_system_time_control(stc: ET.Element, device_info: dict) -> None:
    """Parse ``SystemTimeControl``: the time source and time zone settings."""
    device_info["SystemTimeControl"] = parse_setting_pages(get_item(stc))


def _end_keyword(interface: str) -> str:
    """``END_*`` keyword for the declaration in a POU interface, or ``""`` if unknown."""
    for line in interface.splitlines():
        # Skip blank lines, comments and attribute pragmas before the declaration
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "(*", "{")):
            continue
        keyword = stripped.split()[0].upper()
        return POU_END_KEYWORDS.get(keyword, "")
    return ""


def _parse_archived_functions(archived: str) -> dict:
    """
    Values of the attributes of the top-level elements in a CODESYS
    ``ArchivedContent`` document, keyed by the value of the first attribute.
    """
    functions = {}
    xml_root = ET.fromstring(archived)
    for element in xml_root:
        items = element.items()
        if not items:
            continue
        functions[items[0][1]] = dict(items)
    return functions


def _parse_code(item: ET.Element) -> dict:
    """
    Parse the code of a POU or a logic engine object.

    There are three forms:

    - ``<Content>`` with ``<Interface>`` and ``<Implementation>`` children
      (Structured Text POUs in newer exports)
    - ``<Interface>`` and ``<Implementation>`` directly under the item
      (``LogicEngineObject``)
    - ``<ArchivedContent>``, a CODESYS archive of the object
      (graphical languages, and older exports)
    """
    results = {}

    content = item.find("Content")
    code_parent = content if content is not None and len(content) else item

    interface = get_code(code_parent, "Interface")
    implementation = get_code(code_parent, "Implementation")
    if interface:
        results["interface"] = interface
    if implementation:
        results["implementation"] = implementation

    archived = get_code(item, "ArchivedContent")
    if archived:
        results["archived_content"] = True
        try:
            functions = _parse_archived_functions(archived)
            if functions:
                results["functions"] = functions
        except ET.ParseError as ex:
            results["archived_content_error"] = str(ex)

    return results


def parse_pous(pou: ET.Element, device_info: dict) -> None:
    """
    Parse a ``POU`` (Program Organization Unit), e.g. a program,
    function block or function, in the user logic.
    """
    item = get_item(pou)
    name = get_text(item, "Name", "unknown")

    results = {}
    kind = get_text(item, "POUKind")
    if kind:
        results["kind"] = kind
    results.update(_parse_code(item))

    device_info.setdefault("POU", {})[name] = results


def parse_logic_engine_objects(leo: ET.Element, device_info: dict) -> None:
    """
    Parse a ``LogicEngineObject``: an object in the shared ``POUs`` folder of
    a project, e.g. a POU, a GVL, the ``Library Manager`` or ``Project Information``.

    For the ``Library Manager``, the names and versions of the
    referenced libraries are under ``"libraries"``.
    """
    item = get_item(leo)
    name = get_text(item, "Name", "unknown")

    results = {}
    obj_type = get_text(item, "Type")
    if obj_type:
        results["type"] = obj_type
    results.update(_parse_code(item))
    # The archive of these objects is not a list of functions
    results.pop("functions", None)

    archived = get_code(item, "ArchivedContent")
    if archived and obj_type == "LibraryManager":
        try:
            archive = ET.fromstring(archived)
            libraries = [
                lib.text.strip()
                for lib in archive.iter("Single")
                if lib.get("Name") == "DefaultResolution" and lib.text and lib.text.strip()
            ]
            if libraries:
                results["libraries"] = libraries
        except ET.ParseError as ex:
            results["archived_content_error"] = str(ex)

    device_info.setdefault("LogicEngineObjects", {})[name] = results


def parse_data_types(data_type: ET.Element, device_info: dict) -> None:
    """Parse a ``DataType`` (a ``TYPE ... END_TYPE`` declaration)."""
    item = get_item(data_type)
    name = get_text(item, "Name", "unknown")
    device_info.setdefault("DataTypes", {})[name] = get_code(item, "Content")


def parse_gvls(gvl: ET.Element, device_info: dict) -> None:
    """Parse a ``GVL`` (a Global Variable List, ``VAR_GLOBAL ... END_VAR``)."""
    item = get_item(gvl)
    name = get_text(item, "Name", "unknown")
    device_info.setdefault("GVL", {})[name] = get_code(item, "Content")


def parse_user_libraries(library: ET.Element, device_info: dict) -> None:
    """Parse a ``UserLibrary``: a library that is added to the user logic."""
    item = get_item(library)
    name = get_text(item, "Name", "unknown")

    results = {
        "Company": get_text(item, "Company"),
        "Title": get_text(item, "Title"),
        "Version": get_text(item, "Version"),
    }
    parameters = {}
    for parameter in item.findall("./ParameterList/Parameter"):
        param_name = get_text(parameter, "Name")
        if param_name:
            parameters[param_name] = convert_to_elastic(get_text(parameter, "Value"))
    if parameters:
        results["Parameters"] = parameters

    device_info.setdefault("UserLibraries", {})[name] = {k: v for k, v in results.items() if v}


def parse_project_info(project_info: ET.Element, device_info: dict) -> None:
    """
    Parse ``Project Info.xml``: the devices (RTACs) in the exported project,
    and the project description.
    """
    item = get_item(project_info)
    results = {}

    devices = []
    for device in item.findall("./ExportSource/Devices/Device"):
        dev_results = {}
        for field in ["Schema", "DeviceMOT", "FolderName"]:
            value = get_text(device, field)
            if value:
                dev_results[field] = convert_to_elastic(value) if field == "Schema" else value
        if dev_results:
            devices.append(dev_results)
    if devices:
        results["Devices"] = devices

    pou_folder = get_text(item, "./ExportSource/POUs/FolderName")
    if pou_folder:
        results["POUFolderName"] = pou_folder

    description = get_text(item, "Description")
    if description:
        results["Description"] = description

    device_info["ProjectInfo"] = results


def parse_iec61850_info(info: ET.Element, device_info: dict) -> None:
    """Parse ``IEC61850Info``: the IEC 61850 IED name of the RTAC."""
    item = get_item(info)
    rtac_name = get_text(item, "RtacName")
    device_info["IEC61850Info"] = {"RtacName": rtac_name} if rtac_name else {}


def parse_backupable_objects(obj: ET.Element, device_info: dict) -> None:
    """
    Parse a ``RTACBackupableObject`` ("Advanced Read-in Items"), e.g.
    ``Ethernet Settings``, ``Website Settings`` or ``Hosts``.

    These have the device settings in the form that the RTAC stores them
    (the database schema). The results are a dict of element name to
    a list of the attributes of each element with that name.
    """
    item = get_item(obj)
    name = get_text(item, "ObjectName", "unknown")

    results = {}
    schema = item.find("./ObjectText/schema")
    if schema is not None:
        if schema.get("version"):
            results["schema_version"] = schema.get("version")
        for element in schema:
            results.setdefault(element.tag, []).append(dict(element.attrib))

    device_info.setdefault("AdvancedSettings", {})[name] = results


def parse_visualizations(visu: ET.Element, device_info: dict) -> None:
    """Record the names of the visualizations (HMI screens) in the project."""
    item = get_item(visu)
    name = get_text(item, "Name", "unknown")
    device_info.setdefault("Visualizations", {})[name] = {"type": item.tag}


def build_structured_text(device_info: dict) -> str:
    """
    Combine the Structured Text code of the data types, global variable
    lists and POUs in the parsed ``device_info`` into one string.

    POUs that only have ``ArchivedContent`` (e.g. graphical languages)
    are not included.
    """
    sections = []

    for name, content in device_info.get("DataTypes", {}).items():
        if content.strip():
            sections.append(f"(* Data type: {name} *)\n{content.strip()}")

    for name, content in device_info.get("GVL", {}).items():
        if content.strip():
            sections.append(f"(* Global variable list: {name} *)\n{content.strip()}")

    for label, key in [("POU", "POU"), ("Shared object", "LogicEngineObjects")]:
        for name, pou in device_info.get(key, {}).items():
            interface = pou.get("interface", "").strip()
            implementation = pou.get("implementation", "").strip()
            if not interface and not implementation:
                continue

            kind = pou.get("kind") or pou.get("type") or ""
            header = f"(* {label}: {name}{f' ({kind})' if kind else ''} *)"
            parts = [header]
            if interface:
                parts.append(interface)
            if implementation:
                parts.append(implementation)
            end_keyword = _end_keyword(interface)
            if end_keyword:
                parts.append(end_keyword)
            sections.append("\n".join(parts))

    if not sections:
        return ""
    return "\n\n".join(sections) + "\n"
