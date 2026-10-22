import io
import tarfile
import xml.etree.ElementTree as ET

import pytest
from loguru import logger

from peat import SELRTAC, config, datastore
from peat.modules.sel import rtac_parse

# Public SEL RTAC project exports. Sources and licenses are in data_files/rtac/SOURCES.md.
RTAC_EXPORTS = {
    "ephcc-microgrid-rtac.tar.gz": {"model": "3530", "schema": [22], "logic": True},
    "ephcc-iec61850-loopback-rtac.tar.gz": {"model": "3530", "schema": [22], "logic": False},
    "pv-rtpp-rtac.tar.gz": {"model": "3555", "schema": [36], "logic": True},
    "iec-checker-selxml-rtac.tar.gz": {"model": "3530", "schema": [32], "logic": True},
    "cross-task-library-example-rtac.tar.gz": {"model": "3530-4", "schema": [33], "logic": True},
    "pmu-data-corrector-rtac.tar.gz": {"model": "3555", "schema": [29], "logic": True},
}


@pytest.fixture
def rtac_path(datapath):
    def _rtac_path(filename: str):
        return datapath(f"rtac/{filename}")

    return _rtac_path


@pytest.fixture
def parse_rtac(mocker, tmp_path):
    """Parse a file or directory with SELRTAC, with output in a temporary directory."""
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp_results"},
    )
    # Prevent overwriting same device in the datastore with a different input file
    mocker.patch.object(datastore, "objects", [])

    return SELRTAC.parse


@pytest.fixture
def log_text():
    """Text of the WARNING and higher messages that PEAT logs (with loguru) during the test."""
    messages = []
    handler_id = logger.add(
        lambda msg: messages.append(f"{msg.record['level'].name}: {msg.record['message']}"),
        level="WARNING",
    )
    yield lambda: "\n".join(messages)
    logger.remove(handler_id)


def _xml(text: str) -> ET.Element:
    return ET.fromstring(text)


def _setting_rows(*rows: tuple[str, str]) -> str:
    return "".join(
        f"<Row><Setting enabled='false'><Column>Setting</Column><Value>{name}</Value></Setting>"
        f"<Setting><Column>Value</Column><Value>{value}</Value></Setting>"
        f"<Setting><Column>Comment</Column><Value /></Setting></Row>"
        for name, value in rows
    )


# ---------- Parsing of the public project exports ----------


@pytest.mark.parametrize("filename", list(RTAC_EXPORTS))
def test_parse_rtac_exports(parse_rtac, rtac_path, filename, log_text):
    expected = RTAC_EXPORTS[filename]
    dev = parse_rtac(rtac_path(filename))

    assert dev is not None
    assert dev.description.model == expected["model"]
    assert dev.extra["ExportSource"]["Schema"] == expected["schema"]
    assert "parse_errors" not in dev.extra
    assert bool(dev.logic.formats.get("structured_text")) is expected["logic"]
    assert (dev._out_dir / "device-data-summary.json").is_file()
    assert (dev._out_dir / "device-data-full.json").is_file()

    # The model is extracted, so there must not be a warning about the default model
    assert "defaulting to '3530'" not in log_text()
    assert "ERROR" not in log_text()
    assert "CRITICAL" not in log_text()


def test_parse_rtac_microgrid(parse_rtac, rtac_path):
    dev = parse_rtac(rtac_path("ephcc-microgrid-rtac.tar.gz"))

    assert dev.name == "MGC"  # IEC 61850 IED name of the RTAC
    assert dev.extra["ProjectInfo"]["Devices"] == [
        {"Schema": 22, "DeviceMOT": "3530", "FolderName": "SEL_RTAC"}
    ]

    devices = dev.extra["Devices"]
    assert len(devices) == 25
    assert sum(d["Protocol"] == "ModbusClient" for d in devices.values()) == 23

    cb101 = devices["CB101"]
    assert cb101["Protocol"] == "ModbusClient"
    assert cb101["Connection Type"] == "Ethernet"
    # Read-only cells (enabled="false") are included
    assert cb101["Settings"]["Server MODBUS Address"] == 255
    assert cb101["Settings"]["Server IP Port"] == 502
    assert cb101["holding_registers"]["CB101_MODBUS.CMD"]["Register Address Start"] == 2001
    assert "pou_pin_settings" not in cb101

    assert devices["PHILUDP"]["Settings"] == {
        "Network Connection Type": "UDP Incoming",
        "Local Port Number": 7201,
    }

    # Data model
    assert {"modbus", "iec61850"} == dev.related.protocols
    assert {502, 7200, 7201, 10507} == dev.related.ports
    assert cb101["Settings"]["Server IP Address"] in dev.related.ip
    assert "CB101" in dev.related.hosts
    assert "PHILUDP" not in dev.related.hosts  # access points are local sockets
    # GOOSE multicast destination MACs are not hosts
    assert not any(mac.startswith("01:0C:CD") for mac in dev.related.mac)

    reg = next(r for r in dev.registers if r.name == "CB101_MODBUS.CMD" and r.group == "CB101")
    assert reg.address == "2001"
    assert reg.protocol == "modbus"
    assert reg.data_type == "inc"  # the data model lowercases the type
    assert reg.measurement_type == "analog"
    assert reg.enabled is True
    assert reg.extra["remote_device"] == "CB101"

    # GOOSE
    goose = dev.extra["GooseDevices"]
    assert len(goose) == 20
    tx = goose["MGC_CFG_MGC_TX"]
    assert tx["Protocol"] == "GooseTx"
    assert tx["Settings"]["Ethernet_Port"] == "Eth_02"
    assert tx["Message"]["GocbRef"]
    assert "message_data" in tx

    # Logic
    st = dev.logic.formats["structured_text"]
    assert "PROGRAM HMI_In_proc" in st
    assert "END_PROGRAM" in st
    assert "TYPE CB:" in st
    assert dev.extra["POU"]["HMI_In_proc"]["kind"] == "Program"
    assert (dev._out_dir / "logic.st").read_text(encoding="utf-8") == st

    assert dev.extra["MainController"]["MainTask"] == {"CycleTime": 100, "WatchdogTime": 15000}
    assert set(dev.extra["TagLists"]) == {"HMI1", "HMI_In"}
    assert dev.extra["UserLibraries"]["SELEthernetController"]["Company"]


def test_parse_rtac_cross_task_example(parse_rtac, rtac_path):
    dev = parse_rtac(rtac_path("cross-task-library-example-rtac.tar.gz"))

    # Model is refined from the default host name ("SEL3530-4-<MAC>")
    assert dev.hostname == "SEL3530-4-0030A702E165"
    assert dev.description.model == "3530-4"

    ifaces = {i.name: i for i in dev.interface}
    assert set(ifaces) == {"Eth_01", "Eth_02", "USB_B1"}
    eth1 = ifaces["Eth_01"]
    assert eth1.ip == "192.168.1.2"
    assert eth1.subnet_mask == "255.255.255.0"
    assert eth1.mac == "00:30:A7:02:E1:65"
    assert eth1.enabled is True
    assert eth1.type == "ethernet"
    assert eth1.extra["device"] == "eth0"
    assert eth1.extra["ipv6_address"] == "fda5:26e8:fcff:1::1/64"
    assert ifaces["USB_B1"].type == "usb"
    assert {"192.168.1.2", "192.168.2.2", "172.29.131.1"} <= dev.related.ip

    tasks = dev.extra["MainController"]
    assert tasks["Automation"]["POUs"][0] == {"Name": "prg_autoTask", "Enabled": True}

    libs = dev.extra["LogicEngineObjects"]["Library Manager"]["libraries"]
    assert "VisuElems, 3.5.13.0 (System)" in libs

    assert dev.extra["UserLibraries"]["CrossTaskData"]["Parameters"] == {"G_P_N_CROSSTASKIDS": 10}
    assert "CrossTaskView" in dev.extra["Visualizations"]
    assert "Cross Task library" in dev.logic.description

    contact_io = dev.extra["ContactIO"]["Contact Inputs"]["SystemTags.IN101"]
    assert contact_io["Tag Type"] == "SPS"
    assert contact_io["Pick Up Delay"] == 20

    assert "Eth_01_Bad_Packets_Received" in dev.extra["SystemTags"]["Communications"]
    assert dev.extra["SystemTimeControl"]["SystemTime"]["Demodulated_IRIG_B_Input"] is True
    assert "SolveOrder_1" in dev.extra["TagProcessor"]["Settings"]


def test_parse_rtac_pmu_data_corrector(parse_rtac, rtac_path):
    dev = parse_rtac(rtac_path("pmu-data-corrector-rtac.tar.gz"))

    assert dev.related.protocols == {"c37.118"}
    assert {"PMU100", "PMU200", "PMU300"} <= dev.related.hosts
    # The multicast group of a client with multicast disabled is not a host
    assert "224.0.1.0" not in dev.related.ip
    assert "10.214.153.69" in dev.related.ip

    # Channels of the PMUs of a C37.118 client
    pmu = dev.extra["Devices"]["PMU100"]["pmus"]["PMU100"]
    assert pmu["Type"] == "C37118ClientPMU"
    assert pmu["phasors"]
    assert pmu["frequency"]
    assert dev.extra["TagLists"]["PMU100_out"]["Type"] == "C37118"
    assert "phasors" in dev.extra["TagLists"]["PMU100_out"]
    assert "END_FUNCTION" in dev.logic.formats["structured_text"]


def test_parse_rtac_directory_matches_tarball(parse_rtac, rtac_path, tmp_path):
    tarball = rtac_path("iec-checker-selxml-rtac.tar.gz")
    from_tar = parse_rtac(tarball)
    tar_extra = dict(from_tar.extra)
    tar_extra.pop("existing_files")

    extract_dir = tmp_path / "extracted"
    with tarfile.open(tarball) as tar:
        tar.extractall(extract_dir, filter="data")
    from_dir = parse_rtac(extract_dir / "iec-checker-selxml")

    assert from_dir.extra == tar_extra
    assert from_dir.logic.formats == from_tar.logic.formats
    assert from_dir.description.model == "3530"


def test_parse_rtac_single_xml_file(parse_rtac, tmp_path):
    xml_file = tmp_path / "Main Controller.xml"
    xml_file.write_bytes(
        b"\xef\xbb\xbf<?xml version='1.0' encoding='utf-8'?><RTACModule><MainController>"
        b"<ExportSource><Schema>36</Schema><DeviceMOT>3555</DeviceMOT></ExportSource>"
        b"<MainTask><CycleTime>8</CycleTime></MainTask></MainController></RTACModule>"
    )

    dev = parse_rtac(xml_file)
    assert dev.description.model == "3555"
    assert dev.extra["MainController"] == {"MainTask": {"CycleTime": 8}}


def test_parse_rtac_bad_files(parse_rtac, tmp_path, log_text):
    """A file that can't be parsed doesn't stop the parse of the other files."""
    export = tmp_path / "export"
    export.mkdir()
    (export / "broken.xml").write_text("<RTACModule><Device>", encoding="utf-8")
    (export / "not-rtac.xml").write_text("<Info><Category /></Info>", encoding="utf-8")
    (export / "empty-module.xml").write_text("<RTACModule />", encoding="utf-8")
    (export / "Project Info.xml").write_text(
        "<RTACModule><ProjectInfo><ExportSource><Devices><Device><Schema>22</Schema>"
        "<DeviceMOT>3530HB0AX313X1XXXXXX</DeviceMOT><FolderName>SEL_RTAC</FolderName>"
        "</Device></Devices></ExportSource></ProjectInfo></RTACModule>",
        encoding="utf-8",
    )

    dev = parse_rtac(export)
    assert dev.extra["parse_errors"] == ["broken.xml"]
    assert "Failed to parse 'broken.xml'" in log_text()
    assert dev.extra["ProjectInfo"]["Devices"][0]["DeviceMOT"] == "3530HB0AX313X1XXXXXX"
    assert dev.description.model == "3530"
    assert dev.part_number == "3530HB0AX313X1XXXXXX"


def test_parse_rtac_project_info_model(parse_rtac, tmp_path, log_text):
    """The model and part number are read from "Project Info.xml" (and uppercase .XML works)."""
    export = tmp_path / "export"
    export.mkdir()
    (export / "PROJECT INFO.XML").write_text(
        "<RTACModule><ProjectInfo><ExportSource><Devices><Device><Schema>36</Schema>"
        "<DeviceMOT>3555RB1XXXX4XXXX</DeviceMOT><FolderName>SEL_RTAC</FolderName>"
        "</Device></Devices></ExportSource></ProjectInfo></RTACModule>",
        encoding="utf-8",
    )

    dev = parse_rtac(export)
    assert dev.description.model == "3555"
    assert dev.part_number == "3555RB1XXXX4XXXX"
    assert "defaulting to '3530'" not in log_text()


def test_parse_rtac_multiple_rtacs(parse_rtac, tmp_path, log_text):
    export = tmp_path / "export"
    export.mkdir()
    (export / "Project Info.xml").write_text(
        "<RTACModule><ProjectInfo><ExportSource><Devices>"
        "<Device><Schema>33</Schema><DeviceMOT>3530</DeviceMOT><FolderName>RTAC_A</FolderName>"
        "</Device><Device><Schema>33</Schema><DeviceMOT>3555</DeviceMOT>"
        "<FolderName>RTAC_B</FolderName></Device>"
        "</Devices></ExportSource></ProjectInfo></RTACModule>",
        encoding="utf-8",
    )

    dev = parse_rtac(export)
    assert "has 2 RTACs" in log_text()
    assert "more than one RTAC model" in log_text()
    assert dev.description.model == "3530"


def test_parse_rtac_invalid_interface(parse_rtac, tmp_path, log_text):
    """An invalid value in the Ethernet settings doesn't stop the parse."""
    export = tmp_path / "export"
    export.mkdir()
    (export / "Ethernet Settings.xml").write_text(
        "<RTACModule><RTACBackupableObject><ObjectName>Ethernet Settings</ObjectName>"
        "<ObjectText><schema version='schema_33'>"
        "<ipv4_network_interfaces ipv4_address='192.0.2.10' network_interface_id='0' "
        "name='Eth_01' mac='not-a-mac' />"
        "<ipv4_network_interfaces ipv4_address='192.0.2.20/16' network_interface_id='1' "
        "name='Eth_02' />"
        "</schema></ObjectText></RTACBackupableObject></RTACModule>",
        encoding="utf-8",
    )
    (export / "Main Controller.xml").write_text(
        "<RTACModule><MainController><MainTask><CycleTime>4</CycleTime></MainTask>"
        "</MainController></RTACModule>",
        encoding="utf-8",
    )

    dev = parse_rtac(export)
    assert "Failed to parse Ethernet interface 'Eth_01'" in log_text()
    assert [i.name for i in dev.interface] == ["Eth_02"]
    assert dev.interface[0].ip == "192.0.2.20"
    assert dev.interface[0].subnet_mask == "255.255.0.0"
    assert dev.interface[0].enabled is None  # no "interface_enabled" attribute
    assert dev.extra["MainController"] == {"MainTask": {"CycleTime": 4}}


def test_parse_rtac_tarball_unsafe_members(parse_rtac, tmp_path):
    # ".tgz" is a gzip-compressed tarball too
    tarball = tmp_path / "unsafe-rtac.tgz"
    main_controller = (
        b"<RTACModule><MainController><MainTask><CycleTime>100</CycleTime>"
        b"</MainTask></MainController></RTACModule>"
    )
    with tarfile.open(tarball, "w:gz") as tar:
        for name, data in [
            ("../escape.xml", main_controller),
            ("export/SEL_RTAC/System/Main Controller.xml", main_controller),
            ("export/SEL_RTAC/project.selaprj", b"\x00\xff\xfe binary data"),
        ]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    dev = parse_rtac(tarball)
    assert dev.extra["existing_files"] == [
        "export/SEL_RTAC/System/Main Controller.xml",
        "export/SEL_RTAC/project.selaprj",
    ]
    assert dev.extra["MainController"] == {"MainTask": {"CycleTime": 100}}
    assert "parse_errors" not in dev.extra
    assert not list(tmp_path.rglob("escape.xml"))
    # There is no model in the files, so the default is used
    assert dev.description.model == "3530"


def test_rtac_file_signature(rtac_path, tmp_path):
    rtac_xml = tmp_path / "Relay1.xml"
    rtac_xml.write_text("<RTACModule><Device /></RTACModule>", encoding="utf-8")
    other_xml = tmp_path / "other.xml"
    other_xml.write_text("<Info />", encoding="utf-8")

    assert any(sig.matches(rtac_xml) for sig in SELRTAC.file_signatures)
    assert not any(sig.matches(other_xml) for sig in SELRTAC.file_signatures)
    # Tarballs are found by their file name (filename_patterns), not by the signature
    tarball = rtac_path("ephcc-microgrid-rtac.tar.gz")
    assert not any(sig.matches(tarball) for sig in SELRTAC.file_signatures)


# ---------- Unit tests of the parsing functions ----------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10", 10),
        ("1.5", 1.5),
        ("True", True),
        ("N", False),
        ("NONE", None),
        ("'Security'", "Security"),
        ("nan", "nan"),
        ("inf", "inf"),
        (None, None),
    ],
)
def test_convert_to_elastic(value, expected):
    assert rtac_parse.convert_to_elastic(value) == expected


def test_parse_setting_page_settings():
    page = _xml(
        "<SettingPage><Name>Settings</Name>"
        + _setting_rows(("Server IP Address", "10.0.0.5"), ("Server IP Port", "502"))
        + "</SettingPage>"
    )
    assert rtac_parse.parse_setting_page(page) == {
        "Server IP Address": "10.0.0.5",
        "Server IP Port": 502,
    }


def test_parse_setting_page_table():
    page = _xml(
        "<SettingPage><Name>Binary Inputs</Name>"
        "<Row><Setting><Column>Enable</Column><Value>True</Value></Setting>"
        "<Setting enabled='false'><Column>Tag Name</Column><Value>R1.IN101</Value></Setting>"
        "<Setting><Column>Point Number</Column><Value>0</Value></Setting>"
        "<Setting><Column>Comment</Column><Value /></Setting></Row>"
        "<Row><Setting><Column>Tag Name</Column><Value>R1.IN101</Value></Setting>"
        "<Setting><Column>Point Number</Column><Value>1</Value></Setting></Row>"
        "<Row><Setting><Column>Point Number</Column><Value>2</Value></Setting></Row>"
        "<Row><Setting><Column>Comment</Column><Value /></Setting></Row>"
        "</SettingPage>"
    )
    assert rtac_parse.parse_setting_page(page) == {
        "R1.IN101": {"Enable": True, "Tag Name": "R1.IN101", "Point Number": 0},
        "R1.IN101_row_1": {"Tag Name": "R1.IN101", "Point Number": 1},
        "row_2": {"Point Number": 2},
    }


def test_parse_setting_page_text_columns():
    """Names and other identifiers are not converted to numbers or booleans."""
    page = _xml(
        "<SettingPage><Name>Binary Inputs</Name>"
        "<Row><Setting><Column>Tag Name</Column><Value>Y</Value></Setting>"
        "<Setting><Column>Tag Alias</Column><Value>007</Value></Setting>"
        "<Setting><Column>Point Number</Column><Value>007</Value></Setting></Row>"
        "<Row><Setting><Column>Tag Name</Column><Value>None</Value></Setting>"
        "<Setting><Column>Enable</Column><Value>False</Value></Setting></Row>"
        "</SettingPage>"
    )
    assert rtac_parse.parse_setting_page(page) == {
        "Y": {"Tag Name": "Y", "Tag Alias": "007", "Point Number": 7},
        "None": {"Tag Name": "None", "Enable": False},
    }


def test_parse_devices_dnp():
    info = {}
    rtac_parse.parse_devices(
        _xml(
            "<RTACModule><Device><Name>Relay1</Name><Manufacturer>SEL</Manufacturer>"
            "<Model>SEL-351S</Model><Connection><Protocol>DNPClient</Protocol>"
            "<ConnectionType>Ethernet</ConnectionType><SettingPages>"
            "<SettingPage><Name>Settings</Name>"
            + _setting_rows(("Server IP Address", "10.0.0.5"), ("Server DNP Address", "10"))
            + "</SettingPage><SettingPage><Name>Binary Inputs</Name>"
            "<Row><Setting><Column>Tag Name</Column><Value>Relay1.IN101</Value></Setting>"
            "<Setting><Column>Point Number</Column><Value>3</Value></Setting></Row>"
            "</SettingPage><SettingPage><Name>Analog Inputs</Name></SettingPage>"
            "</SettingPages></Connection></Device></RTACModule>"
        ),
        info,
    )
    assert info["Devices"]["Relay1"] == {
        "Manufacturer": "SEL",
        "Model": "SEL-351S",
        "Protocol": "DNPClient",
        "Connection Type": "Ethernet",
        "Settings": {"Server IP Address": "10.0.0.5", "Server DNP Address": 10},
        "binary_inputs": {"Relay1.IN101": {"Tag Name": "Relay1.IN101", "Point Number": 3}},
    }


def test_rtac_registers_dnp(mocker):
    mocker.patch.object(datastore, "objects", [])
    dev = datastore.get("rtac-registers-test", "id")
    rem_dev = {
        "Protocol": "DNPClient",
        "Settings": {"Server IP Address": "10.0.0.5"},
        "binary_inputs": {"Relay1.IN101": {"Tag Name": "Relay1.IN101", "Point Number": 3}},
    }
    SELRTAC._process_device_registers(dev, "Relay1", rem_dev, "dnp3")

    assert len(dev.registers) == 1
    assert dev.registers[0].address == "3"
    assert dev.registers[0].protocol == "dnp3"
    assert dev.registers[0].measurement_type == "binary"
    assert SELRTAC._normalize_protocol("DNPClient") == "dnp3"
    assert SELRTAC._normalize_protocol("AccessPointServer") == ""
    assert SELRTAC._normalize_protocol("SomethingNew") == "somethingnew"


def test_parse_pous_forms():
    info = {}
    rtac_parse.parse_pous(
        _xml(
            "<RTACModule><POU><Name>P1</Name><POUKind>Program</POUKind><Content>"
            "<Interface><![CDATA[PROGRAM P1\nVAR\n  x : INT;\nEND_VAR]]></Interface>"
            "<Implementation><![CDATA[x := x + 1;]]></Implementation>"
            "</Content></POU></RTACModule>"
        ),
        info,
    )
    rtac_parse.parse_pous(
        _xml(
            "<RTACModule><POU><Name>FB1</Name><POUKind>FunctionBlock</POUKind>"
            "<ArchivedContent><![CDATA[<Single Type='{abc}' Method='IArchivable'>"
            "<Single Name='SpecialFunc' Type='{def}'>None</Single></Single>]]>"
            "</ArchivedContent></POU></RTACModule>"
        ),
        info,
    )
    rtac_parse.parse_pous(_xml("<RTACModule><POU><Name>Empty</Name></POU></RTACModule>"), info)

    assert info["POU"]["P1"] == {
        "kind": "Program",
        "interface": "PROGRAM P1\nVAR\n  x : INT;\nEND_VAR",
        "implementation": "x := x + 1;",
    }
    assert info["POU"]["FB1"] == {
        "kind": "FunctionBlock",
        "archived_content": True,
        "functions": {"SpecialFunc": {"Name": "SpecialFunc", "Type": "{def}"}},
    }
    assert info["POU"]["Empty"] == {}

    st = rtac_parse.build_structured_text(info)
    assert st == (
        "(* POU: P1 (Program) *)\nPROGRAM P1\nVAR\n  x : INT;\nEND_VAR\nx := x + 1;\nEND_PROGRAM\n"
    )


@pytest.mark.parametrize(
    ("interface", "expected"),
    [
        ("PROGRAM P", "END_PROGRAM"),
        ("// comment\n{attribute 'x'}\nFUNCTION_BLOCK FB EXTENDS X", "END_FUNCTION_BLOCK"),
        ("function F : INT", "END_FUNCTION"),
        ("METHOD M : BOOL", ""),
        ("", ""),
    ],
)
def test_end_keyword(interface, expected):
    assert rtac_parse._end_keyword(interface) == expected


def test_parse_maincontroller_unnamed_task():
    info = {}
    rtac_parse.parse_maincontroller(
        _xml(
            "<RTACModule><MainController><MainTask><CycleTime>4</CycleTime></MainTask>"
            "<Task><CycleTime>1000</CycleTime></Task></MainController></RTACModule>"
        ),
        info,
    )
    assert info["MainController"] == {
        "MainTask": {"CycleTime": 4},
        "Task_0": {"CycleTime": 1000},
    }


def test_parse_accesspointrouters():
    info = {}
    rtac_parse.parse_accesspointrouters(
        _xml(
            "<RTACModule><AccessPointRouter><Name>APR1</Name>"
            "<Source><DeviceName>Relay1</DeviceName><DeviceProtocol>SEL</DeviceProtocol>"
            "<type>Engineering</type></Source>"
            "<Destination><DeviceName>AP1</DeviceName></Destination>"
            "<SettingPages><SettingPage><Name>Settings</Name>"
            + _setting_rows(("Enable_Legacy_Port_Command", "False"))
            + "</SettingPage></SettingPages></AccessPointRouter></RTACModule>"
        ),
        info,
    )
    assert info["AccessPointRouters"]["APR1"] == {
        "Source": {"device_name": "Relay1", "device_protocol": "SEL", "type": "Engineering"},
        "Destination": {"device_name": "AP1", "device_protocol": "", "type": ""},
        "Settings": {"Enable_Legacy_Port_Command": False},
    }


def test_get_item_empty_module():
    with pytest.raises(ValueError, match="No item element"):
        rtac_parse.get_item(_xml("<RTACModule />"))
