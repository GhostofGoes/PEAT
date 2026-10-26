import json
import socket

import pytest

from peat import S7, config, datastore, module_api, parse

from .s7_helpers import SZL_001C, SZL_0011, SZL_0424_RUN, FakePLC


@pytest.fixture(autouse=True)
def peat_dirs(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
            "SUMMARIES_DIR": tmp_path / "summaries",
        },
    )
    # Prevent devices from other tests or input files from being reused
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


def make_dev(port: int, rack_slots: list | None = None):
    dev = datastore.get("127.0.0.1")
    dev._runtime_options["s7comm"] = {"port": port, "timeout": 2.0}
    if rack_slots is not None:
        dev._runtime_options["s7"] = {"rack_slots": rack_slots}
    return dev


def test_module_registered():
    assert module_api.get_module("S7") is S7
    assert module_api.get_modules("step7") == [S7]
    assert S7.ip_methods[0].protocol == "s7comm"
    assert S7.ip_methods[0].default_port == 102


def test_parse_step7_project(datapath, caplog):
    source = datapath("dotnetsiemensplctoolboxlibrary/UnitTest_Simatic_Project.zip")
    dev = S7.parse(source)

    assert dev.id == "UnitTest"
    assert dev.type == "PLC"
    assert dev.description.vendor.id == "Siemens"
    assert dev.logic.name == "UnitTest"
    assert dev.logic.id == "{7AC4BFF9-85CA-482A-88C9-72AC3631E1BE}"
    assert dev.logic.description == "TestMC7Converter (S7 CPU), TestParameter (S7 CPU)"
    assert dev.logic.created.year == 2016

    # Symbols from both symbol tables
    assert len(dev.tag) == 11
    assert any(t.name == "GET" and t.address == "SFB 14" for t in dev.tag)

    # Change log entries become events
    assert len(dev.event) == 3
    assert all(e.dataset == "step7_change_log" for e in dev.event)
    assert dev.event[0].extra["computer"] == "WIN-O530NBMG6RG"
    assert "WIN-O530NBMG6RG" in dev.related.hosts

    blocks = dev.extra["step7_project"]["block_folders"][0]["blocks"]
    assert len(blocks) == 10
    assert (dev._out_dir / "step7-project.json").is_file()
    assert (dev._out_dir / source.name).is_file()
    assert "ERROR" not in caplog.text


def test_parse_tia_project(datapath):
    dev = S7.parse(datapath("dotnetsiemensplctoolboxlibrary/TestProjekt.zap19"))
    assert dev.id == "TestProjekt"
    assert dev.description.model == "CPU 1515-2 PN"
    assert dev.logic.description == "TIA Portal V19 project"
    assert dev.extra["tia_project"]["ipv4_addresses"] == ["192.168.0.1", "192.168.1.1"]


def test_parse_simaticml_block(datapath):
    source = datapath("tia-portal-openness-mcp/MCPVerify_FC_SCL_E2E.xml")
    dev = S7.parse(source)
    assert dev.id == "MCPVerify_FC_SCL_E2E"
    assert dev.logic.name == "MCPVerify_FC_SCL_E2E"
    assert dev.logic.formats["scl"].startswith("// MCPVerify_FC_SCL_E2E, network 1\n#OutBool :=")
    assert dev.logic.original == source.read_bytes().decode("utf-8-sig")
    assert dev.extra["simaticml"]["engineering_version"] == "V21"


def test_parse_simaticml_tag_table(datapath):
    dev = S7.parse(datapath("tia-portal-openness-mcp/MCP_E2E_Tags.xml"))
    assert dev.id == "MCP_E2E"
    assert [(t.name, t.address, t.type) for t in dev.tag] == [
        ("StartPB", "%I0.0", "bool"),
        ("StopPB", "%I0.1", "bool"),
        ("EStop", "%I0.2", "bool"),
        ("RunOut", "%Q0.0", "bool"),
    ]


def test_parse_stl_source(datapath):
    source = datapath("step7-classic-algorithms/TON_D_ms.awl")
    dev = S7.parse(source)
    assert dev.id == "TON_D_ms"
    assert dev.logic.author == "LEONARDO"
    assert dev.logic.description == "ON-DELAY_TIMER_MSEC"
    assert dev.logic.formats["stl"] == source.read_bytes().decode()


def test_parse_symbol_table(datapath):
    dev = S7.parse(datapath("awlsim/trafficlights_2.asc"))
    assert dev.id == "trafficlights_2"
    assert len(dev.tag) == 9
    # STEP 7 V5 exports are in the Windows ANSI code page
    assert dev.tag[2].description == "Autoampel Grün"


def test_parse_raw_data(datapath):
    """Data without a file name is identified by the file signatures."""
    data = datapath("dotnetsiemensplctoolboxlibrary/UnitTest_Simatic_Project.zip").read_bytes()
    assert S7.parse(data).id == "UnitTest"

    tags = datapath("tia-portal-openness-mcp/MCP_E2E_Tags.xml").read_bytes()
    assert S7.parse(tags).id == "MCP_E2E"


def test_parse_api_detects_all_files(datadir):
    """
    All the example files are found and parsed by the S7 module when
    parsing the directory with all modules enabled.
    """
    summary = parse(datadir)
    assert summary is not None
    parsed = {r["name"] for r in summary["parse_results"] if r["module"] == "S7"}
    assert parsed >= {
        "UnitTest_Simatic_Project.zip",
        "TestProjekt.zap19",
        "GraphJump.xml",
        "plcBlock_LAD_Block_Logic.xml",
        "MCPVerify_FC_SCL_E2E.xml",
        "DB_HMI_Interface.xml",
        "MCP_E2E_Tags.xml",
        "TON_D_ms.awl",
        "trafficlights_2.awl",
        "trafficlights_2.asc",
        "GET_OUC.scl",
        "Globaldaten.scl",
    }
    assert not [f for f in summary["parse_failures"] if f["module"] == "S7"]


def test_verify_s7comm():
    plc = FakePLC({0x0011: SZL_0011}, accept_slot=0)
    try:
        dev = make_dev(plc.port)
        assert S7._verify_s7comm(dev) is True
    finally:
        plc.close()

    assert dev.part_number == "6ES7 315-2EH14-0AB0"
    assert dev.firmware.version == "3.2.6"
    # Slot 2 (default first try) was refused, so slot 0 was used and cached
    assert dev._cache["s7_rack_slot"] == (0, 0)
    assert dev.service[0].protocol == "s7comm"
    assert dev.service[0].status == "verified"


def test_verify_s7comm_closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    assert S7._verify_s7comm(make_dev(port)) is False


def test_pull():
    plc = FakePLC({0x0011: SZL_0011, 0x001C: SZL_001C, 0x0424: SZL_0424_RUN}, fragment_size=150)
    try:
        dev = make_dev(plc.port, rack_slots=[[0, 2]])
        assert S7.pull(dev) is True
    finally:
        plc.close()

    assert dev.name == "Pump Station 1"
    assert dev.serial_number == "S C-X4U421302009"
    assert dev.description.model == "CPU 315-2 PN/DP"
    assert dev.part_number == "6ES7 315-2EH14-0AB0"
    assert dev.hardware.version == "4"
    assert dev.firmware.version == "3.2.6"
    assert dev.run_mode == "RUN"
    assert dev.status == "running"
    assert dev.extra["block_counts"] == {"OB": 1, "DB": 3, "FC": 2, "FB": 1, "SFC": 16}
    assert dev.extra["component_identification"]["plant_id"] == "PLANT-A"
    assert dev.successful_pulls["s7comm"] is True

    pulled = json.loads((dev.get_out_dir() / "s7comm-pull.json").read_text())
    assert pulled["rack_slot"] == [0, 2]


def test_pull_optional_reads_unsupported(caplog):
    """CPUs that don't support SZL 0x001C or 0x0424 still produce a successful pull."""
    plc = FakePLC({0x0011: SZL_0011})
    try:
        dev = make_dev(plc.port, rack_slots=[[0, 2]])
        assert S7.pull(dev) is True
    finally:
        plc.close()

    assert dev.part_number == "6ES7 315-2EH14-0AB0"
    assert dev.run_mode == ""
    assert "Failed to read component identification" in caplog.text


def test_pull_against_snap7_server():
    snap7_server = pytest.importorskip("snap7.server")
    server = snap7_server.Server()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server.start(tcp_port=port)
    try:
        dev = make_dev(port)
        assert S7._verify_s7comm(dev) is True
        assert S7.pull(dev) is True
    finally:
        server.stop()

    assert dev.part_number == "6ES7 315-2EH14-0AB0"
    assert dev.description.model == "CPU 315-2 PN/DP"
    assert dev.name == "SNAP7-SERVER"
