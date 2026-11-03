import filecmp
import io
from datetime import timedelta
from pathlib import Path

import l5x
import pytest

from peat import L5X, config, datastore
from peat.modules.rockwell import l5x_parse

# !!! NOTE !!!
# If the output format changed and the tests are failing, then regenerate
# the expected output files using the test file regen script :)
# "pdm run python tests/generate_test_data_files.py L5X"


# TODO: re-generate test data from the open-source repos
# Note that the point of these tests is to validate PEAT's
# post-processing of L5X file data into the data model. Most
# of the lower-level parsing is handled by the open-source
# "l5x" python package: https://github.com/jvalenzuela/l5x
data_files = [
    # Default GitHub license
    # https://github.com/drbitboy/plc_rng
    "plc_rng/A_Gauss_RNG.L5X",
    "plc_rng/a_RMPS.L5X",
    "plc_rng/A_Uniform_RNG.L5X",
    "plc_rng/Random_AOI_Test_01042020.L5X",
    # GPLv3 license
    # https://github.com/jmorit/l5x_test/tree/master/l5x_jm
    "basetest.L5X",
]


# TODO: Re-add l5x tests from open-source examples after open sourcing
# https://github.com/drbitboy/plc_rng
# https://github.com/jmorit/l5x_test/tree/master/l5x_jm
@pytest.mark.skip("Re-add l5x tests from open-source examples after open sourcing")
@pytest.mark.parametrize("input_path", data_files)
def test_parse_l5x(
    json_data,
    tmp_path,
    mocker,
    dev_data_compare,
    assert_glob_path,
    input_path,
    examples_dir,
):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "device_results",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    # Prevent overwriting same device in the datastore with a different input file
    mocker.patch.object(datastore, "objects", [])

    source_file = Path(examples_dir, "devices", "l5x", input_path)

    dev = L5X.parse(source_file)

    # Check the exported data without the raw data nearly matches what's expected
    exported_summary = dev.export_summary()
    dev_data_compare(
        json_data(f"{source_file.stem}_expected_device-data-summary.json"),
        exported_summary,
    )

    # Check the exported full data nearly matches what's expected
    exported_full = dev.export(include_original=True)
    dev_data_compare(
        json_data(f"{source_file.stem}_expected_device-data-full.json"), exported_full
    )

    assert dev.logic.hash.sha256 == dev.logic.file.hash.sha256

    with source_file.open(encoding="utf-8", newline="") as f:
        assert dev.logic.original == f.read()

    assert filecmp.cmp(dev._out_dir / source_file.name, source_file)  # type: ignore
    assert_glob_path(dev._out_dir, "device-data-summary.json")
    assert_glob_path(dev._out_dir, "device-data-full.json")


# Synthetic L5X project, in the structure of Studio 5000 exports (verified against
# the public "basetest.L5X" and "plc_rng" samples): a 1756-L83E controller with a
# local 1756-EN2T and a digital input card, a remote 1734-AENT adapter (with an
# input module behind it) on the EN2T's network, and a drive on the controller's
# built-in Ethernet port.
SYNTHETIC_L5X = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RSLogix5000Content SchemaRevision="1.0" SoftwareRevision="32.00" TargetName="Line1"
 TargetType="Controller" ContainsContext="false" Owner="PEAT"
 ExportDate="Mon Jan 06 10:00:00 2025">
<Controller Use="Target" Name="Line1_PLC" ProcessorType="1756-L83E" MajorRev="32"
 MinorRev="11" CommPath="AB_ETHIP-1\\\\192.0.2.10\\\\Backplane\\\\0">
<Modules>
<Module Name="Local" CatalogNumber="1756-L83E" Vendor="1" ProductType="14"
 ProductCode="166" Major="32" Minor="11" ParentModule="Local" ParentModPortId="1"
 Inhibited="false" MajorFault="true">
<Ports>
<Port Id="1" Address="0" Type="ICP" Upstream="false"><Bus Size="10"/></Port>
<Port Id="2" Address="192.0.2.10" Type="Ethernet" Upstream="false"><Bus/></Port>
</Ports>
</Module>
<Module Name="ENET_SLOT2" CatalogNumber="1756-EN2T/D" Vendor="1" ProductType="12"
 ProductCode="166" Major="11" Minor="1" ParentModule="Local" ParentModPortId="1"
 Inhibited="false" MajorFault="false">
<Ports>
<Port Id="1" Address="2" Type="ICP" Upstream="true"/>
<Port Id="2" Address="198.51.100.1" Type="Ethernet" Upstream="false"><Bus/></Port>
</Ports>
</Module>
<Module Name="IO_SLOT3" CatalogNumber="1756-IB16/A" Vendor="1" ProductType="7"
 ProductCode="11" Major="3" Minor="1" ParentModule="Local" ParentModPortId="1"
 Inhibited="false" MajorFault="false">
<Ports><Port Id="1" Address="3" Type="ICP" Upstream="true"/></Ports>
</Module>
<Module Name="Remote_AENT" CatalogNumber="1734-AENT/B" Vendor="1" ProductType="12"
 ProductCode="146" Major="5" Minor="1" ParentModule="ENET_SLOT2" ParentModPortId="2"
 Inhibited="true" MajorFault="false">
<Ports>
<Port Id="1" Address="0" Type="PointIO" Upstream="false"><Bus Size="5"/></Port>
<Port Id="2" Address="198.51.100.20" Type="Ethernet" Upstream="true"/>
</Ports>
</Module>
<Module Name="Remote_IB8" CatalogNumber="1734-IB8/C" Vendor="1" ProductType="7"
 ProductCode="10" Major="3" Minor="1" ParentModule="Remote_AENT" ParentModPortId="1"
 Inhibited="false" MajorFault="false">
<Ports><Port Id="1" Address="1" Type="PointIO" Upstream="true"/></Ports>
</Module>
<Module Name="Drive1" CatalogNumber="PowerFlex 525-EENET" Vendor="1" ProductType="143"
 ProductCode="9" Major="5" Minor="1" ParentModule="Local" ParentModPortId="2"
 Inhibited="false" MajorFault="true">
<Ports><Port Id="2" Address="192.0.2.30" Type="Ethernet" Upstream="true"/></Ports>
</Module>
</Modules>
<Programs>
<Program Name="MainProgram" MainRoutineName="MainRoutine"><Routines/></Program>
<Program Name="Fast"><Routines/></Program>
</Programs>
<Tasks>
<Task Name="MainTask" Type="CONTINUOUS" Priority="10" Watchdog="500"
 DisableUpdateOutputs="false" InhibitTask="false">
<Description><![CDATA[Main control loop]]></Description>
<ScheduledPrograms><ScheduledProgram Name="MainProgram"/></ScheduledPrograms>
</Task>
<Task Name="FastTask" Type="PERIODIC" Rate="10" Priority="5" Watchdog="100"
 InhibitTask="true">
<ScheduledPrograms><ScheduledProgram Name="Fast"/></ScheduledPrograms>
</Task>
<Task Name="OnInput" Type="EVENT" Rate="50" Priority="3" Watchdog="200"
 InhibitTask="false">
<EventInfo EventTrigger="Module Input Data State Change" EnableTimeout="true"/>
</Task>
</Tasks>
</Controller>
</RSLogix5000Content>
"""


@pytest.fixture
def synthetic_project():
    return l5x.Project(io.StringIO(SYNTHETIC_L5X))


def test_l5x_get_tasks(synthetic_project):
    tasks = {t.name: t for t in l5x_parse.get_tasks(synthetic_project)}
    assert list(tasks) == ["MainTask", "FastTask", "OnInput"]

    main = tasks["MainTask"]
    assert main.type == "continuous"
    assert main.priority == 10
    assert main.watchdog == timedelta(milliseconds=500)
    assert main.interval is None
    assert main.enabled is True
    assert main.programs == ["MainProgram"]
    assert main.description == "Main control loop"
    assert main.extra == {"vendor_type": "CONTINUOUS", "disable_update_outputs": False}

    fast = tasks["FastTask"]
    assert fast.type == "periodic"
    assert fast.interval == timedelta(milliseconds=10)
    assert fast.enabled is False  # InhibitTask="true"
    assert fast.programs == ["Fast"]

    event = tasks["OnInput"]
    assert event.type == "event"
    assert event.interval is None
    assert event.extra["vendor_type"] == "EVENT"
    assert event.extra["event_trigger"] == "Module Input Data State Change"


def test_l5x_io_tree(synthetic_project):
    modules = l5x_parse.get_modules_data(synthetic_project)
    assert l5x_parse.get_local_module_names(modules) == {"Local", "ENET_SLOT2", "IO_SLOT3"}

    rels = {r.remote.name: r for r in l5x_parse.get_io_relationships(modules)}
    # The input module behind the adapter is not on the network
    assert set(rels) == {"Remote_AENT", "Drive1"}

    aent = rels["Remote_AENT"]
    assert aent.type == "communicates_with"
    assert aent.protocol == "cip"
    assert aent.direction == "egress"
    assert aent.evidence == {"config"}
    assert aent.local.role == "scanner"
    assert aent.local.ip == "198.51.100.1"  # the local EN2T
    assert aent.remote.role == "adapter"
    assert aent.remote.ip == "198.51.100.20"
    assert aent.extra == {
        "catalog_number": "1734-AENT/B",
        "parent_module": "ENET_SLOT2",
        "inhibited": True,
        "major_fault_on_failure": False,
    }

    drive = rels["Drive1"]
    assert drive.local.ip == "192.0.2.10"  # the controller's built-in port
    assert drive.remote.ip == "192.0.2.30"
    assert drive.extra["major_fault_on_failure"] is True

    # A module whose parent is missing from the project is not local
    orphan = [{"name": "X", "parent_module": "Missing", "parent_mod_port_id": "1", "ports": []}]
    assert l5x_parse.get_local_module_names(orphan) == set()


def test_l5x_parse_synthetic(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "device_results",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    source_file = tmp_path / "line1.L5X"
    source_file.write_text(SYNTHETIC_L5X, encoding="utf-8")

    dev = L5X.parse(source_file)

    assert dev.ip == "192.0.2.10"
    assert sorted(t.name for t in dev.logic.tasks) == ["FastTask", "MainTask", "OnInput"]

    # Only the Ethernet ports of the local chassis are controller interfaces
    # (bug fix: the IPs of the remote adapter and the drive were copied here)
    assert {i.ip for i in dev.interface if i.ip} == {"192.0.2.10", "198.51.100.1"}

    io_rels = [r for r in dev.relationships if r.protocol == "cip"]
    assert {r.remote.ip for r in io_rels} == {"198.51.100.20", "192.0.2.30"}
    assert all(r.id for r in io_rels)
    assert {"198.51.100.20", "192.0.2.30"} <= dev.related.ip

    # Remote modules keep their own interfaces
    aent = next(m for m in dev.module if m.name == "Remote_AENT")
    assert aent.interface[0].ip == "198.51.100.20"

    # Parsing the same project again doesn't duplicate tasks or relationships
    dev = L5X.parse(source_file)
    assert len(dev.logic.tasks) == 3
    assert len([r for r in dev.relationships if r.protocol == "cip"]) == 2


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("500", timedelta(milliseconds=500)),
        ("0.5", timedelta(microseconds=500)),
        ("1e20", None),
        ("inf", None),
        ("-inf", None),
        ("nan", None),
        ("-5", None),
        ("abc", None),
        (None, None),
    ],
)
def test_l5x_milliseconds(value, expected):
    assert l5x_parse._milliseconds(value) == expected


def test_l5x_parse_out_of_range_task_times(mocker, tmp_path):
    """A Rate or Watchdog too large for a timedelta doesn't abort the parse."""
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "device_results",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    text = SYNTHETIC_L5X.replace(
        'Name="MainTask" Type="CONTINUOUS" Priority="10" Watchdog="500"',
        'Name="MainTask" Type="CONTINUOUS" Priority="10" Watchdog="1e20"',
    ).replace(
        'Name="FastTask" Type="PERIODIC" Rate="10"', 'Name="FastTask" Type="PERIODIC" Rate="inf"'
    )
    assert text.count("1e20") == 1
    assert text.count('Rate="inf"') == 1
    source_file = tmp_path / "out_of_range_task_times.L5X"
    source_file.write_text(text, encoding="utf-8")

    dev = L5X.parse(source_file)

    tasks = {t.name: t for t in dev.logic.tasks}
    assert sorted(tasks) == ["FastTask", "MainTask", "OnInput"]
    assert tasks["MainTask"].watchdog is None
    assert tasks["FastTask"].interval is None
    assert tasks["FastTask"].watchdog == timedelta(milliseconds=100)
