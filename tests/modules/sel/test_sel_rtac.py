"""
Tests for the SEL RTAC module helpers (peat/modules/sel/sel_rtac.py,
peat/modules/sel/rtac_parse.py) with synthetic inputs.
"""

import io
import tarfile
import xml.etree.ElementTree as ET

import pytest

from peat import SELRTAC, DeviceData, datastore
from peat.data.validators import ECS_EVENT_VALUES
from peat.modules.sel.rtac_parse import parse_maincontroller
from peat.modules.sel.sel_rtac import (
    config_change_alert,
    maincontroller_tasks,
    rtac_config_relationships,
    rtac_serial_type,
    rtac_tar_member_file,
)

# Rows as pulled by SELRTAC.pull_postgres(): {table: {first column value: {column: value}}}
# (remote_devices row from the code comment in pull_postgres())
CONFIG = {
    "remote_devices": {
        32: {"remote_device_id": 32, "name": "SEL_411L_E1", "model": "411L"},
        33: {"remote_device_id": 33, "name": "SEL_751_FDR2", "model": "751"},
        34: {"remote_device_id": 34, "name": "Eng_Access_40", "model": None},
        35: {"remote_device_id": 35, "name": "METER_7", "model": "735"},
        36: {"remote_device_id": 36, "name": "SEL_351_SER", "model": "351"},
    },
    "dnp_client_ethernet_settings": {
        1: {
            "remote_device_id": 32,
            "server_ip_address": "192.0.2.41",
            "server_ip_port": 20000,
            "local_tcp_port": 0,
            "ssh_username": "rtacuser",
        },
    },
    "sel_client_ethernet_settings": {
        1: {
            "remote_device_id": 33,
            "server_ip_address": "192.0.2.42",
            "server_ip_port": 23,
            "local_tcp_port": None,
        },
    },
    "modbus_ethernet_settings": {
        1: {"server_ip_address": "", "server_ip_port": 502},  # not configured
    },
    "serial_ports": {
        7: {"serial_port_id": 7, "device_file": "/dev/ttyS2", "serial_port_type_id": 485},
    },
    "dnp_serial_ports": {
        1: {"serial_port_id": 7, "remote_device_id": 36},
        2: {"serial_port_id": 99},  # no remote device: skipped
    },
}


@pytest.fixture(autouse=True)
def _clean_datastore(mocker):
    mocker.patch.object(datastore, "objects", [])


def test_config_change_alert_is_valid_ecs():
    alert = config_change_alert(["web_diagnostics.cpu", "users.admin", "users.admin"])
    event = alert["event"]
    assert event["kind"] == "alert"
    assert event["kind"] in ECS_EVENT_VALUES["kind"]
    assert event["category"] == ["configuration"]
    assert set(event["category"]) <= set(ECS_EVENT_VALUES["category"])
    assert event["type"] == ["change"]
    assert event["reason"] == "changed: users.admin, web_diagnostics.cpu"
    assert event["module"] == "SELRTAC"


def test_compare_dictionaries_changed_paths():
    paths = []
    old = {"a": {"b": 1, "c": 2}, "users": {"x": {"last_access": "1"}}, "gone": 1}
    new = {"a": {"b": 1, "c": 3}, "users": {"x": {"last_access": "2"}}, "added": 1}
    keys, values, _ = SELRTAC.compare_dictionaries(old, new, "d1", "d2", changed_paths=paths)
    assert sorted(paths) == ["a.c", "added", "gone"]  # last_access is transient
    assert values
    assert keys


@pytest.mark.parametrize(
    ("type_id", "expected"),
    [(232, "rs_232"), ("422", "rs_422"), (485, "rs_485"), (None, "serial"), ("usb", "serial")],
)
def test_rtac_serial_type(type_id, expected):
    assert rtac_serial_type(type_id) == expected


def test_rtac_config_relationships():
    dev = DeviceData(ip="192.0.2.5")
    for rel in rtac_config_relationships(CONFIG):
        dev.store("relationships", rel)

    by_name = {r.remote.name: r for r in dev.relationships}
    dnp = by_name["SEL_411L_E1"]
    assert (dnp.protocol, dnp.transport, dnp.direction) == ("dnp3", "tcp", "egress")
    assert (dnp.local.role, dnp.remote.role) == ("master", "outstation")
    assert (dnp.remote.ip, dnp.remote.port) == ("192.0.2.41", 20000)
    assert dnp.extra == {"remote_model": "411L"}
    assert dnp.evidence == {"config"}

    sel = by_name["SEL_751_FDR2"]
    assert (sel.protocol, sel.local.role, sel.remote.role) == ("sel", "client", "server")

    tunnel = by_name["Eng_Access_40"]
    assert tunnel.type == "tunnel"
    assert tunnel.remote.role == "engineering_access"

    meter = by_name["METER_7"]  # no connection settings: name only
    assert meter.type == "communicates_with"
    assert not meter.protocol

    serial = by_name["SEL_351_SER"]
    assert serial.protocol == "dnp3"
    assert serial.medium == "rs_485"
    assert serial.local.serial_port == "/dev/ttyS2"
    assert serial.local.role == "master"

    assert len(dev.relationships) == 5
    assert "192.0.2.41" in dev.related.ip


def test_rtac_config_relationships_non_ip_server_address():
    config = {
        "remote_devices": {
            1: {"remote_device_id": 1, "name": "RELAY_A"},
            2: {"remote_device_id": 2, "name": "RELAY_B"},
            3: {"remote_device_id": 3, "name": "RELAY_C"},
        },
        "dnp_client_ethernet_settings": {
            1: {"remote_device_id": 1, "server_ip_address": "relay1.substation.local"},
            2: {"remote_device_id": 2, "server_ip_address": "10.0.0.1/24"},
            3: {"remote_device_id": 3, "server_ip_address": "010.000.000.003"},
        },
    }
    dev = DeviceData(ip="192.0.2.5")
    for rel in rtac_config_relationships(config):
        dev.store("relationships", rel)
    by_name = {r.remote.name: r for r in dev.relationships}
    assert (by_name["RELAY_A"].remote.ip, by_name["RELAY_A"].remote.hostname) == (
        "",
        "relay1.substation.local",
    )
    assert (by_name["RELAY_B"].remote.ip, by_name["RELAY_B"].remote.address) == (
        "",
        "10.0.0.1/24",
    )
    assert by_name["RELAY_B"].remote.hostname == ""
    assert by_name["RELAY_C"].remote.ip == "10.0.0.3"


def test_maincontroller_tasks():
    xml = """<Export><MainController>
      <MainTask><Interval>10</Interval><Priority>1</Priority></MainTask>
      <Task><Name>Automation</Name><Interval>100</Interval></Task>
      <Task><Interval>5</Interval></Task>
    </MainController></Export>"""
    device_info = {}
    parse_maincontroller(ET.fromstring(xml), device_info)
    assert device_info["MainController"] == {
        "MainTask": {"Interval": 10, "Priority": 1},
        "Automation": {"Name": "Automation", "Interval": 100},
    }
    tasks = maincontroller_tasks(device_info["MainController"])
    assert [(t.name, t.extra) for t in tasks] == [
        ("MainTask", {"Interval": 10, "Priority": 1}),
        ("Automation", {"Name": "Automation", "Interval": 100}),
    ]


def _tarball(tmp_path):
    xml = (
        b"<Export><MainController><MainTask><Interval>10</Interval></MainTask>"
        b"</MainController></Export>"
    )
    path = tmp_path / "rtacexport.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("project/Main Controller.xml")
        info.size = len(xml)
        info.mtime = 1700000000
        tar.addfile(info, io.BytesIO(xml))
    return path


def test_parse_tarball_files_and_tasks(tmp_path, mocker):
    mocker.patch.object(DeviceData, "write_file", return_value=tmp_path / "x")
    dev = SELRTAC.parse(_tarball(tmp_path))
    (f,) = dev.files
    assert f.path.as_posix() == "project/Main Controller.xml"
    assert f.size > 0
    assert f.mtime.year == 2023
    assert f.category == {"configuration", "project"}
    assert [t.name for t in dev.logic.tasks] == ["MainTask"]
    assert "MainController" not in dev.extra
    assert "existing_files" not in dev.extra


def test_rtac_tar_member_file():
    info = tarfile.TarInfo("a/b.xml")
    info.size = 3
    f = rtac_tar_member_file(info)
    assert f.type == "file"
    assert f.size == 3
    assert f.mtime is None


def test_rtac_known_defaults_and_credentials():
    (baseline,) = SELRTAC.get_known_defaults()
    assert baseline.id == "sel-rtac-vendor-recommended"
    assert baseline.kind == "vendor_recommended"
    assert baseline.selector.device_type == "RTAC"
    assert SELRTAC.factory_default_credentials == set()
    assert not SELRTAC.is_factory_default_credential("admin", "admin")
