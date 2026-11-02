"""
Woodward MicroNet pulled files and easyGen serial interface (no device needed).
"""

from datetime import datetime
from pathlib import PurePosixPath

import pytest

from peat import DeviceData, Event, config
from peat.modules.woodward import parse_micronet
from peat.modules.woodward.micronet import MicroNet


@pytest.fixture
def dev(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    return DeviceData(id="test_micronet", ip="192.0.2.70")


def test_create_artifact(dev):
    local = dev.get_out_dir() / "HD1Flash" / "app_gaprev3.out"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(b"GAP application")

    file_obj = parse_micronet.create_artifact(dev, local, "2024-01-02T03:04:05")

    assert "file_artifacts" not in dev.extra
    assert dev.files == [file_obj]
    assert file_obj.name == "app_gaprev3.out"
    assert file_obj.path == PurePosixPath("/HD1Flash/app_gaprev3.out")
    assert file_obj.local_path == local.resolve()
    assert file_obj.size == len(b"GAP application")
    assert file_obj.mtime == datetime(2024, 1, 2, 3, 4, 5)  # MDTM from the device
    assert file_obj.hash.sha256
    assert file_obj.peat_module == "MicroNet"
    assert "/HD1Flash/app_gaprev3.out" in dev.related.files

    # Missing local file
    assert parse_micronet.create_artifact(dev, local.with_name("missing.out"), "") is None
    assert len(dev.files) == 1


def test_get_gap_info_from_files(dev):
    local = dev.get_out_dir() / "HD1Flash" / "app_gaprev3.out"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(b"GAP application")
    parse_micronet.create_artifact(dev, local, "2024-01-02T03:04:05")
    dev.store("event", Event(message="Loading app_gaprev3.out gap file"))

    MicroNet.get_gap_info(dev)

    assert dev.logic.file.name == "app_gaprev3.out"
    assert dev.logic.file.path == PurePosixPath("/HD1Flash/app_gaprev3.out")
    assert dev.logic.file.local_path == local.resolve()
    assert dev.logic.file.mtime == datetime(2024, 1, 2, 3, 4, 5)


def test_get_gap_info_no_gap_event(dev):
    """Bug fix: no GAP file load in the logs raised a NameError."""
    MicroNet.get_gap_info(dev)
    assert not dev.logic.file.name


def test_easygen_serial_interface_type(mocker, tmp_path):
    """Bug fix: the serial pull looked for a "serial" interface, verify stored "rs_232"."""
    from peat.modules.woodward import easygen_3500xt
    from peat.modules.woodward.easygen_3500xt import Easygen3500XT

    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path / "devices"})
    dev = DeviceData(serial_port="/dev/ttyUSB0")
    mocker.patch.object(easygen_3500xt, "open_serial_port", return_value=True)
    mocker.patch.object(
        easygen_3500xt, "_svlser_raw_txn", return_value=easygen_3500xt.SVLSER_INIT_ACK
    )
    mocker.patch.object(easygen_3500xt, "_easygen_ser_sys_txn", return_value="EG3500XT-P2")
    assert Easygen3500XT._verify_serial(dev)

    iface = dev.retrieve("interface", {"serial_port": "/dev/ttyUSB0"})
    assert iface.type == "serial"
    assert iface.connected is True

    get_serial = mocker.patch.object(
        Easygen3500XT, "_get_serial_data", return_value={"application": "x"}
    )
    assert Easygen3500XT._pull(dev)
    get_serial.assert_called_once_with("/dev/ttyUSB0")
