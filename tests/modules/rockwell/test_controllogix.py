from peat import ControlLogix, DeviceData, datastore


# TODO: test input file is validated for push (file extension, contents)
def test_controllogix_push_firmware_invalid_content_localhost(mocker):
    mocker.patch.object(datastore, "objects", [])

    dev = datastore.get("127.0.0.6")
    dev._runtime_options["timeout"] = 0.01

    assert ControlLogix.push(dev, b"xyz", "config") is False
    assert ControlLogix.push(dev, b"xyz", "firmware") is False
    assert ControlLogix.push(dev, b"", "firmware") is False
    # TODO: pytest fixture /w firmware content (see test_rest_api)


def _cip_values(serial: int, product_type: str = "Communications Adapter") -> dict:
    return {
        "product_name": "1756-EN2TR/C",
        "product_type": product_type,
        "product_code": 200,
        "serial_number": serial,
        "firmware_version": 11,
        "firmware_revision": 1,
        "state": 3,
        "status": 48,
    }


def test_controllogix_process_fingerprint_comm_module(mocker):
    mocker.patch.object(DeviceData, "write_file")
    dev = DeviceData(ip="192.0.2.11")
    result = {
        **_cip_values(3333),
        "ip": "192.0.2.11",
        "cpu_serial": 1111,
        "modules": {
            0: _cip_values(1111, "PLC"),
            2: _cip_values(3333),
        },
    }
    ControlLogix._process_fingerprint(dev, result)

    assert dev.serial_number == "1111"
    assert dev.extra["cpu_serial"] == 1111
    assert dev.extra["comm_module_serial"] == "3333"

    mod = dev.annotate_comm_module()
    assert mod.slot == "2"
    assert mod.ip == "192.0.2.11"
    assert dev.slot == "2"


def test_annotate_comm_module_missing_module():
    dev = DeviceData(ip="192.0.2.11", mac="00:00:BC:00:00:11")
    assert dev.annotate_comm_module() is None

    dev.extra["comm_module_serial"] = "3333"
    mod = dev.annotate_comm_module()
    assert dev.module == [mod]
    assert mod.serial_number == "3333"
    assert mod.ip == "192.0.2.11"
    assert mod.mac == "00:00:BC:00:00:11"


def test_is_duplicate_controllogix_cpu_serial():
    d1 = DeviceData(ip="192.0.2.10")
    d2 = DeviceData(ip="192.0.2.11")
    assert not d1.is_duplicate(d2)
    d1.extra["cpu_serial"] = 1111
    assert not d1.is_duplicate(d2)
    d2.extra["cpu_serial"] = 1111
    assert d1.is_duplicate(d2)
    assert d2.is_duplicate(d1)
    d2.extra["cpu_serial"] = 2222
    assert not d1.is_duplicate(d2)
