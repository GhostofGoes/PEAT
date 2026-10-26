from peat import DeviceData
from peat.modules.camlin.totus_http import TotusHTTP


def test_process_hardware_info_malformed():
    dev = DeviceData(ip="192.0.2.1")
    # Previously, KeyError for a missing field and ValueError for a non-number
    TotusHTTP.process_hardware_info(
        dev,
        {"serialNumber": "TOTUS-123", "uptime": "not-a-number", "release": "4.19.0-x"},
    )
    assert dev.serial_number == "TOTUS-123"
    assert dev.uptime is None
    assert dev.os.version == "4.19.0"


def test_process_hardware_info():
    dev = DeviceData(ip="192.0.2.1")
    TotusHTTP.process_hardware_info(
        dev,
        {
            "serialNumber": "TOTUS-123",
            "softwareVersion": "1.2.3",
            "hostname": "totus",
            "uptime": 60,
            "arch": "arm",
            "totalmem": "1024",
            "hardwareID": 7,
            "dataSize": 2048,
            "platform": "linux",
            "release": "4.19.0-x",
        },
    )
    assert dev.uptime.total_seconds() == 60
    assert dev.hardware.memory_total == 1024
    assert dev.hardware.id == "7"


def test_process_dnp3_channels_malformed():
    dev = DeviceData(ip="192.0.2.1")
    # Previously, KeyError (no "config") and ValueError (bufferSize)
    TotusHTTP.process_dnp3_channels(
        dev,
        [{"localAddress": 10, "bufferSize": "big"}, {"config": {"port": "20000"}}],
    )
    assert 20000 in dev.related.ports


def test_parse_modbus_map_malformed():
    # Previously, AttributeError (no <body>) and IndexError (no tables)
    assert TotusHTTP.parse_modbus_map("") == []
    assert TotusHTTP.parse_modbus_map("<html><body><p>x</p></body></html>") == []
    assert TotusHTTP.parse_modbus_map("<table></table>") == []

    dev = DeviceData(ip="192.0.2.1")
    TotusHTTP.process_modbus_map(dev, [{"register": "x"}, {"address": "40001", "register": "q"}])
    assert len(dev.registers) == 1
