from datetime import timedelta

import pytest

from peat import DeviceData, config, datastore
from peat.modules.rockwell.clx_http import ClxHTTP
from peat.protocols.http import HTTP


def test_clxhttp_clean_data():
    assert ClxHTTP._clean_data({}) == {}
    assert ClxHTTP._clean_data({" some key ": "   evil \t   value     "}) == {
        "some key": "evil value"
    }


def test_clxhttp_add_padding():
    assert ClxHTTP.add_padding("01") == "00000001"
    assert ClxHTTP.add_padding("1034") == "00001034"
    assert ClxHTTP.add_padding("b9d29221") == "b9d29221"


def test_clxhttp_parse_uptime():
    assert ClxHTTP._parse_uptime("") is None
    assert ClxHTTP._parse_uptime("bogus string") is None
    assert ClxHTTP._parse_uptime("28 days, 15h:43m:33.775s") == timedelta(
        days=28, hours=15, minutes=43, seconds=33, milliseconds=775
    )
    assert ClxHTTP._parse_uptime("28 days, 16h:53m:45s") == timedelta(
        days=28, hours=16, minutes=53, seconds=45
    )


@pytest.fixture
def _http_dirs(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch.object(datastore, "objects", [])
    HTTP.page_cache.clear()
    yield
    HTTP.page_cache.clear()


@pytest.mark.usefixtures("_http_dirs")
def test_clxhttp_get_home_micrologix1100(requests_mock, datapath, read_text):
    """
    Pull and process the ``home.asp`` page of a MicroLogix 1100 (1763-L16DWD),
    which uses the same page layout as the ControlLogix Ethernet modules.

    Data source: ``micrologix1100_home.htm`` is the "home.htm" page from the
    MicroLogix 1100 web profile in the HoneyPLC project (GPL-3.0),
    https://github.com/sefcom/honeyplc (commit 6188234),
    ``plc-profiles/Allen-Bradley MicroLogix 1100/MicroLogix-1100-website.zip``.
    """
    page = read_text(datapath("micrologix1100_home.htm"))
    requests_mock.get("http://192.0.2.30:80/home.asp", text=page)

    dev = DeviceData(ip="192.0.2.30")
    with ClxHTTP("192.0.2.30", dev=dev) as http:
        info = http.get_home()

    assert info == {
        "Device Name": "1763-L16DWD B/8.00",
        "Device Description": "MicroLogix 1100 Processor",
        "Device Location": None,
        "Ethernet Address (MAC)": "00-0F-73-01-99-84",
        "IP Address": "192.168.0.200",
        "O/S Revision": "Series B FRN 8.0",
        "HTML File Revision": "1.10",
        "Current Time": "RTC is disabled",
        "CPU Mode": "Remote Program",
    }
    assert ClxHTTP.parse_home(page) == info

    ClxHTTP.process_home(dev, info)
    assert dev.name == "1763-L16DWD B/8.00"
    assert dev.mac == "00:0F:73:01:99:84"
    assert dev.description.description == "MicroLogix 1100 Processor"
    # The page's IP differs from the address PEAT connected to, so it's kept separately
    assert dev.ip == "192.0.2.30"
    assert dev.extra["http_home_info"] == {
        "ip_address": "192.168.0.200",
        "o/s_revision": "Series B FRN 8.0",
        "html_file_revision": "1.10",
        "current_time": "RTC is disabled",
        "cpu_mode": "Remote Program",
    }
