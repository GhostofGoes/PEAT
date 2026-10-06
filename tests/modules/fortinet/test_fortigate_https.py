"""
Tests for pulling from a FortiGate's web interface over HTTPS, with the
device's responses mocked. The event and debug log data below is synthetic,
written to match the formats PEAT's FortiGate parsers expect.
"""

import pytest

from peat import DeviceData, config, datastore
from peat.modules.fortinet.fortigate import Fortigate
from peat.protocols.http import HTTP

IP = "192.0.2.40"
BASE = f"https://{IP}:443"

EVENT_LOG = (
    'date=2025-03-04 time=10:11:12 eventtime=1741083072000000000 tz="-0700" '
    'logid="0100032001" type="event" subtype="system" level="information" vd="root" '
    'logdesc="Admin login successful" sn="1741083072" user="admin" ui="https(198.51.100.7)" '
    'method="https" srcip=198.51.100.7 dstip=192.0.2.40 action="login" status="success" '
    'reason="none" profile="super_admin" msg="Administrator admin logged in successfully '
    'from https(198.51.100.7)"\n'
    'date=2025-03-04 time=10:15:00 eventtime=1741083300000000000 tz="-0700" '
    'logid="0100032003" type="event" subtype="system" level="information" vd="root" '
    'logdesc="Admin logout successful" user="admin" method="https" srcip=198.51.100.7 '
    'action="logout" status="success" profile="super_admin" '
    'msg="Administrator admin logged out from https(198.51.100.7)"\n'
)

DEBUG_LOG = """\
### get system status
Version: FortiGate-60F v7.2.5,build1517,230606 (GA.F)
Serial-Number: FGT60FTK00000000
BIOS version: 05000029
System Part-Number: P24186-04
Hostname: FGT-TEST
Cluster uptime: 29 minutes, 23 seconds

### diagnose ip address list
IP=192.0.2.40->192.0.2.40/255.255.255.0 index=5 devname=wan1
IP=10.20.30.1->10.20.30.1/255.255.255.0 index=7 devname=internal
"""


@pytest.fixture(autouse=True)
def _http_dirs(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp"},
    )
    mocker.patch.object(datastore, "objects", [])
    HTTP.page_cache.clear()
    yield
    HTTP.page_cache.clear()


@pytest.fixture
def fortigate_web(requests_mock):
    requests_mock.get(f"{BASE}/", text="<html><title>FortiGate</title></html>")
    requests_mock.post(
        f"{BASE}/logincheck", text='1document.location="/prompt?viewOnly&redir=%2F";'
    )
    requests_mock.get(
        f"{BASE}/api/v2/log/memory/event/system/raw",
        text=EVENT_LOG,
        headers={"Content-Disposition": 'attachment; filename="memory-event-system.log"'},
    )
    requests_mock.get(
        f"{BASE}/api/v2/monitor/system/debug/download",
        text=DEBUG_LOG,
        headers={"Content-Disposition": 'attachment; filename="FGT-TEST_debug.log"'},
    )
    return requests_mock


def test_fortigate_verify_and_pull_https(fortigate_web):
    dev = DeviceData(ip=IP)

    assert Fortigate._verify_https(dev) is True
    assert isinstance(dev._cache["https_session"], HTTP)

    assert Fortigate.pull_https(dev) is True

    login = next(r for r in fortigate_web.request_history if r.path == "/logincheck")
    assert login.method == "POST"
    assert "ajax=1" in login.text

    # Debug log
    assert dev.firmware.version.startswith("FortiGate-60F v7.2.5")
    assert dev.serial_number == "FGT60FTK00000000"
    assert dev.hostname == "FGT-TEST"
    assert dev.uptime.total_seconds() == 29 * 60 + 23
    assert {"192.0.2.40", "10.20.30.1"} <= dev.related.ip

    # Memory event log
    assert "admin" in dev.related.user
    assert "super_admin" in dev.related.roles
    assert "198.51.100.7" in dev.related.ip
    assert len(dev.event) == 2

    # Raw files are moved to the device's output directory and parsed versions written
    out_dir = dev.get_out_dir()
    assert (out_dir / "memory-event-system.log").read_text(encoding="utf-8") == EVENT_LOG
    assert (out_dir / "FGT-TEST_debug.log").is_file()
    assert (out_dir / "parsed_events_memory-event-system.json").is_file()
    assert (out_dir / "parsed_debug_log_FGT-TEST_debug.json").is_file()


def test_fortigate_verify_https_not_fortigate(requests_mock):
    requests_mock.get(f"{BASE}/", text="<html><title>Some other device</title></html>")
    dev = DeviceData(ip=IP)
    assert Fortigate._verify_https(dev) is False
    assert "https_session" not in dev._cache


def test_fortigate_pull_https_login_failed(fortigate_web):
    fortigate_web.post(f"{BASE}/logincheck", text="0", status_code=200)
    assert Fortigate.pull_https(DeviceData(ip=IP)) is False
