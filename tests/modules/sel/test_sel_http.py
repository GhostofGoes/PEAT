"""
Tests for the SEL web scraping code (peat/modules/sel/sel_http.py) with
synthetic page contents (no device or network access).
"""

from datetime import UTC, datetime

import pytest

from peat import DeviceData, LogicTask, datastore
from peat.modules.sel.sel_http import (
    SELHTTP,
    aggregate_logon_relationships,
    merge_logic_task,
    post_summary_indicators,
    process_soe_csv,
)

T0 = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)

SOE_HEADER = (
    '"t_value","message","category","priority","tag_name","host_name",'
    '"device_name","comment","creation_timestamp"'
)


def _soe_row(t_value: str, message: str, priority: str = "2", tag: str = "") -> str:
    values = [t_value, message, "System", priority, tag, "rtac-1", "RTAC_1", "", ""]
    return ",".join(f'"{v}"' for v in values)


SOE_CSV = "\n".join(
    [
        SOE_HEADER,
        _soe_row("2026-10-01 10:00:00", "Unknown login attempt from 192.0.2.99 failed", "5"),
        _soe_row("2026-10-01 10:05:00", "Unknown login attempt from 192.0.2.99 failed", "5"),
        _soe_row("2026-10-02 09:00:00", "admin logged on device via Web from 192.0.2.99"),
        _soe_row("2026-10-03 09:00:00", "engineer logged on device via ODBC from 192.0.2.80"),
        _soe_row("2026-10-03 09:30:00", "engineer logged off device via ODBC"),
        _soe_row(
            "2026-10-04 08:00:00",
            "The rtacsnmpmgr application has been restarted",
            tag="RTAC.application_status",
        ),
        _soe_row("2026-10-05 08:00:00", "Factory reset initiated by admin", "1"),
        "",
    ]
)


@pytest.fixture(autouse=True)
def _clean_datastore(mocker):
    mocker.patch.object(datastore, "objects", [])


@pytest.fixture
def session() -> SELHTTP:
    return SELHTTP("192.0.2.10", 80, 1.0)


def test_process_soe_csv_events_and_relationships():
    dev = DeviceData(name="RTAC_1")
    rows = process_soe_csv(SOE_CSV, dev)
    assert len(rows) == 7

    failed = [e for e in dev.event if e.outcome == "failure"]
    assert len(failed) == 2
    assert all(e.reason == "login attempt failed" for e in failed)
    assert all(e.severity == "5" for e in failed)
    assert all("priority" not in e.extra for e in dev.event)

    restart = next(e for e in dev.event if e.action == "application-restarted")
    assert restart.reason == "application restarted"
    assert restart.extra["application"] == "rtacsnmpmgr"
    assert "rtacsnmpmgr" in dev.related.process

    reset = next(e for e in dev.event if "factory reset" in e.message.lower())
    assert reset.reason == "Factory reset initiated by admin"

    rels = {(r.remote.ip, r.protocol): r for r in dev.relationships}
    assert set(rels) == {("192.0.2.99", ""), ("192.0.2.99", "https"), ("192.0.2.80", "postgres")}
    failures = rels[("192.0.2.99", "")]
    assert failures.count == 2
    assert failures.evidence == {"log"}
    assert failures.direction == "ingress"
    assert failures.first_seen < failures.last_seen
    assert failures.extra["logon_failures"] == 2
    web = rels[("192.0.2.99", "https")]
    assert web.count == 1
    assert web.extra["logon_successes"] == 1
    assert web.extra["users"] == ["admin"]
    assert rels[("192.0.2.80", "postgres")].count == 1  # the logoff is not a logon


def test_aggregate_logon_relationships():
    logons = [
        {"ip": "192.0.2.5", "service": "web", "outcome": "success", "timestamp": T0},
        {"ip": "192.0.2.5", "service": "web", "outcome": "failure", "timestamp": T0},
        {"ip": "", "service": "web", "outcome": "success", "timestamp": T0},
    ]
    (rel,) = aggregate_logon_relationships(logons)
    assert rel.protocol == "https"
    assert rel.count == 2
    assert rel.first_seen == rel.last_seen == T0
    assert rel.extra == {"logon_successes": 1, "logon_failures": 1, "logon_services": ["web"]}
    assert aggregate_logon_relationships([]) == []


def test_aggregate_logon_relationships_unmapped_services_share_one_edge():
    # A failed logon (no service) and a logon via a service without a known
    # protocol have the same relationship identity: store() would merge them
    logons = [
        {"ip": "192.0.2.5", "outcome": "failure", "timestamp": T0},
        {"ip": "192.0.2.5", "service": "telnet", "outcome": "success", "timestamp": T0},
        {"ip": "192.0.2.5", "service": "serial", "outcome": "success", "timestamp": T0},
    ]
    rels = aggregate_logon_relationships(logons)
    assert len(rels) == 1
    dev = DeviceData(ip="192.0.2.10")
    for rel in rels:
        dev.store("relationships", rel)
    (rel,) = dev.relationships
    assert rel.protocol == ""
    assert rel.count == 3
    assert rel.extra == {
        "logon_successes": 2,
        "logon_failures": 1,
        "logon_services": ["serial", "telnet"],
    }


def test_post_summary_indicators():
    indicators = post_summary_indicators(
        {"DDR2 SDRAM OK": "", "Flash": "Pass", "RTC Battery": "FAIL", "Fan": ["1200", "RPM"]},
        T0,
    )
    by_name = {i.name: i for i in indicators}
    assert by_name["DDR2 SDRAM OK"].health == "normal"
    assert by_name["Flash"].health == "normal"
    assert by_name["RTC Battery"].health == "failure"
    assert by_name["Fan"].health == ""
    assert by_name["Fan"].value == "1200 RPM"
    assert all(
        i.type == "status_flag" and i.category == "self_test" and i.timestamp == T0
        for i in indicators
    )


def test_merge_logic_task():
    tasks = merge_logic_task([], LogicTask(name="Main Task", cpu_percent=10.0))
    tasks = merge_logic_task(tasks, LogicTask(name="Main Task", cpu_percent=42.0))
    tasks = merge_logic_task(tasks, LogicTask(name="Automation Task", cpu_percent=5.0))
    assert [(t.name, t.cpu_percent) for t in tasks] == [
        ("Main Task", 42.0),
        ("Automation Task", 5.0),
    ]


ETH_PAGE = """
MAC: 00-30-A7-00-00-01
IP ADDRESS: 192.0.2.10/24
DEFAULT GATEWAY: 192.0.2.1
NETMODE: FIXED

PORT 5A   UP      100M    FULL    TX

     PACKETS                 BYTES               ERRORS
   SENT     RCVD         SENT       RCVD      SENT    RCVD
     10       20            300        400         0       0
"""


def test_get_communications(session, mocker):
    mocker.patch.object(session, "read_page", return_value=ETH_PAGE)
    dev = DeviceData(ip="192.0.2.10")
    assert session.get_communications(dev) is True
    iface = next(i for i in dev.interface if i.name == "Port 5")
    assert iface.statistics.ingress.packets == 20
    assert iface.statistics.egress.bytes == 300
    assert iface.statistics.timestamp is not None
    assert iface.redundancy.mode == "fixed"
    assert "communications" not in dev.extra


SHO_F_PAGE = """Front Panel

T01_LED  := 51P1T # TIME OC
T01LEDL  := Y
PB1_LED  := !LT01
FP_TO    := 15
"""


def test_get_front_panel_settings(session, mocker):
    mocker.patch.object(session, "read_page", return_value=SHO_F_PAGE)
    dev = DeviceData()
    assert session.get_front_panel_settings(dev) is True
    names = {i.name: i for i in dev.indicators}
    assert names["T01"].equation == "51P1T"
    assert names["T01"].label == "TIME OC"
    assert names["T01"].latched is True
    assert names["PB1"].type == "pushbutton"
    assert dev.extra["front_panel_data"] == {
        "front_panel": {"FP_TO": {"value": "15", "comment": ""}}
    }


HIS_PAGE = """SEL-351S                     Date: 01/15/21  Time: 17:10:00.000
FEEDER 1
#    DATE      TIME          EVENT        LOCAT   CURR  FREQ  GRP SHOT TARGETS
1 01/15/21 17:09:45.504 Trip 1.23 450 60.00 1 0 11000000
2 01/14/21 10:00:00.000 ER $$$$$$ 12 60.00 1 0
"""


def test_get_historical_events(session, mocker):
    mocker.patch.object(session, "read_page", return_value=HIS_PAGE)
    dev = DeviceData(name="FEEDER 1")
    assert session.get_historical_events(dev) is True
    trip = next(e for e in dev.event if e.sequence == 1)
    assert trip.action == "trip"
    assert "alert" in trip.kind
    assert trip.reason == "Trip; targets 11000000"
    assert trip.module == "SELRelay"
    assert trip.provider == dev.get_id()
    other = next(e for e in dev.event if e.sequence == 2)
    assert other.action == "er"
    assert "locat" not in other.extra


def test_get_historical_events_no_header(session, mocker):
    # Bug fix: next() without a default raised StopIteration
    mocker.patch.object(session, "read_page", return_value="SEL-351S\nFEEDER 1\n")
    assert session.get_historical_events(DeviceData()) is False
    mocker.patch.object(session, "read_page", return_value="History Buffer Empty")
    assert session.get_historical_events(DeviceData()) is False


class _Resp:
    def __init__(self, url: str):
        self.url = url
        self.content = b"<table></table>"


DASHBOARD_TABLES = {
    "device_info.sel": {"Host Name": "RTAC-1", "Firmware Version": "SEL-3530-R151-V0"},
    "diagnostics.sel": {
        "Main Task Usage": ["", "42%"],
        "Automation Task Usage": ["", "7%"],
        "Number of Users Logged In": "2",
        "Memory Usage (RAM)": "1024 KB",
    },
    "post_summary.sel": {"DDR2 SDRAM OK": "", "NAND Flash": "Fail"},
}


def test_view_dashboard(session, mocker):
    mocker.patch.object(session, "post", side_effect=lambda url, **_: _Resp(url))

    def _dump(response, config):
        page = response.url.split("/")[-1].split("?")[0]
        config.update(DASHBOARD_TABLES[page])

    mocker.patch.object(SELHTTP, "dump_htmltable", side_effect=_dump)
    dev = DeviceData()
    dash = session.view_dashboard(dev)
    assert dash["web_device_info"]["Host Name"] == "RTAC-1"

    tasks = {t.name: t.cpu_percent for t in dev.logic.tasks}
    assert tasks == {"Main Task": 42.0, "Automation Task": 7.0}
    https = dev.retrieve("service", {"protocol": "https"})
    assert https.statistics.connections.active == 2
    assert https.statistics.timestamp is not None
    assert dev.hardware.memory_usage == 1024

    diag = dev.extra["web_diagnostics"]
    for key in ("main_task_usage", "automation_task_usage", "number_of_users_logged_in"):
        assert key not in diag
    assert "web_post_summary" not in dev.extra
    post = {i.name: i.health for i in dev.indicators}
    assert post == {"DDR2 SDRAM OK": "normal", "NAND Flash": "failure"}
    assert dev.hardware.memory_type == "ddr2_sdram"


def test_view_filesondevice(session, mocker):
    mocker.patch.object(session, "post", side_effect=lambda url, **_: _Resp(url))
    mocker.patch.object(
        SELHTTP,
        "dump_htmltable",
        side_effect=lambda _r, cfg: cfg.update(
            {"project.zip": ["2026-10-01 10:00:00", "2048"], "": ["", "0"]}
        ),
    )
    dev = DeviceData()
    result = session.view_filesondevice(dev)
    assert result["web_files"]["project.zip"]["size"] == 2048
    (f,) = dev.files
    assert (f.name, f.size, f.type, f.peat_module) == ("project.zip", 2048, "file", "SELRTAC")
    assert f.mtime == datetime(2026, 10, 1, 10, 0, 0)
    assert "web_files" not in dev.extra
    assert dev._cache["web_files"]
