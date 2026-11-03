"""
Unit tests of the OpenPLC Runtime v4 data processing (synthetic API responses,
in the format of the upstream ``openplc-runtime`` web API).
"""

import itertools
from datetime import UTC, datetime, timedelta

import pytest

from peat import DeviceData, config
from peat.modules.openplc import openplcv4

INT64_MAX = 9223372036854775807


@pytest.fixture
def dev(mocker, tmp_path):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": tmp_path})
    return DeviceData(id="test_openplcv4", ip="192.0.2.40")


def test_parse_timing_stats_tasks():
    tasks = openplcv4.parse_timing_stats_tasks(
        {
            "tasks": [
                {
                    "name": "TASK0",
                    "scan_count": 120,
                    "scan_time_min": 10,
                    "scan_time_max": 250,
                    "scan_time_avg": 42,
                    "cycle_time_min": INT64_MAX,  # never measured
                    "cycle_time_max": 1010,
                    "cycle_time_avg": 1000,
                    "cycle_latency_min": 1,
                    "cycle_latency_max": 15,
                    "cycle_latency_avg": 3,
                    "overruns": 2,
                },
                {"name": "TASK1", "scan_count": 1, "scan_time_min": INT64_MAX},
                {"scan_count": 5},  # no name: skipped
            ]
        }
    )
    assert [t.name for t in tasks] == ["TASK0", "TASK1"]

    task0 = tasks[0]
    assert task0.scan_count == 120
    assert task0.overruns == 2
    assert task0.scan_time_min == timedelta(microseconds=10)
    assert task0.scan_time_max == timedelta(microseconds=250)
    assert task0.scan_time_avg == timedelta(microseconds=42)
    assert task0.extra == {
        "cycle_time_max_us": 1010,
        "cycle_time_avg_us": 1000,
        "cycle_latency_min_us": 1,
        "cycle_latency_max_us": 15,
        "cycle_latency_avg_us": 3,
    }

    assert tasks[1].scan_time_min is None
    assert openplcv4.parse_timing_stats_tasks({}) == []


def test_process_status_data(dev, mocker):
    # Strictly increasing read times (the newest indicator reading wins)
    seconds = itertools.count()
    mocker.patch.object(
        openplcv4.utils,
        "utc_now",
        side_effect=lambda: datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=next(seconds)),
    )
    status = {
        "status": "STATUS:RUNNING",
        "plc_file": "/var/lib/openplc/blink.st",
        "switchPosition": "RUN",
        "timing_stats": {
            "tasks": [{"name": "TASK0", "scan_count": 3, "scan_time_avg": 40, "overruns": 0}]
        },
    }
    openplcv4.process_status_data(status, dev)

    assert dev.run_mode == "RUNNING"
    assert dev.status == "Online"
    assert dev.logic.name == "blink.st"
    assert dev.files[0].category == {"logic"}

    # The new timing stats schema is in logic.tasks, not dev.extra
    assert "timing_stats" not in dev.extra
    assert len(dev.logic.tasks) == 1
    assert dev.logic.tasks[0].name == "TASK0"
    assert dev.logic.tasks[0].scan_count == 3

    # RUN/STOP switch
    assert dev.key_switch == "run"
    assert len(dev.indicators) == 1
    switch = dev.indicators[0]
    assert switch.name == "mode_switch"
    assert switch.type == "switch"
    assert switch.category == "mode"
    assert switch.value == "RUN"
    assert switch.state == ""
    assert switch.timestamp is not None
    assert switch.timestamp.tzinfo is not None

    # A second status read updates the same task and indicator
    status["timing_stats"]["tasks"][0]["scan_count"] = 9
    status["switchPosition"] = "STOP"
    openplcv4.process_status_data(status, dev)
    assert len(dev.logic.tasks) == 1
    assert len(dev.indicators) == 1
    assert dev.indicators[0].value == "STOP"
    assert dev.key_switch == "stop"


def test_process_status_data_old_schema(dev):
    openplcv4.process_status_data(
        {"status": "STOPPED", "timing_stats": {"name": "my_program", "scan_count": 1}}, dev
    )
    assert dev.run_mode == "STOPPED"
    assert dev.status == "Offline"
    assert dev.logic.name == "my_program"
    assert dev.extra["timing_stats"] == {"name": "my_program", "scan_count": 1}
    assert not dev.logic.tasks
    assert not dev.indicators
    assert dev.key_switch == ""


def test_process_logs_data(dev):
    openplcv4.process_logs_data(
        {
            "runtime-logs": [
                {"id": 1, "timestamp": "2026-07-16T17:39:51Z", "level": "INFO", "message": "a"},
                {"id": 2, "timestamp": "2026-07-16T17:39:52Z", "level": "ERROR", "message": "b"},
            ]
        },
        dev,
    )
    assert [e.log_level for e in dev.event] == ["INFO", "ERROR"]
    # The deprecated severity is kept in sync from log_level (by annotate())
    exported = dev.export()["event"]
    assert [(e["severity"], e["log_level"]) for e in exported] == [
        ("INFO", "INFO"),
        ("ERROR", "ERROR"),
    ]

    assert len(dev.files) == 1
    log_file = dev.files[0]
    assert log_file.name == "openplc_runtime.log"
    assert log_file.category == {"log"}
    assert "generated by PEAT" in log_file.description
    assert (dev.get_out_dir() / "openplc_runtime.log").is_file()


def test_process_compilation_data(dev):
    openplcv4.process_compilation_data({"status": "SUCCESS", "exit_code": 0, "logs": ["ok"]}, dev)
    assert dev.files[0].name == "compilation_status.log"
    assert dev.files[0].category == {"log"}
    assert "generated by PEAT" in dev.files[0].description


def test_process_plugin_data_ethercat(dev):
    plugin_data = {
        "masters": [
            {
                "name": "default",
                "plugin_state": "IDLE",
                "slave_count": 0,
                "expected_wkc": 0,
                "metrics": {
                    "avg_cycle_us": 0,
                    "consecutive_wkc_errors": 0,
                    "cycle_count": 1500,
                    "noframe_count": 2,
                    "wkc_error_count": 3,
                },
            }
        ]
    }
    openplcv4.process_plugin_data("ethercat", "status", plugin_data, dev)

    # Modeled as a service, not duplicated in dev.extra
    assert "plugin_status" not in dev.extra
    assert len(dev.service) == 1
    svc = dev.service[0]
    assert svc.protocol == "ethercat"
    assert svc.role == "master"
    assert svc.extra["masters"] == [
        {"name": "default", "plugin_state": "IDLE", "slave_count": 0, "expected_wkc": 0}
    ]
    assert svc.statistics.timestamp is not None
    assert svc.statistics.egress.packets == 1500
    assert svc.statistics.ingress.errors == 3
    assert svc.statistics.extra == {
        "avg_cycle_us": 0,
        "consecutive_wkc_errors": 0,
        "noframe_count": 2,
    }
    assert "ethercat" in dev.related.protocols

    assert dev.files[0].name == "ethercat_status.json"
    assert dev.files[0].category == {"diagnostic"}


def test_process_plugin_data_other_plugin(dev):
    openplcv4.process_plugin_data("s7comm", "status", {"running": True}, dev)
    assert dev.extra["plugin_status"] == {"s7comm": {"running": True}}
    assert not dev.service

    # EtherCAT output without masters stays in extra
    openplcv4.process_plugin_data("ethercat", "status", {"error": "not loaded"}, dev)
    assert dev.extra["plugin_status"]["ethercat"] == {"error": "not loaded"}
    assert not dev.service
