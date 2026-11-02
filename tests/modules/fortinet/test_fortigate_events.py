"""
Tests for the FortiGate event log parser with synthetic log lines.

The fields follow the FortiOS log message reference (e.g. log ID 32002,
"Admin login failed": ``logid``, ``level``, ``status``, ``reason``, ``msg``).
"""

from peat import DeviceData
from peat.modules.fortinet.fortigate_events import parse_fg_events, process_fg_events

EVENTS = (
    'date=2024-08-01 time=10:00:00 eventtime=1722506400000000000 tz="-0600" '
    'logid="0100032002" type="event" subtype="system" level="alert" vd="root" '
    'logdesc="Admin login failed" sn="0" user="admin" ui="https(192.0.2.50)" '
    'method="https" srcip=192.0.2.50 dstip=192.0.2.1 action="login" status="failed" '
    'reason="passwd_invalid" msg="Administrator admin login failed from https(192.0.2.50) '
    'because of invalid password"\n'
    'date=2024-08-01 time=10:01:00 eventtime=1722506460000000000 tz="-0600" '
    'logid="0100032001" type="event" subtype="system" level="information" vd="root" '
    'logdesc="Admin login successful" user="admin" ui="ssh(192.0.2.50)" method="ssh" '
    'srcip=192.0.2.50 action="login" status="success" reason="none" '
    'msg="Administrator admin logged in successfully from ssh(192.0.2.50)"\n'
    'date=2024-08-01 time=10:02:00 eventtime=1722506520000000000 tz="-0600" '
    'logid="0100022010" type="event" subtype="system" level="notice" vd="root" '
    'logdesc="Config error" status="failed" action="update"\n'
)


def test_process_fg_events():
    dev = DeviceData()
    process_fg_events(parse_fg_events(EVENTS), dev)
    events = {e.code: e for e in dev.event}

    failed = events["0100032002"]
    assert failed.reason == "passwd_invalid"
    assert failed.log_level == "alert"
    assert failed.id == "0100032002"  # kept for compatibility
    assert failed.outcome == "failure"
    assert failed.action == "login"
    for key in ("reason", "level", "logid"):
        assert key not in failed.extra
    assert failed.extra["status"] == "failed"

    ok = events["0100032001"]
    assert ok.reason == "none"
    assert ok.log_level == "information"
    assert ok.outcome == "success"

    # No message: the outcome comes from "status"
    cfg = events["0100022010"]
    assert cfg.outcome == "failure"
    assert cfg.message == "Config error"
