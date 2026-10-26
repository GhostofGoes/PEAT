import time

from peat.modules.fortinet.fortigate_events import parse_fg_events

# Format of a FortiGate "Memory" event log line
EVENT_LINE = (
    'date=2023-04-11 time=10:21:15 eventtime=1681230075123456789 tz="-0600" '
    'logid="0100032001" type="event" subtype="system" level="information" '
    'vd="root" logdesc="Admin login successful" sn="1681230075" user="admin" '
    'ui="https(192.168.1.10)" method="https" srcip=192.168.1.10 dstip=192.168.1.99 '
    'action="login" status="success" reason="none" profile="super_admin" '
    'msg="Administrator admin logged in successfully from https(192.168.1.10)"'
)


def test_parse_fg_events_real_line():
    (event,) = parse_fg_events(EVENT_LINE)
    assert event["date"] == "2023-04-11"
    assert event["time"] == "10:21:15"
    assert event["eventtime"] == "1681230075123456789"
    assert event["tz"] == "-0600"
    assert event["logid"] == "0100032001"
    assert event["srcip"] == "192.168.1.10"
    assert event["msg"] == "Administrator admin logged in successfully from https(192.168.1.10)"
    assert event["raw_line"] == EVENT_LINE
    assert len(event) == 22  # 21 fields and raw_line


def test_parse_fg_events_edge_cases():
    (event,) = parse_fg_events('a=b=c empty="" x-y=1 key="unterminated')
    assert event == {"a": "b", "y": "1", "raw_line": 'a=b=c empty="" x-y=1 key="unterminated'}


def test_parse_fg_events_redos():
    """Long hostile lines must parse in linear time (previously quadratic)."""
    for line in ["a" * 40_000, "a" * 40_000 + '="', 'x="' + "y " * 20_000, "a=" * 20_000]:
        start = time.monotonic()
        parse_fg_events(line)
        assert time.monotonic() - start < 2.0, repr(line[:20])
