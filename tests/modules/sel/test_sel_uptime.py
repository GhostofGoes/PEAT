"""
Tests for calculating the uptime of SEL relays from their SER power-up records
(``compute_uptime`` and ``apply_uptime`` in ``peat/modules/sel/relay_parse.py``).

The SER records are synthetic. The power-up messages are the automatic SER
entries listed in public SEL instruction manuals: "Relay newly powered up"
(SEL-351S IM 20171023 Table 12.5), "Relay Powered Up" (SEL-751A IM 20130329
and SEL-700G IM 20150521 section 9), "Power-up" with the active group as the
state (SEL-421 IM 20130627 Figure 3.18), and "Relay newly powered up or
settings changed" (SEL-551, SEL-710, and SEL-749M manuals).
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from peat import DeviceData, Event, SELRelay, config, datastore, utils
from peat.modules.sel.relay_parse import (
    SER_DEVICE_TIME_KEY,
    apply_uptime,
    compute_uptime,
    parse_and_process_events,
    ser_power_up_kind,
)
from peat.modules.sel.sel_http import SELHTTP

NOW = datetime(2024, 4, 12, 10, 0, 0)


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])


def _ser(message: str, created: datetime | None, sequence: int = 1) -> Event:
    element, _, state = message.partition("  ")
    extra = {"element": element}
    if state:
        extra["state"] = state
    return Event(
        dataset="ser",
        created=created,
        message=f"{element} {state}".strip(),
        sequence=sequence,
        extra=extra,
    )


@pytest.mark.parametrize(
    "message",
    [
        "Relay newly powered up",  # 351S, 351A
        "Relay Powered Up",  # 700G, 751A
        "Power-up  Group 1",  # 421, 487B
        "Diagnostic restart",  # 351S
    ],
)
def test_compute_uptime_power_up(message):
    events = [
        _ser("OUT101  Asserted", NOW - timedelta(hours=3), 3),
        _ser(message, NOW - timedelta(hours=2), 2),
        _ser("OUT101  Deasserted", NOW - timedelta(hours=1), 1),
    ]

    uptime, info = compute_uptime(events, NOW)

    assert uptime == timedelta(hours=2)
    assert info == {"last_boot": NOW - timedelta(hours=2), "source": "ser_power_up"}


@pytest.mark.parametrize(
    ("element", "state", "expected"),
    [
        ("Relay newly powered up", "", "power_up"),
        ("Relay Powered Up", "", "power_up"),
        ("Power-up", "Group 1", "power_up"),
        ("Diagnostic Restart", "", "power_up"),
        ("Relay_Powered_Up", "", "power_up"),  # CSER may have underscores
        ("Relay newly powered up or settings changed", "", "ambiguous"),
        # SER trigger elements (or their aliases) aren't records of a power-up
        ("UPS POWER UP", "Asserted", ""),
        ("Power-up", "Deasserted", ""),
        ("GEN POWER UP ALARM", "", ""),
        ("POWERUP_DLY", "Asserted", ""),
        ("SALARM", "Deasserted", ""),
        ("", "", ""),
    ],
)
def test_ser_power_up_kind(element, state, expected):
    assert ser_power_up_kind(element, state) == expected


def test_uptime_ignores_ser_alias_with_power_up():
    dev = datastore.get("192.0.2.74", "ip")
    parse_and_process_events(
        "#  DATE  TIME  ELEMENT  STATE\n"
        "2  01/15/2024  17:09:45.504  Relay Powered Up\n"
        "1  01/19/2024  08:00:00.000  UPS POWER UP  Asserted",
        "SER",
        dev,
    )

    alias = next(e for e in dev.event if e.extra["element"] == "UPS POWER UP")
    assert "start" not in alias.type

    dev.extra["device_time"] = datetime(2024, 1, 20, 10, 0, 0)
    SELRelay._apply_uptime(dev, live=True)

    boot = datetime(2024, 1, 15, 17, 9, 45, 504000)
    assert dev.extra["last_boot_device_time"] == boot
    assert dev.uptime == datetime(2024, 1, 20, 10, 0, 0) - boot


def test_compute_uptime_newest_by_time_not_sequence():
    # The sequence numbers are out of order (e.g. events from two reads)
    events = [
        _ser("Relay Powered Up", NOW - timedelta(days=10), 1),
        _ser("Relay Powered Up", NOW - timedelta(days=1), 50),
        _ser("Relay Powered Up", NOW - timedelta(days=5), 2),
    ]

    uptime, _ = compute_uptime(events, NOW)
    assert uptime == timedelta(days=1)


def test_compute_uptime_ambiguous_message():
    events = [
        _ser("Relay newly powered up or settings changed", NOW - timedelta(minutes=30), 1),
        _ser("51P1  Asserted", NOW - timedelta(days=2), 2),
    ]

    uptime, info = compute_uptime(events, NOW)

    assert uptime is None
    assert info == {"source": "ser_ambiguous_power_up", "lower_bound": timedelta(minutes=30)}


def test_compute_uptime_ambiguous_after_power_up():
    # The relay may have restarted (or the settings changed) after the power-up
    events = [
        _ser("Relay newly powered up", NOW - timedelta(days=3), 2),
        _ser("Relay newly powered up or settings changed", NOW - timedelta(hours=1), 1),
    ]

    uptime, info = compute_uptime(events, NOW)

    assert uptime is None
    assert "last_boot" not in info
    assert info["lower_bound"] == timedelta(hours=1)

    # A power-up after the ambiguous record is a boot
    events.append(_ser("Relay newly powered up", NOW - timedelta(minutes=5), 0))
    assert compute_uptime(events, NOW)[0] == timedelta(minutes=5)


def test_compute_uptime_no_power_up_record():
    # e.g. the 20 newest records from "ser" on a 400-series relay
    events = [
        _ser("OUT101  Asserted", NOW - timedelta(days=4), 2),
        _ser("OUT101  Deasserted", NOW - timedelta(days=1), 1),
        _ser("Invalid Data", None, 3),  # No time, ignored
    ]

    uptime, info = compute_uptime(events, NOW)

    assert uptime is None
    assert info == {"source": "ser_oldest_record", "lower_bound": timedelta(days=4)}


def test_compute_uptime_negative():
    # The relay's clock is before the power-up (e.g. the clock was reset)
    events = [_ser("Relay Powered Up", NOW + timedelta(hours=1))]
    uptime, info = compute_uptime(events, NOW)
    assert uptime is None
    assert "source" not in info

    events = [_ser("OUT101  Asserted", NOW + timedelta(hours=1))]
    assert compute_uptime(events, NOW) == (None, {})


def test_compute_uptime_without_device_time():
    events = [_ser("Relay Powered Up", NOW - timedelta(hours=2))]
    assert compute_uptime(events, None) == (None, {"last_boot": NOW - timedelta(hours=2)})

    assert compute_uptime([], NOW) == (None, {})
    assert compute_uptime([_ser("Invalid Data", None)], NOW) == (None, {})


def test_compute_uptime_timezone_aware_device_time():
    # The 451 "date" and "time" commands include the UTC offset, the SER doesn't.
    # Both are the relay's local time.
    events = [_ser("Power-up  Group 1", NOW - timedelta(hours=2))]
    aware_now = NOW.replace(tzinfo=timezone(timedelta(hours=-8)))
    assert compute_uptime(events, aware_now)[0] == timedelta(hours=2)


def test_apply_uptime_sets_uptime_and_start_time():
    dev = DeviceData(id="relay")
    dev.event = [
        _ser("Relay Powered Up", NOW - timedelta(hours=2)),
        Event(dataset="history", created=NOW - timedelta(minutes=1), message="Relay Powered Up"),
    ]

    before = utils.utc_now()
    assert apply_uptime(dev, NOW) == timedelta(hours=2)
    after = utils.utc_now()

    assert dev.uptime == timedelta(hours=2)
    assert before - timedelta(hours=2) <= dev.start_time <= after - timedelta(hours=2)
    assert dev.start_time.tzinfo == UTC
    assert dev.extra["uptime_source"] == "ser_power_up"
    assert dev.extra["last_boot_device_time"] == NOW - timedelta(hours=2)
    assert "uptime_lower_bound" not in dev.extra


def test_apply_uptime_does_not_overwrite():
    dev = DeviceData(id="relay")
    dev.uptime = timedelta(days=100)
    start_time = datetime(2020, 1, 1, tzinfo=UTC)
    dev.start_time = start_time
    dev.event = [_ser("Relay Powered Up", NOW - timedelta(hours=2))]

    assert apply_uptime(dev, NOW) == timedelta(hours=2)
    assert dev.uptime == timedelta(days=100)
    assert dev.start_time == start_time
    assert "uptime_source" not in dev.extra


def test_apply_uptime_lower_bound():
    dev = DeviceData(id="relay")
    dev.event = [_ser("OUT101  Asserted", NOW - timedelta(days=4))]

    assert apply_uptime(dev, NOW) is None
    assert dev.uptime is None
    assert dev.start_time is None
    assert dev.extra["uptime_lower_bound"] == timedelta(days=4)
    assert dev.extra["uptime_source"] == "ser_oldest_record"

    # A later pull finds the power-up record
    dev.event.append(_ser("Relay Powered Up", NOW - timedelta(days=5)))
    assert apply_uptime(dev, NOW) == timedelta(days=5)
    assert "uptime_lower_bound" not in dev.extra
    assert dev.extra["uptime_source"] == "ser_power_up"


def test_apply_uptime_offline():
    dev = DeviceData(id="relay")
    dev.event = [_ser("Relay Powered Up", NOW - timedelta(hours=2))]

    assert apply_uptime(dev) is None
    assert dev.uptime is None
    assert dev.extra == {"last_boot_device_time": NOW - timedelta(hours=2)}


def test_apply_uptime_no_ser_events():
    dev = DeviceData(id="relay")
    assert apply_uptime(dev, NOW) is None
    assert dev.extra == {}


def test_apply_uptime_device_time_string():
    dev = DeviceData(id="relay")
    dev.event = [_ser("Relay Powered Up", NOW - timedelta(hours=2))]
    assert apply_uptime(dev, "2024-04-12 10:00:00") == timedelta(hours=2)


# ---------------------------------------------------------------------------
# SELRelay and SELHTTP
# ---------------------------------------------------------------------------

SER_700G = """
SEL-700G                                         Date: 04/12/2024   Time: 10:00:00.000
GENERATOR RELAY                                  Time Source: Internal

#        DATE            TIME               ELEMENT             STATE
3     04/12/2024     07:59:59.500   Relay Powered Up
2     04/12/2024     08:00:01.000   SALARM                   Deasserted
1     04/12/2024     09:30:00.000   IN101                    Asserted
"""


def test_ser_header_time_is_the_reference():
    dev = datastore.get("192.0.2.70", "ip")
    parse_and_process_events(SER_700G, "SER", dev)

    assert dev._cache[SER_DEVICE_TIME_KEY] == NOW

    # A different device_time (e.g. from logging out later) isn't used
    dev.extra["device_time"] = NOW + timedelta(hours=5)
    SELRelay._apply_uptime(dev, live=True)

    assert dev.uptime == timedelta(hours=2, seconds=0.5)


def test_selrelay_apply_uptime_device_time_fallback():
    # No SER header, e.g. "ser" output without the front matter
    dev = datastore.get("192.0.2.71", "ip")
    parse_and_process_events(
        "#  DATE  TIME  ELEMENT  STATE\n1  04/12/2024  08:00:00.000  Relay Powered Up",
        "SER",
        dev,
    )
    dev.extra["device_time"] = NOW
    SELRelay._apply_uptime(dev, live=True)
    assert dev.uptime == timedelta(hours=2)


def test_selrelay_apply_uptime_offline_and_errors(mocker, caplog):
    dev = datastore.get("192.0.2.72", "ip")
    parse_and_process_events(SER_700G, "SER", dev)

    SELRelay._apply_uptime(dev, live=False)
    assert dev.uptime is None
    assert dev.extra["last_boot_device_time"] == datetime(2024, 4, 12, 7, 59, 59, 500000)

    mocker.patch("peat.modules.sel.sel_relay.apply_uptime", side_effect=ValueError("bad"))
    SELRelay._apply_uptime(dev, live=True)  # Doesn't raise
    assert "Failed to calculate the uptime" in caplog.text


def test_pull_http_uptime_from_ser_page(mocker):
    dev = datastore.get("192.0.2.73", "ip")
    dev._is_verified = True
    http = SELHTTP("192.0.2.73", 80)
    http.relay_logged_in = True
    mocker.patch.object(http, "read_page", return_value=SER_700G)
    mocker.patch("peat.modules.sel.sel_relay.time.sleep")
    for name in [
        "get_status",
        "get_communications",
        "get_port_settings",
        "get_front_panel_settings",
        "get_historical_events",
        "get_meter_automation",
        "get_meter_protection",
        "get_meter_energy",
        "get_output_data",
    ]:
        method = mocker.patch.object(http, name, return_value=False)
        method.__name__ = name
    dev._cache["web_session"] = http
    dev._cache["web_protocol"] = "http"

    SELRelay.pull_http(dev)

    assert len(dev.event) == 3
    assert dev.uptime == timedelta(hours=2, seconds=0.5)
    assert dev.extra["uptime_source"] == "ser_power_up"
