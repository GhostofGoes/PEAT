import time
from datetime import datetime

from peat.modules.sel import relay_parse

# Front matter of SER.TXT/HISTORY.TXT and the "sta" command output
SER_TXT = """\
FEEDER 1                                 Date: 01/15/2021  Time: 17:10:02.123
GENERATOR RELAY                          Time Source: Internal
FID=SEL-351-5-R514-V0-Z105104-D20170922  CID=F029

#    DATE        TIME            ELEMENT                      STATE
1024 12/09/2020  18:08:43.048    SALARM                       Deasserted
213  01/15/2021  17:09:45.504    Relay Powered Up
"""


def test_parse_status_output_real_lines():
    info = relay_parse.parse_status_output(SER_TXT.splitlines()[:3])
    assert info["device_identifier"] == "FEEDER 1"
    assert info["device_time"] == datetime(2021, 1, 15, 17, 10, 2, 123000)
    assert info["device_name"] == "GENERATOR RELAY"
    assert info["time_source"] == "Internal"
    assert info["FID"] == "SEL-351-5-R514-V0-Z105104-D20170922"
    assert info["CID"] == "F029"


def test_parse_status_output_identifier_variants():
    for line, expected in [
        ("SEL-700G   Date: 03/11/21  Time: 13:03:22", "SEL-700G"),
        ("Relay  1        Date: 03/11/2021  Time: 13:03:22.5", "Relay  1"),
        ("=>STATION A.B   Date: 3/1/2021  Time: 1:03:22", "STATION A.B"),
        ("     Date: 03/11/2021  Time: 13:03:22", ""),
    ]:
        info = relay_parse.parse_status_output([line, "STATION A"])
        assert info["device_identifier"] == expected, line
        assert info["device_time"].minute == 3
        assert info["device_name"] == "STATION A"


def test_parse_ser_real_file():
    events, info = relay_parse.parse_ser(SER_TXT.splitlines())
    assert info["device_identifier"] == "FEEDER 1"
    assert [e["sequence"] for e in events] == [1024, 213]
    assert events[1]["element"] == "Relay Powered Up"


def test_parse_status_output_redos():
    """Hostile status lines must not cause catastrophic regex backtracking."""
    hostile = [
        " " * 3000 + "x",  # previously cubic: ~15 seconds
        "a " * 10_000,
        "A-1. " * 4000 + "Date: 1/1/2021",
    ]
    for line in hostile:
        start = time.monotonic()
        info = relay_parse.parse_status_output([line, line + " Time Source"])
        assert time.monotonic() - start < 2.0, repr(line[:20])
        assert "device_time" not in info
