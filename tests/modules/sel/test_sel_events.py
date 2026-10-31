"""
Tests for parsing SEL relay events: SER, CSER, history (HIS), and CHISTORY,
from files, Telnet/serial commands, and the web interface.

The reports are synthetic. Their layouts are modeled on the example SER and
event history reports in public SEL instruction manuals (SEL-351S IM 20171023
section 12; SEL-421 IM 20130627 Applications Handbook section 3; SEL-487B IM;
SEL-551 IM 20151105 section 7; SEL-700G IM 20150521 section 9; SEL-710 IM;
SEL-751A IM 20130329 section 9) and on output PEAT has seen from relays.
The values (dates, names, currents, etc.) are made up.
"""

from datetime import datetime
from pathlib import Path

import pytest

from peat import DeviceData, SELRelay, config, datastore
from peat.modules.sel import relay_parse
from peat.modules.sel.relay_parse import (
    event_data_present,
    event_dataset_kind,
    extract_date_format,
    infer_date_format,
    parse_and_process_events,
    parse_chistory,
    parse_config_data,
    parse_cser,
    parse_history,
    parse_sel_datetime,
    parse_ser,
    process_events,
    split_lines,
)
from peat.modules.sel.sel_cascii import format_record
from peat.modules.sel.sel_http import SELHTTP
from peat.modules.sel.sel_telnet import SELTelnet
from peat.protocols import FTP

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"


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
    return tmp_path


def _dev(ident: str = "192.0.2.50") -> DeviceData:
    return datastore.get(ident, "ip")


def _lines(text: str) -> list[str]:
    return text.strip("\n").splitlines()


# ---------------------------------------------------------------------------
# SER reports
# ---------------------------------------------------------------------------

# 300 series (SEL-351S style), with a 2-digit year
SER_351S = """
FEEDER 1                               Date: 04/12/24         Time: 10:20:16.896

STATION A

FID=SEL-351S-6-R514-V0-Z105103-D20220101             CID=1A2B
#     DATE      TIME           ELEMENT                  STATE

19       04/12/24    08:30:33.222    Relay newly powered up
18       04/12/24    09:20:22.830   IN102              Asserted
17       04/12/24    09:27:58.364   LB4                Asserted
2        04/12/24    09:28:31.879   OUT101             Deasserted
1        04/12/24    09:28:36.874   OUT102             Asserted
"""

# 400 series (SEL-421 style), with element names and states with spaces
SER_421 = """
Relay 1                                       Date: 03/16/2024 Time: 13:09:29.341
Station A                                     Serial Number: 2024001234

FID=SEL-421-5-R320-V0-Z001001-D20230315

#        DATE         TIME           ELEMENT               STATE
6      03/15/2024   00:00:00.004   Power-up              Group 1
5      03/15/2024   00:00:00.022   Relay                 Enabled
4      03/15/2024   00:30:00.021   GROUND O/C 1 LINE 1   51S1 PICKED UP
2      03/15/2024   00:32:00.114   GROUND O/C 1 LINE 1   51S1 RESET
1      03/15/2024   00:32:00.114   GROUND O/C 1 LINE 1   51S1 DROPOUT
"""

# 400 series (SEL-487B style), settings change and a target reset
SER_487B = """
Relay 1                                          Date: 07/24/2024 Time: 10:52:10.104
Station A                                        Serial Number: 2024000040

FID=SEL-487B-1-R110-V0-Z001001-D20230724

#        DATE            TIME           ELEMENT             STATE
4      07/23/2024      08:09:50.300   Power-up            Group 1
3      07/23/2024      08:20:54.006   Settings changed    Class R 1
2      07/23/2024      08:21:12.674   TARGET RESET PB     TEST
1      07/23/2024      08:21:13.695   TARGET RESET PB     OFF
"""

# 700 series (SEL-751A style), serial number, FID, and CID in the front matter
SER_751A = """
SEL-751A                                     Date: 02/28/2024   Time: 16:34:28
FEEDER RELAY                                 Time Source: Internal

Serial No = 2024000000001
FID = SEL-751A-R400-V0-Z001001-D20230410                    CID = 5052

#        DATE            TIME               ELEMENT             STATE
8     02/28/2024     13:54:09.602   51P1P                    Asserted
7     02/28/2024     13:54:10.511   TRIP                     Deasserted
6     02/28/2024     13:50:00.000   Relay Powered Up
"""

# 700 series SER.TXT, as seen by PEAT (rows from the old parse_ser docstring)
SER_700 = """
SEL-751                  Date: 01/16/2021  Time: 08:00:00.000
FEEDER RELAY             Time Source: Internal

#    DATE        TIME             ELEMENT                      STATE
1024 12/09/2020  18:08:43.048    SALARM                       Deasserted
213  01/15/2021  17:09:45.504    Relay Powered Up
214  01/13/2021  10:17:40.740    SALARM Deasserted
"""

# SEL-551 style: "Row" header, and each row is followed by a line of analog
# values and relay word bits (which aren't events), and the combined message
SER_551 = """
FEEDER 1                            Date: 02/27/24   Time: 13:46:26.988
STATION A
FID=SEL-551-R101-V0-D20200321        CID=00FF

                                      51    50       S Lcl Rem
Row         Date       Time                 PPPANGQ h
      IA      IB      IC      IN   IG 121112246C222 9t

13      02/27/24 13:44:30.146        Relay newly powered up or settings changed
      2      0      2      1       4 ............. L2 .........
12      02/27/24 13:45:02.487        51P1        Asserted
      0      0      2      1       2 ............. L2 1........
"""


def test_parse_ser_351s():
    events, info = parse_ser(_lines(SER_351S))

    assert len(events) == 5
    assert events[0] == {
        "sequence": 19,
        "date": "04/12/24",
        "time": "08:30:33.222",
        "original": "19       04/12/24    08:30:33.222    Relay newly powered up",
        "element": "Relay newly powered up",
        "state": "",
    }
    assert events[1]["element"] == "IN102"
    assert events[1]["state"] == "Asserted"
    assert info["device_identifier"] == "FEEDER 1"
    assert info["device_name"] == "STATION A"
    assert info["device_time"] == datetime(2024, 4, 12, 10, 20, 16, 896000)


def test_parse_ser_421_spaces_in_names():
    events, info = parse_ser(_lines(SER_421))

    assert [(e["element"], e["state"]) for e in events] == [
        ("Power-up", "Group 1"),
        ("Relay", "Enabled"),
        ("GROUND O/C 1 LINE 1", "51S1 PICKED UP"),
        ("GROUND O/C 1 LINE 1", "51S1 RESET"),
        ("GROUND O/C 1 LINE 1", "51S1 DROPOUT"),
    ]
    assert info["device_name"] == "Station A"
    assert info["serial_number"] == "2024001234"
    assert info["FID"] == "SEL-421-5-R320-V0-Z001001-D20230315"


def test_parse_ser_487b():
    events, _ = parse_ser(_lines(SER_487B))
    assert [(e["element"], e["state"]) for e in events] == [
        ("Power-up", "Group 1"),
        ("Settings changed", "Class R 1"),
        ("TARGET RESET PB", "TEST"),
        ("TARGET RESET PB", "OFF"),
    ]


def test_parse_ser_751a():
    events, info = parse_ser(_lines(SER_751A))

    assert [e["element"] for e in events] == ["51P1P", "TRIP", "Relay Powered Up"]
    assert events[2]["state"] == ""
    assert info["serial_number"] == "2024000000001"
    assert info["FID"] == "SEL-751A-R400-V0-Z001001-D20230410"
    assert info["CID"] == "5052"
    assert info["device_time"] == datetime(2024, 2, 28, 16, 34, 28)


def test_parse_ser_700_single_space_state():
    events, _ = parse_ser(_lines(SER_700))
    assert [(e["sequence"], e["element"], e["state"]) for e in events] == [
        (1024, "SALARM", "Deasserted"),
        (213, "Relay Powered Up", ""),
        (214, "SALARM", "Deasserted"),
    ]


def test_parse_ser_551_skips_analog_lines():
    events, info = parse_ser(_lines(SER_551))

    assert [(e["sequence"], e["element"], e["state"]) for e in events] == [
        (13, "Relay newly powered up or settings changed", ""),
        (12, "51P1", "Asserted"),
    ]
    assert info["FID"] == "SEL-551-R101-V0-D20200321"


def test_parse_and_process_ser_551_fid_without_settings_version():
    # Older firmware IDs don't have the settings version (Z...), e.g. in the
    # SEL-551 IM status report: "FID=SEL-551-R101-Vr-D960321"
    dev = _dev()
    report = SER_551.replace("SEL-551-R101-V0-D20200321", "SEL-551-R101-Vr-D960321")
    events, _ = parse_and_process_events(report, "SER", dev)

    assert events
    assert len(dev.event) == len(events)
    assert dev.description.model == "551"
    assert dev.firmware.revision == "R101"
    assert dev.firmware.release_date == datetime(1996, 3, 21)
    assert "settings_version" not in dev.firmware.extra


def test_parse_ser_skips_bad_lines():
    # The old parser returned no events after the first line it couldn't parse
    lines = _lines(SER_351S)
    lines.insert(8, "10       Invalid Data")
    lines.insert(9, "9        not a date   OUT101   Asserted")
    events, _ = parse_ser(lines)
    assert len(events) == 5


def test_parse_ser_without_header():
    # e.g. HEAT, which passes unstripped lines without a header
    events, info = parse_ser(["  5   01/02/2024  03:04:05.006   OUT101   Asserted  ", ""])
    assert events[0]["element"] == "OUT101"
    assert info == {}

    assert parse_ser(["=>"]) == ([], {})
    assert parse_ser(["garbage", "more garbage"])[0] == []


def test_parse_ser_2032_front_matter_is_skipped():
    lines = [
        "SEL-2032   Date: 07/23/2024  Time: 08:20:00",
        "Port 2, SER Data",
        "#        DATE      TIME         ELEMENT                STATE",
        "9     07/23/2024 08:15:32.123   52A                  Deasserted",
    ]
    events, info = parse_ser(lines)
    assert len(events) == 1
    assert info == {}


# ---------------------------------------------------------------------------
# CSER
# ---------------------------------------------------------------------------

# 700-series layout seen by PEAT, with a row without a STATE
CSER_700 = [
    '"FID","SERIAL NO","CID","0570"',
    '"FID=SEL-751-R400-V0-Z008004-D20200101","1234567890","ABCD","0C95"',
    '"REC_NUM","DATE","TIME","ELEMENT","STATE","0A31"',
    '1,"01/15/2021","17:09:45.504","Relay Powered Up","0BE4"',
    '2,"12/09/2020","18:08:43.048","SALARM","Deasserted","0C46"',
]

# 400-series layout (SEL-421 IM Figure 3.19 labels)
CSER_421 = [
    '"RID","SID","FID","03E2"',
    '"Relay 1","Station A","FID=SEL-421-R101-V0-Z001001-D20010315","0F03"',
    '"#","MONTH","DAY","YEAR","HOUR","MIN","SEC","MSEC","ELEMENT","STATE","0FC8"',
    '1,3,15,2001,00,32,00,114,"GROUND O/C 1 LINE 1","51S1 DROPOUT","0D59"',
    '6,3,15,2001,00,00,00,004,"Power-up","Group 1","0B03"',
]


def test_parse_cser_700():
    events, info = parse_cser(CSER_700)

    assert info == {
        "FID": "SEL-751-R400-V0-Z008004-D20200101",
        "serial_number": "1234567890",
        "CID": "ABCD",
    }
    assert events == [
        {
            "sequence": 1,
            "date": "01/15/2021",
            "time": "17:09:45.504",
            "original": CSER_700[3],
            "element": "Relay Powered Up",
            "state": "",
        },
        {
            "sequence": 2,
            "date": "12/09/2020",
            "time": "18:08:43.048",
            "original": CSER_700[4],
            "element": "SALARM",
            "state": "Deasserted",
        },
    ]


def test_parse_cser_421():
    events, info = parse_cser(CSER_421)

    assert info == {
        "FID": "SEL-421-R101-V0-Z001001-D20010315",
        "device_identifier": "Relay 1",
        "device_name": "Station A",
        "serial_number": "",
        "CID": "",
    }
    assert events[0]["created"] == datetime(2001, 3, 15, 0, 32, 0, 114000)
    assert events[0]["date"] == "03/15/2001"
    assert events[0]["time"] == "00:32:00.114"
    assert events[0]["element"] == "GROUND O/C 1 LINE 1"
    assert events[1]["time"] == "00:00:00.004"
    assert (events[1]["element"], events[1]["state"]) == ("Power-up", "Group 1")


def test_parse_cser_framing_and_bad_checksum(caplog):
    # Like HEAT, which passes the lines of the file, with STX/ETX
    lines = ["\x02" + CSER_700[0], *CSER_700[1:4], CSER_700[4].replace("SALARM", "SALARN"), "\x03"]
    events, _ = parse_cser(lines)

    assert len(events) == 2
    assert "checksum_valid" not in events[0]
    assert events[1]["checksum_valid"] is False
    assert "Invalid Compressed ASCII checksum" in caplog.text


def test_parse_cser_no_data():
    assert parse_cser(['"No Data Available","0668"']) == (
        [],
        {"serial_number": "", "FID": "", "CID": ""},
    )


def test_parse_and_process_cser_421_skips_empty_info():
    # The empty keys of parse_cser aren't added to the device
    dev = _dev()
    parse_and_process_events("\r\n".join(CSER_421), "CSER.TXT", dev)
    assert dev.extra["device_name"] == "Station A"
    assert "CID" not in dev.extra
    assert "serial_number" not in dev.extra
    assert not dev.serial_number


# ---------------------------------------------------------------------------
# History reports
# ---------------------------------------------------------------------------

HIS_351S = """
FEEDER 1                              Date: 02/01/24      Time: 08:40:16.740
STATION A

#      DATE       TIME     EVENT     LOCAT   CURR   FREQ GRP SHOT TARGETS

1    02/01/24 08:33:00.365 TRIG    $$$$$$$      1 60.00   3    2   10000000    10000000
2    Invalid History Data
3    01/29/24 07:30:11.055 AG T       9.65   2279 60.00   3    2   11100100    01010010
4    01/28/24 07:18:19.088 PULSE  26.92 2144 60.00 1    0
"""

HIS_421 = """
Relay 1                                       Date: 03/16/2024 Time: 11:57:27.803
Station A                                     Serial Number: 2024001234

#        DATE        TIME     EVENT   LOCAT   CURR GRP TARGETS
10007 03/15/2024 23:30:49.026 BCG T    48.17 8892 1 INST TIME ZONE_1 B_PHASE
10006 03/15/2024 07:15:00.635 ABC T  $$$$.$$ 8203 1 INST ZONE_1 A_PHASE
"""

HIS_751A = """
SEL-751A                                    Date: 02/28/2024   Time: 15:06:13
FEEDER RELAY                                Time Source: Internal

FID = SEL-751A-R400-V0-Z001001-D20230410

#      DATE          TIME            EVENT        CURRENT      FREQ    TARGETS
1   02/28/2024   13:58:23.629   Trigger             110.7      60.0    10000000
2   02/28/2024   13:54:10.003   Phase 51 Trip      1170.1      60.0    11010001
"""

HIS_700G = """
#          DATE            TIME               EVENT         CURRENT     FREQX        TARGETS
1       02/24/2024       19:08:09.705    Diff 87 Trip          526.5    60.00       11100000
2       02/24/2024       19:00:20.948    Volt/Hz 24 Trip         1.4    60.00       11000100
"""

HIS_551 = """
#        DATE         TIME        EVENT   SHOT      CURR      TARGETS
1     03/05/24    10:03:49.109    TRIG    2               6
4     02/29/24    16:16:07.174    TRIP    0            2279   INST A N
"""

HIS_710 = """
#   DATE           TIME            EVENT                 CURR     FREQ     TARGETS
1   12/03/2023      22:24:00.101    Overcurrent Trip   1049.2     60       11010000
7   12/02/2023      20:50:54.846    Lockd Rotor Trip       1.2    60       11100000
"""


def test_parse_history_351s():
    events, info = parse_history(_lines(HIS_351S))

    assert [e["sequence"] for e in events] == [1, 3, 4]  # "Invalid History Data" is skipped
    assert events[0] == {
        "sequence": 1,
        "date": "02/01/24",
        "time": "08:33:00.365",
        "original": events[0]["original"],
        "event": "TRIG",
        "current": 1.0,
        "frequency": 60.0,
        "targets": "10000000    10000000",
        "group": 3,
        "shot": 2,
    }
    assert "locat" not in events[0]  # "$$$$$$$"
    assert events[1]["event"] == "AG T"
    assert events[1]["locat"] == 9.65
    assert events[1]["targets"] == "11100100    01010010"
    assert events[2]["targets"] == ""
    assert events[2]["shot"] == 0
    assert info["device_identifier"] == "FEEDER 1"


def test_parse_history_421():
    events, info = parse_history(_lines(HIS_421))

    assert [(e["sequence"], e["event"], e.get("locat"), e["current"]) for e in events] == [
        (10007, "BCG T", 48.17, 8892.0),
        (10006, "ABC T", None, 8203.0),
    ]
    assert events[0]["targets"] == "INST TIME ZONE_1 B_PHASE"
    assert events[0]["group"] == 1
    assert events[0]["frequency"] is None  # No FREQ column
    assert info["serial_number"] == "2024001234"


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (
            HIS_751A,
            [("Trigger", 110.7, 60.0, "10000000"), ("Phase 51 Trip", 1170.1, 60.0, "11010001")],
        ),
        (
            HIS_700G,
            [
                ("Diff 87 Trip", 526.5, 60.0, "11100000"),
                ("Volt/Hz 24 Trip", 1.4, 60.0, "11000100"),
            ],
        ),
        (HIS_551, [("TRIG", 6.0, None, ""), ("TRIP", 2279.0, None, "INST A N")]),
        (
            HIS_710,
            [
                ("Overcurrent Trip", 1049.2, 60.0, "11010000"),
                ("Lockd Rotor Trip", 1.2, 60.0, "11100000"),
            ],
        ),
    ],
)
def test_parse_history_families(report, expected):
    events, _ = parse_history(_lines(report))
    assert [(e["event"], e["current"], e["frequency"], e["targets"]) for e in events] == expected


def test_parse_history_551_shot():
    events, _ = parse_history(_lines(HIS_551))
    assert [e["shot"] for e in events] == [2, 0]


def test_parse_history_ref_layout():
    lines = [
        "#    REF       DATE        TIME          EVENT        CURRENT   FREQX   TARGETS",
        "1    10003  02/24/2024  19:08:09.705   Diff 87 Trip     526.5   60.00   11100000",
    ]
    events, _ = parse_history(lines)
    assert events[0]["sequence"] == 10003
    assert events[0]["record_number"] == 1
    assert events[0]["event"] == "Diff 87 Trip"


def test_parse_history_legacy_layout():
    # A header without the known column names uses the layout PEAT parsed before
    lines = [
        "#    REF       DATE        TIME      TYPE    AMPS   HZ   TARGETS",
        "1    10003  02/24/2024  19:08:09.705   Trip   1.00   60.0   11000000",
    ]
    events, _ = parse_history(lines)
    assert (events[0]["sequence"], events[0]["event"], events[0]["targets"]) == (
        10003,
        "Trip",
        "11000000",
    )


def test_parse_history_row_header():
    # A "Row" header (like the SEL-551 SER report) is the record number
    events, _ = parse_history(
        ["Row  DATE TIME EVENT SHOT CURR TARGETS", "1  01/01/96 01:00:00.000  TRIG 0 1"]
    )
    assert len(events) == 1
    assert (events[0]["sequence"], events[0]["shot"], events[0]["current"]) == (1, 0, 1.0)


def test_parse_history_no_header():
    assert parse_history(["History Buffer Empty"]) == ([], {})


# ---------------------------------------------------------------------------
# CHISTORY
# ---------------------------------------------------------------------------


def test_parse_chistory_700():
    lines = [
        '"FID","0143"',
        '"FID=SEL-700G-R100-V0-Z001001-D20100429","08DE"',
        '"REC_NUM","REF_NUM","MONTH","DAY","YEAR","HOUR","MIN","SEC","MSEC",'
        '"EVENT","CURRENT","FREQX","TARGETS","1904"',
        '1,10003,2,24,2010,19,8,9,705,"Diff 87 Trip",526.5,60.00,"11100000","0DF9"',
    ]
    events, info = parse_chistory(lines)

    # The same keys as before CHISTORY was parsed by its labels (HEAT uses this)
    assert info == {"FID": "SEL-700G-R100-V0-Z001001-D20100429", "serial_number": "", "CID": ""}
    assert events == [
        {
            "sequence": 10003,
            "date": "02/24/2010",
            "time": "19:08:09.705",
            "original": lines[3],
            "event": "Diff 87 Trip",
            "current": 526.5,
            "frequency": 60.0,
            "targets": "11100000",
            "created": datetime(2010, 2, 24, 19, 8, 9, 705000),
        }
    ]


def test_parse_chistory_351s_and_421_layouts():
    # SEL-351S CHI labels (SEL-351S IM Appendix K)
    labels_351s = [
        "REC_NUM", "REF_NUM", "MONTH", "DAY", "YEAR", "HOUR", "MIN", "SEC", "MSEC",
        "EVENT", "LOCATION", "CURR", "FREQ", "GROUP", "SHOT", "TARGETS",
    ]  # fmt: skip
    data = "\r\n".join(
        [
            format_record(["FID"]),
            format_record(["FID=SEL-351S-6-R514-V0-Z105103-D20220101"]),
            format_record(labels_351s),
            format_record(
                [
                    1,
                    10381,
                    11,
                    7,
                    2024,
                    5,
                    32,
                    24,
                    62,
                    "ABG T",
                    94.95,
                    10000,
                    60.0,
                    1,
                    0,
                    "11100110",
                ]
            ),
            format_record(
                [2, 10379, 10, 17, 2024, 19, 1, 38, 302, "TRIP", "$$$$$$$", 8455, 60.0, 1, 0, None]
            ),
        ]
    )
    events, _ = parse_chistory(data)

    assert [
        (e["sequence"], e["event"], e.get("locat"), e["group"], e["shot"]) for e in events
    ] == [
        (10381, "ABG T", 94.95, 1, 0),
        (10379, "TRIP", None, 1, 0),
    ]
    assert events[0]["time"] == "05:32:24.062"
    assert events[1]["targets"] == ""

    # SEL-421 CHI labels start with EVENT_NUM, and have USEC
    data_421 = "\r\n".join(
        [
            format_record(["RID", "SID", "FID"]),
            format_record(["Relay 1", "Station A", "FID=SEL-421-R101"]),
            format_record(
                [
                    "EVENT_NUM",
                    "MONTH",
                    "DAY",
                    "YEAR",
                    "HOUR",
                    "MIN",
                    "SEC",
                    "MSEC",
                    "USEC",
                    "EVENT",
                    "LOCATION",
                    "TIME_SOURCE",
                    "FREQUENCY",
                    "GROUP",
                ]
            ),
            format_record(
                [10007, 3, 15, 2024, 23, 30, 49, 26, 250, "BCG T", "$$$$.$$", "HIRIG", 60.01, 1]
            ),
        ]
    )
    events, info = parse_chistory(data_421)
    assert events[0]["sequence"] == 10007
    assert events[0]["created"] == datetime(2024, 3, 15, 23, 30, 49, 26250)
    assert events[0]["frequency"] == 60.01
    assert "locat" not in events[0]
    assert info["device_name"] == "Station A"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ("", False),
        ("   \r\n  ", False),
        (b"No data available", False),
        ("FEEDER 1   Date: 01/01/24  Time: 00:00:00\nSTATION A\n\nHistory Buffer Empty", False),
        ('\x02"No Data Available","0668"\r\n\x03', False),
        ("=>", False),
        ("#  DATE  TIME  ELEMENT  STATE\n", False),
        (SER_351S, True),
        (b"\xb0\r\n1   01/01/2024  00:00:00.000  IN101  Asserted", True),
        ("\n".join(CSER_700), True),
    ],
)
def test_event_data_present(data, expected):
    assert event_data_present(data) is expected


@pytest.mark.parametrize(
    ("dataset", "expected"),
    [
        ("SER.TXT", ("ser", False)),
        ("CSER.TXT", ("ser", True)),
        ("192.0.2.1_SER.TXT", ("ser", False)),
        # A prefix doesn't change the kind, even if it has "his" or "ser" in it
        ("Whistler_SER.TXT", ("ser", False)),
        ("this_SER.TXT", ("ser", False)),
        ("docser_HISTORY.TXT", ("history", False)),
        ("user_HISTORY.TXT", ("history", False)),
        ("site_CHISTORY.TXT", ("history", True)),
        ("USER.TXT", ("", False)),
        ("chis", ("history", True)),
        ("SER", ("ser", False)),
        ("cser", ("ser", True)),
        ("CSE", ("ser", True)),
        ("Sequential Event Recorder ('ser')", ("ser", False)),
        ("HISTORY.TXT", ("history", False)),
        ("CHISTORY.TXT", ("history", True)),
        ("HIS", ("history", False)),
        ("CHI", ("history", True)),
        ("Historical Events ('his')", ("history", False)),
        ("SET_1.TXT", ("", False)),
    ],
)
def test_event_dataset_kind(dataset, expected):
    assert event_dataset_kind(dataset) == expected


def test_split_lines():
    assert split_lines(b"\x02 a \r\n\r\n  \r\n\xb0\x03") == ["a", "\xb0"]
    assert split_lines("\x03\x02") == []


def test_date_formats():
    assert infer_date_format(["01/02/2024", "25/03/2024"]) == "DMY"
    assert infer_date_format(["01/02/2024", "03/25/2024"]) == "MDY"
    assert infer_date_format(["2024/03/05"]) == "YMD"
    assert infer_date_format(["01/02/2024", "11/07", "bad"]) == ""

    assert parse_sel_datetime("05/03/2024", "01:02:03.456") == datetime(
        2024, 5, 3, 1, 2, 3, 456000
    )
    assert parse_sel_datetime("05/03/2024", "01:02:03", "DMY") == datetime(2024, 3, 5, 1, 2, 3)
    assert parse_sel_datetime("24/03/05", "01:02:03", "YMD") == datetime(2024, 3, 5, 1, 2, 3)
    with pytest.raises(ValueError):
        parse_sel_datetime("99/99/99", "01:02:03")


def test_extract_date_format():
    assert extract_date_format({"G": {"DATE_F": {"value": "YMD", "description": ""}}}) == "YMD"
    assert extract_date_format({"G": {"DATE_F": "dmy"}}) == "DMY"
    assert extract_date_format({"G": {"DATE_F": "XYZ"}, "INFO": ["a"]}) == ""

    configs = parse_config_data((RELAY_DIR / "sel-710_SET_ALL.TXT").read_bytes())
    assert extract_date_format(configs) == "MDY"


def test_parse_set_all_stores_date_format():
    dev = SELRelay.parse(RELAY_DIR / "sel-710_SET_ALL.TXT")
    assert dev.extra["date_format"] == "MDY"


# ---------------------------------------------------------------------------
# Events in the data model
# ---------------------------------------------------------------------------


def test_process_ser_events():
    dev = _dev()
    events, _ = parse_and_process_events(SER_351S, "SER.TXT", dev)

    assert len(events) == 5
    assert dev.extra["device_time"] == datetime(2024, 4, 12, 10, 20, 16, 896000)
    assert len(dev.event) == 5

    power_up = dev.event[0]
    assert power_up.dataset == "ser"
    assert power_up.created == datetime(2024, 4, 12, 8, 30, 33, 222000)
    assert power_up.message == "Relay newly powered up"
    assert power_up.action == "relay-newly-powered-up"
    assert power_up.type == {"start"}
    assert power_up.category == {"host"}
    assert power_up.sequence == 19
    assert power_up.provider == "192.0.2.50"
    assert power_up.module == "SELRelay"
    assert power_up.extra == {
        "source_datasets": ["SER.TXT"],
        "element": "Relay newly powered up",
    }

    asserted = dev.event[1]
    assert asserted.message == "IN102 Asserted"
    assert asserted.action == "asserted-in102"
    assert asserted.type == {"change"}
    assert asserted.extra["state"] == "Asserted"


def test_process_events_classification():
    dev = _dev()
    raw = [
        # Combined message (551, 710, 749M): checked before "change"
        {"sequence": 3, "date": "01/01/2024", "time": "00:00:01", "original": "a",
         "element": "Relay newly powered up or settings changed", "state": ""},
        {"sequence": 2, "date": "01/01/2024", "time": "00:00:02", "original": "b",
         "element": "Settings changed", "state": "Class R 1"},
        {"sequence": 1, "date": "01/01/2024", "time": "00:00:03", "original": "c",
         "element": "Diagnostic restart", "state": ""},
        {"sequence": 4, "date": "01/01/2024", "time": "00:00:04", "original": "d",
         "element": "SER archive cleared", "state": ""},
    ]  # fmt: skip
    process_events(raw, dev, "SER")

    by_seq = {e.sequence: e for e in dev.event}
    assert by_seq[3].type == {"start", "change"}
    assert by_seq[3].category == {"host", "configuration"}
    assert by_seq[2].type == {"change"}
    assert by_seq[2].category == {"host", "configuration"}
    assert by_seq[1].type == {"start"}
    assert by_seq[4].type == {"change", "deletion"}


def test_process_history_events():
    dev = _dev()
    parse_and_process_events(HIS_351S, "HIS", dev)

    trig, fault, pulse = dev.event
    assert trig.dataset == "history"
    assert trig.message == "TRIG"
    assert trig.type == {"info"}
    assert trig.extra == {
        "source_datasets": ["HIS"],
        "event": "TRIG",
        "current": 1.0,
        "frequency": 60.0,
        "targets": "10000000    10000000",
        "group": 3,
        "shot": 2,
    }
    # "AG T" is a trip (fault type and "T")
    assert fault.type == {"info", "change"}
    assert fault.message == (
        "AG T (Targets: 11100100    01010010, Current: 2279.0, Frequency: 60.0)"
    )
    assert fault.extra["locat"] == 9.65
    assert pulse.message == "PULSE"


def test_trip_message():
    dev = _dev()
    process_events(
        [{"sequence": 1, "date": "1/1/2024", "time": "00:00:00", "original": "x",
          "event": "Trip", "current": 1.0, "frequency": 60.0, "targets": "110"}],
        dev,
        "HISTORY.TXT",
    )  # fmt: skip
    # The old message was "Trip 110 (Current: 1.0- Frequency: 60.0"
    assert dev.event[0].message == "Trip (Targets: 110, Current: 1.0, Frequency: 60.0)"


def test_ser_and_history_with_same_sequence_are_separate():
    # The old code stored events by sequence, so these were merged into one event
    dev = _dev()
    parse_and_process_events(
        "#  DATE  TIME  ELEMENT  STATE\n1  01/02/2024  03:04:05.006  OUT101  Asserted", "SER", dev
    )
    parse_and_process_events(HIS_700G, "HISTORY.TXT", dev)

    assert sorted((e.dataset, e.sequence) for e in dev.event) == [
        ("history", 1),
        ("history", 2),
        ("ser", 1),
    ]


def test_same_event_from_different_sources_is_merged():
    dev = _dev()
    parse_and_process_events(SER_421, "SER.TXT", dev)
    parse_and_process_events(SER_421, "SER", dev)
    # The CSER has underscores in the names (SEL-421 IM Figure 3.19), and
    # one of the rows (the power-up) is also in the SER
    cser = "\r\n".join(
        [
            format_record(
                ["#", "MONTH", "DAY", "YEAR", "HOUR", "MIN", "SEC", "MSEC", "ELEMENT", "STATE"]
            ),
            format_record([1, 3, 15, 2024, 0, 32, 0, 114, "GROUND_O/C_1_LINE_1", "51S1_DROPOUT"]),
            format_record([7, 3, 15, 2024, 0, 0, 0, 4, "Power-up", "Group 1"]),
        ]
    )
    parse_and_process_events(cser, "CSER.TXT", dev)

    assert len(dev.event) == 5
    power_up = next(e for e in dev.event if e.message == "Power-up Group 1")
    assert power_up.extra["source_datasets"] == ["SER.TXT", "SER", "CSER.TXT"]
    assert power_up.sequence == 6  # From the first source


def test_two_digit_years_from_chistory_and_history_are_merged():
    # Relays with 2-digit years (e.g. SEL-551) use the same century for the
    # YEAR label in CHISTORY as dates in HISTORY, so the events are merged
    dev = _dev()
    parse_and_process_events(
        "#  DATE  TIME  EVENT  SHOT  CURR  TARGETS\n"
        "1  02/29/96  13:44:30.146  TRIP  0  2279  INST A N",
        "HISTORY.TXT",
        dev,
    )
    labels = "REC_NUM REF_NUM MONTH DAY YEAR HOUR MIN SEC MSEC EVENT SHOT CURR TARGETS"
    chistory = "\r\n".join(
        [
            format_record(["FID"]),
            format_record(["FID=SEL-551-R101-V0-D20200321"]),
            format_record(labels.split()),
            format_record([1, 1, 2, 29, 96, 13, 44, 30, 146, "TRIP", 0, 2279, "INST A N"]),
        ]
    )
    events, _ = parse_and_process_events(chistory, "CHISTORY.TXT", dev)

    assert events[0]["created"] == datetime(1996, 2, 29, 13, 44, 30, 146000)
    assert events[0]["date"] == "02/29/1996"
    assert len(dev.event) == 1
    assert dev.event[0].extra["source_datasets"] == ["HISTORY.TXT", "CHISTORY.TXT"]


def test_dates_use_the_date_format_setting():
    ser = "#  DATE  TIME  ELEMENT  STATE\n1  {}  03:04:05.006  OUT101  Asserted"

    dev = _dev("192.0.2.51")
    dev.extra["date_format"] = "YMD"
    parse_and_process_events(ser.format("24/03/05"), "SER", dev)
    assert dev.event[0].created == datetime(2024, 3, 5, 3, 4, 5, 6000)

    dev = _dev("192.0.2.52")
    dev.extra["date_format"] = "DMY"
    parse_and_process_events(ser.format("05/03/2024"), "SER", dev)
    assert dev.event[0].created == datetime(2024, 3, 5, 3, 4, 5, 6000)

    # MDY is the default
    dev = _dev("192.0.2.53")
    parse_and_process_events(ser.format("05/03/2024"), "SER", dev)
    assert dev.event[0].created == datetime(2024, 5, 3, 3, 4, 5, 6000)


def test_dates_use_the_inferred_date_format():
    dev = _dev()
    report = (
        "RELAY   Date: 04/03/2024  Time: 10:00:00.000\nSTATION\n"
        "#  DATE  TIME  ELEMENT  STATE\n"
        "2  25/03/2024  03:04:05.006  OUT101  Asserted\n"
        "1  05/03/2024  03:04:05.006  OUT101  Deasserted\n"
    )
    parse_and_process_events(report, "SER", dev)

    assert [e.created.date() for e in dev.event] == [
        datetime(2024, 3, 25).date(),
        datetime(2024, 3, 5).date(),
    ]
    assert dev.extra["device_time"] == datetime(2024, 3, 4, 10, 0)


def test_invalid_events_are_skipped(caplog):
    dev = _dev()
    process_events(
        [
            {"sequence": 1, "date": "13/13/2024", "time": "00:00:00", "original": "bad date",
             "element": "OUT101", "state": "Asserted"},
            {"sequence": 2, "original": "no date", "element": "OUT101"},
            {"sequence": 3, "date": "01/01/2024", "time": "00:00:00", "original": "no element"},
            {"sequence": 4, "date": "01/01/2024", "time": "00:00:00", "original": "ok",
             "element": "OUT101", "state": "Asserted"},
        ],
        dev,
        "SER",
    )  # fmt: skip

    assert [e.original for e in dev.event] == ["ok"]
    assert "Skipped 3 invalid events" in caplog.text


def test_parse_and_process_events_cser_and_compressed_detection():
    dev = _dev()
    events, info = parse_and_process_events("\r\n".join(CSER_421), "CSER.TXT", dev)

    assert len(events) == 2
    assert dev.event[0].created == datetime(2001, 3, 15, 0, 32, 0, 114000)
    assert dev.firmware.id == "SEL-421-R101-V0-Z001001-D20010315"
    assert dev.name == "Station A - Relay 1"
    assert info["device_identifier"] == "Relay 1"

    # Compressed ASCII in a file named SER.TXT is parsed as CSER
    dev = _dev("192.0.2.54")
    assert len(parse_and_process_events("\r\n".join(CSER_700), "SER.TXT", dev)[0]) == 2
    assert dev.serial_number == "1234567890"


def test_parse_and_process_events_empty_buffer_front_matter():
    dev = _dev()
    report = (
        "FEEDER 1        Date: 12/03/24   Time: 09:01:10.354\r\n"
        "STATION A\r\n\r\n"
        "History Buffer Empty\r\n"
    )
    events, info = parse_and_process_events(report, "HIS", dev)

    assert events == []
    assert info["device_time"] == datetime(2024, 12, 3, 9, 1, 10, 354000)
    assert dev.extra["device_time"] == info["device_time"]


def test_parse_and_process_events_unknown_dataset():
    assert parse_and_process_events(SER_351S, "SET_1.TXT", _dev()) == ([], {})


def test_parse_and_process_events_non_ascii_bytes():
    # Byte 0xB0 (degree sign in Latin-1) used to raise UnicodeDecodeError
    data = SER_351S.replace("LB4 ", "LB\xb0 ").encode("latin-1")
    events, _ = parse_and_process_events(data, "SER.TXT", _dev())
    assert events[2]["element"] == "LB\xb0"


# ---------------------------------------------------------------------------
# Pulls and parsing files
# ---------------------------------------------------------------------------


class FakeFTP(FTP):
    """A relay's FTP server, with the files in memory."""

    def __init__(self, files: dict[str, bytes], ip: str) -> None:
        super().__init__(ip)
        self.files = files

    def nlst_files(self, directory: str | None = None) -> list[str]:
        if not directory:
            return sorted({path.split("/")[0] for path in self.files})
        return sorted(
            path.split("/", 1)[1] for path in self.files if path.startswith(f"{directory}/")
        )

    def download_binary(self, filename, save_path=None, save_to_file=True) -> bytes | None:  # noqa: ARG002
        return self.files.get(filename)


def test_pull_configs_parses_ser_and_history():
    dev = _dev("192.0.2.60")
    files = {
        "REPORTS/SER.TXT": SER_421.encode(),
        "REPORTS/CSER.TXT": "\r\n".join(CSER_421).encode(),  # Not parsed, SER has events
        "REPORTS/HISTORY.TXT": HIS_421.encode(),
    }

    SELRelay.pull_configs(dev, FakeFTP(files, ip="192.0.2.60"))

    datasets = sorted({(e.dataset, e.extra["source_datasets"][0]) for e in dev.event})
    assert datasets == [("history", "HISTORY.TXT"), ("ser", "SER.TXT")]
    assert len([e for e in dev.event if e.dataset == "ser"]) == 5
    assert len([e for e in dev.event if e.dataset == "history"]) == 2
    # The uptime, from the SER header time and the power-up record
    assert dev.uptime is not None


def test_pull_configs_cser_fallback():
    dev = _dev("192.0.2.61")
    files = {
        # A FILE READ of SER.TXT on 400-series relays clears the viewed records
        # for that port (SER CV), so a later read from the same port is empty
        "REPORTS/SER.TXT": b"No data available\r\n",
        "REPORTS/CSER.TXT": "\r\n".join(CSER_421).encode(),
    }

    SELRelay.pull_configs(dev, FakeFTP(files, ip="192.0.2.61"))

    assert len(dev.event) == 2
    assert {e.extra["source_datasets"][0] for e in dev.event} == {"CSER.TXT"}


def test_parse_relay_files_dir_non_ascii(tmp_path):
    relay = tmp_path / "relay"
    (relay / "REPORTS").mkdir(parents=True)
    # A 0xB0 byte in SER.TXT used to raise UnicodeDecodeError in directory parses
    (relay / "REPORTS" / "SER.TXT").write_bytes(
        SER_351S.replace("LB4 ", "LB\xb0 ").encode("latin-1")
    )
    (relay / "REPORTS" / "HISTORY.TXT").write_text(HIS_351S)

    dev = SELRelay.parse(relay)

    assert dev is not None
    assert len([e for e in dev.event if e.dataset == "ser"]) == 5
    assert len([e for e in dev.event if e.dataset == "history"]) == 3
    # Offline parse: the uptime "now" isn't known
    assert dev.uptime is None
    assert dev.extra["last_boot_device_time"] == datetime(2024, 4, 12, 8, 30, 33, 222000)


def test_parse_single_files(tmp_path):
    ser = tmp_path / "SER.TXT"
    ser.write_text(SER_751A)
    dev = SELRelay.parse(ser)
    assert len(dev.event) == 3
    assert dev.uptime is None

    chistory = tmp_path / "CHISTORY.TXT"
    chistory.write_text(
        "\r\n".join(
            [
                '"FID","0143"',
                '"FID=SEL-700G-R100-V0-Z001001-D20100429","08DE"',
                '"REC_NUM","REF_NUM","MONTH","DAY","YEAR","HOUR","MIN","SEC","MSEC",'
                '"EVENT","CURRENT","FREQX","TARGETS","1904"',
                '1,10003,2,24,2010,19,8,9,705,"Diff 87 Trip",526.5,60.00,"11100000","0DF9"',
            ]
        )
    )
    dev = SELRelay.parse(chistory)
    assert dev.event[0].dataset == "history"
    assert dev.description.model == "700G"

    empty = tmp_path / "CSER.TXT"
    empty.write_text('"No Data Available","0668"\r\n')
    dev = SELRelay.parse(empty)
    assert dev is not None
    assert dev.event == []


def test_parse_prefixed_event_files(tmp_path):
    # A prefix with "his" or "ser" in it doesn't select the wrong parser
    ser = tmp_path / "Whistler_SER.TXT"
    ser.write_text(SER_751A)
    dev = SELRelay.parse(ser)
    assert len(dev.event) == 3
    assert {e.dataset for e in dev.event} == {"ser"}

    history = tmp_path / "docser_HISTORY.TXT"
    history.write_text(HIS_700G)
    dev = SELRelay.parse(history)
    assert [e.extra["event"] for e in dev.event] == ["Diff 87 Trip", "Volt/Hz 24 Trip"]
    assert {e.dataset for e in dev.event} == {"history"}


def test_pull_more_commands_his_and_ser(mocker):
    tn = SELTelnet("192.0.2.62")
    mocker.patch.object(tn, "elevate", return_value=True)
    for name in ["get_sta", "get_device_time", "show_mac", "get_active_group"]:
        mocker.patch.object(tn, name, return_value=None)
    for name in ["show_eth", "show_bre", "show_eve", "show_sum", "show_status"]:
        mocker.patch.object(tn, name, return_value=[])
    # The Telnet "his" path used to fail on 351-format output
    mocker.patch.object(tn, "show_his", return_value=split_lines(HIS_351S))
    mocker.patch.object(tn, "show_ser", return_value=split_lines(SER_351S))
    dev = _dev("192.0.2.62")

    assert SELRelay.pull_more_commands(dev, tn) is True

    assert len([e for e in dev.event if e.dataset == "history"]) == 3
    assert len([e for e in dev.event if e.dataset == "ser"]) == 5
    assert str(dev.uptime) == "1:49:43.674000"
    assert dev.extra["uptime_source"] == "ser_power_up"


def test_selhttp_get_historical_events(mocker):
    dev = _dev("192.0.2.63")
    http = SELHTTP("192.0.2.63", 80)

    mocker.patch.object(http, "read_page", return_value=HIS_351S)
    assert http.get_historical_events(dev) is True
    assert len(dev.event) == 3
    assert dev.event[0].dataset == "history"
    assert dev.event[0].extra["source_datasets"] == ["Historical Events ('his')"]
    assert dev.event[0].extra["group"] == 3
    assert dev.name == "STATION A - FEEDER 1"  # From the front matter

    # Reading the page again doesn't add duplicates
    assert http.get_historical_events(dev) is True
    assert len(dev.event) == 3

    # 451 (no events)
    mocker.patch.object(http, "read_page", return_value="No data available\n")
    assert http.get_historical_events(_dev("192.0.2.64")) is False

    # No header line (the old code raised StopIteration) or blank lines (IndexError)
    mocker.patch.object(http, "read_page", return_value="\n  \nsomething else\n")
    assert http.get_historical_events(_dev("192.0.2.65")) is False

    mocker.patch.object(http, "read_page", side_effect=relay_parse.ParseError("broken"))
    assert http.get_historical_events(_dev("192.0.2.66")) is False
