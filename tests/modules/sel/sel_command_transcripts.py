"""
Canned SEL ASCII command outputs for the tests of the additional commands
(``test_sel_commands.py``), for the scripted relay in ``fake_sel_relay.py``.

All of the data is synthetic. The layouts follow the command examples in public
SEL instruction manuals, with made-up values:

- SEL-351S IM 20171023: ``STA``, ``TIM Q``, and ``HIS`` (Section 10, Command Explanations),
  ``GOO`` (Figure 10.9), ``SHO`` (Section 10), ``CAS``, ``CHI``, ``SNS``, ``BNA``,
  and ``DNA X`` (Appendices J and K).
- SEL-421 IM 20130627: ``TIME Q`` (Figure 4.67), ``STA A`` (Figure 6.32),
  ``SER`` (Figure 3.18), and the Compressed ASCII SER layout (Reference Manual Section 5).
- SEL-751A IM 20130329: ``STA`` (Figure 1.3), ``STA S`` (Figure 7.22), ``GOO``
  (Figure 7.19), ``MAC``, and ``ETH`` (Section 7).

The ``VER`` and ``ETH`` layouts are the ones in ``data_files/web/`` (refer to
its README). IP addresses are from RFC 5737 and MAC addresses use the SEL OUI
with made-up device parts.
"""

from peat.modules.sel.sel_cascii import format_record
from peat.modules.sel.sel_commands import normalize_command

from .fake_sel_relay import FID_451

FID_351S = "SEL-351S-7-R516-V2-Z106105-D20190111"
FID_421 = "SEL-421-5-R310-V0-Z016013-D20120223"
FID_751A = "SEL-751A-R400-V0-Z008004-D20190118"


def cascii(records: list[list]) -> str:
    """A Compressed ASCII message (STX, the records with checksums, ETX)."""
    return "\x02" + "".join(format_record(r) + "\r\n" for r in records) + "\x03"


# ---------------------------------------------------------------------------
# 300 series (SEL-351S)
# ---------------------------------------------------------------------------

HEADER_351S = [
    "FEEDER 1                         Date: 04/12/24    Time: 10:20:16.896",
    "STATION A",
    "",
]

STA_351S = [
    *HEADER_351S,
    f"FID={FID_351S}            CID=83ED",
    "SELF TESTS",
    "W=Warn         F=Fail",
    "         IA       IB       IC      IN       VA      VB     VC      VS       MOF",
    "OS       -1       1        1       1        2       0      1       2        0",
    "OSH      -1       0        0       1",
    "         15V_PS   5V_REG   3.3V_REG",
    "PS       14.93    4.99     3.27",
    "         RAM      ROM      FPGA    EEPROM   FLASH   A/D    USB_BRD COM_BRD IO_BRD",
    "         OK       OK       OK      OK       OK      OK     OK      OK      OK",
    "         TEMP     RTC      HMI",
    "         32.2     OK       OK",
    "Relay Enabled",
]

TIM_Q_351S = [
    *HEADER_351S,
    f"FID={FID_351S}     CID=83ED",
    "",
    "UTC: 15:20:16",
    "UTC Offset: -5.00 hrs",
    "",
    "Time Source: OTHER",
    "Last Update Source: NONV CLK",
    "",
    "Last Update Time: 08:00:01   04/12/24",
    "",
    "Internal Clock Period: 20.000156 ns",
]

VER_351S = [
    "Partnumber: 0351S7XHD3E5462",
    "Serial Number: 2009000123",
    "Analog Input Voltage (PT): 300 Vac, Wye, Delta, or Single connected",
    "Analog Input Current (CT): 5 Amp Phase, 5 Amp Neutral",
    "Relay Features:",
    "  DNP",
    "  Modbus",
    "  IEC61850",
    "SELboot checksum 58FF OK",
    f"FID={FID_351S}",
    "BFID=SLBT-3CF1-R200-V0-Z100100-D20120321",
]

ETH_351S = [
    *HEADER_351S,
    "NETMODE: FAILOVER",
    "PRIMARY PORT: 5A",
    "ACTIVE PORT: 5A",
    "",
    "        LINK  SPEED  DUPLEX  MEDIA",
    "PORT 5A Up    100M   Full    TX",
    "PORT 5B Down  --     --      TX",
    "",
    "IP Port:",
    "  MAC: 00-30-A7-01-09-2E",
    "  IP ADDRESS: 192.0.2.30",
    "  SUBNET MASK: 255.255.255.0",
    "  DEFAULT GATEWAY: 192.0.2.1",
    "",
    "  PACKETS         BYTES          ERRORS",
    "  SENT   RCVD     SENT   RCVD    SENT  RCVD",
    "  1200   1100     54000  48000   0     0",
    "GOOSE Port:",
    "  MAC: 00-30-A7-01-09-2F",
]

#: The MAC format PEAT's authors saw on a SEL-351S
MAC_351S = [
    "(IP) MAC Address:    00-30-A7-01-09-2E",
    "(GOOSE) MAC Address: 00-30-A7-01-09-2F",
]

GOO_351S = [
    "GOOSE Transmit Status",
    "",
    " MultiCastAddr   Ptag:Vlan AppID StNum       SqNum      TTL    Code",
    "-----------------------------------------------------------------------------",
    "SEL_351S_1CFG/LLN0$GO$GooseDSet13",
    " 01-0C-CD-01-00-12 4:1     4114   1          11175      638",
    " Data Set: SEL_351S_1CFG/LLN0$DSet13",
    "",
    "GOOSE Receive Status",
    "",
    " MultiCastAddr   Ptag:Vlan AppID StNum       SqNum      TTL    Code",
    "-----------------------------------------------------------------------------",
    "SEL_487E_1CFG/LLN0$GO$GOOSEMessage1",
    " 01-0C-CD-01-00-10 4:1     4112   2          18248      2000",
    " Data Set: SEL_487E_1CFG/LLN0$DSet13",
    "",
    "SEL_487E_1CFG/LLN0$GO$GOOSEMessage2",
    " 01-0C-CD-01-00-05 4:3     5      3          18249      2000   TTL EXPIRED",
    " Data Set: SEL_487E_1CFG/LLN0$DSet03",
]

SER_351S = [
    *HEADER_351S,
    f"FID={FID_351S}     CID=83ED",
    "",
    "#        DATE      TIME            ELEMENT               STATE",
    "3        04/12/24  08:30:33.222    Relay newly powered up",
    "2        04/12/24  09:20:22.830    IN102                 Asserted",
    "1        04/12/24  09:20:23.001    IN102                 Deasserted",
]

#: CAS on a SEL-351S: no CSE (SEL-351S IM 20171023, Appendix K)
CAS_351S = cascii(
    [
        ["CAS", 3],
        ["CST", 1],
        ["1H", "FID"],
        ["1D", "45S"],
        ["CHI", 1],
        ["1H", "FID"],
        ["1D", "45S"],
        [
            "16H",
            "REC_NUM",
            "REF_NUM",
            "MONTH",
            "DAY",
            "YEAR",
            "HOUR",
            "MIN",
            "SEC",
            "MSEC",
            "EVENT",
            "LOCATION",
            "CURR",
            "FREQ",
            "GROUP",
            "SHOT",
            "TARGETS",
        ],
        ["44D", "I", "I", "I", "I", "I", "I", "I", "I", "I", "6S", "F", "I", "F", "I", "I", "22S"],
        ["CEV", 1],
        ["1H", "FID"],
        ["1D", "45S"],
    ]
)

#: The event history as text (the HIS command example in Section 10), with the
#: event of CHI_351S
HIS_351S = [
    *HEADER_351S,
    "#      DATE       TIME     EVENT     LOCAT   CURR   FREQ GRP SHOT TARGETS",
    "",
    "1    04/12/24 09:30:01.250 AG T       2.15    820 60.00   1    0   11100100    01010010",
]

CHI_351S = cascii(
    [
        ["FID"],
        [f"FID={FID_351S}"],
        [
            "REC_NUM",
            "REF_NUM",
            "MONTH",
            "DAY",
            "YEAR",
            "HOUR",
            "MIN",
            "SEC",
            "MSEC",
            "EVENT",
            "LOCATION",
            "CURR",
            "FREQ",
            "GROUP",
            "SHOT",
            "TARGETS",
        ],
        [1, 10002, 4, 12, 2024, 9, 30, 1, 250, "AG T", 2.15, 820, 60.0, 1, 0, "INST A G"],
    ]
)

CST_351S = cascii(
    [
        ["FID"],
        [f"FID={FID_351S}"],
        ["MONTH", "DAY", "YEAR", "HOUR", "MIN", "SEC", "MSEC"],
        [4, 12, 2024, 10, 20, 16, 896],
        ["RAM", "ROM", "FPGA", "TEMP"],
        ["OK", "OK", "OK", "32.2"],
    ]
)

SNS_351S = cascii([["TRIP", "51P1T", "51G1T", "67P1", "PB10", "OC", "CLOSE", "52A"], ["CF"]])

BNA_351S = cascii([["*", "*", "*", "*", "*", "PWRUP", "STSET", "*"]])

DNA_351S = cascii(
    [
        ["EN", "TRIP", "TIME", "COMM", "SOTF", "RCRS", "RCLO", "51"],
        ["50A1", "50B1", "50C1", "*", "*", "*", "*", "*"],
    ]
)

SHO_G_351S = [
    "Global Settings:",
    "TGR     =    3.00      NFREQ   = 60          PHROT   = ABC",
    "DATE_F  = MDY          FP_TO   = 15.00",
]

SHO_1_351S = [
    "Group 1",
    "Group Settings:",
    "RID     =FEEDER 1                            TID      =STATION A",
    "CTR     = 120        CTRN      = 120         PTR      = 180.00",
]

SHO_L_1_351S = [
    "SELogic group 1",
    "",
    "SELogic Control Equations:",
    "TR      = 51P1T + 51G1T + 67P1 + PB10 + OC",
    "ULTR    = !(51P1 + 51G1)",
]

SHO_P_351S = [
    "Port 5",
    "",
    "EPORT   = Y         IPADDR = 192.0.2.30",
    "SUBNETM = 255.255.255.0",
    "DEFRTR = 192.0.2.1",
    "ETELNET = Y",
    "EFTPSERV= N         EHTTP   = N",
]

SHO_R_351S = [
    "Sequential Events Recorder trigger lists:",
    "SER1    = TRIP,51P1T,51G1T,67P1,PB10,OC",
    "SER2    = CLOSE,52A,CF",
]

OUTPUTS_351S: dict[str, list[str] | str] = {
    "STA": STA_351S,
    "TIM Q": TIM_Q_351S,
    "VER": VER_351S,
    "ETH": ETH_351S,
    "MAC": MAC_351S,
    "GOO": GOO_351S,
    "SER": SER_351S,
    "HIS": HIS_351S,
    "CAS": CAS_351S,
    "CHI": CHI_351S,
    "CST": CST_351S,
    "SNS": SNS_351S,
    "BNA": BNA_351S,
    "DNA X": DNA_351S,
    "SHO G": SHO_G_351S,
    "SHO 1": SHO_1_351S,
    "SHO L 1": SHO_L_1_351S,
    "SHO P": SHO_P_351S,
    "SHO R": SHO_R_351S,
}

# ---------------------------------------------------------------------------
# 400 series (SEL-421)
# ---------------------------------------------------------------------------

HEADER_421 = [
    "Relay 1                                       Date: 02/02/2009 Time: 08:31:10.341",
    "Station A                                     Serial Number: 2009001234",
    "",
]

STA_421 = [
    *HEADER_421,
    f"FID={FID_421}            CID=0x9AED",
    "",
    "Failures",
    "  No Failures",
    "",
    "Warnings",
    "  No Warnings",
    "",
    "SELogic Relay Programming Environment Errors",
    "  No Errors",
    "",
    "Relay Enabled",
]

STA_A_421 = [
    *HEADER_421,
    f"FID={FID_421}            CID=0x9AED",
    "",
    "Failures",
    "  No Failures",
    "",
    "Warnings",
    "  IO_BRD1 Warning",
    "",
    "Channel Offsets (mV)        WWarn      FFail",
    "  CH1 CH2 CH3 CH4 CH5 CH6 MOF",
    "    0    1    0    0    2    0    0",
    "",
    "Power Supply Voltages (V)  WWarn    FFail",
    "  3.3V_PS 5V_PS N5V_PS 15V_PS     N15V_PS",
    "     3.28   4.91   -4.93  14.70    -14.79",
    "",
    "Temperature",
    "   23.7 degrees Celsius",
    "",
    "Active High Accuracy Time Synchronization Source: IRIG-B",
    "",
    "Relay Enabled",
]

TIME_Q_421 = [
    *HEADER_421,
    "Time Source: HIRIG",
    "Last Update Source: HIRIG",
    "",
    "IRIG Time Mark Period:       1000.000000 ms",
    "",
    "Internal Clock Period:       24.999995 ns",
]

HELP_421 = [
    *HEADER_421,
    "2AC      Go to Access Level 2",
    "ACC      Go to Access Level 1",
    "CAS      Compressed ASCII configuration",
    "CSE      Compressed SER",
    "DAT      Date",
    "ETH      Ethernet status",
    "GRO      Active group",
    "HIS      Event history",
    "ID       Identification",
    "QUI      Quit",
    "SER      Sequential Events Recorder",
    "SHO      Show settings",
    "STA      Relay status",
    "TIM      Time",
    "VER      Version",
]

#: CAS on a SEL-421: CSE is listed
CAS_421 = cascii(
    [
        ["CAS", 2],
        ["CST", 1],
        ["1H", "FID"],
        ["1D", "45S"],
        ["CSE", 1],
        ["3H", "RID", "SID", "FID"],
        ["1D", "30S", "30S", "45S"],
        ["10H", "#", "MONTH", "DAY", "YEAR", "HOUR", "MIN", "SEC", "MSEC", "ELEMENT", "STATE"],
        ["1000D", "I", "I", "I", "I", "I", "I", "I", "I", "40S", "40S"],
    ]
)

#: The 421 SER report (Figure 3.18), as Compressed ASCII. The relay's clock
#: (DATE and TIME in fake_sel_relay.py) is 02/02/09 08:31:10.
CSE_421_ROWS = [
    [6, 2, 1, 2009, 0, 0, 0, 4, "Power-up", "Group 1"],
    [5, 2, 1, 2009, 0, 0, 0, 22, "Relay", "Enabled"],
    [4, 2, 1, 2009, 0, 30, 0, 21, "GROUND O/C 1 LINE 1", "51S1 PICKED UP"],
    [3, 2, 1, 2009, 0, 30, 3, 221, "GROUND O/C 1 LINE 1", "51S1 TIMEOUT"],
]

CSE_421 = cascii(
    [
        ["RID", "SID", "FID"],
        ["Relay 1", "Station A", f"FID={FID_421}"],
        ["#", "MONTH", "DAY", "YEAR", "HOUR", "MIN", "SEC", "MSEC", "ELEMENT", "STATE"],
        *CSE_421_ROWS,
    ]
)

#: The same records in a text SER report
SER_421 = [
    *HEADER_421,
    f"FID={FID_421}",
    "",
    "#        DATE         TIME           ELEMENT               STATE",
    "6      02/01/2009   00:00:00.004   Power-up              Group 1",
    "5      02/01/2009   00:00:00.022   Relay                 Enabled",
    "4      02/01/2009   00:30:00.021   GROUND O/C 1 LINE 1   51S1 PICKED UP",
    "3      02/01/2009   00:30:03.221   GROUND O/C 1 LINE 1   51S1 TIMEOUT",
]

OUTPUTS_421: dict[str, list[str] | str] = {
    normalize_command("HELP"): HELP_421,
    "CAS": CAS_421,
    "CSE": CSE_421,
    "STA": STA_421,
    "STA A": STA_A_421,
    "TIM Q": TIME_Q_421,
    "SER 1000": SER_421,
}

# ---------------------------------------------------------------------------
# 700 series (SEL-751A)
# ---------------------------------------------------------------------------

STA_751A = [
    "SEL-751A                                   Date: 08/13/2024   Time: 20:24:29",
    "FEEDER RELAY                               Time Source: External",
    "Serial Num = 000000000000000",
    f"FID = {FID_751A}                  CID = CD05",
    "PART NUM = 751A01B1X0X7386163X",
    "SELF TESTS (W=Warn)",
    "  FPGA GPSB HMI  RAM  ROM  CR_RAM  NON_VOL  CLOCK  CID_FILE  +0.9V  +1.2V",
    "  OK   OK   OK   OK   OK   OK      OK       OK     OK        0.90   1.19",
    "Option Cards",
    "  CARD_C CARD_D CARD_E CURRENT",
    "  OK     OK     OK     OK",
    "Offsets",
    "  IA IB IC IN VA VB VC VS",
    "  OK OK OK OK OK OK OK OK",
    " Relay Enabled",
]

STA_S_751A = [
    "SEL-751A                                        Date: 08/13/2024   Time: 15:04:16",
    "FEEDER RELAY                                    Time Source: Internal",
    "",
    "Part Number     751A01BBX5X7186030X",
    "Global (%)       81",
    "FP (%)           69",
    "Report (%)       96",
    "",
    "                 GROUP 1    GROUP 2   GROUP 3",
    "Execution (%)     90         90        90",
    "Group (%)         81         81        81",
    "Logic (%)         89         89        89",
]

MAC_751A = ["Port 1 MAC Address:   00-30-A7-00-75-6A"]

OUTPUTS_751A: dict[str, list[str] | str] = {
    "STA": STA_751A,
    "STA S": STA_S_751A,
    "MAC": MAC_751A,
}

__all__ = [
    "FID_351S",
    "FID_421",
    "FID_451",
    "FID_751A",
    "OUTPUTS_351S",
    "OUTPUTS_421",
    "OUTPUTS_751A",
    "cascii",
]
