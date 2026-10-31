"""
Tests for classifying SEL relay settings as SELOGIC control equations (sel_logic.py).

Settings from the SEL-710 are from the real (MIT-licensed) settings in
data_files/relay/ (see the README there). The 300-series and 400-series
values are short, hand-written examples of the documented syntax: symbols
for the 300-series (SEL-351S Instruction Manual, Appendix F, "SELOGIC Control
Equation Operators"), and keywords and free-form ``LHS := RHS # comment`` lines
for the 400-series (SEL-421 Instruction Manual, Reference Manual Section 3,
"SELOGIC Control Equation Programming").
"""

import pytest

from peat.modules.sel.sel_logic import (
    classify_setting,
    format_equations,
    group_logic,
    is_freeform_logic,
    logic_variable,
    looks_like_equation,
    parse_freeform_line,
    relay_family,
)


@pytest.mark.parametrize(
    ("identifier", "family"),
    [
        ("0351", "3xx"),
        ("SEL-351S", "3xx"),
        ("SEL-351-5-R510-V0-Z103103-D20110429", "3xx"),
        ("351S", "3xx"),
        ("300G", "3xx"),
        ("SEL-710", "7xx"),
        ("0710", "7xx"),
        ("700G", "7xx"),
        ("SEL-710-Rxxx-Vx-Z008004-Dxxxxxxxx", "7xx"),
        ("SEL-487E-3", "4xx"),
        ("487E", "4xx"),
        ("SEL-421", "4xx"),
        # Not relay families PEAT knows the logic of
        ("SEL-2032", None),
        ("SEL-2411", None),
        ("SEL-3530", None),
        ("587Z", None),
        ("SLBT-710-Rxxx-V0-Z007004-Dxxxxxxxx", None),
        ("", None),
        (None, None),
    ],
)
def test_relay_family(identifier, family):
    assert relay_family(identifier) == family


def test_relay_family_first_known():
    assert relay_family(None, "", "SEL-2032", "751") == "7xx"


@pytest.mark.parametrize(
    ("section", "name", "value", "kind"),
    [
        # SEL-710 equations, including ones with a single Relay Word bit or a constant
        (
            "L1",
            "SV01",
            "WDGTRIP OR BRGTRIP OR OTHTRIP OR AMBTRIP OR REMTRIP OR 37PT OR PTCTRIP",
            "equation",
        ),
        ("1", "TR", "49T OR LOSSTRIP OR JAMTRIP OR (27P1T AND NOT LOP) OR SV01T", "equation"),
        ("1", "87M2TC", "NOT 50S", "equation"),
        ("1", "87M1TC", "50S", "equation"),
        ("1", "51ATC", "1", "equation"),
        ("1", "STREQ", "PB03", "equation"),
        ("1", "52A", "0", "equation"),
        ("L1", "OUT102", "START", "equation"),
        ("L1", "OUT301", "0", "equation"),
        ("G", "FAULT", "STARTING OR 50S OR 50G1P OR 50N1P OR TRIP", "equation"),
        ("G", "BFI", "R_TRIG TRIP", "equation"),
        ("G", "BKMON", "TRIP", "equation"),
        ("G", "DSABLSET", "0", "equation"),
        ("G", "SS1", "1", "equation"),
        ("F", "T05_LED", "(NOT STOPPED AND 27P1T) OR 59P1T", "equation"),
        ("F", "PB3B_LED", "STARTING OR RUNNING", "equation"),
        ("F", "PB1B_LED", "0", "equation"),
        ("R", "ER", "R_TRIG LOSSALRM OR R_TRIG 46UBA OR R_TRIG 49A", "equation"),
        ("R", "MSRTRG", "0", "equation"),
        # Unused equations
        ("L1", "SET01", "NA", "equation_unset"),
        ("L1", "SV02", "NA", "equation_unset"),
        ("G", "BFI", "", "equation_unset"),
        # SEL-710 settings next to the equations
        ("L1", "SV01PU", "0.00", "setting"),
        ("L1", "SV01DO", "0.00", "setting"),
        ("L1", "OUT101FS", "Y", "setting"),
        ("L1", "ESV", "1", "setting"),
        ("L1", "ELAT", "N", "setting"),
        ("F", "T01LEDL", "Y", "setting"),
        ("1", "TDURD", "0.5", "setting"),
        ("1", "TID", "MOTOR RELAY", "setting"),
        ("1", "51AC", "U3", "setting"),
        ("1", "E49MOTOR", "Y", "setting"),
        ("1", "EPTC", "N", "setting"),
        ("1", "BLK49PTC", "N", "setting"),
        ("G", "52ABF", "N", "setting"),
        ("G", "DMTC", "15", "setting"),
        ("F", "DP01", 'RID,"{16}"', "setting"),
        ("P1", "NETMODE", "FAILOVER", "setting"),
        ("P1", "IPADDR", "192.168.1.2", "setting"),
        ("P1", "FTPUSER", "FTPUSER", "setting"),
        ("M", "MOD_001", "IA_MAG", "setting"),
        ("R", "EALIAS", "15", "setting"),
        ("R", "LDLIST", "NA", "setting"),
        # Bit lists and aliases
        ("R", "SER1", "IN101 IN102 PB01 PB02 PB03 PB04 ABSLO TBSLO NOSLO THERMLO", "bit_list"),
        ("R", "ALIAS4", "JAMTRIP LOAD_JAM_TRIP PICKUP DROPOUT", "alias"),
        # Close failure delays are timers, not equations (I19b)
        ("1", "CFD", "0.50", "setting"),
        ("1", "CFDX", "0.50", "setting"),
        ("1", "CLX", "CC1X OR CLX_PB", "equation"),
        # Equations that start with "E" (not enable settings)
        ("G", "ETHRFLT", "NOT IN101", "equation"),
        # Not settings
        ("INFO", "TR", "A OR B", "setting"),
        ("CLASSES", "TR", "A OR B", "setting"),
        # Text and labels with words like NOT and OR
        ("G", "RID", "NOT USED", "setting"),
        ("G", "TID", "LINE1 OR LINE2", "setting"),
        ("F", "NLB01", "NOT USED", "setting"),
        ("F", "SLB01", "OPEN OR CLOSE", "setting"),
        ("F", "DP05", "NOT IN101", "setting"),
        ("G", "PMSTN", "BUS1 OR BUS2", "setting"),
        ("1", "RTD01LOC", "NOT USED", "setting"),
        # Outside the logic classes, a value of a setting with another name needs
        # an operator between two operands, and uppercase Relay Word bits
        ("G", "XYZ", "NOT USED", "setting"),
        ("G", "XYZ", "R_TRIG IN101", "setting"),
        ("G", "XYZ", "Feeder OR Bus", "setting"),
        ("G", "XYZ", "COS(X)", "setting"),
        ("G", "XYZ", "IN101 AND NOT IN102", "equation"),
        ("G", "XYZ", "COS(MV01) > 0.5", "equation"),
        ("SHOW", "XYZ", "NOT USED", "setting"),
        ("SHOW", "XYZ", "IN101 OR IN102", "equation"),
        # In the logic classes, a prefix is enough
        ("L1", "XYZ", "NOT IN101", "equation"),
    ],
)
def test_classify_setting_7xx(section, name, value, kind):
    assert classify_setting(name, value, section, "7xx") == kind


@pytest.mark.parametrize(
    ("section", "name", "value", "kind"),
    [
        ("L1", "TR", "M1P + Z1G + 51PT + 51GT + 50P1*SH0", "equation"),
        ("L1", "ER", "/50P1 + /51G1T + !52A", "equation"),
        # Every setting in the logic classes is an equation
        ("L1", "LED12", "TRIP", "equation"),
        ("L1", "DP1", "52A", "equation"),
        ("L1", "SV1", "0", "equation"),
        ("L1", "E32IV", "1", "equation"),
        ("L", "BFI", "", "equation_unset"),
        # Settings
        ("G", "LED12L", "Y", "setting"),
        ("1", "SV1PU", "0.00", "setting"),
        ("1", "TDURD", "9.00", "setting"),
        ("1", "CFD", "OFF", "setting"),
        ("1", "RID", "FEEDER 1", "setting"),
        # Symbols are text outside the logic classes
        ("1", "TID", "SUB+1", "setting"),
        # Keywords aren't used in the 300-series dialect
        ("SHOW", "XYZ", "A AND B", "setting"),
        ("SHOW", "XYZ", "A*B + !C", "equation"),
    ],
)
def test_classify_setting_3xx(section, name, value, kind):
    assert classify_setting(name, value, section, "3xx") == kind


@pytest.mark.parametrize(
    ("section", "name", "value", "kind"),
    [
        # Free-form protection (L) and automation (A) logic lines
        ("L1", "PROTSEL1", "PSV01 := R_TRIG 52AA1 # Pulse for each close", "equation"),
        ("L1", "PROTSEL3", "PSV02 := PCN01CV > 400", "equation"),
        ("A1", "AUTO_1", "AMV001 := AMV001 + 1", "equation"),
        ("L1", "PROTSEL4", "", "equation_unset"),
        ("L1", "PROTSEL5", "# A comment line", "equation_unset"),
        ("L1", "PROTSEL6", "PSV03 :=", "equation_unset"),
        ("L1", "PROTSEL7", "not a logic line", "setting"),
        # Timer and counter parameters are a constant (a setting) or an expression
        ("L1", "PROTSEL2", "PCN01PV := 500", "setting"),
        ("L1", "PROTSEL8", "PCT01PU := 5.3 # Pickup", "setting"),
        ("L1", "PROTSEL9", "PCT01DO := 0", "setting"),
        ("L1", "PROTSEL10", "PST01PT := 150.00", "setting"),
        ("A1", "AUTO_2", "AST01PT := 7.5", "setting"),
        ("A1", "AUTO_3", "ACN09PV := 1000", "setting"),
        ("L1", "PROTSEL11", "PCT02PU := PMV01 * 2", "equation"),
        ("L1", "PROTSEL12", "PCN02PV := PMV02", "equation"),
        ("L1", "PROTSEL13", "PCN01IN := PSV01", "equation"),
        ("L1", "PROTSEL14", "PST01R := IN101", "equation"),
        ("L1", "PROTSEL15", "PMV01 := 10", "equation"),
        # Not free-form logic outside of the logic classes
        ("P5", "PROTSEL1", "1", "setting"),
        # Group settings
        ("1", "TR", "M2P OR Z2G OR 51S1T", "equation"),
        ("1", "TRSOTF", "M2P OR Z2G", "equation"),
        ("1", "52AA1", "IN101", "equation"),
        ("1", "PSV01", "IN101", "equation"),
        ("1", "PCT01PU", "5.000000", "setting"),
        ("1", "PCT01PU", "PMV01", "equation"),
        # Settings
        ("P5", "TPORT", "23", "setting"),
        ("P5", "FTPCBAN", "FTP SERVER:", "setting"),
        ("P5", "TERSTRN", "\\005", "setting"),
        ("1", "TID", "SUB A OR B", "setting"),
        ("G", "SID", "NOT USED", "setting"),
        ("G", "BID1", "BREAKER 1 OR 2", "setting"),
        ("F", "T1LEDA", "NOT USED", "setting"),
    ],
)
def test_classify_setting_4xx(section, name, value, kind):
    assert classify_setting(name, value, section, "4xx") == kind


@pytest.mark.parametrize(
    ("section", "name", "value", "kind"),
    [
        # The family isn't known, e.g. SHOW output without a FID
        ("SHOW", "TR", "50P1T OR REMTRIP", "equation"),
        ("SHOW", "XYZ", "A OR B", "equation"),
        ("SHOW", "XYZ", "A*B", "equation"),
        ("1", "XYZ", "A*B", "setting"),
        ("1", "XYZ", "MV01 > 5", "equation"),
        ("L1", "PROTSEL1", "PSV01 := IN101", "equation"),
        ("1", "RID", "Feeder and bus", "setting"),
        ("1", "XYZ", "N/A", "setting"),
        ("1", "RID", "NOT USED", "setting"),
        ("1", "XYZ", "NOT USED", "setting"),
        ("SHOW", "XYZ", "NOT USED", "setting"),
        ("SHOW", "XYZ", "!LOP", "setting"),
        ("", "XYZ", "Feeder OR Bus", "setting"),
    ],
)
def test_classify_setting_unknown_family(section, name, value, kind):
    assert classify_setting(name, value, section) == kind


def test_classify_setting_case_and_types():
    assert classify_setting(" tr ", "50P1T OR 51P1T", "1", "7xx") == "equation"
    assert classify_setting("TR", None, "1", "7xx") == "equation_unset"
    assert classify_setting("", "A OR B", "1", "7xx") == "setting"


@pytest.mark.parametrize(
    "value",
    [
        "50P1T OR 51P1T",
        "NOT 50S",
        "R_TRIG TRIP",
        "(NOT STOPPED AND 27P1T) OR 59P1T",
        "MV01 >= 2.5",
        "ABS(PMV55) > 10.000000 AND PSV01",
        "NOT PSV01*PMV55+PSV01*PMV02",
        "-PMV01 < 0 OR IN101",
    ],
)
def test_looks_like_equation_keyword(value):
    assert looks_like_equation(value, "7xx")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "NA",
        "0",
        "PB03",
        "MOTOR RELAY",
        "FEEDER A OR B",
        "OR",
        "NOT",
        "A OR",
        "(A OR B",
        "A OR B)",
        "A*B",
        "1-30",
        "-5",
        "192.168.1.2",
        "23,1025-65534",
        "2~10",
        'IAV, "I MOTOR {6} A"',
        "a or b",
    ],
)
def test_looks_like_equation_keyword_false(value):
    assert not looks_like_equation(value, "7xx")


def test_looks_like_equation_strict():
    for value in ["50P1T OR 51P1T", "NOT 50S AND IN101", "MV01 >= 2.5", "-PMV01 < 0 OR IN101"]:
        assert looks_like_equation(value, "7xx", strict=True), value

    # A prefix alone, or lowercase words, could be text
    for value in ["NOT USED", "R_TRIG TRIP", "COS(X)", "NOT (A)", "Feeder OR Bus"]:
        assert looks_like_equation(value, "7xx"), value
        assert not looks_like_equation(value, "7xx", strict=True), value
    assert not looks_like_equation("LINE1 + 2", "7xx", strict=True)

    assert looks_like_equation("A*B + !C", "3xx", strict=True)
    assert looks_like_equation("!LOP", "3xx")
    assert not looks_like_equation("!LOP", "3xx", strict=True)


def test_looks_like_equation_symbolic():
    assert looks_like_equation("M1P + Z1G + 50P1*SH0", "3xx")
    assert looks_like_equation("/51P1 + \\51G1", "3xx")
    assert not looks_like_equation("A OR B", "3xx")
    assert not looks_like_equation("M1P + Z1G", "3xx", symbolic=False)
    assert not looks_like_equation("N/A", "3xx")
    assert not looks_like_equation("1+2", "3xx")
    # Both dialects if the family isn't known
    assert looks_like_equation("A OR B")
    assert looks_like_equation("A*B")
    assert not looks_like_equation("A*B", symbolic=False)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "PSV01 := R_TRIG 52AA1 # Pulse for each close",
            {"lhs": "PSV01", "rhs": "R_TRIG 52AA1", "comment": "Pulse for each close"},
        ),
        ("PCN01PV := 500", {"lhs": "PCN01PV", "rhs": "500", "comment": None}),
        (
            "  psv03 :=(PMV01 > 10.0) AND PSV01#no space",
            {"lhs": "PSV03", "rhs": "(PMV01 > 10.0) AND PSV01", "comment": "no space"},
        ),
        ("PSV04 :=", {"lhs": "PSV04", "rhs": "", "comment": None}),
        ("# A comment line ", {"lhs": None, "rhs": None, "comment": "A comment line"}),
        ("#", {"lhs": None, "rhs": None, "comment": None}),
        ("", None),
        ("   ", None),
        ("not a logic line", None),
        ("TR = M1P + Z1G", None),
    ],
)
def test_parse_freeform_line(value, expected):
    assert parse_freeform_line(value) == expected


def test_is_freeform_logic():
    assert is_freeform_logic("PROTSEL1", "L1", "4xx")
    assert is_freeform_logic("AUTO_10", "A10", "4xx")
    assert is_freeform_logic("PROTSEL1", "L1", None)
    assert is_freeform_logic("PROTSEL1", "SHOW", None)
    assert is_freeform_logic("PROTSEL1", "", None)
    assert not is_freeform_logic("PROTSEL1", "L1", "7xx")
    assert not is_freeform_logic("PROTSEL1", "P5", "4xx")
    assert not is_freeform_logic("TR", "L1", "4xx")


@pytest.mark.parametrize(
    ("name", "variable"),
    [
        ("SV01", "SV01"),
        ("SV01PU", "SV01"),
        ("SV1DO", "SV1"),
        ("SET01", "LT01"),
        ("RST01", "LT01"),
        ("RST9", "LT9"),
        ("SC01PV", "SC01"),
        ("SC12LD", "SC12"),
        ("OUT101FS", "OUT101"),
        ("T01LEDL", "T01_LED"),
        ("LED12L", "LED12"),
        ("PLT01S", "PLT01"),
        ("PCT02PU", "PCT02"),
        ("PST03PT", "PST03"),
        ("PCN04PV", "PCN04"),
        ("ALT05R", "ALT05"),
        ("AST06IN", "AST06"),
        ("ACN07PV", "ACN07"),
        ("TR", "TR"),
        ("PSV01", "PSV01"),
        ("SETMETH", "SETMETH"),
        (" sv01pu ", "SV01"),
    ],
)
def test_logic_variable(name, variable):
    assert logic_variable(name) == variable


def _rec(section, name, value, kind, **extra):
    return {"section": section, "name": name, "value": value, "kind": kind, **extra}


def test_group_logic():
    records = [
        _rec("L1", "SET01", "IN101", "equation"),
        _rec("L1", "RST01", "NA", "equation_unset"),
        _rec("L1", "SET02", "NA", "equation_unset"),
        _rec("L1", "RST02", "NA", "equation_unset"),
        _rec("L1", "SV01", "IN102 OR IN103", "equation"),
        _rec("L1", "SV01PU", "0.50", "setting"),
        _rec("L1", "SV01DO", "0.00", "setting"),
        _rec("L1", "SV02", "NA", "equation_unset"),
        _rec("L1", "SV02PU", "0.00", "setting"),
        _rec("L1", "OUT101", "TRIP", "equation"),
        _rec("L1", "OUT101FS", "Y", "setting"),
        _rec("1", "TR", "50P1T", "equation"),
        _rec("1", "SV01PU", "1.00", "setting"),  # Different section than SV01
        _rec("G", "EPORT", "Y", "setting"),
    ]

    assert group_logic(records) == {
        "L1": {
            "LT01": {"value": None, "parts": {"SET01": "IN101", "RST01": "NA"}},
            "SV01": {"value": "IN102 OR IN103", "parts": {"SV01PU": "0.50", "SV01DO": "0.00"}},
            "OUT101": {"value": "TRIP", "parts": {"OUT101FS": "Y"}},
        },
        "1": {"TR": {"value": "50P1T", "parts": {}}},
    }


def test_group_logic_freeform():
    def line(n, lhs, rhs, comment=None, kind="equation"):
        value = f"{lhs} := {rhs}" + (f" # {comment}" if comment else "")
        return _rec("L1", f"PROTSEL{n}", value, kind, lhs=lhs, rhs=rhs, comment=comment)

    records = [
        line(1, "PSV01", "R_TRIG 52AA1", "Pulse for each close"),
        line(2, "PCN01PV", "500", kind="setting"),
        line(3, "PCN01IN", "PSV01", "Count closes"),
        line(4, "PMV01", "10", "Start at 10"),
        line(5, "PMV01", "PMV01 + 1"),
        _rec("L1", "PROTSEL6", "# Only a comment", "equation_unset", comment="Only a comment"),
        # A timer with only a constant isn't used
        line(7, "PCT01PU", "5.3", kind="setting"),
    ]

    assert group_logic(records) == {
        "L1": {
            "PSV01": {
                "value": "R_TRIG 52AA1",
                "parts": {},
                "comments": {"PSV01": "Pulse for each close"},
            },
            "PCN01": {
                "value": None,
                "parts": {"PCN01PV": "500", "PCN01IN": "PSV01"},
                "comments": {"PCN01IN": "Count closes"},
            },
            # The same variable is assigned twice. The comment was for the
            # first assignment, so it's only in the assignments.
            "PMV01": {
                "value": "PMV01 + 1",
                "parts": {},
                "assignments": [
                    {"name": "PMV01", "value": "10", "comment": "Start at 10"},
                    {"name": "PMV01", "value": "PMV01 + 1", "comment": None},
                ],
            },
        }
    }


def test_group_logic_last_assignment():
    def line(n, lhs, rhs, comment=None, kind="equation"):
        return _rec("L1", f"PROTSEL{n}", "", kind, lhs=lhs, rhs=rhs, comment=comment)

    grouped = group_logic(
        [
            line(1, "PSV01", "IN101", "First"),
            line(2, "PSV01", "IN102", "Second"),
            line(3, "PCT01PU", "5", kind="setting"),
            line(4, "PCT01IN", "PSV01"),
            line(5, "PCT01PU", "6", "Longer", kind="setting"),
        ]
    )["L1"]

    assert grouped["PSV01"]["value"] == "IN102"
    assert grouped["PSV01"]["comments"] == {"PSV01": "Second"}
    assert grouped["PCT01"]["parts"] == {"PCT01PU": "6", "PCT01IN": "PSV01"}
    assert grouped["PCT01"]["comments"] == {"PCT01PU": "Longer"}
    assert [a["value"] for a in grouped["PCT01"]["assignments"]] == ["5", "PSV01", "6"]


def test_group_logic_empty():
    assert group_logic([]) == {}
    assert group_logic([_rec("1", "TR", "NA", "equation_unset")]) == {}


def test_format_equations():
    records = [
        _rec("1", "RID", "FEEDER 1", "setting"),
        _rec("1", "TR", "50P1T OR 51P1T", "equation"),
        _rec("L1", "SET01", "NA", "equation_unset"),
        _rec("L1", "OUT101", "TRIP", "equation"),
        _rec(
            "L2",
            "PROTSEL1",
            "PSV01 := R_TRIG 52AA1 # Pulse",
            "equation",
            lhs="PSV01",
            rhs="R_TRIG 52AA1",
            comment="Pulse",
        ),
    ]

    assert format_equations(records) == (
        "[1]\nTR := 50P1T OR 51P1T\n[L1]\nOUT101 := TRIP\n[L2]\nPSV01 := R_TRIG 52AA1 # Pulse\n"
    )
    assert format_equations([_rec("1", "RID", "FEEDER 1", "setting")]) == ""


def test_classify_setting_is_fast():
    # Values come from files and devices, make sure odd ones don't take forever
    parse_freeform_line("PSV01 := " + " " * 100000 + "IN101")
    classify_setting("X" * 50000 + "TC", "A OR " * 20000 + "B", "SHOW")
    assert not looks_like_equation("(" * 50000 + "A" + ")" * 49999)
    assert not looks_like_equation(" " * 100000 + "+")
