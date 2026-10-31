"""
Tell SELOGIC control equations apart from other SEL relay settings.

SEL relays mix SELOGIC control equations (e.g. ``TR``, the trip equation)
with ordinary settings (e.g. ``TDURD``, the minimum trip duration time, or
``CFDX``, the close failure time delay) in the same settings classes. The
functions here classify each setting, so equations can be reported separately
from the settings (variables) that they use.

There are two SELOGIC dialects, and 400-series relays also have free-form logic:

- 300-series relays (e.g. SEL-311C, SEL-351S) use symbols: ``*`` is AND,
  ``+`` is OR, ``!`` is NOT, and ``/`` and ``\\`` are rising and falling edges,
  e.g. ``TR = M1P + Z1G + 51PT + 50P1*SH0``. Every setting in the logic
  classes (``L``, ``L1``-``L6``) is an equation.
- 700-series (e.g. SEL-710, SEL-751) and 400-series (e.g. SEL-421, SEL-487E)
  relays use keywords: ``AND``, ``OR``, ``NOT``, ``R_TRIG`` and ``F_TRIG``, plus
  comparisons, math functions, and the math operators ``*``, ``/``, ``+`` and
  ``-``, e.g. ``TR := 50P1T OR (27P1T AND NOT LOP)``. In the 700-series, an
  equation set to ``NA`` isn't used.
- 400-series protection (``L``) and automation (``A``) logic is free-form:
  each setting (``PROTSEL1``, ``AUTO_1``, ...) is a line such as
  ``PSV01 := R_TRIG 52AA1 # Pulse for each close``, which is split into the
  variable (``PSV01``), the equation, and the comment. Lines that set the
  pickup time or preset of a timer or counter to a number
  (``PCN01PV := 500``) are settings, not equations.

Setting names and operators are from the public SEL-351S, SEL-421, SEL-700G,
SEL-710, SEL-751A and SEL-787 instruction manuals (SELOGIC control equation
sections and settings sheets). Equations often have values such as ``0``,
``1``, ``NA`` or a single Relay Word bit, so names are checked before values.

Authors

- Christopher Goes
"""

import re
from typing import Any, Final, Literal

RelayFamily = Literal["3xx", "4xx", "7xx"]
SettingKind = Literal["equation", "equation_unset", "setting", "bit_list", "alias"]

#: Values of an equation that isn't used. 700-series relays use ``NA``.
UNSET_VALUES: Final = frozenset({"", "NA"})

#: Sections that never have SELOGIC equations
NON_LOGIC_SECTIONS: Final = frozenset({"INFO", "CLASSES", "STORAGE"})

#: Model number in a RELAYTYPE (``0351``, ``SEL-710``), FID or model (``487E``)
_FAMILY_RE: Final = re.compile(r"^(?:SEL-?)?0?([347])\d{2}(?![0-9])", re.IGNORECASE)

#: Logic classes. On 300-series relays every setting in these is an equation,
#: and on 400-series relays the protection (``L``) and automation (``A``)
#: classes hold free-form logic.
_LOGIC_SECTION_RE: Final = re.compile(r"^L\d*$")
_FREEFORM_SECTION_RE: Final = re.compile(r"^[LA]\d*$")

#: Settings with a line of 400-series free-form logic
FREEFORM_NAME_RE: Final = re.compile(r"^(?:PROTSEL_?|AUTO_?)\d+$")

#: The variable that's assigned in a line of free-form logic
_LHS_RE: Final = re.compile(r"[A-Z][A-Z0-9_]*", re.IGNORECASE)

#: Settings that are SELOGIC control equations, whatever their value
SELOGIC_NAME_RE: Final = re.compile(
    r"^(?:"
    # Trip and close logic (TRX, CLX, ULCLY, etc. are the X/Y breakers on the 700G
    # and the terminals on the 487E)
    r"TR(?:\d|[STUWXY]\d?)?|TRCOMM|TRSOTF|TRQUAL|TRXFMR|DTT|ULTR[A-Z0-9]*|REMTRIP|"
    r"BK\dMTR|ULMTR\d|52A(?:[A-Z]\d?|\d)?|CL[STUWXY]?\d?|ULCL[A-Z0-9]*|"
    r"79(?:RI|RIS|DTL|DLS|SKP|STL|BRS|SEQ|CLS)|BFI(?:3P|[ABCXY])?\d?|BFTR\d?|BFULTR\d?|"
    r"PT[12]|LOG[12]|BT|"
    # SELOGIC variables, latches, counters, and math variables
    r"SV\d{1,3}|SET\d{1,2}|RST\d{1,2}|SC\d{2}(?:R|LD|CU|CD)|MV\d{2}|"
    # Outputs, LEDs, and MIRRORED BITS transmit
    r"OUT\d{3}|ALRMOUT|LED\d{1,2}|TLED_?\d{1,2}|T\d{2}_LED|PB\d{1,2}[AB]_LED|TMB\d[AB]|"
    # Group selection, event reports, resets, and other control
    r"SS\d|ER|FAULT|MSRTRG|GSRTRG|DSABLSET|PMTRIG|TREA\d|RSTTRGT|RSTENRGY|RSTMXMN|RSTDEM|"
    r"RSTPKDEM|RSTDNPE|RST_[A-Z]+|BSYNCH[XY]?|CLMON|BKMON[XY]?|BKCLS|E32IV|LOPBLK|"
    # Motor (710) and generator (700G) control
    r"STREQ|EMRSTR|SPEED2|SPEEDSW|81RFBL|FSYNCST|VSYNCST|ETHRFLT|HSM|"
    # Torque control, e.g. 51P1TC, 87M2TC, 24TC, REF1TC
    r"\d{2}[A-Z0-9]*TC|(?:REF\d|OOS|INAD|HBL\d)TC|"
    # 400-series protection and automation logic variables
    r"P(?:SV|MV)\d{2}|PLT\d{2}[SR]|PCT\d{2}(?:IN|PU|DO)|PST\d{2}(?:IN|PT|R)|PCN\d{2}(?:IN|PV|R)|"
    r"A(?:SV\d{3}|MV\d{3}|LT\d{2}[SR]|ST\d{2}(?:IN|PT|R)|CN\d{2}(?:IN|PV|R))"
    r")$"
)

#: Numeric, enumerated, or label settings that go with equations, e.g. the
#: pickup and dropout timers for a SELOGIC variable (``SV01PU``, ``SV01DO``),
#: the preset of a counter (``SC01PV``), an output's fail-safe (``OUT101FS``),
#: or if a target LED latches (``T01LEDL``, ``LED12L``).
NOT_EQUATION_NAME_RE: Final = re.compile(
    r"^(?:SV\d{1,3}(?:PU|DO)|SC\d{2}PV|OUT\d{3}FS|T\d{2}LEDL|LED\d{1,2}L)$"
)

#: Parameters of 400-series timers and counters: the pickup and dropout times
#: of conditioning timers (``PCT01PU``, ``PCT01DO``), the preset times of
#: sequencing timers (``PST01PT``, ``AST01PT``), and the preset values of
#: counters (``PCN01PV``, ``ACN01PV``). These are a constant (a setting) or
#: a math expression (an equation).
PARAMETER_NAME_RE: Final = re.compile(r"^(?:PCT\d{2}(?:PU|DO)|[PA]ST\d{2}PT|[PA]CN\d{2}PV)$")

#: Enable settings, e.g. ``E50P``, ``ESV``, ``ETELNET``
ENABLE_NAME_RE: Final = re.compile(r"^E[A-Z0-9_]+$")

#: Text settings, which are never equations, even if they have words such as
#: ``NOT`` or ``OR`` (``RID := NOT USED``): identifiers of the relay, terminal,
#: station and breakers (``RID``, ``TID``, ``SID``, ``BID1``), display points
#: (``DP01``), local bit labels (``NLB01``, ``CLB01``, ``SLB01``, ``PLB01``),
#: target LED aliases (``T1LEDA``), messenger point text (``MPTX01``), names
#: and units (``PMSTN``, ``FTPUSER``, ``AI301TAG``, ``AI301EU``), and the
#: settings of RTDs (``RTD01LOC``), which are never SELOGIC.
TEXT_NAME_RE: Final = re.compile(
    r"^(?:RID|TID|SID|BID\d|DP\d{1,2}|[NCSP]LB\d{1,2}|T\d{1,2}LEDA|MPTX\d{2}|"
    r"PMSTN|FTPUSER|AI\d{3}(?:TAG|EU)|RTD\d{1,2}[A-Z]{2,3})$"
)

#: Sequential Events Recorder (SER) trigger lists, e.g. ``SER1``.
#: The value is a space-separated list of Relay Word bits.
BIT_LIST_NAME_RE: Final = re.compile(r"^SER\d+$")

#: Relay Word bit aliases (700-series ``SET R``), e.g. ``ALIAS4``
#: with ``JAMTRIP LOAD_JAM_TRIP PICKUP DROPOUT``.
ALIAS_NAME_RE: Final = re.compile(r"^ALIAS\d+$")

#: Parts of SELOGIC variables, latches, timers and counters, and the variable
#: they belong to, e.g. ``SV01PU`` => ``SV01``, ``SET01`` => ``LT01``.
_PART_PATTERNS: Final = (
    (re.compile(r"^SV(\d{1,3})(?:PU|DO)$"), r"SV\1"),
    (re.compile(r"^(?:SET|RST)(\d{1,2})$"), r"LT\1"),
    (re.compile(r"^SC(\d{2})(?:PV|R|LD|CU|CD)$"), r"SC\1"),
    (re.compile(r"^OUT(\d{3})FS$"), r"OUT\1"),
    (re.compile(r"^T(\d{2})LEDL$"), r"T\1_LED"),
    (re.compile(r"^LED(\d{1,2})L$"), r"LED\1"),
    (re.compile(r"^([PA](?:LT|CT|ST|CN))(\d{2})(?:S|R|IN|PU|DO|PT|PV)$"), r"\1\2"),
)

# Tokens of an equation. Identifiers include Relay Word bits that start
# with a number (e.g. 50P1T) and numbers (e.g. 0.50).
_TOKEN_RE: Final = re.compile(
    r"\s*(?:(?P<op><>|<=|>=|[()<>=*/+\-!\\])|(?P<word>[A-Za-z0-9_]+(?:\.[0-9]+)?))"
)
_NUMBER_RE: Final = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")

_KEYWORD_BINARY: Final = frozenset({"AND", "OR"})
_KEYWORD_UNARY: Final = frozenset({"NOT", "R_TRIG", "F_TRIG"})
_MATH_FUNCTIONS: Final = frozenset(
    {"SQRT", "LN", "EXP", "LOG", "COS", "SIN", "ACOS", "ASIN", "ABS", "CEIL", "FLOOR"}
)
_COMPARISONS: Final = frozenset({"<", ">", "<=", ">=", "<>"})
_RESERVED: Final = _KEYWORD_BINARY | _KEYWORD_UNARY | _MATH_FUNCTIONS

#: Dialects: (binary operators, prefix operators, operators that only appear
#: in equations). Plain math (``+``, ``-``, ``*``, ``/``) and ``=`` aren't enough
#: to tell that a value of a setting with an unknown name is an equation.
_DIALECTS: Final = {
    "keyword": (
        _KEYWORD_BINARY | _COMPARISONS | {"=", "*", "/", "+", "-"},
        _KEYWORD_UNARY | _MATH_FUNCTIONS | {"-"},
        _KEYWORD_BINARY | _KEYWORD_UNARY | _MATH_FUNCTIONS | _COMPARISONS,
    ),
    "symbolic": (
        frozenset({"*", "+"}),
        frozenset({"!", "/", "\\"}),
        frozenset({"*", "+", "!", "/", "\\"}),
    ),
}


def relay_family(*identifiers: str | None) -> RelayFamily | None:
    """
    Get the SEL relay family from a ``RELAYTYPE`` (``0351``, ``SEL-710``),
    a FID (``SEL-487E-3-R317-...``), or a model (``351S``, ``700G``).

    The first identifier with a known family is used.

    Returns:
        ``"3xx"``, ``"4xx"`` or ``"7xx"``, or None if the family isn't known
        (e.g. the SEL-2032 or SEL-587Z)
    """
    for ident in identifiers:
        if not ident or not isinstance(ident, str):
            continue

        match = _FAMILY_RE.match(ident.strip())
        if match:
            return f"{match.group(1)}xx"  # type: ignore[return-value]

    return None


def parse_freeform_line(value: str) -> dict[str, str | None] | None:
    """
    Split a line of 400-series free-form SELOGIC into its parts.

    Example: ``PSV01 := R_TRIG 52AA1 # Pulse`` =>
    ``{"lhs": "PSV01", "rhs": "R_TRIG 52AA1", "comment": "Pulse"}``

    Lines that only have a comment have a ``lhs`` and ``rhs`` of None.

    Returns:
        Dict with ``lhs``, ``rhs`` and ``comment`` (None if there's no comment),
        or None if the line is empty or isn't free-form logic
    """
    if not value or not value.strip():
        return None

    # "#" starts a comment, and ":=" assigns the equation to the variable
    code, has_comment, comment = value.partition("#")
    lhs, has_assignment, rhs = code.partition(":=")
    line = {"lhs": None, "rhs": None, "comment": comment.strip() or None}

    if has_assignment and _LHS_RE.fullmatch(lhs.strip()):
        line["lhs"] = lhs.strip().upper()
        line["rhs"] = rhs.strip()
        return line

    if has_comment and not code.strip():
        return line  # Only a comment

    return None


def is_freeform_logic(name: str, section: str = "", family: RelayFamily | None = None) -> bool:
    """
    If a setting is a line of 400-series free-form logic,
    e.g. ``PROTSEL1`` or ``AUTO_1``.
    """
    if not FREEFORM_NAME_RE.match(name.upper()):
        return False

    # PROTSELn and AUTO_n are only free-form logic in the logic classes of
    # 400-series relays. Allow any section if the family or class isn't known.
    return family in (None, "4xx") and (
        not section or section == "SHOW" or bool(_FREEFORM_SECTION_RE.match(section.upper()))
    )


def _is_expression(value: str, dialect: str, strict: bool = False) -> bool:
    """
    If a value is a valid expression in a SELOGIC dialect, with at least one
    operator that's only used in equations and at least one Relay Word bit or
    variable (not just numbers).

    This checks that operators and operands alternate, so text with words
    like "OR" (``TID := FEEDER A OR B``) isn't an equation.

    If ``strict``, at least one of those operators has to be between two
    operands (e.g. ``AND``, ``OR`` or a comparison, not only ``NOT``), and the
    Relay Word bits and variables have to be uppercase, so text such as
    ``NOT USED`` or ``Feeder OR Bus`` isn't an equation.
    """
    binary, prefix, qualifying = _DIALECTS[dialect]
    expect_operand = True
    depth = 0
    qualified = False
    qualified_binary = False
    has_bit = False
    pos = 0
    value = value.rstrip()

    while pos < len(value):
        match = _TOKEN_RE.match(value, pos)
        if not match:
            return False  # Characters that aren't in equations, e.g. "," or "~"
        pos = match.end()

        token = match.group("op") or match.group("word")
        # Keywords are uppercase, "Feeder and bus" is text
        is_operator = bool(match.group("op")) or token in _RESERVED

        if expect_operand:
            if is_operator and token in prefix:
                qualified = qualified or token in qualifying
            elif token == "(":
                depth += 1
            elif not is_operator:
                is_number = bool(_NUMBER_RE.match(token))
                if strict and not is_number and token != token.upper():
                    return False  # "Feeder OR Bus"
                expect_operand = False
                has_bit = has_bit or not is_number
            else:
                return False
        elif is_operator and token in binary:
            expect_operand = True
            if token in qualifying:
                qualified = qualified_binary = True
        elif token == ")" and depth > 0:
            depth -= 1
        else:
            return False  # Two operands in a row, e.g. "FEEDER A"

    if strict and not qualified_binary:
        return False

    return not expect_operand and depth == 0 and qualified and has_bit


def looks_like_equation(
    value: str, family: RelayFamily | None = None, symbolic: bool = True, strict: bool = False
) -> bool:
    """
    If a value looks like a SELOGIC control equation, based on its syntax.

    700-series and 400-series relays use the keyword dialect
    (``50P1T OR (27P1T AND NOT LOP)``), and 300-series relays use the
    symbolic dialect (``M1P + Z1G + 50P1*SH0``). If the family isn't known,
    both are tried.

    Args:
        value: Value of a setting
        family: Relay family from :func:`relay_family`, if it's known
        symbolic: If the symbolic dialect should be tried. Symbols such as
            ``+`` and ``/`` are also in text, e.g. a label ``A+B``.
        strict: Only count values with an operator between two operands
            (``AND``, ``OR``, a comparison, or ``*`` and ``+`` in the symbolic
            dialect) and uppercase Relay Word bits. A prefix alone isn't enough,
            since text such as ``NOT USED`` would be an equation.
    """
    if not value or not isinstance(value, str):
        return False

    if family == "3xx":
        dialects = ("symbolic",) if symbolic else ()
    elif family in ("4xx", "7xx"):
        dialects = ("keyword",)
    else:
        dialects = ("keyword", "symbolic") if symbolic else ("keyword",)

    return any(_is_expression(value, dialect, strict) for dialect in dialects)


def _equation_kind(value: str) -> SettingKind:
    return "equation_unset" if value.strip().upper() in UNSET_VALUES else "equation"


def _is_parameter_constant(name: str, value: str) -> bool:
    # A 400-series timer or counter parameter that's a number, e.g. PCN01PV := 500
    return bool(PARAMETER_NAME_RE.match(name) and _NUMBER_RE.match(value.strip()))


def classify_setting(
    name: str, value: Any, section: str = "", family: RelayFamily | None = None
) -> SettingKind:
    """
    Classify a SEL relay setting.

    The checks are done in this order:

    #. 400-series free-form logic lines (``PROTSELn``, ``AUTO_n``) are
       equations, or ``equation_unset`` if they're blank or only a comment.
       Lines that set a timer or counter parameter to a number
       (``PCN01PV := 500``) are settings.
    #. SER trigger lists (``SERn``) are ``bit_list``, and Relay Word bit
       aliases (``ALIASn``) are ``alias``.
    #. Timers, counter presets and fail-safe settings that go with
       equations (``SV01PU``, ``SC01PV``, ``OUT101FS``) are settings, and
       so are 400-series timer and counter parameters that are a number
       (``PCT01PU``, ``PCN01PV``).
    #. Names of SELOGIC control equations (``TR``, ``SV01``, ``OUT101``,
       ``87M2TC``, ``T01_LED``, ...) are equations, whatever their value.
    #. Every setting in the logic classes (``L``, ``L1``-``L6``) of
       300-series relays is an equation.
    #. Enable settings (``E50P``, ``ESV``, ``ETELNET``) and text settings
       (``RID``, ``TID``, ``DP01``, ``NLB01``, ...) are settings.
    #. Values with the syntax of an equation (operators like ``AND`` and
       ``NOT``, comparisons or math functions) are equations. Values with
       the 300-series symbols are only equations in the logic classes, or if
       the class isn't known. Outside the logic classes (``L`` and ``A``),
       the value has to have an operator between two operands (``AND``,
       ``OR``, a comparison, or ``*`` and ``+``) and uppercase Relay Word
       bits, so a label such as ``NOT USED`` is a setting.
    #. Anything else is a setting.

    Equations set to ``NA`` (700-series) or empty are ``equation_unset``.

    Args:
        name: Setting name, e.g. ``TR``
        value: Setting value, e.g. ``50P1T OR 51P1T``
        section: Settings class, e.g. ``1``, ``L1`` or ``G``
        family: Relay family from :func:`relay_family`, if it's known

    Returns:
        ``"equation"``, ``"equation_unset"``, ``"setting"``, ``"bit_list"`` or ``"alias"``
    """
    name = str(name).strip().upper()
    value = "" if value is None else str(value)
    section = str(section).strip().upper()

    if not name or section in NON_LOGIC_SECTIONS:
        return "setting"

    if is_freeform_logic(name, section, family):
        line = parse_freeform_line(value)
        if line is None:
            return "equation_unset" if not value.strip() else "setting"
        if not line["lhs"] or not line["rhs"]:
            return "equation_unset"
        return "setting" if _is_parameter_constant(line["lhs"], line["rhs"]) else "equation"

    if BIT_LIST_NAME_RE.match(name):
        return "bit_list"

    if ALIAS_NAME_RE.match(name):
        return "alias"

    if NOT_EQUATION_NAME_RE.match(name) or _is_parameter_constant(name, value):
        return "setting"

    if SELOGIC_NAME_RE.match(name):
        return _equation_kind(value)

    if family == "3xx" and _LOGIC_SECTION_RE.match(section):
        return _equation_kind(value)

    if ENABLE_NAME_RE.match(name) or TEXT_NAME_RE.match(name):
        return "setting"

    # 300-series equations are all in the logic classes, so only look for the
    # symbolic dialect there, or if the class isn't known (e.g. SHOW output).
    # Other classes have labels and other text, so a lone prefix ("NOT USED")
    # or lowercase words ("Feeder OR Bus") aren't enough there.
    logic_or_unknown = section in ("", "SHOW") or bool(_LOGIC_SECTION_RE.match(section))
    strict = not _FREEFORM_SECTION_RE.match(section)
    if looks_like_equation(value, family, symbolic=logic_or_unknown, strict=strict):
        return "equation"

    return "setting"


def logic_variable(name: str) -> str:
    """
    Get the name of the SELOGIC variable, latch, timer or counter
    that a setting is a part of.

    Examples: ``SV01PU`` => ``SV01``, ``SET01`` and ``RST01`` => ``LT01``,
    ``SC01PV`` => ``SC01``, ``OUT101FS`` => ``OUT101``, ``PLT01S`` => ``PLT01``,
    ``PCT01PU`` => ``PCT01``. Other names are returned as-is (``TR`` => ``TR``).
    """
    name = name.strip().upper()

    for pattern, replacement in _PART_PATTERNS:
        if pattern.match(name):
            return pattern.sub(replacement, name)

    return name


def logic_assignment(record: dict) -> tuple[str, str]:
    """
    The name and value that a settings record assigns.

    For a line of 400-series free-form logic, this is the variable and the
    equation (``PSV01`` and ``R_TRIG 52AA1``), not the name of the setting
    the line is in (``PROTSEL1``). For other settings, it's the name and value.
    """
    if record.get("lhs"):
        return record["lhs"], record.get("rhs") or ""
    return record["name"], record.get("value") or ""


def group_logic(records: list[dict]) -> dict[str, dict[str, dict]]:
    """
    Group the SELOGIC control equations in settings records by section and
    by the variable they belong to.

    Each variable has the ``value`` of its own equation (None if it doesn't
    have one, e.g. a latch ``LT01`` is set by ``SET01`` and reset by ``RST01``),
    and the ``parts`` that go with it in the same section, e.g. the pickup and
    dropout timer settings (``SV01PU``, ``SV01DO``) for ``SV01``. Variables are
    only included if they have at least one equation that's set. Comments from
    free-form logic are in ``comments``. 400-series free-form logic can assign
    the same variable more than once: if it does, ``assignments`` lists every
    assignment (``name``, ``value`` and ``comment``) in order, and ``value``,
    ``parts`` and ``comments`` have the last.

    Example:

    .. code-block:: python

       {
           "L1": {
               "SV01": {"value": "IN101 OR IN102", "parts": {"SV01PU": "0.00", "SV01DO": "0.00"}},
               "LT01": {"value": None, "parts": {"SET01": "IN103", "RST01": "NA"}},
           }
       }

    Args:
        records: Settings records, with ``section``, ``name``, ``value`` and ``kind``
            (and ``lhs``, ``rhs`` and ``comment`` for free-form logic)

    Returns:
        Equations keyed by section, then variable
    """
    grouped = {}  # type: dict[str, dict[str, dict]]
    assigned = {}  # type: dict[tuple[str, str], list[dict[str, str | None]]]
    used = set()  # type: set[tuple[str, str]]

    for rec in records:
        kind = rec.get("kind")
        if kind not in ("equation", "equation_unset", "setting"):
            continue

        section = rec["section"]
        name, value = logic_assignment(rec)
        variable = logic_variable(name)

        # Settings and unset equations are only parts of a variable,
        # e.g. SV01PU or RST01 (not TDURD or SV02 := NA)
        if kind != "equation" and name == variable:
            continue

        if kind == "equation":
            used.add((section, variable))

        entry = grouped.setdefault(section, {}).setdefault(variable, {"value": None, "parts": {}})
        if name == variable:
            entry["value"] = value
        else:
            entry["parts"][name] = value

        # The comment of the last assignment of each name
        comment = rec.get("comment") or None
        comments = entry.setdefault("comments", {})
        if comment:
            comments[name] = comment
        else:
            comments.pop(name, None)
        if not comments:
            del entry["comments"]

        assigned.setdefault((section, variable), []).append(
            {"name": name, "value": value, "comment": comment}
        )

    # Only the variables with an equation that's set
    results = {}  # type: dict[str, dict[str, dict]]
    for section, variables in grouped.items():
        for variable, entry in variables.items():
            if (section, variable) not in used:
                continue

            names = [a["name"] for a in assigned[(section, variable)]]
            if len(set(names)) != len(names):
                entry["assignments"] = assigned[(section, variable)]
            results.setdefault(section, {})[variable] = entry

    return results


def format_equations(records: list[dict]) -> str:
    """
    Text listing of the SELOGIC control equations that are set, by section,
    in the order they're in the settings.

    Example:

    .. code-block:: text

       [1]
       TR := 49T OR LOSSTRIP OR JAMTRIP
       [L1]
       OUT101 := HALARM OR SALARM
       PSV01 := R_TRIG 52AA1 # Pulse for each close

    Returns:
        The listing, or an empty string if there are no equations
    """
    lines = []  # type: list[str]
    section = None

    for rec in records:
        if rec.get("kind") != "equation":
            continue

        if rec["section"] != section:
            section = rec["section"]
            lines.append(f"[{section}]")

        name, value = logic_assignment(rec)
        line = f"{name} := {value}"
        if rec.get("comment"):
            line += f" # {rec['comment']}"
        lines.append(line)

    return "\n".join(lines) + "\n" if lines else ""


__all__ = [
    "RelayFamily",
    "SettingKind",
    "classify_setting",
    "format_equations",
    "group_logic",
    "is_freeform_logic",
    "logic_assignment",
    "logic_variable",
    "looks_like_equation",
    "parse_freeform_line",
    "relay_family",
]
