"""
The SEL ASCII commands PEAT runs on relays, and the commands it never sends.

Many SEL ASCII commands that change the state of a relay are allowed at
access level 1, the level PEAT reads at, e.g. ``SER C`` (clears the
Sequential Events Recorder), ``TAR R`` (resets the targets), ``MET RD``
(resets the demand meters on the SEL-751A), ``ETH C`` (clears the Ethernet
counters), or ``TRI`` (triggers an event report). So the access level doesn't
keep PEAT read-only. Instead:

- Every line PEAT sends on a SEL ASCII session goes through :func:`check_command`
  (in :meth:`SELAscii._send() <peat.modules.sel.sel_ascii.SELAscii._send>`, which
  every write uses). A command that matches :data:`DENIED_COMMANDS` (known to
  change the state of a relay, e.g. ``SER C``, ``STA C``, ``SET``, ``PAS``,
  ``L_D``, ``STR`` to start a motor, or ``Y`` to confirm a question) or contains
  a line break is refused with :class:`SELCommandRefused`. Only the answer to a
  password prompt during a login, and CAN (Ctrl+X), aren't checked, since they
  aren't commands. Other ``sensitive`` writes are checked (and not logged).
- The commands that :meth:`~peat.modules.sel.sel_relay.SELRelay.pull_more_commands`
  runs are in the registry :data:`COMMANDS`, and must also match
  :data:`ALLOWED_COMMANDS`, the read-only commands PEAT uses
  (:meth:`SELAscii.run_read_command()
  <peat.modules.sel.sel_ascii.SELAscii.run_read_command>` checks this with
  ``strict=True``), so a command that isn't known to be read-only isn't run either.

The only exceptions are the code paths that are meant to change the relay, which
are only run when the user asks for them: a restart (``STA C``), a push
(``FILE WRITE``), an active group change (``GRO n``), and a login to level C
(``CAL``). They use :meth:`SELAscii._allow_state_changes()
<peat.modules.sel.sel_ascii.SELAscii._allow_state_changes>`, and the answer
``Y`` to a confirmation question is only allowed there.

The command names, arguments, and access levels are from the command tables of
public SEL instruction manuals: SEL-351S IM 20171023 (Table 10.19 and the command
summary), SEL-421 IM 20130627 (Reference Manual Section 9), SEL-751A IM 20130329
(Section 7 and the command summary), SEL-700G IM 20150521 (Section 7 and the
command summary), SEL-710 IM 20090327 and SEL-749M IM 20080918 (the command
summaries), and SEL-2032 IM 20120126 (Section 8). Relays accept the first three characters
of a command (``STATUS A`` is ``STA A``), so commands are compared by their
first three characters.
"""

import re
from dataclasses import dataclass, field
from typing import Final

from peat import PeatError

from .sel_default_creds import (
    FAMILY_300,
    FAMILY_400,
    FAMILY_700,
    FAMILY_2030,
    model_family,
)


class SELCommandRefused(PeatError):
    """
    PEAT refused to send a SEL ASCII command, because it may change the state of
    the device, or it isn't one of the read-only commands PEAT knows
    (refer to :mod:`peat.modules.sel.sel_commands`).
    """


#: Characters that are allowed in a command line (no control characters, so a
#: command can't contain a second line, e.g. ``"ID\rSER C"``)
_PRINTABLE_RE: Final = re.compile(r"[\x20-\x7e]*")


def normalize_command(command: str) -> str:
    """
    Normalize a SEL ASCII command for comparisons: uppercase, single spaces,
    and the first word cut to its first three characters, since relays only
    read the first three characters of a command (``status a`` => ``STA A``).
    The sub-command of ``FILE`` is cut to three characters too
    (``FILE SHOW SET_1.TXT`` => ``FIL SHO SET_1.TXT``).

    Returns:
        The normalized command (an empty string for an empty line)
    """
    words = command.strip().upper().split()
    if not words:
        return ""

    words[0] = words[0][:3]
    if words[0] == "FIL" and len(words) > 1:
        words[1] = words[1][:3]

    return " ".join(words)


#: Commands that change the state of a relay (or start a mode PEAT doesn't
#: support), with the reason, matched against :func:`normalize_command`.
#: These are refused even if they would match :data:`ALLOWED_COMMANDS`.
#:
#: An argument that clears, resets, or acknowledges is refused by its first
#: letters (e.g. ``STA CL`` like ``STA C``, ``SER CVX`` like ``SER CV``), and
#: any line that starts with ``Y`` (``YE``, ``Yes please``) like ``Y``: the
#: manuals don't say whether relays read longer words as the short ones, and
#: refusing a read-only command costs less than sending a reset. Some read-only
#: forms are refused too (e.g. ``TAR ROW``), but PEAT doesn't use them.
#:
#: The motor, generator, and DNP3 commands are from the command summaries of the
#: SEL-710 IM 20090327, SEL-749M IM 20080918, SEL-700G IM 20150521, and
#: SEL-421 IM 20130627 (Table 9.46, ``DNP param`` sets the DNP3 settings).
DENIED_COMMANDS: Final[tuple[tuple[re.Pattern, str], ...]] = tuple(
    (re.compile(pattern), reason)
    for pattern, reason in (
        (r"STA (?:.* )?(?:C|R|SC|SR)\w*(?: .*)?", "restarts the relay or clears its status"),
        (r"SER (?:.* )?(?:C|R)\w*(?: .*)?", "clears SER records"),
        (r"HIS (?:.* )?(?:C|R)\w*(?: .*)?", "clears the event history"),
        (r"SUM (?:.* )?(?:A|C|R)\w*(?: .*)?", "acknowledges or clears event summaries"),
        (r"(?:CEV|EVE|CSU|CHI|CSE|CST) (?:.* )?AC\w*(?: .*)?", "acknowledges events"),
        (r"LDP (?:.* )?(?:C|D)\w*(?: .*)?", "clears the load profile"),
        (
            r"SSI (?:.* )?(?:C|R|T)\w*(?: .*)?",
            "clears, resets, or triggers the sag/swell recorder",
        ),
        # MET RMS (SEL-700 series) shows the RMS values. MET WE (SEL-700G) preloads energy.
        (
            r"MET (?:.* )?(?:(?!RMS(?: |$))R\w*|W\w*)(?: .*)?",
            "resets or preloads meter values",
        ),
        (r"TAR (?:.* )?R\w*(?: .*)?", "resets the targets"),
        (r"COM (?:.* )?(?:C|R)\w*(?: .*)?", "clears communication statistics"),
        (r"ETH (?:.* )?C\w*(?: .*)?", "clears the Ethernet statistics"),
        (r"GOO (?:.* )?C\w*(?: .*)?", "clears GOOSE statistics"),
        (r"BRE (?:.* )?(?:R|W|C|P)\w*(?: .*)?", "resets or presets the breaker monitor"),
        (
            r"(?:MOT|MST) (?:.* )?(?:C|R)\w*(?: .*)?",
            "clears motor statistics or motor start trends",
        ),
        (r"(?:GEN|SYN) (?:.* )?R\w*(?: .*)?", "resets statistics"),
        (r"GSH (?:.* )?C\w*(?: .*)?", "clears statistics"),
        (r"(?:DAT|TIM) (?!Q$|DST$).+", "sets the relay's date or time"),
        (r"GRO .+", "changes the active settings group"),
        (r"DNP (?!VIEW?$).+", "changes the serial port DNP3 settings"),
        (r"FIL (?:WRI|DEL|REN|ERA)(?: .*)?", "writes or deletes files"),
        (r"(?:SET|PAS|PAR|COP)(?: .*)?", "changes settings, passwords, or the part number"),
        (r"R_S(?: .*)?", "restores the factory default settings"),
        (r"(?:L_D|LD)(?: .*)?", "disables the relay and starts its firmware loader"),
        (r"DTO(?: .*)?", "loads a curve into the relay"),
        (r"CAL(?: .*)?", "logs in to the calibration level"),
        (r"(?:TRI|IRI|GST)(?: .*)?", "triggers an event or synchronism report, or a time update"),
        (r"(?:CON|CLO|OPE|PUL|LOO|ANA|AFT|TES|TEC)(?: .*)?", "operates or tests the relay"),
        (
            r"(?:STR|STO)(?: .*)?",
            "starts or stops a motor, or stores data in a SEL-2030/2032",
        ),
        (r"RLP(?: .*)?", "resets the learned motor parameters"),
        (r"(?:AST|ASP)(?: .*)?", "starts or stops automatic generator synchronizing"),
        (r"(?:BRO|POR)(?: .*)?", "connects the session to another port or device"),
        (r"(?:CLE|SWA|TOG|DEF)(?: .*)?", "changes the data or memory of a SEL-2030/2032"),
        (r"(?:BAU|ERA|REC)(?: .*)?", "SELBOOT (firmware loader) command"),
        (r"Y\w*(?: .*)?", "only a restart, push, or group change may confirm a question"),
    )
)

#: Read-only commands PEAT uses, matched against :func:`normalize_command`.
#: The commands in :data:`COMMANDS` must match one of these (refer to
#: :func:`check_command` with ``strict``).
ALLOWED_COMMANDS: Final[tuple[re.Pattern, ...]] = tuple(
    re.compile(pattern)
    for pattern in (
        r"",  # An empty line, which makes the relay show its prompt
        r"N",  # The answer to a question PEAT doesn't expect (declines it)
        r"(?:ID|ACC|2AC|QUI|EXI)",  # Identification, logins (not CAL), and logging out
        r"HE[L](?: [A-Z0-9_]+)?",  # HELP [command], cut to three characters
        r"(?:CAS|SNS|BNA|DNA(?: [XT])?)",  # Level 0 Compressed ASCII and names
        r"(?:VER|ETH|MAC|WHO|DNP|MOD)",
        r"(?:DAT|TIM)(?: Q| DST)?",  # Show the date or time, no argument to set it
        r"GRO",  # Show the active group, no argument to change it
        r"STA(?: A| S)?",
        r"GOO(?: S(?: \d+| ALL)?(?: L)?)?",
        r"(?:SER|CSE)(?: \d+){0,2}",
        r"SER GLOBAL \d+",  # SEL-2032
        r"HIS(?: \d+| E)?",
        r"(?:CHI|CST)",
        r"(?:SUM|EVE)(?: \d+)?",
        r"BRE(?: \d+)?(?: H)?",
        r"SHO(?: [A-Z0-9_]+){0,4}",  # Settings classes and names (SHO P 5, SHO L 1)
        r"CAR \d+",  # SEL-2032 CARD n
        r"FIL(?: (?:DIR|SHO|REA)(?: [A-Z0-9_.\\/-]+){0,2})?",
    )
)


def command_refusal(command: str, strict: bool = False) -> str:
    """
    Why PEAT won't send a command (refer to :mod:`peat.modules.sel.sel_commands`).

    Args:
        command: A command line, e.g. ``"SER C"``
        strict: Also refuse commands that don't match :data:`ALLOWED_COMMANDS`

    Returns:
        The reason, or an empty string if the command may be sent
    """
    if not _PRINTABLE_RE.fullmatch(command):
        return "it contains control characters or a line break"

    normalized = normalize_command(command)

    for pattern, reason in DENIED_COMMANDS:
        if pattern.fullmatch(normalized):
            return f"it may change the state of the device ({reason})"

    if strict and not is_read_only(command):
        return "it isn't one of the read-only commands PEAT uses"

    return ""


def is_read_only(command: str) -> bool:
    """
    If a command is one of the read-only commands PEAT uses
    (:data:`ALLOWED_COMMANDS`, and not :data:`DENIED_COMMANDS`).
    """
    if not _PRINTABLE_RE.fullmatch(command):
        return False

    normalized = normalize_command(command)
    return any(p.fullmatch(normalized) for p in ALLOWED_COMMANDS) and not any(
        p.fullmatch(normalized) for p, _ in DENIED_COMMANDS
    )


def check_command(command: str, strict: bool = False) -> None:
    """
    Raise :class:`SELCommandRefused` if PEAT must not send a command.

    Args:
        command: A command line, e.g. ``"SER C"``
        strict: Also refuse commands that don't match :data:`ALLOWED_COMMANDS`

    Raises:
        SELCommandRefused: The command may change the state of the device
            (or with ``strict``, it isn't one of the read-only commands PEAT uses)
    """
    reason = command_refusal(command, strict=strict)
    if reason:
        raise SELCommandRefused(f"PEAT won't send '{command}': {reason}")


# ---------------------------------------------------------------------------
# Registry of the commands pull_more_commands() runs
# ---------------------------------------------------------------------------

#: Model families of relays (an empty string is a model that isn't known,
#: e.g. the SEL-2411, which is treated like a relay)
RELAY_FAMILIES: Final = frozenset({FAMILY_300, FAMILY_400, FAMILY_700, ""})

#: Number of SER records to ask for on SEL-400 series relays, where ``SER``
#: without arguments returns only the 20 newest records (SEL-421 IM 20130627,
#: Table 9.96). The SEL-421 keeps the latest 1000 records.
SER_400_RECORDS: Final = 1000


@dataclass(frozen=True)
class ReadCommand:
    """
    A read-only command in :data:`COMMANDS`.
    """

    #: Name of the result, the key in ``additional-command-outputs.json``
    name: str
    #: The command that's sent, unless it's different for the family (``by_family``)
    command: str
    #: Method of :class:`~peat.modules.sel.sel_ascii.SELAscii` that runs the
    #: command and returns its result, or an empty string to run ``command``
    #: with :meth:`~peat.modules.sel.sel_ascii.SELAscii.run_read_command`
    method: str = ""
    #: Model families the command is sent to
    families: frozenset[str] = RELAY_FAMILIES
    #: The command for some families, e.g. ``{"400": "SER 1000"}``
    by_family: dict[str, str] = field(default_factory=dict)
    #: Minimum access level (0 or 1). New commands at level 1 are only run if
    #: ``HELP`` lists them (if ``HELP`` worked), unless they're ``legacy``.
    min_level: int = 1
    #: PEAT ran this command before the registry existed, so it's run even if
    #: ``HELP`` doesn't list it, under the same result name as before
    legacy: bool = False
    #: Families on which the command is run before PEAT elevates to level 2,
    #: e.g. ``STA`` on 400 series relays, which may ask "Accept new hardware
    #: configuration (Y/N)?" at level 2 (SEL-421 IM 20130627, Table 9.125)
    below_level_2: frozenset[str] = frozenset()
    #: Compressed ASCII command, only run if ``CAS`` lists it
    compressed: bool = False
    #: The text command this compressed command is used instead of, and falls
    #: back to, e.g. ``ser`` for ``CSE``
    replaces: str = ""
    #: The text command this compressed command is only run after, if that
    #: command failed, e.g. ``his`` for ``CHI``
    fallback_for: str = ""
    #: The command may have a lot of output
    long: bool = False
    #: With ``sel.legacy_ascii_timing``, seconds to wait for the output
    legacy_delay: float = 2.0
    #: What the command shows
    description: str = ""

    def command_for(self, model: str | None) -> str:
        """The command to send to a device of a model."""
        return self.by_family.get(model_family(model), self.command)


_ALL_FAMILIES: Final = RELAY_FAMILIES | {FAMILY_2030}

#: The read-only commands :meth:`~peat.modules.sel.sel_relay.SELRelay.pull_more_commands`
#: runs on relays, keyed by the name of their result
COMMANDS: Final[dict[str, ReadCommand]] = {
    spec.name: spec
    for spec in (
        # Discovery, at level 1, before the other commands
        ReadCommand(
            "id",
            "ID",
            method="get_id",
            families=_ALL_FAMILIES,
            min_level=0,
            description="Identification (only run if the FID isn't known yet)",
        ),
        ReadCommand("help", "HELP", min_level=0, description="Commands at the present level"),
        ReadCommand("cas", "CAS", min_level=0, long=True, description="Compressed ASCII commands"),
        # Events
        ReadCommand(
            "ser",
            "SER",
            method="show_ser",
            legacy=True,
            families=_ALL_FAMILIES,
            by_family={FAMILY_400: f"SER {SER_400_RECORDS}", FAMILY_2030: "SER GLOBAL 100"},
            long=True,
            legacy_delay=10.0,
            description="Sequential Events Recorder",
        ),
        ReadCommand(
            "cse",
            "CSE",
            compressed=True,
            replaces="ser",
            long=True,
            legacy_delay=10.0,
            description="Sequential Events Recorder (Compressed ASCII)",
        ),
        ReadCommand(
            "his",
            "HIS",
            method="show_his",
            legacy=True,
            long=True,
            legacy_delay=15.0,
            description="Event history",
        ),
        ReadCommand(
            "chi",
            "CHI",
            compressed=True,
            fallback_for="his",
            long=True,
            legacy_delay=15.0,
            description="Event history (Compressed ASCII)",
        ),
        # Status and configuration
        ReadCommand(
            "sta",
            "STA",
            method="get_sta",
            legacy=True,
            families=_ALL_FAMILIES,
            below_level_2=frozenset({FAMILY_400}),
            long=True,
            description="Self-test status",
        ),
        *(
            ReadCommand(name, command, method=method, legacy=True, description=description)
            for name, command, method, description in (
                ("device_time", "DAT", "get_device_time", "Date and time"),
                ("active_group", "GRO", "get_active_group", "Active group"),
                ("mac", "MAC", "show_mac", "MAC addresses"),
                ("eth", "ETH", "show_eth", "Ethernet port status"),
                ("bre", "BRE", "show_bre", "Breaker monitor"),
                ("eve", "EVE", "show_eve", "Event report"),
                ("sum", "SUM", "show_sum", "Event summary"),
            )
        ),
        ReadCommand(
            "status",
            "STA S",
            method="show_status",
            legacy=True,
            below_level_2=frozenset({FAMILY_400}),
            description="SELOGIC usage (700 series) or errors (400 series)",
        ),
        ReadCommand(
            "sta_all",
            "STA A",
            families=frozenset({FAMILY_400}),
            below_level_2=frozenset({FAMILY_400}),
            long=True,
            description="Full status report (400 series)",
        ),
        ReadCommand("ver", "VER", long=True, description="Firmware and hardware configuration"),
        ReadCommand("time_quality", "TIM Q", description="Time source and clock quality"),
        ReadCommand("goose", "GOO", long=True, description="GOOSE transmit and receive status"),
        ReadCommand("sns", "SNS", min_level=0, description="Names of the SER trigger elements"),
        ReadCommand("dna", "DNA X", min_level=0, description="Fast Meter Relay Word bit names"),
        ReadCommand("bna", "BNA", min_level=0, description="Fast Meter status bit names"),
        ReadCommand("cst", "CST", compressed=True, description="Status (Compressed ASCII)"),
    )
}

#: The commands PEAT runs on the SEL-2030/2032 communications processors, as
#: before (``SER GLOBAL 100``, ``STATUS``, ``CARD n``, ...), keyed by the name
#: of their result. Some have the same name as a relay command.
COMMANDS_2030: Final[dict[str, ReadCommand]] = {
    spec.name: spec
    for spec in (
        COMMANDS["ser"],
        COMMANDS["sta"],
        ReadCommand(
            "dnpmap",
            "DNPMAP",
            legacy=True,
            families=frozenset({FAMILY_2030}),
            description="DNP map",
        ),
        ReadCommand(
            "who",
            "WHO",
            legacy=True,
            families=frozenset({FAMILY_2030}),
            legacy_delay=3.0,
            description="Devices on the ports",
        ),
        ReadCommand(
            "status",
            "STATUS",
            legacy=True,
            families=frozenset({FAMILY_2030}),
            legacy_delay=4.0,
            description="Status of the ports",
        ),
        *(
            ReadCommand(
                f"card_{n}",
                f"CARD {n}",
                legacy=True,
                families=frozenset({FAMILY_2030}),
                legacy_delay=4.0,
            )
            for n in (17, 18)
        ),
    )
}

#: Order of the commands on relays, the same for Telnet and serial. The commands
#: PEAT ran before come first, in the same order, except on SEL-400 series
#: relays, where ``STA``, ``STA S``, and ``STA A`` run first, at level 1 (refer to
#: ``below_level_2`` in :class:`ReadCommand`). ``CSE`` is run instead of ``ser``
#: if ``CAS`` lists it, and ``CHI`` after ``his`` if ``HIS`` failed. The ``SHO``
#: commands are run last (refer to :data:`SHOW_SETTINGS_DEFAULT`).
RELAY_ORDER: Final = (
    "ser",
    "his",
    "sta",
    "device_time",
    "active_group",
    "mac",
    "eth",
    "bre",
    "eve",
    "sum",
    "status",
    "sta_all",
    "ver",
    "time_quality",
    "goose",
    "sns",
    "dna",
    "bna",
    "cst",
)

#: Default ``SHO`` commands (``sel.show_settings``). ``{group}`` is the active
#: settings group (from ``GRO``); if it isn't known, the relay shows the
#: active group (``SHO``, ``SHO L``).
SHOW_SETTINGS_DEFAULT: Final = ("G", "{group}", "L {group}", "P", "R")


def ser_command(model: str | None) -> str:
    """
    The ``SER`` command for a model: ``SER 1000`` on SEL-400 series relays (``SER``
    without arguments only returns the 20 newest records), ``SER GLOBAL 100`` on
    the SEL-2030/2032 (which keeps a SER for each port), otherwise ``SER``
    (all of the records, up to 1024 on the 300 and 700 series).
    """
    return COMMANDS["ser"].command_for(model)


def command_key(command: str) -> str:
    """
    The first word of a command, cut to three characters, as relays read it,
    e.g. ``"GOOSE"`` => ``"GOO"``.
    """
    normalized = normalize_command(command)
    return normalized.split(" ", 1)[0] if normalized else ""


def listed(command: str, names: set[str] | list[str] | dict) -> bool:
    """
    If a command is in a list of command names (e.g. from ``HELP`` or ``CAS``),
    comparing the first three characters (``CSER`` is ``CSE``).
    """
    key = command_key(command)
    return any(command_key(str(name)) == key for name in names)


def show_settings_commands(classes: list[str] | tuple[str, ...], group: str = "") -> list[str]:
    """
    ``SHO`` commands for settings classes (``sel.show_settings``), e.g.
    ``["G", "{group}", "L {group}"]`` => ``["SHO G", "SHO 1", "SHO L 1"]``.
    If ``group`` isn't known, ``{group}`` is removed (the relay shows the active
    group), and duplicates are removed.
    """
    commands = []
    for cls in classes:
        args = " ".join(str(cls).replace("{group}", group or "").split())
        command = f"SHO {args}".strip()
        if command not in commands:
            commands.append(command)
    return commands


__all__ = [
    "ALLOWED_COMMANDS",
    "COMMANDS",
    "COMMANDS_2030",
    "DENIED_COMMANDS",
    "RELAY_FAMILIES",
    "RELAY_ORDER",
    "SER_400_RECORDS",
    "SHOW_SETTINGS_DEFAULT",
    "ReadCommand",
    "SELCommandRefused",
    "check_command",
    "command_key",
    "command_refusal",
    "is_read_only",
    "listed",
    "normalize_command",
    "ser_command",
    "show_settings_commands",
]
