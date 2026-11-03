"""
Factory default credentials of SEL relays, by model family.

PEAT uses these when the PEAT configuration doesn't have credentials for a
device. Credentials in the configuration always win: they're used as they are,
in the order they're configured, and the defaults aren't tried in addition.

The access level passwords are from the tables of factory default passwords
in public SEL instruction manuals:

- SEL-300 series (e.g. SEL-311C, SEL-351, SEL-351S, SEL-387, SEL-587):
  SEL-351S Instruction Manual (date code 20171023), Section 10, Table 10.21
  "Factory Default Passwords for Access Levels 1, B, 2, and C":
  1 ``OTTER``, B ``EDITH``, 2 ``TAIL``, C ``CLARKE``. The SEL-551 manual
  (20151105, "PAS Command") lists only levels 1, 2, and C, with the same passwords.
- SEL-400 series (e.g. SEL-411L, SEL-421, SEL-451, SEL-487E): SEL-421 Instruction
  Manual (20130627), User's Guide Section 4, Table 4.4 "Access Level Commands and
  Passwords": 1 ``OTTER``, B ``EDITH``, P ``AMPERE``, A ``VOLTA``, O ``WATT``,
  2 ``TAIL``, C ``Sel-1``. ``Sel-1`` was also seen on a SEL-451-5 (R324) by the
  PEAT team. ``CLARKE`` (the level C password of the other series) isn't
  documented for the 400 series, so it's only tried if ``sel.cal_clarke_fallback``
  is enabled.
- SEL-700 series (e.g. SEL-700G, SEL-710, SEL-751, SEL-751A, SEL-787): SEL-751A
  Instruction Manual (20130329) Table 7.34 and SEL-700G Instruction Manual
  (20150521) Table 7.37 "Factory Default Passwords for Access Levels 1, 2, and C":
  1 ``OTTER``, 2 ``TAIL``, C ``CLARKE``. These relays don't have level B.
  The SEL-710 (20090327, Table 7.36) and SEL-749M (20080918, Table 7.35)
  manuals list only levels 1 and 2.
- SEL-2030 and SEL-2032 communications processors: SEL-2032 Instruction Manual
  (20120126), Table 3.1 "Factory-Default Passwords for Access Levels 1, 2, and C":
  1 ``OTTER``, 2 ``TAIL``, C ``CLARKE``.

Models that aren't in one of these families (e.g. the SEL-2411) use the
defaults PEAT had before this table: 1 ``OTTER``, B ``EDITH``, 2 ``TAIL``, C ``CLARKE``.

FTP (refer to :func:`ftp_candidates`):

- SEL-300 and SEL-700 series: the user name is the ``FTPUSER`` port setting
  (factory default ``FTPUSER``), and the password is the level 2 password
  (SEL-351S manual, Section 10 "Access Control"; ``FTPUSER`` default in the
  SEL-751A and SEL-700G port settings). The SEL-351 (not 351S) uses ``FTP``.
- SEL-400 series and devices with a SEL-2701 Ethernet card (e.g. the SEL-2032):
  the user name is the access level command (``ACC``, ``2AC``), and the password is
  the password for that level (SEL-421 manual, User's Guide Section 3, "FTP", and
  Reference Manual Table 4.12 "Access Level User Names and Passwords").

Failed logins are counted by relays: after three wrong passwords in a row in a
terminal session the relay blocks access for 30 seconds and pulses the BADPASS
Relay Word bit (SEL-351S manual, Section 10, "ACC, BAC, 2AC, and CAL"), and
many relays allow 5 FTP login attempts. So PEAT tries each access level at most
once per connection, and tries at most :data:`MAX_DEFAULT_FTP_ATTEMPTS` default
FTP logins.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, NamedTuple

from peat import DeviceData, datastore
from peat.data.data_utils import DeepChainMap

#: Name of each access level ("key" used in the ``sel.creds`` option),
#: and the command that changes to it
LEVEL_COMMANDS: Final[dict[str, str]] = {
    "acc": "ACC",  # Level 1
    "bac": "BAC",  # Level B (breaker)
    "pac": "PAC",  # Level P (protection), 400 series
    "aac": "AAC",  # Level A (automation), 400 series
    "oac": "OAC",  # Level O (output), 400 series
    "2ac": "2AC",  # Level 2
    "cal": "CAL",  # Level C (calibration)
}

#: Model families with documented defaults (refer to the module docstring)
FAMILY_300: Final = "300"
FAMILY_400: Final = "400"
FAMILY_700: Final = "700"
FAMILY_2030: Final = "2030"

#: Factory default password of each access level, by model family
#: (refer to the module docstring for the sources)
FAMILY_PASSWORDS: Final[dict[str, dict[str, str]]] = {
    # SEL-351S IM 20171023, Table 10.21
    FAMILY_300: {"acc": "OTTER", "bac": "EDITH", "2ac": "TAIL", "cal": "CLARKE"},
    # SEL-421 IM 20130627, User's Guide Table 4.4
    FAMILY_400: {
        "acc": "OTTER",
        "bac": "EDITH",
        "pac": "AMPERE",
        "aac": "VOLTA",
        "oac": "WATT",
        "2ac": "TAIL",
        "cal": "Sel-1",
    },
    # SEL-751A IM 20130329, Table 7.34; SEL-700G IM 20150521, Table 7.37 (no level B)
    FAMILY_700: {"acc": "OTTER", "2ac": "TAIL", "cal": "CLARKE"},
    # SEL-2032 IM 20120126, Table 3.1
    FAMILY_2030: {"acc": "OTTER", "2ac": "TAIL", "cal": "CLARKE"},
}

#: Models whose manual lists fewer levels than the rest of their family
MODEL_PASSWORDS: Final[dict[str, dict[str, str]]] = {
    # SEL-551 IM 20151105, "PAS Command": levels 1, 2, and C
    "551": {"acc": "OTTER", "2ac": "TAIL", "cal": "CLARKE"},
    # SEL-749M IM 20080918, Table 7.35: levels 1 and 2
    "749M": {"acc": "OTTER", "2ac": "TAIL"},
}

#: Defaults for models that aren't in a known family (PEAT's previous defaults)
GENERIC_PASSWORDS: Final[dict[str, str]] = {
    "acc": "OTTER",
    "bac": "EDITH",
    "2ac": "TAIL",
    "cal": "CLARKE",
}

#: Level C password that's tried after "Sel-1" on 400 series relays,
#: only if the ``sel.cal_clarke_fallback`` option is enabled
CAL_CLARKE_FALLBACK: Final = "CLARKE"

#: Maximum number of default FTP logins that are tried. Many relays
#: lock out FTP after 5 failed logins.
MAX_DEFAULT_FTP_ATTEMPTS: Final = 4

# 4-digit devices (2032, 2411, 3530), or a 3-digit model with an optional letter (351S, 700G)
_FOUR_DIGIT_RE: Final = re.compile(r"2\d{3}|3\d{3}(?!\d)")
_MODEL_RE: Final = re.compile(r"\d{3}[A-Z]?")
# A 4-digit model that isn't a part number (part numbers start with a 0), e.g. "5030"
_FOUR_DIGIT_MODEL_RE: Final = re.compile(r"[1-9]\d{3}(?![\dA-Z])")

#: Letters that are part of a model number (e.g. 351S, 351R, 700G, 411L, 487E, 587Z),
#: rather than an ordering option in a part number
_MODEL_LETTERS: Final = "ABCEGLMPRSVZ"


class Credential(NamedTuple):
    """
    A user name and password, and where PEAT got them (for log messages).
    The password isn't in the ``repr()``, so it isn't logged by accident.
    """

    user: str
    password: str
    source: str

    def __repr__(self) -> str:
        return f"Credential(user={self.user!r}, source={self.source!r})"

    def __str__(self) -> str:
        return f"'{self.user}' ({self.source})"


def normalize_model(value: str | None) -> str:
    """
    Get the model number from a SEL firmware ID (``FID``), device ID (``DEVID``),
    ``RELAYTYPE``, part number, or model string.

    .. code-block:: python

       >>> from peat.modules.sel.sel_default_creds import normalize_model
       >>> normalize_model("SEL-451-5-R324-V1-Z027013-D20201009")
       '451'
       >>> normalize_model("0351S61H4455421")
       '351S'
       >>> normalize_model("sel-700g")
       '700G'
       >>> normalize_model("SEL-2032")
       '2032'

    Returns:
        The model, or an empty string if it isn't recognized
    """
    if not value:
        return ""

    text = str(value).strip().upper()
    for prefix in ("SEL-", "SEL "):
        text = text.removeprefix(prefix)
    text = text.split("-")[0].strip()
    part_number = text.startswith("0")
    text = text.lstrip("0")

    match = (
        (None if part_number else _FOUR_DIGIT_MODEL_RE.match(text))
        or _FOUR_DIGIT_RE.match(text)
        or _MODEL_RE.match(text)
    )
    if not match:
        return ""

    model = match.group(0)
    # Part numbers continue with ordering options after the model,
    # e.g. "351S61H..." or "751A01A1...".
    if len(model) == 4 and model[3].isalpha() and model[3] not in _MODEL_LETTERS:
        model = model[:3]
    return model


def model_family(model: str | None) -> str:
    """
    Model family of a SEL device, which determines its default credentials.

    Args:
        model: Model, FID, part number, etc. (refer to :func:`normalize_model`)

    Returns:
        One of ``"300"``, ``"400"``, ``"700"``, ``"2030"``, or an empty string if unknown
    """
    model = normalize_model(model)
    if not model:
        return ""

    if model in ("2030", "2032"):
        return FAMILY_2030
    if len(model) >= 4 and model[3].isdigit():  # Other 2xxx/3xxx devices, e.g. 2411, 3530
        return ""

    first = model[0]
    if first in "35":  # e.g. 311C, 351S, 387, 551, 587Z
        return FAMILY_300
    if first == "4":  # e.g. 411L, 421, 451, 487E
        return FAMILY_400
    if model.startswith("73"):
        # SEL-734 and SEL-735 meters: no table of default passwords was checked
        return ""
    if first == "7":  # e.g. 700G, 710, 751A, 787
        return FAMILY_700
    return ""


def describe_family(family: str) -> str:
    """Human-readable name of a model family, for log messages."""
    if family == FAMILY_2030:
        return "SEL-2030/2032"
    if family:
        return f"SEL-{family} series"
    return "SEL devices (model unknown)"


def default_passwords(
    model: str | None, cal_fallback: bool = False
) -> dict[str, list[Credential]]:
    """
    Factory default password(s) of each access level for a model.

    Args:
        model: Model, FID, part number, etc. (refer to :func:`normalize_model`)
        cal_fallback: Also try ``CLARKE`` for level C on 400 series relays
            (after ``Sel-1``). This isn't documented for the 400 series.

    Returns:
        The candidate credentials of each level, keyed by the level name
        (``acc``, ``2ac``, ...). The user of each credential is the level command.
        A level that the model doesn't have isn't included.
    """
    normalized = normalize_model(model)
    family = model_family(normalized)

    if normalized in MODEL_PASSWORDS:
        table = MODEL_PASSWORDS[normalized]
        source = f"SEL-{normalized} default"
    elif family:
        table = FAMILY_PASSWORDS[family]
        source = f"{describe_family(family)} default"
    else:
        table = GENERIC_PASSWORDS
        source = "PEAT generic default (model unknown)"

    result = {
        level: [Credential(LEVEL_COMMANDS[level], password, source)]
        for level, password in table.items()
    }

    if cal_fallback and family == FAMILY_400 and "cal" in result:
        result["cal"].append(
            Credential("CAL", CAL_CLARKE_FALLBACK, "opt-in fallback (sel.cal_clarke_fallback)")
        )

    return result


def resolve_level_passwords(
    model: str | None,
    configured: Mapping[str, Any] | None = None,
    cal_fallback: bool = False,
) -> dict[str, list[Credential]]:
    """
    Candidate passwords for each access level: the configured password of a
    level wins, otherwise the model's default (:func:`default_passwords`).

    Args:
        model: Model, FID, part number, etc. (refer to :func:`normalize_model`)
        configured: Passwords from the configuration or the caller, keyed by level
            name (``{"acc": "pass1", "2ac": "pass2"}``). A value may be a list of
            passwords, which are tried in that order (on separate connections).
        cal_fallback: refer to :func:`default_passwords`

    Returns:
        The candidates for each level, keyed by the level name
    """
    result = default_passwords(model, cal_fallback=cal_fallback)

    for level, value in (configured or {}).items():
        level = str(level).lower()
        if value is None or (isinstance(value, str | list | tuple) and not value):
            continue
        values = [value] if isinstance(value, str) else list(value)
        result[level] = [
            Credential(LEVEL_COMMANDS.get(level, level.upper()), str(v), "configured")
            for v in values
            if v is not None and str(v) != ""
        ]

    return result


def ftp_candidates(
    model: str | None,
    level_passwords: Mapping[str, Sequence[Credential]],
    ftp_user: str | None = None,
    anonymous_enabled: bool = False,
) -> list[Credential]:
    """
    Default FTP logins to try for a model, at most :data:`MAX_DEFAULT_FTP_ATTEMPTS`.

    Args:
        model: Model, FID, part number, etc. (refer to :func:`normalize_model`)
        level_passwords: The candidates for each access level
            (from :func:`resolve_level_passwords`). The FTP password is the
            level 2 password (or the level 1 password, for the ``ACC`` user).
        ftp_user: The ``FTPUSER`` port setting, if it's known (e.g. from settings
            pulled before), which is tried first
        anonymous_enabled: If the relay's settings say anonymous FTP is enabled
            (``FTPANMS``). Anonymous logins aren't tried otherwise.

    Returns:
        The logins to try, in order
    """
    normalized = normalize_model(model)
    family = model_family(normalized)

    def _first(level: str) -> Credential | None:
        values = level_passwords.get(level) or []
        return values[0] if values else None

    l1 = _first("acc")
    l2 = _first("2ac")
    candidates = []  # type: list[Credential]

    def _add(user: str, cred: Credential | None, source: str) -> None:
        if cred is None:
            return
        candidate = Credential(user, cred.password, f"{source}, {cred.source} password")
        if not any(c.user == user and c.password == cred.password for c in candidates):
            candidates.append(candidate)

    if ftp_user:
        _add(ftp_user, l2, "FTPUSER from the relay settings")

    if family in (FAMILY_400, FAMILY_2030):
        _add("2AC", l2, f"{describe_family(family)} FTP user")
        _add("ACC", l1, f"{describe_family(family)} FTP user")
    elif normalized == "351":
        _add("FTP", l2, "SEL-351 FTP user")
        _add("FTPUSER", l2, "FTPUSER default")
    elif family in (FAMILY_300, FAMILY_700):
        _add("FTPUSER", l2, "FTPUSER default")
    else:
        # Unknown model: the users PEAT tried before, in the same order
        _add("FTPUSER", l2, "FTPUSER default")
        _add("2AC", l2, "SEL-400 series FTP user")
        _add("FTP", l2, "SEL-351 FTP user")

    if anonymous_enabled:
        # Keep a place for it. SEL's anonymous user doesn't need a password.
        candidates = candidates[: MAX_DEFAULT_FTP_ATTEMPTS - 1]
        candidates.append(
            Credential("anonymous", "anonymous@", "anonymous FTP is enabled in the settings")
        )

    return candidates[:MAX_DEFAULT_FTP_ATTEMPTS]


#: Access levels tried as web logins, in order. PEAT only reads from the web
#: interface, which level 1 allows. Level 2 is tried in case level 1 doesn't work.
#: Levels B and C aren't tried (PEAT tried all four before), since each wrong
#: login is a failed password attempt on the relay.
WEB_LEVELS: Final = ("acc", "2ac")


def web_candidates(level_passwords: Mapping[str, Sequence[Credential]]) -> list[Credential]:
    """
    Default logins for the web interface of a relay: the user name is the access
    level (refer to :data:`WEB_LEVELS`: ``acc``, then ``2ac``), with the
    configured or default password of the level.
    """
    candidates = []  # type: list[Credential]
    for level in WEB_LEVELS:
        values = level_passwords.get(level) or []
        if values:
            candidates.append(Credential(level, values[0].password, values[0].source))
    return candidates


def configured_option(dev: DeviceData, section: str, key: str) -> Any:
    """
    Value of a device option that was set by the user, in the PEAT configuration
    (global ``device_options`` or the host's ``options``) or at runtime. Module
    default options are ignored, so this tells configured values apart from
    defaults. Empty values (``""``, ``[]``, ``{}``) are treated as not set.

    Args:
        dev: The device
        section: Option section, e.g. ``"sel"`` or ``"ftp"``
        key: Option name, e.g. ``"creds"``

    Returns:
        The value (a :class:`dict` for nested options), or :obj:`None` if it isn't set
    """
    layers = DeepChainMap(
        dev._runtime_options,
        dev._host_option_overrides,
        datastore.global_options,
    )

    try:
        value = layers[section][key]
    except (KeyError, TypeError):
        return None

    if isinstance(value, DeepChainMap):
        value = value.to_dict()

    if value is None or (isinstance(value, str | list | tuple | dict) and not value):
        return None

    return value


__all__ = [
    "CAL_CLARKE_FALLBACK",
    "FAMILY_PASSWORDS",
    "GENERIC_PASSWORDS",
    "LEVEL_COMMANDS",
    "MAX_DEFAULT_FTP_ATTEMPTS",
    "MODEL_PASSWORDS",
    "WEB_LEVELS",
    "Credential",
    "configured_option",
    "default_passwords",
    "describe_family",
    "ftp_candidates",
    "model_family",
    "normalize_model",
    "resolve_level_passwords",
    "web_candidates",
]
