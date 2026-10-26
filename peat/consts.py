import getpass
import os
import platform
import shutil
import sys
import warnings
from base64 import b64encode
from datetime import UTC, datetime
from pathlib import PurePosixPath
from random import randint
from string import ascii_letters, digits
from typing import Any, Final, Literal

import pathvalidate

# Hide beautiful soup warnings caused by the ION HTTP parsing
# (it's not relevant to what PEAT's doing)
try:
    from bs4.builder import XMLParsedAsHTMLWarning

    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

try:  # tzlocal can be problematic sometimes (Macs, Docker containers, etc.)
    import tzlocal

    #: str: Timezone of the local system
    TIMEZONE: str = str(tzlocal.get_localzone())
except Exception:
    TIMEZONE = str(datetime.now(UTC).astimezone().tzinfo)

# Determine the beautifulsoup4 parser to use based on the availability of lxml
try:
    import lxml  # noqa: F401

    #: str: The ``beautifulsoup4`` parser to use
    BS4_PARSER: str = "lxml"
except ImportError:
    BS4_PARSER = "html.parser"

#: bool: If the local system is a Windows system (this is FALSE if in :term:`WSL`)
WINDOWS: Final[bool] = os.name == "nt"

#: bool: If the local system is a POSIX system (Linux, OSX, BSD, etc.)
POSIX: Final[bool] = os.name == "posix"

#: bool: If the local system is Linux-based
LINUX: Final[bool] = sys.platform == "linux"

#: bool: If the local system is a Windows Subsystem for Linux (WSL) environment
WSL: Final[bool] = LINUX and "Microsoft" in platform.version()

#: str: Format to use for timestamp strings
TIME_FMT: Final[str] = "%Y-%m-%d_%H-%M-%S"

#: str: TIME_FMT without an underscore, and a colon instead of a dash for H/M/S
LOG_TIME_FMT: Final[str] = "%Y-%m-%d %H:%M:%S"

#: datetime: UTC time of when PEAT was imported that can be used for time stamping
START_TIME_UTC: Final[datetime] = datetime.now(UTC)

#: datetime: Local time of when PEAT was imported that can be used for time stamping
START_TIME_LOCAL: Final[datetime] = START_TIME_UTC.astimezone()

#: str: Formatted local time (TIME_FMT) of when PEAT was imported ("2022-09-13_15-04-33")
START_TIME: Final[str] = START_TIME_LOCAL.strftime(TIME_FMT)

#: int: Unique "ID" to track all artifacts associated with a single run of PEAT
#: RUN_ID := 12-digit integer (current UTC time + random 2-digit integer)
#: NOTE: previously, the Run ID was 10 digits (changed 02/20/2020)
RUN_ID: Final[int] = int(f"{int(START_TIME_UTC.timestamp()):10}{randint(0, 99):02}")

NO_COLOR_LOGO: Final[str] = r"""
    ____  _________  ______
   / __ \/ ____/   |/_  __/
  / /_/ / __/ / /| | / /
 / ____/ /___/ ___ |/ /
/_/   /_____/_/  |_/_/
"""
LOGO: Final[str] = f"\033[32m\033[1m{NO_COLOR_LOGO}\33[0m"

#: Resolves a IANA IP protocol ID to the name of the protocol
IANA_IP_PROTOS: Final[dict[int, str]] = {
    0: "hopopts",
    1: "icmp",
    2: "igmp",
    3: "ggp",
    4: "ipv4",
    5: "st",
    6: "tcp",
    7: "cbt",
    8: "egp",
    9: "igp",
    12: "pup",
    17: "udp",
    22: "idp",
    27: "rdp",
    41: "ipv6",
    43: "routing",
    44: "fragment",
    50: "esp",
    51: "ah",
    58: "icmpv6",
    59: "none",
    60: "dstopts",
    77: "nd",
    78: "iclfxbm",
    103: "pim",
    113: "pgm",
    115: "l2tp",
    132: "sctp",
    255: "raw",
    256: "max",
}

# Custom types
# These can be turned into a list with typing.get_args(type),
# Example: typing.get_args(AllowedCommTypes) == ('unicast_ip', 'broadcast_ip', 'serial')
AllowedCommTypes = Literal["unicast_ip", "broadcast_ip", "serial"]
PushType = Literal["config", "firmware"]
EntrypointType = Literal["CLI", "Server", "Package"]


class PeatError(Exception):
    """
    Generic class for any error raised by PEAT.
    """


class ParseError(PeatError):
    """
    Parsing errors.
    """


class CommError(PeatError):
    """
    Communication errors.
    """


class DeviceError(PeatError):
    """
    Errors related to a device or :class:`~peat.device.DeviceModule` module.
    """


def convert(value: Any) -> str | bool | int | float | list | dict | None:
    """
    Recursively convert values into JSON-friendly standard Python types.

    .. note::
       :class:`set` objects are sorted after being converted to a :class:`list`.
       The order of a Python :class:`set` is not defined and therefore may
       vary between runs. Sorting helps alleviate that somewhat.

    .. note::
       This is located in consts.py so it can be used in locations that are not
       safe to import ``utils.py`` from, such as ``settings_manager.py``.

    Args:
        value: Value to convert

    Returns:
        The converted value
    """
    if value is None:
        return None
    elif isinstance(value, (str, bool, int, float)):
        return value
    elif isinstance(value, (bytes, bytearray)):
        # Fallback to Base64 encoding if UTF-8 decode fails
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return b64encode(value).decode("utf-8")
    elif isinstance(value, dict):
        return {k: convert(v) for k, v in value.items()}
    elif isinstance(value, (list, tuple)):
        # TODO: remove empty strings and Nones here instead? then set can be processed here too
        return [convert(i) for i in value]
    elif isinstance(value, set):
        # Remove empty strings and Nones from the set before exporting
        for empty_val in ["", None]:
            if empty_val in value:
                value.remove(empty_val)
        # Sort sets for determinism
        return sorted(convert(list(value)))  # type: ignore
    else:
        return str(value)


#: Replaces secret values (e.g. passwords) in logs and results
REDACTED: Final[str] = "<redacted>"

#: Keys (e.g. in device options and configuration files) with values that are
#: secrets (passwords, SNMP communities, etc.)
#: NOTE: module authors must add any new option key whose value is a secret,
#: or it will be saved in the results in plaintext. Keys ending in
#: :data:`SECRET_KEY_SUFFIXES` (e.g. ``sel_creds``) are secrets as well.
SECRET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "pass",
        "passwd",
        "password",
        "passphrase",
        "community",
        "communities",
        "creds",
        "passwords",
        "meter_pass",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "secret_key",
    }
)

#: Suffixes of keys (e.g. in device options and configuration files) with
#: values that are secrets, in addition to :data:`SECRET_KEYS`
SECRET_KEY_SUFFIXES: Final[tuple[str, ...]] = ("_creds",)


def is_secret_key(key: Any) -> bool:
    """
    If the value of this option or configuration key is a secret:
    it's in :data:`SECRET_KEYS` or ends with one of :data:`SECRET_KEY_SUFFIXES`.
    """
    key = str(key).lower()
    return key in SECRET_KEYS or key.endswith(SECRET_KEY_SUFFIXES)


#: Command line options with values that are secrets
SECRET_CLI_OPTIONS: Final[tuple[str, ...]] = ("-p", "--password")

#: Characters allowed in the host part of a URL (including the port and
#: IPv6 brackets), used to find the user information in a URL
_HOST_CHARS: Final[str] = ascii_letters + digits + "-._~%:[]"

#: Command line options with values that are URLs that may include credentials
URL_CLI_OPTIONS: Final[tuple[str, ...]] = (
    "-e",
    "--elastic-server",
    "--opensearch-server",
    "--heat-elastic-server",
)


def _split_url_userinfo(url: str, require_scheme: bool) -> tuple[str, str, str, str, str] | None:
    """
    Split a URL into (prefix, user, colon, password, suffix), where the user
    information is everything before the last ``@`` that is followed by a host.

    .. note::
       The password may contain ``@`` or ``/``, and :func:`urllib.parse.urlsplit`
       treats everything after the first ``/`` as the path, leaving such a
       password in the URL.

    Returns:
        The parts of the URL, or :obj:`None` if it has no user information
    """
    if not isinstance(url, str) or "@" not in url:
        return None

    scheme, sep, rest = url.partition("://")
    if not sep:
        if require_scheme:
            return None
        scheme, rest = "", url

    at = -1
    for index, char in enumerate(rest):
        if char != "@":
            continue
        userinfo, host_candidate = rest[:index], rest[index + 1 :].split("/", 1)[0]
        if not host_candidate or host_candidate.strip(_HOST_CHARS):
            continue  # not a host, e.g. "http://host/path@notuserinfo"
        if "/" in userinfo and (":" not in userinfo or userinfo.index(":") > userinfo.index("/")):
            continue  # not user information: it has a path but no password
        at = index

    if at < 0:
        return None

    user, colon, password = rest[:at].partition(":")
    return f"{scheme}{sep}", user, colon, password, rest[at + 1 :]


def url_password(url: str, require_scheme: bool = False) -> str | None:
    """
    The password (or token) in the user information of a URL, e.g. ``changeme``
    for ``https://elastic:changeme@localhost:9200/``.

    Returns:
        The password, or :obj:`None` if the URL doesn't have one
    """
    parts = _split_url_userinfo(url, require_scheme)
    if parts is None:
        return None
    _, user, colon, password, _ = parts
    return (password if colon else user) or None


def redact_url(url: str, require_scheme: bool = True, replacement: str | None = REDACTED) -> str:
    """
    Redact the password (or token) in the user information of a URL, e.g.
    ``https://elastic:changeme@localhost:9200/`` becomes
    ``https://elastic:<redacted>@localhost:9200/``.

    Args:
        url: The URL to redact
        require_scheme: Only redact URLs with a scheme (e.g. ``https://``).
            If :obj:`False`, ``user:password@host`` is also redacted.
        replacement: What to replace the password with. If :obj:`None`, the
            password is removed (``https://elastic@localhost:9200/``), and a
            token without a username is removed with the ``@``.

    Returns:
        The URL with the password redacted, or the original value if there isn't one
    """
    parts = _split_url_userinfo(url, require_scheme)
    if parts is None:
        return url

    prefix, user, colon, _, host_and_path = parts
    if replacement is None:
        userinfo = f"{user}@" if colon else ""
    else:
        userinfo = f"{user}:{replacement}@" if colon else f"{replacement}@"

    return f"{prefix}{userinfo}{host_and_path}"


def redact_argv(argv: list[str]) -> list[str]:
    """
    Redact secrets in command line arguments, so they can be recorded in logs
    and results: the values of :data:`SECRET_CLI_OPTIONS` (e.g. ``-p <password>``,
    including bundled short options such as ``-Vp <password>``) and passwords in
    URLs (e.g. ``-e https://user:password@host:9200/``).
    """
    redacted = []
    redact_next = False
    url_next = False

    for arg in argv:
        if redact_next:
            redacted.append(REDACTED)
            redact_next = False
            continue

        if url_next:
            redacted.append(redact_url(arg, require_scheme=False))
            url_next = False
            continue

        option, eq, _ = arg.partition("=")
        if arg in SECRET_CLI_OPTIONS:
            redact_next = True
        elif arg in URL_CLI_OPTIONS:
            url_next = True
        elif (
            eq and option.startswith("--") and len(option) > 3 and "--password".startswith(option)
        ):
            # "--password=secret", including abbreviations argparse accepts ("--pass=")
            arg = f"{option}={REDACTED}"
        elif eq and option in URL_CLI_OPTIONS:
            arg = f"{option}={redact_url(arg[len(option) + 1 :], require_scheme=False)}"
        elif len(arg) > 2 and arg.startswith("-") and not arg.startswith("--") and "p" in arg:
            # A cluster of short options ending with the password option, e.g.
            # "-psecret", "-p=secret", "-Vp secret" or "-vpsecret"
            cluster, _, value = arg[1:].partition("p")
            if cluster.isalpha() or not cluster:
                arg = f"-{cluster}p{REDACTED}" if value else f"-{cluster}p"
                redact_next = not value
            else:
                arg = redact_url(arg)
        elif arg.startswith("--") and len(arg) > 3 and "--password".startswith(arg):
            redact_next = True  # "--pass secret"
        else:
            arg = redact_url(arg)

        redacted.append(arg)

    return redacted


def omit_secrets(value: Any, path: str = "") -> tuple[Any, list[str]]:
    """
    Remove secrets from configuration values (e.g. an export of the configuration
    that may be loaded again): secret keys (:func:`is_secret_key`, at any depth,
    e.g. in device options) are removed, and passwords are removed from URLs
    (``https://elastic:pw@host/`` becomes ``https://elastic@host/``).

    Nothing is replaced with :data:`REDACTED`, so loading the result doesn't
    use a placeholder as a password, and the default values of the removed
    options (e.g. SNMP communities) are used instead.

    Args:
        value: The values to remove secrets from
        path: Path of ``value``, used for the paths returned

    Returns:
        A copy of the value without secrets (the value isn't modified), and
        the paths of the values that were removed (e.g. ``device_options.sel.pass``)
    """
    omitted: list[str] = []

    if isinstance(value, dict):
        result = {}
        for key, val in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if is_secret_key(key):
                omitted.append(key_path)
                continue
            result[key], key_omitted = omit_secrets(val, key_path)
            omitted.extend(key_omitted)
        return result, omitted

    if isinstance(value, list | tuple | set):
        items = []
        for index, item in enumerate(value):
            item, item_omitted = omit_secrets(item, f"{path}[{index}]")
            items.append(item)
            omitted.extend(item_omitted)
        return (items if not isinstance(value, tuple) else tuple(items)), omitted

    if isinstance(value, str):
        without_password = redact_url(value, replacement=None)
        if without_password != value:
            omitted.append(f"{path} (password)" if path else "(password)")
        return without_password, omitted

    return value, omitted


#: Returned by :func:`drop_redacted` for a value that was redacted
DROPPED: Final[object] = object()


def _is_redacted(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value == REDACTED:
        return True
    # A URL with a redacted password, e.g. "https://elastic:<redacted>@host/"
    return url_password(value) == REDACTED


def drop_redacted(value: Any, path: str = "") -> tuple[Any, list[str]]:
    """
    Remove values that were redacted (:data:`REDACTED`, e.g. copied from PEAT's
    logs or from a configuration saved by a development version of PEAT), so
    loading a configuration with them doesn't use the placeholder as a password
    or SNMP community. A ``[username, <redacted>]``
    pair is removed, as are lists and dicts that are empty once redacted values
    are removed (so default values are used instead), and URLs with a redacted
    password.

    Args:
        value: The values to check
        path: Path of ``value``, used for the paths returned

    Returns:
        A copy of the value with redacted values removed (:data:`DROPPED` if the
        value itself was redacted), and the paths of the values that were removed
    """
    if _is_redacted(value):
        return DROPPED, [path]

    dropped: list[str] = []

    if isinstance(value, dict):
        result = {}
        for key, val in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            val, key_dropped = drop_redacted(val, key_path)
            dropped.extend(key_dropped)
            if val is not DROPPED:
                result[key] = val
        if value and not result:
            return DROPPED, dropped
        return result, dropped

    if isinstance(value, list | tuple | set):
        items = []
        for index, item in enumerate(value):
            item_path = f"{path}[{index}]"
            if isinstance(item, list | tuple) and len(item) == 2 and _is_redacted(item[1]):
                dropped.append(item_path)  # a (username, password) pair
                continue
            item, item_dropped = drop_redacted(item, item_path)
            dropped.extend(item_dropped)
            if item is not DROPPED:
                items.append(item)
        if value and not items:
            return DROPPED, dropped
        return (items if not isinstance(value, tuple) else tuple(items)), dropped

    return value, dropped


def get_platform_info() -> dict[str, str | int | bool]:
    """
    Collect information about the system PEAT is running on.
    """
    info: dict[str, str | int | bool] = {
        "start_time": START_TIME_LOCAL.strftime(LOG_TIME_FMT),
        "timezone": TIMEZONE,
        "run_id": RUN_ID,
        "python_exe": sys.executable,
        "python_version": platform.python_version(),
        "python_impl": platform.python_implementation(),
        "arch": platform.architecture()[0],
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "hostname": platform.node(),
        "username": getpass.getuser(),
        "cpu": platform.processor() if platform.processor() else platform.machine(),
        "os_family": platform.system().lower(),  # "linux", "windows"
        "os_rel": platform.release(),  # "5.0.0-20-generic", "10"
        "os_name": platform.system(),  # "Linux", "Windows"
        "os_ver": platform.version(),  # "10.0.17134"
        # "Windows 10 (10.0.17134)"
        "os_full": f"{platform.system()} {platform.release()} ({platform.version()})",
        "containerized": bool(os.environ.get("PEAT_IN_CONTAINER")),
        "podman": bool(os.environ.get("container", "").lower() == "podman"),
    }

    tcpdump = shutil.which("tcpdump")
    info["tcpdump"] = str(tcpdump) if tcpdump else ""

    if len(sys.argv) > 1:
        # NOTE: secrets (e.g. "-p <password>") are redacted, since
        # this is recorded in the logs and results
        argv = redact_argv(sys.argv)
        info["cli_exe"] = argv[0]
        info["cli_arguments"] = " ".join(argv[1:])

    if LINUX:
        try:
            import distro

            info["os_family"] = distro.id().lower()  # "ubuntu", "debian"
            info["os_ver"] = distro.version(best=True)  # "19.04"
            # "Linux 5.0.0-20-generic (Ubuntu 19.04)"
            info["os_full"] = f"{info['os_name']} {info['os_rel']} ({distro.name(True)})"
        except Exception:
            pass  # Fail silently if anything goes wrong, info is non-critical

    return info


def sanitize_filepath(path: str) -> str:
    """
    Sanitize an untrusted relative file path, e.g. a file name or path
    supplied by a device or found in a file being parsed.

    Every component is sanitized with :func:`sanitize_filename`, so characters
    that are invalid on Windows are replaced with ``_``. Backslashes are treated
    as path separators. Empty, ``.`` and ``..`` components and any leading root
    (``/``) are removed, so the result is always a relative path that can't
    walk out of the directory it's joined to.

    .. note::
       An empty input returns an empty string. A non-empty input that has no
       usable components (e.g. ``"../.."``) returns ``"unnamed"``.

    Args:
        path: The untrusted path to sanitize

    Returns:
        The sanitized relative path, in POSIX format (``/`` separators)
    """
    if not path:
        return ""

    parts = []
    for part in PurePosixPath(str(path).replace("\\", "/")).parts:
        if part.strip("/") in ("", ".", ".."):
            continue

        clean = sanitize_filename(part)
        if clean in ("", ".", ".."):
            continue

        parts.append(clean)

    if not parts:
        return "unnamed"

    return PurePosixPath(*parts).as_posix()


def sanitize_filename(filename: str) -> str:
    """
    Validate and sanitize filenames to work on all platforms, notably Windows.

    This replaces any invalid characters with ``_``.
    """
    return str(
        pathvalidate.sanitize_filename(
            filename=filename, replacement_text="_", platform="universal"
        )
    )


def gen_random_dev_id() -> str:
    """
    Generate a randomized device ID.

    Format: ``unknown-dev-<run-id>-<random-integer>``
    """
    return f"unknown-dev-{RUN_ID}-{randint(0, 9999):04}"


def lower_dict(to_lower: dict[str, Any], children: bool = True) -> dict[str, Any]:
    """
    Convert keys of a dict and it's immediate children dicts to lowercase.
    Dict keys must be strings.

    Args:
        children: if values that are dicts should have their keys converted as well
    """
    return {
        key.lower(): (lower_dict(value) if isinstance(value, dict) and children else value)
        for key, value in to_lower.items()
    }


def str_to_bool(val: str) -> bool:
    """
    Convert a string representation of truth to :obj:`True` or :obj:`False`.

    True values are: 'y', 'yes', 't', 'true', 'on', '1', 'enable', 'enabled', 'up'

    False values are: 'n', 'no', 'f', 'false', 'off', '0', 'disable', 'disabled', 'down'

    Args:
        val: String to evaluate

    Returns:
        The boolean representation of the string

    Raises:
        ValueError: val is anything other than a boolean value
    """
    val = val.strip().lower()

    if val in ("y", "yes", "t", "true", "on", "1", "enable", "enabled", "up"):
        return True
    elif val in ("n", "no", "f", "false", "off", "0", "disable", "disabled", "down"):
        return False
    else:
        raise ValueError(f"invalid bool string {val}")


#: dict: Information about the system PEAT is running on from
#: :func:`~peat.consts.get_platform_info`
SYSINFO: Final[dict[str, str | int | bool]] = get_platform_info()
