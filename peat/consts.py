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
    }
)

#: Command line options with values that are secrets
SECRET_CLI_OPTIONS: Final[tuple[str, ...]] = ("-p", "--password")

#: Command line options with values that are URLs that may include credentials
URL_CLI_OPTIONS: Final[tuple[str, ...]] = (
    "-e",
    "--elastic-server",
    "--opensearch-server",
    "--heat-elastic-server",
)


def redact_url(url: str, require_scheme: bool = True) -> str:
    """
    Redact the password (or token) in the user information of a URL, e.g.
    ``https://elastic:changeme@localhost:9200/`` becomes
    ``https://elastic:<redacted>@localhost:9200/``.

    Args:
        url: The URL to redact
        require_scheme: Only redact URLs with a scheme (e.g. ``https://``).
            If :obj:`False`, ``user:password@host`` is also redacted.

    Returns:
        The URL with the password redacted, or the original value if there isn't one
    """
    if not isinstance(url, str) or "@" not in url:
        return url

    scheme, sep, rest = url.partition("://")
    if not sep:
        if require_scheme:
            return url
        scheme, rest = "", url

    netloc, slash, path = rest.partition("/")
    if "@" not in netloc:
        return url

    userinfo, _, host = netloc.rpartition("@")
    user, colon, _ = userinfo.partition(":")
    userinfo = f"{user}:{REDACTED}" if colon else REDACTED

    return f"{scheme}{sep}{userinfo}@{host}{slash}{path}"


def redact_argv(argv: list[str]) -> list[str]:
    """
    Redact secrets in command line arguments, so they can be recorded in logs
    and results: the values of :data:`SECRET_CLI_OPTIONS` (e.g. ``-p <password>``)
    and passwords in URLs (e.g. ``-e https://user:password@host:9200/``).
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
        elif arg.startswith("-p") and not arg.startswith("--") and len(arg) > 2:
            arg = f"-p{REDACTED}"  # "-psecret"
        elif arg.startswith("--") and len(arg) > 3 and "--password".startswith(arg):
            redact_next = True  # "--pass secret"
        else:
            arg = redact_url(arg)

        redacted.append(arg)

    return redacted


def redact_secrets(value: Any, is_secret: bool = False) -> Any:
    """
    Redact secrets in configuration values (e.g. an export of the configuration):
    the values of keys in :data:`SECRET_KEYS` (at any depth, e.g. in device
    options) and passwords in URLs. The structure of the values is kept, e.g.
    ``creds: [[user, password]]`` becomes ``creds: [[user, <redacted>]]``.

    Returns:
        A redacted copy of the value (the value isn't modified)
    """
    if isinstance(value, dict):
        return {
            key: redact_secrets(val, is_secret or str(key).lower() in SECRET_KEYS)
            for key, val in value.items()
        }

    if isinstance(value, list | tuple | set):
        items = []
        for item in value:
            if (
                is_secret
                and isinstance(item, list | tuple)
                and len(item) == 2
                and all(isinstance(v, str) for v in item)
            ):
                # A (username, password) pair, e.g. "creds: [[user, pass], ...]"
                pair = [item[0], REDACTED]
                items.append(pair if isinstance(item, list) else tuple(pair))
            else:
                items.append(redact_secrets(item, is_secret))
        return items if not isinstance(value, tuple) else tuple(items)

    if isinstance(value, str):
        if is_secret:
            return REDACTED if value else value
        return redact_url(value)

    if is_secret and isinstance(value, int | float | bytes) and not isinstance(value, bool):
        return REDACTED

    return value


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
