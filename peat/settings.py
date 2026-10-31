from __future__ import annotations

import re
import typing
from collections import ChainMap, defaultdict
from copy import deepcopy
from ipaddress import IPv4Interface, IPv4Network
from pathlib import Path
from typing import Any

import yaml

from .consts import RUN_ID, START_TIME, AllowedCommTypes, EntrypointType
from .settings_manager import _LAYERS, SettingsManager, yaml_error_summary

if typing.TYPE_CHECKING:
    try:
        import peat
    except Exception:
        pass


# NOTE: these are module-level constants instead of class attributes on
# Configuration, since any annotated class attribute becomes a config option.

#: PEAT commands that have a section in the configuration file,
#: mapped to the name of the option holding that section.
COMMAND_SECTIONS: dict[str, str] = {
    "scan": "SCAN",
    "pull": "PULL",
    "push": "PUSH",
    "parse": "PARSE",
}

#: Short names that can be used in a command section, mapped to the full option
#: name. These match the names of the command line arguments, e.g. ``--skip-scan``.
SECTION_KEY_ALIASES: dict[str, dict[str, str]] = {
    "scan": {"SWEEP": "SCAN_SWEEP"},
    "pull": {"SKIP_SCAN": "PULL_SKIP_SCAN"},
    "push": {"SKIP_SCAN": "PUSH_SKIP_SCAN"},
}

#: Options that are not allowed in a command section
SECTION_DISALLOWED_KEYS: frozenset[str] = frozenset({"METADATA", *COMMAND_SECTIONS.values()})

#: Type of the normalized ``excluded_modules`` value. Values are :obj:`True` (exclude
#: for all targets), :obj:`False` (no-op), or a list of target strings.
ExcludedModulesType = dict[str, bool | list[str]]

#: Whitespace around commas and equals signs in the string form of ``excluded_modules``,
#: e.g. ``"SEL=192.0.2.5, 192.0.2.6"`` or ``"SEL = 192.0.2.5"``
_TOKEN_SEPARATOR_RE = re.compile(r"\s*([,=])\s*")

_TRUE_STRINGS = ("true", "yes", "on")
_FALSE_STRINGS = ("false", "no", "off")


def normalize_excluded_modules(value: Any) -> ExcludedModulesType:
    """
    Normalize any of the accepted forms of ``excluded_modules`` into a mapping.

    Accepted forms:

    - Mapping of module name or alias to :obj:`True`, :obj:`None` (same as
      :obj:`True`), :obj:`False` (no-op), a list of targets, or a
      comma-separated string of targets, e.g.
      ``{"ControlLogix": True, "SEL": ["192.0.2.5", "192.0.2.6"]}``
    - List of tokens, e.g. ``["ControlLogix", "SEL=192.0.2.5,192.0.2.6"]``.
      Each token is either ``NAME`` (or ``NAME1,NAME2``), meaning exclude for
      all targets, or ``NAME=TARGET[,TARGET...]``, meaning exclude for those
      targets. This is the form used by the ``-x`` command line argument.
    - A string with whitespace-separated tokens (environment variables), e.g.
      ``"ControlLogix SEL=192.0.2.5,192.0.2.6"``. Whitespace around commas and
      equals signs is ignored, so ``"SEL=192.0.2.5, 192.0.2.6"`` is the same
      as ``"SEL=192.0.2.5,192.0.2.6"``.
    - A string with a JSON or YAML mapping or list, e.g.
      ``'{"ControlLogix": true, "SEL": ["192.0.2.5"]}'``

    Module names are not validated here, since modules may be imported later.

    .. code-block:: python

       >>> from peat.settings import normalize_excluded_modules
       >>> normalize_excluded_modules("ControlLogix SEL=192.0.2.5,192.0.2.6")
       {'ControlLogix': True, 'SEL': ['192.0.2.5', '192.0.2.6']}
       >>> normalize_excluded_modules("SEL = 192.0.2.5, 192.0.2.6")
       {'SEL': ['192.0.2.5', '192.0.2.6']}
       >>> normalize_excluded_modules({"m340": None, "sel": "192.0.2.5"})
       {'m340': True, 'sel': ['192.0.2.5']}

    Args:
        value: The value to normalize

    Returns:
        Mapping of module names or aliases to :obj:`True`, :obj:`False`,
        or a list of target strings

    Raises:
        ValueError: If the value isn't in one of the accepted forms
    """
    if value is None:
        return {}

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}

        if text[0] in "[{":
            try:
                parsed = yaml.safe_load(text)
            except yaml.YAMLError as ex:
                raise ValueError(
                    f"invalid JSON or YAML for excluded_modules: {yaml_error_summary(ex)}"
                ) from None
            if not isinstance(parsed, (dict, list)):
                raise ValueError("excluded_modules must be a mapping or a list")
            return normalize_excluded_modules(parsed)

        # Whitespace-separated tokens. Whitespace next to "," and "=" doesn't
        # separate tokens, otherwise "SEL=192.0.2.5, 192.0.2.6" would result in
        # a module named "192.0.2.6" instead of a second target for SEL.
        value = _TOKEN_SEPARATOR_RE.sub(r"\1", text).split()

    out: ExcludedModulesType = {}

    if isinstance(value, (list, tuple, set)):
        for item in value:
            if not isinstance(item, str):
                raise ValueError(f"invalid excluded_modules entry {item!r}, expected a string")

            if "=" in item:
                name, _, raw_targets = item.partition("=")
                targets = _split_targets(raw_targets)
                if not name.strip() or not targets:
                    raise ValueError(
                        f"invalid excluded_modules entry {item!r}, "
                        f"expected NAME=TARGET[,TARGET...]"
                    )
                _add_rule(out, name.strip(), targets)
            else:
                for name in item.split(","):
                    if name.strip():
                        _add_rule(out, name.strip(), True)

        return out

    if isinstance(value, dict):
        for key, rule in value.items():
            name = str(key).strip()
            if not name:
                raise ValueError("excluded_modules has an empty module name")

            if rule is None or rule is True:
                _add_rule(out, name, True)
            elif rule is False:
                _add_rule(out, name, False)
            elif isinstance(rule, str):
                if rule.strip().lower() in _TRUE_STRINGS:
                    _add_rule(out, name, True)
                elif rule.strip().lower() in _FALSE_STRINGS:
                    _add_rule(out, name, False)
                else:
                    _add_rule(out, name, _split_targets(rule))
            elif isinstance(rule, (list, tuple, set)):
                targets = []
                for target in rule:
                    if not isinstance(target, (str, int, float)) or isinstance(target, bool):
                        raise ValueError(
                            f"invalid target {target!r} for excluded module '{name}', "
                            f"expected a string"
                        )
                    if str(target).strip():
                        targets.append(str(target).strip())
                _add_rule(out, name, targets)
            else:
                raise ValueError(
                    f"invalid value {rule!r} for excluded module '{name}', "
                    f"expected true, false, or a list of targets"
                )

        return out

    raise ValueError(
        f"excluded_modules must be a mapping, list, or string, not a {type(value).__name__}"
    )


def _split_targets(raw: str) -> list[str]:
    return [t.strip() for t in raw.split(",") if t.strip()]


def _add_rule(out: ExcludedModulesType, name: str, rule: bool | list[str]) -> None:
    """
    Add an exclusion rule to a normalized mapping, combining it with any existing rule.

    Names are matched without regard to case (the first spelling seen is kept).
    :obj:`True` always wins, lists of targets are combined, and :obj:`False`
    never removes anything.
    """
    key = next((k for k in out if k.casefold() == name.casefold()), name)
    current = out.get(key, False)

    if current is True or rule is True:
        out[key] = True
    elif isinstance(rule, list):
        base = list(current) if isinstance(current, list) else []
        out[key] = base + [t for t in rule if t not in base]
    else:  # rule is False
        out.setdefault(key, False)


def merge_excluded_modules(*rule_sets: ExcludedModulesType | None) -> ExcludedModulesType:
    """
    Combine normalized ``excluded_modules`` mappings (the union of all of them).

    Args:
        rule_sets: Normalized mappings, as returned by
            :func:`~peat.settings.normalize_excluded_modules`

    Returns:
        A new mapping with all of the rules
    """
    out: ExcludedModulesType = {}

    for rules in rule_sets:
        for name, rule in (rules or {}).items():
            _add_rule(out, name, list(rule) if isinstance(rule, list) else rule)

    return out


def merged_excluded_modules(cfg: SettingsManager) -> ExcludedModulesType:
    """
    Combine ``EXCLUDED_MODULES`` from every configuration layer.

    Exclusions from all sources (defaults, config file, command section,
    environment variables, and command line arguments or runtime changes)
    are combined. A source with a higher precedence can add exclusions,
    but never remove them.

    Args:
        cfg: Configuration to get the values from (usually :data:`~peat.settings.config`)

    Returns:
        The combined exclusion rules

    Raises:
        ValueError: If a value is invalid. Values loaded from files, environment
            variables, or command line arguments are already validated, but values
            set at runtime (e.g. ``config.EXCLUDED_MODULES = ...``) aren't.
    """
    return merge_excluded_modules(
        *(
            normalize_excluded_modules(cfg[layer].get("EXCLUDED_MODULES"))
            for layer in reversed(_LAYERS)
        )
    )


def exclusions_to_tokens(rules: ExcludedModulesType) -> list[str]:
    """
    Convert normalized ``excluded_modules`` rules to a list of strings.

    The strings use the same format as the ``-x`` command line argument,
    e.g. ``["ControlLogix", "SEL=192.0.2.5,192.0.2.6"]``. :obj:`False`
    (no-op) rules are omitted.

    .. code-block:: python

       >>> from peat.settings import exclusions_to_tokens
       >>> exclusions_to_tokens({"ControlLogix": True, "SEL": ["192.0.2.5"], "M340": False})
       ['ControlLogix', 'SEL=192.0.2.5']
    """
    tokens = []

    for name, rule in rules.items():
        if rule is True:
            tokens.append(name)
        elif isinstance(rule, list) and rule:
            tokens.append(f"{name}={','.join(rule)}")

    return tokens


def _deep_merge(base: dict, override: dict) -> dict:
    """
    Merge ``override`` onto a copy of ``base`` (values in ``override`` win).

    Mappings are merged recursively, all other values replace the value in ``base``.
    """
    out = deepcopy(base)

    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = deepcopy(value)

    return out


class Configuration(SettingsManager):
    """
    Global configuration settings used throughout PEAT.
    """

    METADATA: dict = {
        "name": "",
        "description": "",
        "author": "",
        "created": "",
        "updated": "",
    }
    """
    Metadata for the PEAT YAML configuration file.
    """

    ADDITIONAL_MODULES: list[str | Path] = []
    """
    File paths to external/third-party PEAT device modules to import.

    These can be the path to a ``.py`` file with a :class:`~peat.device.DeviceModule`
    subclass or a path to a folder with an ``__init__.py`` file and any number
    of ``.py`` files containing :class:`~peat.device.DeviceModule` subclasses
    to import.
    """

    DEBUG: int = 0
    """
    DEBUG level (higher = more output, 0 = disabled).
    """

    VERBOSE: bool = False
    """
    Include DEBUG messages in the :term:`CLI` terminal output.
    """

    QUIET: bool = False
    """
    Don't write log messages to the :term:`CLI` terminal.
    """

    PRINT_RESULTS: bool = False
    """
    Print JSON-formatted results from the operation to
    the terminal (stdout). Note that log messages will still
    be printed unless '--quiet' is specified.
    """

    NO_COLOR: bool = False
    """
    Don't color log messages in the :term:`CLI` terminal.
    """

    NO_LOGO: bool = False
    """
    Don't print the PEAT logo at startup in the :term:`CLI` terminal.
    """

    DRY_RUN: bool = False
    """
    "Dry run" when running on the CLI, do everything except running commands or
    connecting to servers. Actions won't be executed, but logs and state will
    still be written to files and saved to Elasticsearch (if enabled).
    This includes loading and verifying configuration and importing modules

    Useful for verifying a YAML config file or other settings are correct,
    or that a third-party PEAT module is imported correctly.
    """

    ASSUME_ONLINE: bool = False
    """
    Skip the host online check before scan/pull/push.
    """

    MAX_THREADS: int = 260
    """
    Maximum number of threads for any concurrent operations (scanning, etc.).
    """

    OVERRIDE_MAX_FILE_DISCOVERY_THREADS: int = 0
    """
    Overrides the default max thread count of the file discovery phase of ``peat parse`` when
    pointed at a directory. Invalid values (<1) equate to unset (as in use the default). The
    default is defined by :class:`concurrent.futures.ThreadPoolExecutor` (and varies between
    Python versions).

    .. note::
        This is bound (upper limit) by :attr:`~peat.settings.Configuration.MAX_THREADS`. An invalid
        (<1) value will cause this value to stay as default; regardless of what is set.
    """

    DEFAULT_TIMEOUT: float = 5.0
    """
    Default timeout for sockets and potentially other things.
    """

    RESOLVE_IP: bool = True
    """
    If PEAT should attempt to resolve device :term:`IP`
    address from a hostname or :term:`MAC` address.
    """

    RESOLVE_MAC: bool = True
    """
    If PEAT should attempt to resolve device :term:`MAC`
    address from it's :term:`IP` address.
    """

    RESOLVE_HOSTNAME: bool = True
    """
    If PEAT should attempt to resolve device hostname
    from it's :term:`IP` address.
    """

    FORCE_ONLINE_METHOD_PING: bool = False
    """
    Force :term:`ARP` and :term:`ICMP` requests to be used to check if a host
    is online, even if the system running PEAT isn't able to use them.
    """

    FORCE_ONLINE_METHOD_TCP: bool = False
    """
    Force :term:`TCP` SYNs to be used to check if a host is online, even if
    the system running PEAT is able to use :term:`ARP` or :term:`ICMP` to
    perform the checks.
    """

    ICMP_FALLBACK_TCP_SYN: bool = True
    """
    In the case of a :term:`ICMP` failure, fallback to attempting a
    :term:`TCP` SYN RST to check if the host is online. If false,
    then :term:`ICMP` failures will result in the host being marked
    as down, even if they're blocked by a firewall or gateway.
    """

    SYN_PORT: int = 80
    """
    Default port used for basic :term:`TCP` SYN online checks.
    The default :term:`HTTP` (web) port 80 is generally safe to check.
    """

    PUSH_SKIP_SCAN: bool = False
    """
    Skip scanning and verification of hosts being pushed to and assume
    all hosts are online and valid devices.

    .. note::
       This requires a single device type to be specified
       (the ``-d`` argument on the :term:`CLI`)
    """

    PULL_SKIP_SCAN: bool = False
    """
    Skip scanning and verification of hosts before pulling and assume
    all hosts are online and valid devices.

    .. note::
       This requires either a single device type (the ``-d`` argument on
       the :term:`CLI`) or per-host ``peat_module`` mappings defined in
       the ``hosts`` list of a YAML config file.
    """

    SCAN_SWEEP: bool = False
    """
    Simple host up/down check (equivalent to ``nmap -Pn <hosts>``).

    If serial ports are targeted, this will enumerate the active
    serial ports on the host.
    """

    INTENSIVE_SCAN: bool = False
    """
    Force identification checks of all ports during scanning.
    """

    DEVICE_TYPES: list[str] = []
    """
    PEAT modules to use, as module names or aliases (the same values as the
    ``-d`` command line argument), e.g. ``["sel", "ControlLogix"]``.

    If empty, ``scan``, ``pull``, and ``parse`` use all modules (``"all"``),
    and ``push`` requires a device type to be set (with ``-d``, this option,
    or the ``PEAT_DEVICE_TYPES`` environment variable). The ``-d`` argument
    overrides this option. This option is ignored when a host file
    (``-f``) is used, since the modules come from the host file.

    The Python API functions (e.g. :func:`peat.api.scan_api.scan`) also use
    this option when they're called without device types (``None``).

    Environment variable example: ``PEAT_DEVICE_TYPES="sel,controllogix"``
    (or a JSON list, e.g. ``'["sel", "controllogix"]'``).

    See :ref:`config-device-types`.
    """

    EXCLUDED_MODULES: dict[str, bool | list[str]] = {}
    """
    PEAT modules to never use, either for all targets or only for specific targets.

    Keys are module names or aliases (case-insensitive). Values are ``true``
    (exclude the module for all targets) or a list of targets to exclude the
    module for (IP addresses, subnets, IP ranges, hostnames, labels of
    hosts in ``hosts``, MAC addresses, serial ports, or host files). Example:
    ``{"ControlLogix": true, "SEL": ["192.0.2.5", "192.0.2.6"]}``.

    Exclusions from all sources (config file, command section, environment
    variable, and the ``-x`` command line argument) are combined. A source
    with a higher precedence can add exclusions, but can't remove them.
    PEAT refuses to run if a name doesn't match any module or alias, or if
    a target can't be used, so that a broken exclusion is never ignored.

    Environment variable examples: ``PEAT_EXCLUDED_MODULES="ControlLogix SEL=192.0.2.5"``
    or ``PEAT_EXCLUDED_MODULES='{"ControlLogix": true, "SEL": ["192.0.2.5"]}'``.

    See :ref:`config-excluded-modules`.
    """

    TARGETS: list[str] = []
    """
    Network (IP) targets for ``scan`` and ``pull``, used when no targets are given on
    the command line (``-i``, ``-s``, ``-f``, or ``-b``). These use the same format as
    ``-i``: IP addresses, subnets, IP ranges, hostnames, labels of hosts in ``hosts``,
    ``all`` (every host in ``hosts``), and host files.

    ``push`` always requires targets on the command line. This option is only
    used by the command line interface, the Python API functions always take
    the targets as an argument.

    Environment variable example: ``PEAT_TARGETS="192.0.2.0/24,192.0.2.50"``.

    See :ref:`config-targets`.
    """

    HASH_ALGORITHMS: list[str] = ["md5", "sha1", "sha256", "sha512"]
    """
    Hash algorithms to use wherever hashes are calculated.
    Available algorithms are any provided by :mod:`hashlib`.
    """

    OUT_DIR: Path = Path.cwd() / "peat_results"
    """
    Default directory for all file output.

    :meta hide-value:
    """

    RUN_DIR: Path = OUT_DIR / f"default-run-dir_{START_TIME}_{RUN_ID}"
    """
    Output directory for all files associated with a single run of PEAT.

    Name format: ``<command>_<config-name>_<timestamp>_<run-id>``

    - ``<command>`` : PEAT command, e.g. "scan", "pull", "parse", etc.
    - ``<config-name>`` : name of YAML config file, set in ``metadata: name: "name"``.
        If no config name is specified, then the string ``default-config`` is used.
    - ``<timestamp>`` : start time of the PEAT run, e.g. ``2022-06-15_13-08-59``.
        This value is retrieved from ``consts.START_TIME``.
    - ``<run-id>`` : Run ID, aka ``agent.id``, e.g. ``165532013980``.
        This value is retrieved from ``consts.RUN_ID``.

    Examples:

    - ``pull_sceptre-test-config_2022-06-17_165532013980``
    - ``scan_default-config_2022-09-27_165532013980``

    :meta hide-value:
    """

    DEVICE_DIR: Path = RUN_DIR / "devices"
    """
    Output directory for files generated by PEAT device modules,
    e.g. pulled config files, firmware images, etc.
    This is the most relevant directory for the majority of PEAT users.

    .. note::
       Device file output can be disabled entirely by setting this to
       a empty string (``""``) or :obj:`None`. This can be useful for
       low-footprint use cases.

    :meta hide-value:
    """

    ELASTIC_DIR: Path = RUN_DIR / "elastic_data"
    """
    Directory where raw documents pushed to Elasticsearch are saved in JSON format.
    These can be used to rebuild the Elasticsearch indices if needed.

    .. note::
       Elastic doc saving can be disabled entirely by setting this to
       a empty string (``""``) or :obj:`None`.

    :meta hide-value:
    """

    LOG_DIR: Path = RUN_DIR / "logs"
    """
    Directory for PEAT's log files.
    Setting this to an empty string will disable output of these files.

    :term:`JSON` formatted log files are also saved here.
    These can be used to rebuild the ``peat-logs`` Elasticsearch index.

    Files that may be created in this directory include:

    - enip/* (Rockwell-specific)
    - peat.log
    - json-log.jsonl
    - elasticsearch.log
    - telnet.log

    :meta hide-value:
    """

    META_DIR: Path = RUN_DIR / "peat_metadata"
    """
    Directory for PEAT's run metadata, notably dumps of PEAT's
    configuration and internal state.

    Setting this to an empty string will disable output of these files.

    .. note::
       Log files are stored separately, in ``logs/``

    Files that may be created in this directory include:

    - peat_configuration.yaml
    - peat_configuration.json
    - peat_state.json
    - Copy of the config file used for the run,
        if applicable (e.g. ``-c my-config.yaml``)

    :meta hide-value:
    """

    SUMMARIES_DIR: Path = RUN_DIR / "summaries"
    """
    Directory for summary results for PEAT commands.

    Files that may be created in this directory include:

    - scan-summary.json
    - pull-summary.json
    - parse-summary.json

    :meta hide-value:
    """

    TEMP_DIR: Path = RUN_DIR / "temp"
    """
    Working directory for file artifacts.
    May be deleted when PEAT exits.

    :meta hide-value:
    """

    ZEEK_LOGDIR: Path = RUN_DIR / "zeek_logs"
    """
    Directory where Zeek logs will be saved. Also contains Zeek artifacts.
    """

    ELASTIC_SERVER: str | None = None
    """
    URL of the Elasticsearch server.
    """

    ELASTIC_SAVE_LOGS: bool = True
    """
    If PEAT logs should be sent to Elasticsearch.
    """

    ELASTIC_SAVE_CONFIG: bool = True
    """
    If PEAT Configuration dumps should be sent to Elasticsearch on exit.
    """

    ELASTIC_SAVE_STATE: bool = True
    """
    If PEAT State dumps should be sent to Elasticsearch on exit.
    """

    ELASTIC_SAVE_BLOBS: bool = False
    """
    If large binary blobs should be stored in Elasticsearch
    (e.g. firmware images).
    """

    ELASTIC_TIMEOUT: float = 10.0
    """
    Timeout to connect to the Elasticsearch server.
    """

    ELASTIC_DISABLE_DATED_INDICES: bool = False
    """
    Append the current date to Elasticsearch index names.

    Example: when false, a push to ``peat-configs`` on Feb 25 2021
    will actually push to an index named ``peat-configs-2021.02.25``.
    When this option disabled (set to True), the push will instead
    go to ``peat-configs`` (as above, without the date).
    """

    ELASTIC_ADDITIONAL_TAGS: list[str] = []
    """
    Additional tag strings to add to the ``tags`` field for
    each document pushed to Elasticsearch.
    """

    ELASTIC_LOG_INDEX: str = "peat-logs"
    """
    Base name of Elasticsearch index to use PEAT logging events.
    """

    ELASTIC_SCAN_INDEX: str = "peat-scan-summaries"
    """
    Base name of Elasticsearch index to use for scan result summaries,
    e.g. what normally gets written in ``peat_results/<run-dir>/summaries/``.
    """

    ELASTIC_PULL_INDEX: str = "peat-pull-summaries"
    """
    Base name of Elasticsearch index to use for pull result summaries,
    e.g. what normally gets written in ``peat_results/<run-dir>/summaries/``.
    """

    ELASTIC_PARSE_INDEX: str = "peat-parse-summaries"
    """
    Base name of Elasticsearch index to use for parse result summaries,
    e.g. what normally gets written in ``peat_results/<run-dir>/summaries/``.
    """

    ELASTIC_CONFIG_INDEX: str = "peat-configs"
    """
    Base name of Elasticsearch index to use for PEAT configuration dumps
    from runs of PEAT, e.g. what normally gets written in
    ``peat_results/<run-dir>/metadata/``.
    """

    ELASTIC_STATE_INDEX: str = "peat-state"
    """
    Base name of Elasticsearch index to use for PEAT state dumps
    from runs of PEAT, e.g. what normally gets written in
    ``peat_results/<run-dir>/metadata/``.
    """

    ELASTIC_HOSTS_INDEX: str = "ot-device-hosts-timeseries"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.DeviceData`
    data in 'timeseries' form (new entries are created for every collection
    performed or data parsed).

    Information collected by PEAT from field devices or parsed files.
    A new Elasticsearch document is created for every pull of datafrom a device
    (the data is 'timeseries', with differences visible between pulls over time).
    """

    ELASTIC_FILES_INDEX: str = "ot-device-files"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.File` data.

    Information about files present on the device, or that were present on the
    device at one point in time.
    """

    ELASTIC_REGISTERS_INDEX: str = "ot-device-registers"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Register` data.

    Information about individual communication 'registers' (e.g. Modbus
    registers/coils, DNP3 data points, BACNet objects, etc.) that are
    configured on devices, as extracted from device configuration
    information.
    """

    ELASTIC_TAGS_INDEX: str = "ot-device-tags"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Tag` data.

    Information about tag variables that are configured on devices,
    as extracted from device configuration information.
    """

    ELASTIC_IO_INDEX: str = "ot-device-io"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.IO` data.

    Information about I/O (Input/Output) available and/or configured
    on a device, as extracted from device configuration information.
    """

    ELASTIC_EVENTS_INDEX: str = "ot-device-events"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Event`
    data from devices.

    Logging and other event history as extracted from devices.
    Examples include access logs, system logs, or protection history
    """

    ELASTIC_MEMORY_INDEX: str = "ot-device-memory"
    """
    Base name of Elasticsearch index to use for :class:`~peat.data.models.Memory`
    data from devices.

    Memory reads from devices, including address in memory, the value read,
    and information about where it came from and when the read occurred.
    """

    ELASTIC_UEFI_FILES_INDEX: str = "uefi-files"
    """
    Base name of elasticsearch index to use for :class:`peat.data.models.UEFIFiles`

    Information is parsed from a file
    """

    ELASTIC_UEFI_HASHES_INDEX: str = "uefi-hashes"
    """
    Base name of elasticsearch index to use for :class:`peat.data.models.UEFIHash`
    """
    HEAT_ELASTIC_SERVER: str | None = None
    """
    Elasticsearch server to pull :term:`HEAT` data from.
    """

    HEAT_INDEX_NAMES: str = "packets-*"
    """
    Names and/or patterns of Elasticsearch indices with Packetbeat
    data for :term:`HEAT`.
    """

    HEAT_DATE_RANGE: str | None = None
    """
    Date range to filter :term:`HEAT` extraction to.
    """

    HEAT_EXCLUDE_IPS: list[str] = []
    """
    IP addresses to exclude from packetbeat search
    (source and/or destination IP).
    """

    HEAT_ONLY_IPS: list[str] = []
    """
    IP address to limit packetbeat search to
    (source or destination IP).
    """

    HEAT_FILE_ONLY: bool = False
    """
    Extract the file(s) but don't parse them using PEAT.
    """

    HEAT_ARTIFACTS_DIR: Path = RUN_DIR / "heat_artifacts"
    """
    Directory where :term:`HEAT` artifacts should be saved.

    :meta hide-value:
    """

    PILLAGE: dict = {}
    """
    Configuration for ``peat pillage`` (:ref:`pillage`).
    """

    DEVICE_OPTIONS: dict = {}
    """
    Protocol and module configuration options that apply to all hosts.
    """

    HOSTS: list[dict] = []
    """
    Specify or override options for specific hosts.
    """

    SCAN: dict = {}
    """
    Settings that only apply to ``peat scan``. Any other option can be set here,
    as well as ``sweep`` (short for ``scan_sweep``).

    Command sections are applied by the command line interface. When using PEAT
    as a Python package, use ``initialize_peat({"func": "scan", ...})`` or
    :meth:`~peat.settings.Configuration.apply_command_section`.

    See :ref:`config-command-sections`.
    """

    PULL: dict = {}
    """
    Settings that only apply to ``peat pull``. Any other option can be set here,
    as well as ``skip_scan`` (short for ``pull_skip_scan``).

    See :ref:`config-command-sections`.
    """

    PUSH: dict = {}
    """
    Settings that only apply to ``peat push``. Any other option can be set here,
    as well as ``skip_scan`` (short for ``push_skip_scan``).

    See :ref:`config-command-sections`.
    """

    PARSE: dict = {}
    """
    Settings that only apply to ``peat parse``. Any other option can be set here.

    See :ref:`config-command-sections`.
    """

    PCAPS: Path | None = None
    """
    Specify folder that contains PCAPS for processing by HEAT.

    :meta hide-value:
    """

    HEAT_PROTOCOLS: list = []
    """
    Specify protocols for HEAT to use.
    """

    NO_RUN_ZEEK: bool = False
    """
    Don't have PEAT run Zeek on a PCAP, instead run it
    on a PCAP file, then process the output of the PCAP.

    NOTE: zeek_dir must be specified if no_run_zeek is true.
    """

    ZEEK_DIR: Path | None = None
    """
    Directory with existing Zeek output to use as input.

    This is an alternative to PEAT running Zeek on the PCAPs itself.

    NOTE: This argument is required if no_run_zeek is true.

    :meta hide-value:
    """

    FORMATTED_OUTPUT: bool = False
    """
    If JSON data should be formatted with 4 space indentation.
    """

    def typecast(self, key: str, value: Any) -> Any:
        """
        Same as :meth:`~peat.settings_manager.SettingsManager.typecast`, with
        special handling of ``EXCLUDED_MODULES``
        (see :func:`~peat.settings.normalize_excluded_modules`).
        """
        if key == "EXCLUDED_MODULES":
            return normalize_excluded_modules(value)

        return super().typecast(key, value)

    def apply_command_section(self, command: str | None) -> tuple[dict[str, Any], list[str]]:
        """
        Apply the configuration section for a command (e.g. ``pull:``).

        The values from the section are put in the ``section_configs`` layer,
        which has a higher precedence than values at the top level of the config
        file, and a lower precedence than environment variables and command line
        arguments. Only the section for ``command`` is applied, and any values
        from a section applied previously are removed.

        Mappings (e.g. ``device_options``) are merged with the value from the
        config file (or the default value), and the value in the section wins if
        both have the same key. All other values (including lists) replace the
        value from the config file.

        .. note::
           Nothing is logged here, since this is called before logging is
           configured. The caller should log the warnings that are returned.

        Args:
            command: Name of the command, e.g. ``"scan"`` or ``"pull"``.
                If :obj:`None` or a command without a section, then
                no values are applied.

        Returns:
            Tuple with the values that were applied, keyed by option name,
            and a list of warning messages about values in the section that
            were ignored. Values in the section that are overridden by
            environment variables or runtime changes (e.g. command line
            arguments) aren't in the applied values, but they remain in
            ``self["section_configs"]``.
        """
        self["section_configs"].clear()
        self["section_command"] = command or ""
        for err_key in [k for k in self["load_errors"] if k[0] == "section_configs"]:
            del self["load_errors"][err_key]

        section_key = COMMAND_SECTIONS.get(command or "")
        if not section_key:
            return {}, []

        section = self["CONFIG"].get(section_key)
        if not section:
            return {}, []

        name = section_key.lower()
        if not isinstance(section, dict):
            return {}, [f"The '{name}' section of the config must be a mapping, ignoring it"]

        aliases = SECTION_KEY_ALIASES.get(command, {})
        below = ChainMap(self["file_configs"], self["default_configs"])
        resolved: dict[str, Any] = {}
        warnings: list[str] = []

        for raw_key, value in section.items():
            key = str(raw_key).strip().upper()
            key = aliases.get(key, key)

            if key in SECTION_DISALLOWED_KEYS:
                warnings.append(
                    f"'{raw_key}' isn't allowed in the '{name}' section of the config, ignoring it"
                )
                continue

            if key not in self["default_configs"]:
                warnings.append(
                    f"Unknown option '{raw_key}' in the '{name}' section of the config, "
                    f"ignoring it"
                )
                continue

            if key in resolved:
                warnings.append(
                    f"Option '{key.lower()}' is set more than once in the '{name}' "
                    f"section of the config, using the last value ('{raw_key}')"
                )

            if value is None:
                continue

            if (
                isinstance(value, dict)
                and isinstance(below.get(key), dict)
                and key != "EXCLUDED_MODULES"  # Exclusions are always combined
            ):
                value = _deep_merge(below[key], value)

            resolved[key] = value

        self._load_values(resolved, load_to="section_configs")

        # Values overridden by environment variables or command line arguments aren't
        # applied. Exclusions from every source are combined, so they always apply.
        applied = {
            key: value
            for key, value in self["section_configs"].items()
            if key == "EXCLUDED_MODULES" or self.source_of(key) == "section_configs"
        }

        return applied, warnings


class State(SettingsManager):
    """
    Global persistent state singleton, e.g. caching results of expensive operations.
    """

    arp_table: str = ""
    """
    The host's ARP table. This is updated if a MAC address lookup is made and the ARP
    table is queried by PEAT. The ARP table is not always queried during lookups,
    so this variable may not always be populated. It also won't be populated if
    ``RESOLVE_MAC`` is False.
    """

    comm_type: AllowedCommTypes | None = None
    """
    Communication method being used for an active command (scan, pull, or push).
    This is a bit of a hack to allow leaking a bit of CLI-specific info
    to device modules that need it.

    Allowed values: ``unicast_ip``, ``broadcast_ip``, ``serial``

    :meta hide-value:
    """

    elastic: peat.Elastic | None = None
    """
    Elastic instance used to interact with a Elasticsearch or OpenSearch database.

    :meta hide-value:
    """

    local_interface_names: list[str] = []
    """
    Names of local network interfaces on the current system, e.g. ``eth0``.

    :meta hide-value:
    """

    local_interface_details: dict[str, dict[str, str]] = {}
    """
    Detailed local interface IPv4 and link configuration information.

    :meta hide-value:
    """

    local_interface_ips: list[str] = []
    """
    :term:`IP` addresses of local interfaces.

    :meta hide-value:
    """

    local_interface_macs: list[str] = []
    """
    :term:`MAC` addresses of local interfaces.

    :meta hide-value:
    """

    local_interface_objects: list[IPv4Interface] = []
    """
    :class:`~ipaddress.IPv4Interface` objects of the local interfaces.

    :meta hide-value:
    """

    local_interface_networks: dict[str, list[IPv4Network]] = defaultdict(list)
    """
    Mapping of local interface names to their associated subnets.

    :meta hide-value:
    """

    local_networks: list[IPv4Network] = []
    """
    Networks the local system is connected to.

    :meta hide-value:
    """

    default_interface_name: str = ""
    """
    The name of the default network interface of the local system.

    :meta hide-value:
    """

    default_interface_ip: str = ""
    """
    The :term:`IP` address of the default network interface of the local system.

    :meta hide-value:
    """

    default_interface_mac: str = ""
    """
    The :term:`MAC` address of the default network interface of the local system.

    :meta hide-value:
    """

    default_gateway: str = ""
    """
    The :term:`IP` address of the default gateway of the local system.

    :meta hide-value:
    """

    raw_socket_capable: bool = False
    """
    If RAW sockets are available (e.g. for :term:`ARP` or :term:`ICMP` requests).

    :meta hide-value:
    """

    entrypoint: EntrypointType = "Package"
    """
    How PEAT is being used (PEAT's "entrypoint").

    Allowed values:

    - CLI: PEAT's CLI internals.
    - Server: if being run as a server, e.g. web UI.
    - Package: any other use of PEAT's API.

    :meta hide-value:
    """

    peat_initialized: bool = False
    """
    If PEAT has been initialized, in other words
    :func:`peat.init.initialize_peat` has been called at least once.

    :meta hide-value:
    """

    written_files: set[str] = set()
    """
    Paths of files written by PEAT during the current run.
    Only includes files that were written using PEAT's APIs.

    .. note::
       These are NOT ordered by when they were written! (it's a :class:`set`)

    :meta hide-value:
    """

    superuser_privs: bool | None = None
    """
    Is PEAT running with permissions of ``root`` (POSIX)
    or ``Administrator`` (Windows).

    :meta hide-value:
    """

    error: bool = False
    """
    If any critical errors occurred during the run of PEAT.

    :meta hide-value:
    """


config = Configuration(label="configuration", env_prefix="PEAT_", init_env=True)
state = State(label="state", env_prefix="PEAT_STATE_", init_env=True)


__all__ = [
    "COMMAND_SECTIONS",
    "Configuration",
    "State",
    "config",
    "exclusions_to_tokens",
    "merge_excluded_modules",
    "merged_excluded_modules",
    "normalize_excluded_modules",
    "state",
]
