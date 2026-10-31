"""
Selection of the PEAT modules used by a command.

This covers the device types to use (the ``-d`` command line argument and the
``device_types`` option) and the modules to exclude (the ``-x`` command line
argument and the ``excluded_modules`` option). The scan, pull, push, and parse
APIs use :func:`~peat.module_selection.select_modules` to resolve the modules
to use, and :func:`~peat.module_selection.get_exclusions` to check exclusions
that only apply to specific targets.

Refer to :ref:`config-device-types` and :ref:`config-excluded-modules` for
details on how these are configured.

.. code-block:: python
   :caption: Checking which modules would be used

   >>> from peat import SELRelay
   >>> from peat.module_selection import ModuleExclusions, select_modules
   >>> exclusions = ModuleExclusions({"SELRTAC": True, "SELRelay": ["192.0.2.5"]})
   >>> [m.__name__ for m in select_modules(["sel"], exclusions=exclusions)]
   ['SEL3620', 'SELRelay']
   >>> exclusions.is_excluded(SELRelay, target="192.0.2.5")
   True
   >>> exclusions.is_excluded(SELRelay, target="192.0.2.6")
   False
"""

import json
import re
import threading
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address
from pathlib import Path
from typing import Any

from humanfriendly.text import pluralize

from peat import DeviceData, DeviceModule, config, log, module_api, utils
from peat.consts import PeatError
from peat.protocols.addresses import clean_mac, host_string_to_objs
from peat.settings import ExcludedModulesType, merged_excluded_modules
from peat.settings_manager import LAYER_DESCRIPTIONS

#: Maximum number of targets shown in log messages about exclusions
_MAX_LOGGED_TARGETS = 20

#: Strings that only contain characters used in IPv4 addresses, subnets, and ranges.
#: These are never resolved as hostnames (``socket.gethostbyname("10.1")`` is
#: ``10.0.0.1``, and ``192.0.2.300`` is almost certainly a typo).
_NUMERIC_TARGET_RE = re.compile(r"[\d./\-]+", re.ASCII)

_SERIAL_PORT_RE = re.compile(r"com\d+", re.ASCII | re.IGNORECASE)

#: Identifiers of hosts in the ``hosts`` config that are used for label targets
_LABEL_IDENTIFIERS = ("ip", "mac", "serial_port", "hostname", "name")

#: Traffic that exclusions for specific targets can't stop, with the reason
_UNENFORCED_TRAFFIC = {
    "sweep": ("the sweep (--sweep)", "sweeps don't use PEAT modules"),
    "serial_sweep": ("the serial port sweep (--sweep)", "sweeps don't use PEAT modules"),
    "broadcast": (
        "broadcast probes (-b)",
        "broadcasts reach every device on the network, only the responses are ignored",
    ),
}


@dataclass
class TargetMatcher:
    """
    Targets that an exclusion rule applies to.

    Matching is done on the IP address, MAC address, serial port, hostname,
    and name of a device, as well as the target string being checked.
    Strings (serial ports, hostnames, names) are compared without regard to case.
    """

    ips: set[IPv4Address] = field(default_factory=set)
    networks: set[IPv4Network] = field(default_factory=set)
    macs: set[str] = field(default_factory=set)
    serial_ports: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    entries: list[str] = field(default_factory=list)  # As configured, for log messages

    def merge(self, other: "TargetMatcher") -> None:
        """
        Add the targets from another matcher to this one.
        """
        self.ips.update(other.ips)
        self.networks.update(other.networks)
        self.macs.update(other.macs)
        self.serial_ports.update(other.serial_ports)
        self.names.update(other.names)
        self.entries.extend(e for e in other.entries if e not in self.entries)

    def matches(self, dev: DeviceData | None = None, target: str | None = None) -> bool:
        """
        If a device or target string matches any of the targets.

        Args:
            dev: Device to check
            target: Target string to check, e.g. an IP address or serial port

        Returns:
            If the device or target matches
        """
        if self.ips or self.networks:
            for ip_str in {dev.ip if dev is not None else "", target or ""}:
                if not ip_str or not utils.is_ip(ip_str):
                    continue
                addr = ip_address(ip_str.strip())
                if addr in self.ips or any(addr in net for net in self.networks):
                    return True

        candidates = {target or ""}
        if dev is not None:
            candidates.update((dev.serial_port, dev.hostname, dev.name))
        candidates = {c.strip().casefold() for c in candidates if c and c.strip()}

        if candidates & self.serial_ports or candidates & self.names:
            return True

        return bool(dev is not None and dev.mac and clean_mac(dev.mac) in self.macs)


class ModuleExclusions:
    """
    Exclusion rules from ``excluded_modules``, resolved to PEAT modules and targets.

    Use :func:`~peat.module_selection.get_exclusions` to get an instance
    for the current configuration instead of creating one directly.

    Args:
        rules: Normalized exclusion rules
            (see :func:`~peat.settings.normalize_excluded_modules`)
        host_labels: Identifiers of hosts in the ``hosts`` config, keyed by
            the host's label (casefolded)
        global_only: Only use the rules that exclude modules for every target.
            The targets of the other rules aren't resolved (e.g. no DNS lookups),
            which is used for commands without targets, such as ``parse``.

    Raises:
        PeatError: If a name in the rules doesn't match any PEAT module or alias,
            or if a target in the rules is invalid or can't be resolved. The run
            should not continue in this case, since PEAT can't honor the exclusion.
    """

    def __init__(
        self,
        rules: ExcludedModulesType,
        host_labels: dict[str, dict[str, Any]] | None = None,
        global_only: bool = False,
    ) -> None:
        self.rules = rules
        self.global_only = global_only

        #: Modules excluded for every target
        self.global_mods: set[type[DeviceModule]] = set()

        #: Modules excluded for specific targets
        self.per_target: dict[type[DeviceModule], TargetMatcher] = {}

        #: Names of the rules for specific targets that were ignored (``global_only``)
        self.ignored_target_keys: list[str] = []

        # Rules for specific targets, for log messages: (name, modules, targets)
        self._target_rules: list[tuple[str, list[type[DeviceModule]], list[str]]] = []

        self._lock = threading.Lock()
        self._skips: dict[str, set[str]] = defaultdict(set)  # module name -> targets
        self._summary_logged = False
        self._compile(host_labels or {})

    def __bool__(self) -> bool:
        return bool(self.global_mods or self.per_target)

    def _compile(self, host_labels: dict[str, dict[str, Any]]) -> None:
        # Fail closed: a misspelled module name must not quietly turn into no exclusion
        unknown = [
            key
            for key, rule in self.rules.items()
            if rule is not False and rule and not module_api.lookup_types([key])
        ]
        if unknown:
            raise PeatError(
                f"excluded_modules: {'; '.join(_unknown_key_message(k) for k in unknown)}. "
                f"PEAT won't run without the requested exclusions. Run 'peat scan "
                f"--list-all' to list the available modules and aliases."
            )

        for key, rule in self.rules.items():
            if rule is False or not rule:
                continue

            mods = module_api.lookup_types([key])

            if rule is True:
                self.global_mods.update(mods)
                continue

            if self.global_only:
                self.ignored_target_keys.append(key)
                continue

            matcher = compile_targets(key, rule, host_labels)
            for mod in mods:
                self.per_target.setdefault(mod, TargetMatcher()).merge(matcher)
            self._target_rules.append((key, mods, matcher.entries))

    def is_excluded(
        self,
        module: type[DeviceModule],
        dev: DeviceData | None = None,
        target: str | None = None,
    ) -> bool:
        """
        If a module is excluded, either for every target or for the device or target.

        Args:
            module: The PEAT module to check
            dev: Device the module would be used with, if any
            target: Target string the module would be used with, if any,
                e.g. an IP address or serial port

        Returns:
            If the module is excluded
        """
        if module in self.global_mods:
            return True

        matcher = self.per_target.get(module)
        return bool(matcher and (dev is not None or target) and matcher.matches(dev, target))

    def filter_global(self, modules: Iterable[type[DeviceModule]]) -> list[type[DeviceModule]]:
        """
        Remove the modules that are excluded for every target.
        """
        return [m for m in modules if m not in self.global_mods]

    def filter_for(
        self,
        modules: Iterable[type[DeviceModule]],
        dev: DeviceData | None = None,
        target: str | None = None,
    ) -> tuple[list[type[DeviceModule]], list[type[DeviceModule]]]:
        """
        Split modules into those allowed and those excluded for a device or target.

        The excluded modules are recorded for the summary logged by
        :meth:`~peat.module_selection.ModuleExclusions.log_skip_summary`.

        Returns:
            Tuple with the modules that are allowed and the modules that are excluded
        """
        kept: list[type[DeviceModule]] = []
        removed: list[type[DeviceModule]] = []

        for mod in modules:
            if self.is_excluded(mod, dev, target):
                removed.append(mod)
            else:
                kept.append(mod)

        for mod in removed:
            self.record_skip(mod, dev, target)

        return kept, removed

    def fully_excluded(
        self,
        modules: Iterable[type[DeviceModule]],
        dev: DeviceData | None = None,
        target: str | None = None,
    ) -> bool:
        """
        If there are modules and all of them are excluded for a device or target.
        """
        modules = list(modules)
        return bool(modules) and all(self.is_excluded(m, dev, target) for m in modules)

    def record_skip(
        self,
        module: type[DeviceModule],
        dev: DeviceData | None = None,
        target: str | None = None,
    ) -> None:
        """
        Record that a module was skipped for a target due to a per-target exclusion.
        """
        if module in self.global_mods:
            return  # Global exclusions are logged in the summary

        target_id = target or (dev.get_comm_id() if dev is not None else "") or "unknown"
        with self._lock:
            self._skips[module.__name__].add(target_id)

    def log_summary(self) -> None:
        """
        Log the exclusions that are configured (only once for each instance).
        """
        if self._summary_logged:
            return
        self._summary_logged = True

        if self.global_mods:
            names = sorted(m.__name__ for m in self.global_mods)
            log.info(f"Excluded modules (all targets): {', '.join(names)}")

        for key, mods, entries in self._target_rules:
            mods = [m for m in mods if m not in self.global_mods]
            if not mods:
                continue

            if len(mods) <= 3:
                mod_names = ", ".join(m.__name__ for m in mods)
            else:
                mod_names = pluralize(len(mods), "module")

            log.info(
                f"Excluded '{key}' ({mod_names}) for "
                f"{pluralize(len(entries), 'target')}: {_shorten(entries)}"
            )

    def warn_unenforced(self, kind: str) -> None:
        """
        Log a warning if there are exclusions for specific targets that can't stop traffic.

        Sweeps don't use PEAT modules, and broadcasts reach every device on
        a network, so exclusions for specific targets can't stop them from
        reaching those targets.

        Args:
            kind: The type of traffic: ``"sweep"``, ``"serial_sweep"``, or ``"broadcast"``
        """
        traffic, reason = _UNENFORCED_TRAFFIC[kind]
        entries: list[str] = []
        for _key, mods, rule_entries in self._target_rules:
            if any(m not in self.global_mods for m in mods):
                entries.extend(e for e in rule_entries if e not in entries)

        if entries:
            log.warning(
                f"excluded_modules can't stop {traffic} from reaching targets that "
                f"have modules excluded for them ({reason}): {_shorten(entries)}. To "
                f"send no traffic to a target, leave it out of the targets of sweeps, "
                f"and don't use broadcast scans on its network."
            )

    def log_skip_summary(self) -> None:
        """
        Log which modules were skipped for how many targets, then reset the record.
        """
        with self._lock:
            skips = sorted(self._skips.items())
            self._skips.clear()

        if skips:
            log.info(
                "Modules skipped due to per-target exclusions: "
                + "; ".join(
                    f"{name} for {pluralize(len(targets), 'target')}" for name, targets in skips
                )
            )


def compile_targets(
    key: str,
    entries: Iterable[str],
    host_labels: dict[str, dict[str, Any]] | None = None,
) -> TargetMatcher:
    """
    Resolve the targets of an exclusion rule.

    Targets are interpreted in this order:

    1. Label of a host in ``hosts`` (case-insensitive), which matches
       the host's identifiers (``ip``, ``mac``, ``serial_port``,
       ``hostname``, and ``name``)
    2. MAC address
    3. Serial port (starts with ``/dev/``, or ``COM`` and a number)
    4. Host file (a ``.txt`` or ``.json`` file, same format as for ``-i``)
    5. IP address, subnet (CIDR), IP range (e.g. ``192.0.2.10-20``), or
       hostname (resolved to an IP address using DNS, the same as ``-i``)

    Args:
        key: Module name or alias of the rule, for error messages
        entries: The target strings
        host_labels: Identifiers of hosts in the ``hosts`` config, keyed by
            the host's label (casefolded)

    Returns:
        The resolved targets

    Raises:
        PeatError: If a target is invalid or can't be resolved. The run should
            not continue in this case, since PEAT can't honor the exclusion.
    """
    matcher = TargetMatcher()
    host_labels = host_labels or {}

    for raw_entry in entries:
        entry = str(raw_entry).strip()
        if not entry:
            continue

        try:
            _add_target(matcher, entry, host_labels)
        except PeatError as ex:
            raise PeatError(
                f"Invalid target '{entry}' in excluded_modules for '{key}': {ex}"
            ) from None
        except (ValueError, OSError) as ex:  # Includes DNS lookup and JSON errors
            raise PeatError(
                f"Invalid target '{entry}' in excluded_modules for '{key}': {ex}. Fix or "
                f"remove the target (PEAT won't run without the requested exclusions). "
                f"Targets can be IP addresses, subnets, IP ranges, hostnames, labels of "
                f"hosts in 'hosts', MAC addresses, serial ports, or host files."
            ) from None

        matcher.entries.append(entry)

    return matcher


def _add_target(matcher: TargetMatcher, entry: str, host_labels: dict) -> None:
    if entry.casefold() in ("all", "*"):
        raise PeatError(
            "to exclude a module for every target, use 'true' instead of a list "
            "of targets in the config file, or '-x NAME' on the command line"
        )

    # Label of a host in the YAML config
    if entry.casefold() in host_labels:
        identifiers = host_labels[entry.casefold()]
        found = False

        for id_key in _LABEL_IDENTIFIERS:
            value = str(identifiers.get(id_key) or "").strip()
            if not value:
                continue
            found = True

            if id_key == "ip":
                _add_network_target(matcher, value)
            elif id_key == "mac":
                matcher.macs.add(clean_mac(value))
            elif id_key == "serial_port":
                matcher.serial_ports.add(value.casefold())
            else:  # hostname, name. These are not resolved using DNS.
                matcher.names.add(value.casefold())

        if not found:
            raise PeatError(
                f"the host with label '{entry}' in 'hosts' has no identifiers "
                f"({', '.join(_LABEL_IDENTIFIERS)})"
            )
        return

    if utils.is_mac(entry.replace("-", ":")):
        matcher.macs.add(clean_mac(entry))
    elif entry.startswith("/dev/") or _SERIAL_PORT_RE.fullmatch(entry):
        matcher.serial_ports.add(entry.casefold())
    elif entry.lower().endswith((".txt", ".json")) or Path(entry).is_file():
        for host in _read_host_file(Path(entry)):
            _add_target(matcher, host, host_labels)
    else:
        _add_network_target(matcher, entry)


def _add_network_target(matcher: TargetMatcher, entry: str) -> None:
    if _NUMERIC_TARGET_RE.fullmatch(entry):
        if entry.count(".") != 3:
            raise ValueError("not a valid IPv4 address, subnet, or IP range")
        if "/" not in entry and "-" not in entry:
            ip_address(entry)  # Raises ValueError if invalid

    try:
        objs = host_string_to_objs(entry, strict_network=False)
    except OSError as ex:  # DNS lookup of a hostname failed (socket.gaierror)
        raise ValueError(
            f"couldn't resolve the hostname using DNS ({ex}). Use the IP address "
            f"or the label of a host in 'hosts' instead"
        ) from None

    if isinstance(objs, IPv4Network):
        matcher.networks.add(objs)
    elif isinstance(objs, IPv4Address):
        matcher.ips.add(objs)
    elif isinstance(objs, set):
        if not objs:
            raise ValueError("the IP range is empty")
        matcher.ips.update(o for o in objs if isinstance(o, IPv4Address))
    else:
        raise ValueError(f"unsupported address type '{type(objs).__name__}'")

    # Hostnames also match the device's hostname
    if not _NUMERIC_TARGET_RE.fullmatch(entry):
        matcher.names.add(entry.casefold())


def _read_host_file(path: Path) -> list[str]:
    if not path.is_file():
        raise ValueError(f"the host file '{path}' doesn't exist or isn't a file")

    text = path.read_text(encoding="utf-8")

    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError(f"the JSON host file '{path.name}' must contain a list of hosts")
        hosts = [str(x).strip() for x in data if x is not None and str(x).strip()]
    else:
        hosts = text.split()  # Space, tab, or newline-separated

    if not hosts:
        raise ValueError(f"the host file '{path.name}' doesn't contain any hosts")

    # Prevent recursion: hosts in files can't be other host files
    for host in hosts:
        if host.lower().endswith((".txt", ".json")):
            raise ValueError(f"host files can't reference other host files ('{host}')")

    return hosts


def _looks_like_target(name: str) -> bool:
    """
    If a name in ``excluded_modules`` looks like a target instead of a module name.
    """
    return bool(
        (_NUMERIC_TARGET_RE.fullmatch(name) and name.count(".") == 3)
        or utils.is_mac(name.replace("-", ":"))
        or name.startswith("/dev/")
        or _SERIAL_PORT_RE.fullmatch(name)
        or name.lower().endswith((".txt", ".json"))
    )


def _unknown_key_message(key: str) -> str:
    if _looks_like_target(key):
        return (
            f"'{key}' isn't a PEAT module or alias, it looks like a target. Targets go "
            f"after the module name, e.g. 'SEL=192.0.2.5,192.0.2.6' with '-x' or "
            f"PEAT_EXCLUDED_MODULES, or 'SEL: [192.0.2.5, 192.0.2.6]' in a config file"
        )

    message = f"'{key}' doesn't match any PEAT module or alias (check the spelling)"
    if " " in key:
        message += (
            ". With '-x', use one name or NAME=TARGETS per '-x', e.g. "
            "'-x ControlLogix -x SEL=192.0.2.5'"
        )

    return message


def _shorten(entries: list[str]) -> str:
    shown = ", ".join(entries[:_MAX_LOGGED_TARGETS])
    if len(entries) > _MAX_LOGGED_TARGETS:
        shown += f", ... ({len(entries) - _MAX_LOGGED_TARGETS} more)"
    return shown


def _host_labels() -> dict[str, dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}

    for host in config.HOSTS or []:
        if isinstance(host, dict) and host.get("label"):
            identifiers = host.get("identifiers")
            labels[str(host["label"]).strip().casefold()] = (
                dict(identifiers) if isinstance(identifiers, dict) else {}
            )

    return labels


_CACHE: dict[str, ModuleExclusions] = {}
_CACHE_LOCK = threading.Lock()


def get_exclusions(global_only: bool = False) -> ModuleExclusions:
    """
    Exclusions for the current configuration and imported modules.

    The exclusions from all configuration sources are combined
    (see :func:`~peat.settings.merged_excluded_modules`). The result
    is cached until the configuration or the imported modules change.

    Args:
        global_only: Only use the exclusions for every target, and don't resolve
            the targets of the other exclusions (e.g. no DNS lookups). This is
            for commands that don't have targets, such as ``parse``.

    Returns:
        The resolved exclusions

    Raises:
        PeatError: If ``excluded_modules`` is invalid, if a name in it doesn't match
            any PEAT module or alias, or if a target in it is invalid or can't be resolved
    """
    try:
        rules = merged_excluded_modules(config)
    except ValueError as ex:
        raise PeatError(f"Invalid value for excluded_modules: {ex}") from None

    labels = {}
    if not global_only and any(isinstance(r, list) for r in rules.values()):
        labels = _host_labels()
    modules = sorted((name, id(mod)) for name, mod in module_api.modules.items())
    cache_key = json.dumps([rules, labels, modules, global_only], sort_keys=True, default=str)

    with _CACHE_LOCK:
        if cache_key not in _CACHE:
            exclusions = ModuleExclusions(rules, labels, global_only=global_only)
            _CACHE.clear()
            _CACHE[cache_key] = exclusions

        return _CACHE[cache_key]


def select_modules(
    device_types: Any = None,
    filter_attr: str | None = None,
    exclusions: ModuleExclusions | None = None,
) -> list[type[DeviceModule]]:
    """
    Resolve device types to PEAT modules, without the modules excluded for every target.

    This is the place to add any filters that apply to all of the commands,
    so that scan, pull, push, and parse select modules the same way.

    Args:
        device_types: Module names, aliases, or classes (same as
            :meth:`~peat.module_manager.ModuleManager.lookup_types`).
            If :obj:`None`, the ``device_types`` option is used
            (:attr:`config.DEVICE_TYPES <peat.settings.Configuration.DEVICE_TYPES>`),
            or all imported modules if that option isn't set.
        filter_attr: Only include modules for which this attribute is truthy,
            e.g. ``"ip_methods"``
        exclusions: Exclusions to apply. If :obj:`None`, the exclusions for the
            current configuration are used (:func:`~peat.module_selection.get_exclusions`).

    Returns:
        Sorted list of module classes

    Raises:
        PeatError: If ``excluded_modules`` is invalid (see
            :func:`~peat.module_selection.get_exclusions`)
    """
    if device_types is None and config.DEVICE_TYPES:
        device_types = list(config.DEVICE_TYPES)

    mods = module_api.lookup_types(device_types, filter_attr=filter_attr)

    if exclusions is None:
        exclusions = get_exclusions()

    return exclusions.filter_global(mods)


def configured_device_types(args: dict[str, Any] | None = None) -> tuple[list[str] | None, str]:
    """
    Device types explicitly configured by the user, and where they came from.

    The ``-d`` command line argument (``args["device_types"]``) has precedence,
    followed by the ``device_types`` configuration option (command line or
    runtime change, environment variable, command section of the config file,
    or the config file).

    Args:
        args: Command line arguments, if any

    Returns:
        Tuple with the device types and a human-readable description of their source.
        If device types aren't configured anywhere, ``(None, "")`` is returned and
        the caller should use the default for the command.
    """
    if args and args.get("device_types"):
        return [str(x) for x in args["device_types"]], "command line argument '-d'"

    if config.DEVICE_TYPES:
        return [str(x) for x in config.DEVICE_TYPES], describe_source("DEVICE_TYPES")

    return None, ""


def describe_source(key: str) -> str:
    """
    Human-readable description of where the current value of an option came from.

    Args:
        key: Name of the configuration option, e.g. ``"DEVICE_TYPES"``

    Returns:
        The description, e.g. ``"environment variable PEAT_DEVICE_TYPES"``
    """
    layer = config.source_of(key)

    if layer == "env_configs":
        return f"environment variable {config.env_prefix}{key}"

    if layer == "section_configs" and config.get("section_command"):
        return f"'{config['section_command']}' section of the config file"

    return f"{LAYER_DESCRIPTIONS.get(layer, layer)} ('{key.lower()}')"


def warn_unknown_device_types(names: Iterable[Any], source: str) -> None:
    """
    Log a warning for device types that don't match any PEAT module or alias.
    """
    for name in names:
        if isinstance(name, str) and not module_api.lookup_types([name]):
            log.warning(
                f"Unknown device type '{name}' from {source} (not the name or alias "
                f"of a PEAT module), ignoring it"
            )


def warn_requested_but_excluded(
    names: Iterable[Any],
    exclusions: ModuleExclusions,
    source: str,
) -> None:
    """
    Log a warning for requested device types that only match excluded modules.
    """
    if not exclusions.global_mods:
        return

    for name in names:
        mods = module_api.lookup_types([name]) if isinstance(name, str) else []
        if mods and all(m in exclusions.global_mods for m in mods):
            log.warning(
                f"Device type '{name}' from {source} only matches modules that are "
                f"excluded by excluded_modules "
                f"({', '.join(m.__name__ for m in mods)}), it won't be used"
            )


__all__ = [
    "ModuleExclusions",
    "TargetMatcher",
    "compile_targets",
    "configured_device_types",
    "describe_source",
    "get_exclusions",
    "select_modules",
    "warn_requested_but_excluded",
    "warn_unknown_device_types",
]
