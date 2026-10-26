#!/usr/bin/env python3
"""
Check that PEAT device modules correctly implement the device module API.

This finds mistakes that would break a module or keep PEAT from using it,
and suggests improvements to modules written for older versions of the API.
Each problem found is reported with a severity:

- ``error``: the module is broken, or PEAT will not use part of it
- ``warning``: the module works, but should be fixed or cleaned up
- ``info``: optional suggestions (shown with ``--verbose``)

Usage:

    # Check all modules included with PEAT
    pdm run python scripts/check_module.py

    # Check specific modules, by name or alias
    pdm run python scripts/check_module.py SELRelay sage

    # Check a module that isn't included with PEAT (same as "peat -I")
    pdm run python scripts/check_module.py examples/example_peat_module/awesome_module.py

    # Also parse a real file with the module and check the results
    pdm run python scripts/check_module.py awesome_module.py --parse awesome_output.json

The exit code is 1 if any errors were found (or warnings, with ``--strict``).
"""

import argparse
import difflib
import importlib
import inspect
import json
import pkgutil
import re
import sys
import tempfile
import traceback
from collections import defaultdict
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Final, Literal
from unittest import mock

import peat
from peat import DeviceData, DeviceModule, IPMethod, SerialMethod, config, log, module_api, utils
from peat.api.parse_api import parsable_file_by_pattern, parsable_file_by_signature
from peat.data.default_options import DEFAULT_OPTIONS
from peat.file_signature import FileSignature

Severity = Literal["error", "warning", "info"]

SEVERITIES: Final[tuple[Severity, ...]] = ("error", "warning", "info")

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent

#: Module attributes that are strings
STR_ATTRS: Final[tuple[str, ...]] = ("device_type", "vendor_id", "vendor_name", "brand", "model")

#: Module attributes that are lists, and the type of their items
LIST_ATTRS: Final[dict[str, type]] = {
    "ip_methods": IPMethod,
    "serial_methods": SerialMethod,
    "supported_models": str,
    "filename_patterns": str,
    "file_signatures": FileSignature,
    "module_aliases": str,
}

#: Module attributes that are dicts with string keys
DICT_ATTRS: Final[tuple[str, ...]] = ("annotate_fields", "default_options")

#: Methods that modules implement, and the arguments PEAT calls them with
IMPLEMENTED_METHODS: Final[dict[str, tuple[tuple, dict]]] = {
    "_pull": ((object(),), {}),  # cls._pull(dev)
    "_push": ((object(), object(), object()), {}),  # cls._push(dev, to_push, push_type)
    "_parse": ((), {"file": object(), "dev": object()}),  # cls._parse(file=file, dev=dev)
}

#: Methods of DeviceModule that modules should not override
#: (overriding is fine if the override calls super(), unless noted)
WRAPPER_METHODS: Final[dict[str, str]] = {
    "pull": "implement _pull() instead, or call super().pull()",
    "push": "implement _push() instead, or call super().push()",
    "parse": "implement _parse() instead, or call super().parse()",
    "update_dev": "call super().update_dev(), or set annotate_fields instead",
}

#: Methods of DeviceModule that modules must never override
INTERNAL_METHODS: Final[tuple[str, ...]] = ("method_implemented",)

#: Names from older versions of the API that PEAT no longer calls
LEGACY_NAMES: Final[dict[str, str]] = {
    "pull_project": "_pull()",
    "identify": "ip_methods or serial_methods",
    "_identify": "ip_methods or serial_methods",
    "identify_ip": "ip_methods",
    "identify_serial": "serial_methods",
}

#: Module API attributes, used to find misspelled attributes
API_ATTRS: Final[frozenset[str]] = frozenset(
    {*STR_ATTRS, *LIST_ATTRS, *DICT_ATTRS, "can_parse_dir"}
)


@dataclass
class Finding:
    severity: Severity
    check: str
    message: str


@dataclass
class ModuleReport:
    name: str
    source: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity: Severity, check: str, message: str) -> None:
        self.findings.append(Finding(severity, check, message))

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _source(mod: type) -> str:
    try:
        return _display_path(Path(inspect.getfile(mod)))
    except (TypeError, OSError):
        return mod.__module__


def _norm_name(name: str) -> str:
    return module_api._norm_name(name)


def _norm_alias(alias: str) -> str:
    return module_api._norm_alias(alias)


def _call_error(func: Callable, args: tuple, kwargs: dict) -> str | None:
    """
    Check if a function accepts the arguments PEAT calls it with.

    Returns:
        Why the call would fail, or None if the arguments are accepted
    """
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return None  # Can't inspect it (e.g. a builtin), assume it's fine

    try:
        sig.bind(*args, **kwargs)
    except TypeError as ex:
        return f"signature is {sig} ({ex})"
    return None


def _defined_in(mod: type, name: str) -> type | None:
    """
    The class in the module's inheritance chain that defines an attribute.
    """
    for klass in mod.__mro__:
        if name in klass.__dict__:
            return klass
    return None


def _implemented(mod: type, name: str) -> bool:
    """
    If a module overrides a DeviceModule method.

    Unlike DeviceModule.method_implemented(), this works for any
    attribute value, e.g. ``_pull = None``.
    """
    return _defined_in(mod, name) is not DeviceModule


def _is_function(value: Any) -> bool:
    """
    If DeviceModule.method_implemented() works for a value (it reads ``__code__``).
    """
    return hasattr(value, "__code__")


def _calls_super(klass: type, name: str) -> bool:
    """
    If a method calls ``super()``. Assumes it does if the source isn't available.
    """
    func = inspect.unwrap(getattr(klass.__dict__[name], "__func__", klass.__dict__[name]))
    try:
        source = inspect.getsource(func)
    except (TypeError, OSError):
        return True
    return "super(" in source


def check_class(mod: type, r: ModuleReport) -> bool:
    """
    The module is a class that PEAT will import. Returns False if it isn't.
    """
    if not inspect.isclass(mod) or not issubclass(mod, DeviceModule):
        r.add("error", "class", "Module is not a subclass of peat.DeviceModule")
        return False

    if mod is DeviceModule:
        r.add("error", "class", "DeviceModule is the base class, not a module")
        return False

    if not mod.__doc__ or not mod.__doc__.strip():
        r.add("warning", "class", "Module class has no docstring")

    for name in vars(mod):
        if name.startswith("__"):
            continue
        if name in LEGACY_NAMES:
            r.add(
                "warning",
                "legacy-api",
                f"'{name}' is from an older version of the module API and is never "
                f"called by PEAT. Use {LEGACY_NAMES[name]}.",
            )
        elif name not in API_ATTRS and not name.startswith("_") and len(name) >= 8:
            matches = difflib.get_close_matches(name, API_ATTRS, n=1, cutoff=0.9)
            if matches:
                r.add(
                    "warning",
                    "spelling",
                    f"'{name}' is not part of the module API, did you mean '{matches[0]}'?",
                )

    return True


def check_attribute_types(mod: type[DeviceModule], r: ModuleReport) -> set[str]:
    """
    Class attributes have the types PEAT expects.

    Returns:
        Names of attributes with the wrong type
    """
    bad: set[str] = set()

    for attr in STR_ATTRS:
        value = getattr(mod, attr)
        if not isinstance(value, str):
            r.add("error", "types", f"{attr} must be a str, not {type(value).__name__}")
            bad.add(attr)

    for attr, item_type in LIST_ATTRS.items():
        value = getattr(mod, attr)
        if not isinstance(value, (list, tuple)):
            r.add("error", "types", f"{attr} must be a list, not {type(value).__name__}")
            bad.add(attr)
            continue
        for item in value:
            if not isinstance(item, item_type):
                r.add(
                    "error",
                    "types",
                    f"{attr} must only contain {item_type.__name__} objects, "
                    f"found {type(item).__name__}: {item!r}",
                )
                bad.add(attr)

    for attr in DICT_ATTRS:
        value = getattr(mod, attr)
        if not isinstance(value, dict):
            r.add("error", "types", f"{attr} must be a dict, not {type(value).__name__}")
            bad.add(attr)
            continue
        for key in value:
            if not isinstance(key, str):
                r.add("error", "types", f"{attr} keys must be strings, found {key!r}")
                bad.add(attr)

    if not isinstance(mod.can_parse_dir, bool):
        r.add(
            "warning",
            "types",
            f"can_parse_dir should be a bool, not {type(mod.can_parse_dir).__name__}",
        )

    return bad


def check_metadata(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    Descriptive attributes used to populate device data and look up modules.
    """
    if not mod.device_type:
        r.add("warning", "metadata", "device_type is not set (populates 'host.type')")

    for attr in ("vendor_id", "vendor_name"):
        if not getattr(mod, attr):
            r.add(
                "warning",
                "metadata",
                f"{attr} is not set (populates 'host.description.vendor."
                f"{attr.split('_')[1]}'). Set it unless the module is vendor-agnostic.",
            )

    for attr in ("brand", "model"):
        if not getattr(mod, attr):
            r.add("info", "metadata", f"{attr} is not set")

    for attr in STR_ATTRS:
        value = getattr(mod, attr)
        if value != value.strip():
            r.add("warning", "metadata", f"{attr} has leading or trailing whitespace: {value!r}")

    seen: set[str] = set()
    for model in mod.supported_models:
        if not model.strip():
            r.add("warning", "metadata", "supported_models has an empty value")
        elif model.lower() in seen:
            r.add("warning", "metadata", f"supported_models has a duplicate: {model!r}")
        seen.add(model.lower())


def check_device_type(
    mod: type[DeviceModule], r: ModuleReport, all_modules: Iterable[type[DeviceModule]]
) -> None:
    """
    The device type is spelled the same way as in other modules.
    """
    others = {
        m.device_type
        for m in all_modules
        if m is not mod and isinstance(m.device_type, str) and m.device_type
    }
    if not mod.device_type or mod.device_type in others:
        return

    matches = sorted(t for t in others if t.lower() == mod.device_type.lower())
    if matches:
        r.add(
            "warning",
            "metadata",
            f"device_type {mod.device_type!r} differs in case from {matches[0]!r}, "
            f"which other modules use",
        )


def check_shared_defaults(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    A module that mutates an inherited list or dict changes it for every module.
    """
    for attr in (*LIST_ATTRS, *DICT_ATTRS):
        value = getattr(mod, attr)
        if value and value is DeviceModule.__dict__[attr]:
            r.add(
                "error",
                "shared-default",
                f"{attr} is the list or dict inherited from DeviceModule, and was "
                f"changed in place (e.g. with .append() or .update()). This changes "
                f"it for every module. Assign a new value instead.",
            )


def check_capabilities(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    The module implements something, and PEAT can reach what it implements.
    """
    implemented = {
        m for m in IMPLEMENTED_METHODS if _implemented(mod, m) and _is_function(getattr(mod, m))
    }
    has_methods = bool(mod.ip_methods or mod.serial_methods)
    parse_attrs = bool(mod.filename_patterns or mod.file_signatures or mod.can_parse_dir)

    if not implemented and not has_methods:
        r.add(
            "error",
            "capabilities",
            "Module doesn't implement _pull(), _push(), or _parse(), and has no "
            "ip_methods or serial_methods, so PEAT can't do anything with it",
        )
    elif not implemented:
        r.add("info", "capabilities", "Module only supports scanning (identification)")

    if "_parse" in implemented and not parse_attrs:
        r.add(
            "error",
            "capabilities",
            "_parse() is implemented, but filename_patterns, file_signatures, and "
            "can_parse_dir are all unset. 'peat parse' skips modules without them, "
            "even when the module is given with '-d'.",
        )
    elif "_parse" not in implemented and parse_attrs:
        r.add(
            "error",
            "capabilities",
            "filename_patterns, file_signatures, or can_parse_dir is set, but "
            "_parse() is not implemented. Parsing with this module will fail.",
        )

    for method, command in (("_pull", "pull"), ("_push", "push")):
        if method in implemented and not has_methods:
            r.add(
                "error",
                "capabilities",
                f"{method}() is implemented, but the module has no ip_methods or "
                f"serial_methods. 'peat {command}' only uses modules that can "
                f"identify devices.",
            )

    for name, advice in WRAPPER_METHODS.items():
        klass = _defined_in(mod, name)
        if klass is not None and klass is not DeviceModule and not _calls_super(klass, name):
            r.add(
                "warning",
                "overrides",
                f"{klass.__name__} overrides DeviceModule.{name}() without calling "
                f"super(), which skips what PEAT does in it: {advice}",
            )

    for name in INTERNAL_METHODS:
        klass = _defined_in(mod, name)
        if klass is not None and klass is not DeviceModule:
            r.add(
                "warning",
                "overrides",
                f"{klass.__name__} overrides DeviceModule.{name}(), which PEAT uses "
                f"internally. Rename the method, unless the override is intended.",
            )


def check_method_signatures(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    Implemented methods are classmethods that accept the arguments PEAT passes.
    """
    for name, (args, kwargs) in IMPLEMENTED_METHODS.items():
        if not _implemented(mod, name):
            continue

        static = inspect.getattr_static(mod, name)
        func = getattr(mod, name)
        if not _is_function(func):
            r.add(
                "error",
                "signatures",
                f"{name} must be a method, not {type(static).__name__}. PEAT checks "
                f"if it's implemented by reading its __code__, which fails.",
            )
            continue

        call = ", ".join([*("_" for _ in args), *(f"{k}=..." for k in kwargs)])
        error = _call_error(func, args, kwargs)
        is_classmethod = isinstance(static, classmethod)
        if error:
            hint = "" if is_classmethod else " Is the @classmethod decorator missing?"
            r.add("error", "signatures", f"PEAT calls {name}({call}), but the {error}.{hint}")
        elif not is_classmethod:
            r.add("warning", "signatures", f"{name}() should be a @classmethod")


def _check_function(
    r: ModuleReport, check: str, label: str, attr: str, func: Any, required: bool
) -> None:
    if func is None:
        if required:
            r.add("error", check, f"{label}: {attr} is not set, so the method is never used")
        return

    if not callable(func):
        r.add("error", check, f"{label}: {attr} is not callable: {func!r}")
        return

    error = _call_error(func, (object(),), {})
    if error:
        r.add("error", check, f"{label}: PEAT calls {attr} with one argument, but the {error}")


def check_identify_methods(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    Identification methods used by scanning.
    """
    module_options = mod.default_options
    names: set[str] = set()

    for method in [*mod.ip_methods, *mod.serial_methods]:
        kind = "IPMethod" if isinstance(method, IPMethod) else "SerialMethod"
        label = f"{kind} '{method.name}'"

        if not method.name.strip():
            r.add("warning", "identify-methods", f"{kind} has an empty name")
        elif method.name in names:
            r.add("warning", "identify-methods", f"{label}: name is used by another method")
        names.add(method.name)

        if not method.description.strip():
            r.add("warning", "identify-methods", f"{label}: description is empty")

        if method.reliability == 0:
            r.add("info", "identify-methods", f"{label}: reliability is 0 (unknown)")

        _check_function(
            r, "identify-methods", label, "identify_function", method.identify_function, True
        )

    for method in mod.ip_methods:
        label = f"IPMethod '{method.name}'"

        _check_function(r, "identify-methods", label, "port_function", method.port_function, False)

        if method.type == "broadcast_ip" and method.transport == "tcp":
            r.add(
                "warning",
                "identify-methods",
                f"{label}: type is 'broadcast_ip', but TCP can't be broadcast",
            )

        defaults = DEFAULT_OPTIONS.get(method.protocol)
        if method.type == "unicast_ip" and not (isinstance(defaults, dict) and "port" in defaults):
            r.add(
                "error",
                "identify-methods",
                f"{label}: scanning looks up the default port of protocol "
                f"'{method.protocol}' in PEAT's default options "
                f"(peat/data/default_options.py), which have no 'port' for it, so "
                f"scanning with the method fails. Add the protocol there.",
            )
        elif method.protocol not in DEFAULT_OPTIONS and method.protocol not in module_options:
            r.add(
                "warning",
                "identify-methods",
                f"{label}: protocol '{method.protocol}' has no options in PEAT's "
                f"default options or the module's default_options, so it has no "
                f"default port or timeout",
            )


def _patterns_overlap(pattern: str, other: str) -> bool:
    """
    If every filename matched by ``pattern`` is also matched by ``other``.

    PEAT matches patterns case-insensitively with a leading "*". This is
    exact for patterns with no wildcards other than "*". Patterns with other
    wildcards ("?" or "[...]") are never reported as overlapping.
    """
    if any(c in p for p in (pattern, other) for c in "?["):
        return False
    pattern = pattern.lower() if pattern.startswith("*") else f"*{pattern.lower()}"
    other = other.lower() if other.startswith("*") else f"*{other.lower()}"
    return fnmatchcase(pattern, other)


def check_filename_patterns(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    Patterns of files the module can parse.
    """
    patterns = [p for p in mod.filename_patterns if p.strip()]

    if len(patterns) != len(mod.filename_patterns):
        r.add("error", "filename-patterns", "filename_patterns has an empty value")

    for i, pattern in enumerate(patterns):
        if pattern.strip("*.") == "":
            r.add(
                "warning",
                "filename-patterns",
                f"'{pattern}' matches every file, so the module will try to parse all of them",
            )

        if not pattern.startswith("*"):
            r.add(
                "info",
                "filename-patterns",
                f"'{pattern}' matches any filename ending in '{pattern}', since PEAT "
                f"adds a leading '*'. Write it as '*{pattern}' to make that clear.",
            )

        for j, other in enumerate(patterns):
            if i == j or not _patterns_overlap(pattern, other):
                continue
            if _patterns_overlap(other, pattern):
                # Same pattern, ignoring case. Only report the second one.
                if j < i:
                    r.add(
                        "warning",
                        "filename-patterns",
                        f"'{pattern}' is the same as '{other}' "
                        f"(matching is case-insensitive). Remove one.",
                    )
                    break
            else:
                r.add(
                    "warning",
                    "filename-patterns",
                    f"'{pattern}' appears to be redundant, since '{other}' also "
                    f"matches it (matching is case-insensitive)",
                )
                break


def check_file_signatures(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    Signatures used to find files the module can parse.
    """
    seen: list[FileSignature] = []

    for sig in mod.file_signatures:
        label = f"FileSignature '{sig.default_filename}'"

        if not sig.default_filename.strip():
            r.add("warning", "file-signatures", "FileSignature has an empty default_filename")

        if sig in seen:
            r.add("warning", "file-signatures", f"{label} is a duplicate of another signature")
        seen.append(sig)

        _check_function(r, "file-signatures", label, "custom_check", sig.custom_check, False)


def check_aliases(
    mod: type[DeviceModule], r: ModuleReport, all_modules: Iterable[type[DeviceModule]]
) -> None:
    """
    Aliases used to look up modules, e.g. with "-d".
    """
    automatic = {
        _norm_alias(a)
        for a in ("all", mod.device_type, mod.vendor_id, mod.vendor_name, mod.brand, mod.model)
        if a
    }
    other_names = {_norm_name(m.__name__): m for m in all_modules if m is not mod}
    seen: set[str] = set()

    for alias in mod.module_aliases:
        normalized = _norm_alias(alias)

        if not normalized:
            r.add("warning", "aliases", "module_aliases has an empty value")
            continue

        if normalized in seen:
            r.add(
                "warning",
                "aliases",
                f"'{alias}' is a duplicate (aliases are case-insensitive)",
            )
            continue
        seen.add(normalized)

        if _norm_name(alias) == _norm_name(mod.__name__):
            r.add(
                "info",
                "aliases",
                f"'{alias}' isn't needed, since the module name already matches it",
            )
        elif _norm_name(alias) in other_names:
            r.add(
                "warning",
                "aliases",
                f"'{alias}' is the name of the module "
                f"{other_names[_norm_name(alias)].__name__}, which takes precedence "
                f"over aliases, so the alias is never used",
            )
        elif normalized in automatic:
            r.add(
                "info",
                "aliases",
                f"'{alias}' isn't needed, since PEAT adds it automatically "
                f"(from 'all', device_type, vendor_id, vendor_name, brand, or model)",
            )


def check_annotate_fields(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    Fields set on devices by update_dev().
    """
    for path, value in mod.annotate_fields.items():
        dev = DeviceData()

        try:
            utils.rgetattr(dev, path)
        except AttributeError:
            r.add(
                "error",
                "annotate-fields",
                f"'{path}' is not a field of DeviceData (refer to the data model docs)",
            )
            continue

        try:
            utils.rsetattr(dev, path, deepcopy(value))
        except Exception as ex:
            r.add("error", "annotate-fields", f"'{path}' can't be set to {value!r}: {ex}")


def _documented_options(config_file: Path) -> set[str]:
    """
    Keys under "device_options" in the example PEAT config file.
    """
    keys: set[str] = set()
    in_section = False

    for line in config_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("device_options:"):
            in_section = True
        elif in_section and re.match(r"^\S", line) and not line.startswith("#"):
            break
        elif in_section and (match := re.match(r"^  ([\w-]+):", line)):
            keys.add(match.group(1))

    return keys


def _same_kind(value: Any, default: Any) -> bool:
    """
    If an option value has the same type as PEAT's default for it.
    """
    for kinds in ((int, float), (list, tuple)):
        if isinstance(default, kinds) and isinstance(value, kinds):
            return not isinstance(value, bool)
    return type(value) is type(default)


def check_default_options(mod: type[DeviceModule], r: ModuleReport, bundled: bool) -> None:
    """
    Default options for the module.
    """
    try:
        deepcopy(mod.default_options)
    except Exception as ex:
        r.add(
            "error",
            "default-options",
            f"default_options can't be copied, which PEAT does for every device: {ex}",
        )
        return

    config_file = REPO_ROOT / "examples" / "peat-config.yaml"
    documented = _documented_options(config_file) if config_file.is_file() else set()

    for key, value in mod.default_options.items():
        if key in DEFAULT_OPTIONS:
            default = DEFAULT_OPTIONS[key]
            if isinstance(default, dict) and not isinstance(value, dict):
                r.add(
                    "error",
                    "default-options",
                    f"'{key}' must be a dict, since PEAT's default for it is a dict",
                )
            elif not isinstance(default, dict) and not _same_kind(value, default):
                r.add(
                    "warning",
                    "default-options",
                    f"'{key}' is a {type(value).__name__}, but PEAT's default "
                    f"for it is a {type(default).__name__}",
                )
            continue

        if not isinstance(value, dict):
            r.add(
                "warning",
                "default-options",
                f"'{key}' isn't one of PEAT's options. Put options specific to the "
                f"module under a key named after the module, e.g. "
                f"{{'{mod.__name__.lower()}': {{'{key}': ...}}}}.",
            )
        elif bundled and documented and key not in documented:
            r.add(
                "warning",
                "default-options",
                f"'{key}' options are not documented under 'device_options' "
                f"in examples/peat-config.yaml",
            )


def check_registration(mod: type[DeviceModule], r: ModuleReport) -> None:
    """
    Modules included with PEAT are exported and tested.
    """
    name = mod.__name__

    if module_api.modules.get(name.lower()) is not mod:
        r.add(
            "error",
            "registration",
            f"{name} is not imported in peat/modules/__init__.py, so PEAT can't "
            f"use it. Import it in the __init__.py file of each package above it.",
        )
    elif getattr(peat, name, None) is not mod:
        r.add("warning", "registration", f"{name} can't be imported with 'from peat import'")

    cli_args = REPO_ROOT / "peat" / "cli_args.py"
    if cli_args.is_file():
        names = {name.lower(), *(a.lower() for a in mod.module_aliases)}
        text = cli_args.read_text(encoding="utf-8").lower()
        if not any(f"-d {n}" in text for n in names):
            r.add("info", "registration", f"peat/cli_args.py has no examples that use {name}")

    tests_dir = REPO_ROOT / "tests"
    if tests_dir.is_dir():
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        tested = any(
            pattern.search(f.read_text(encoding="utf-8", errors="replace"))
            for f in tests_dir.rglob("*.py")
            if f.name != "test_check_module.py"  # Its tests use module names
        )
        if not tested:
            r.add("warning", "registration", f"No tests in tests/ refer to {name}")


def check_vendors(
    modules: Iterable[type[DeviceModule]], reports: dict[type, ModuleReport]
) -> None:
    """
    Modules for the same vendor use the same vendor_name.
    """
    by_vendor: dict[str, list[type[DeviceModule]]] = defaultdict(list)
    for mod in modules:
        if isinstance(mod.vendor_id, str) and mod.vendor_id:
            by_vendor[mod.vendor_id.lower()].append(mod)

    for group in by_vendor.values():
        ids = sorted({m.vendor_id for m in group})
        names = sorted({m.vendor_name for m in group if isinstance(m.vendor_name, str)})

        for mod in group:
            if mod not in reports:
                continue
            others = ", ".join(sorted(m.__name__ for m in group if m is not mod))
            if len(ids) > 1:
                reports[mod].add(
                    "warning",
                    "vendors",
                    f"vendor_id is {mod.vendor_id!r}, but other modules ({others}) "
                    f"use {', '.join(repr(i) for i in ids if i != mod.vendor_id)}",
                )
            if len(names) > 1:
                reports[mod].add(
                    "warning",
                    "vendors",
                    f"vendor_name is {mod.vendor_name!r}, but other modules with vendor_id "
                    f"{mod.vendor_id!r} ({others}) use "
                    f"{', '.join(repr(n) for n in names if n != mod.vendor_name)}",
                )


def check_parse_file(mod: type[DeviceModule], r: ModuleReport, path: Path) -> None:
    """
    Parse a real file with the module and check the results.
    """
    if not _implemented(mod, "_parse") or not _is_function(mod._parse):
        r.add("error", "parse-file", "Can't parse a file, _parse() is not implemented")
        return

    path = path.resolve()
    try:
        selected = path.is_dir() or (
            parsable_file_by_pattern(path.name, mod) or parsable_file_by_signature(str(path), mod)
        )
    except Exception as ex:
        r.add(
            "error",
            "parse-file",
            f"PEAT's check of filename_patterns and file_signatures raised an "
            f"exception for '{path.name}': {ex!r}",
        )
        selected = True
    if not selected:
        r.add(
            "warning",
            "parse-file",
            f"'{path.name}' doesn't match the module's filename_patterns or "
            f"file_signatures, so 'peat parse' won't use the module for it unless "
            f"it's the only module given with '-d'",
        )

    with tempfile.TemporaryDirectory(prefix="peat-check-module-") as tmp:
        overrides = {
            "TEMP_DIR": Path(tmp, "temp"),
            "DEVICE_DIR": Path(tmp, "devices"),
            "RESOLVE_IP": False,
            "RESOLVE_MAC": False,
            "RESOLVE_HOSTNAME": False,
        }
        with mock.patch.dict(config["CONFIG"], overrides):
            try:
                dev = mod.parse(path)
            except Exception as ex:
                r.add(
                    "error",
                    "parse-file",
                    f"parse() raised an exception for '{path.name}': {ex!r}\n"
                    f"{traceback.format_exc()}",
                )
                return

            if dev is None:
                r.add("error", "parse-file", f"parse() returned None for '{path.name}'")
                return

            try:
                json.dumps(dev.export(), default=str)
                dev.elastic()
            except Exception as ex:
                r.add(
                    "error",
                    "parse-file",
                    f"Parsed data can't be exported (bad values in the data model?): {ex!r}",
                )
                return

            if not list(Path(tmp, "devices").rglob("*")):
                r.add("warning", "parse-file", "parse() didn't write any output files")


def _crashed(report: ModuleReport, check: str, ex: Exception) -> None:
    report.add(
        "error",
        "crash",
        f"{check}() crashed, which is likely caused by a problem with the module "
        f"that the check doesn't handle: {ex!r}\n{traceback.format_exc()}",
    )


def check_module(
    mod: type[DeviceModule],
    all_modules: Iterable[type[DeviceModule]],
    parse_file: Path | None = None,
) -> ModuleReport:
    """
    Run all checks on a single module.
    """
    report = ModuleReport(name=getattr(mod, "__name__", repr(mod)), source=_source(mod))

    try:
        if not check_class(mod, report):
            return report
        bad = check_attribute_types(mod, report)
    except Exception as ex:
        _crashed(report, "check_class", ex)
        return report

    bundled = mod.__module__.startswith("peat.modules.")

    # Checks, and the attributes they need to have the correct types
    # Checks, their extra arguments, and the attributes they need to have the right types
    checks: list[tuple[Callable[..., None], tuple, tuple[str, ...]]] = [
        (check_metadata, (), (*STR_ATTRS, "supported_models")),
        (check_device_type, (all_modules,), STR_ATTRS),
        (check_shared_defaults, (), ()),
        (check_capabilities, (), ()),
        (check_method_signatures, (), ()),
        (check_identify_methods, (), ("ip_methods", "serial_methods", "default_options")),
        (check_filename_patterns, (), ("filename_patterns",)),
        (check_file_signatures, (), ("file_signatures",)),
        (check_aliases, (all_modules,), (*STR_ATTRS, "module_aliases")),
        (check_annotate_fields, (), ("annotate_fields",)),
        (check_default_options, (bundled,), ("default_options",)),
    ]
    if bundled:
        checks.append((check_registration, (), ()))
    if parse_file and bad:
        report.add(
            "error",
            "parse-file",
            f"Didn't parse '{parse_file.name}', since {', '.join(sorted(bad))} "
            f"{'has' if len(bad) == 1 else 'have'} the wrong type",
        )
    elif parse_file:
        checks.append((check_parse_file, (parse_file,), ()))

    for check, args, needs in checks:
        if bad.intersection(needs):
            continue
        try:
            check(mod, report, *args)
        except Exception as ex:
            _crashed(report, getattr(check, "__name__", repr(check)), ex)

    return report


def find_bundled_modules() -> tuple[list[type[DeviceModule]], list[ModuleReport]]:
    """
    Find every module class in ``peat/modules/``, including any that aren't
    imported in ``peat/modules/__init__.py``.

    Returns:
        The module classes, and reports for Python modules that failed to import
    """
    found: dict[str, type[DeviceModule]] = {}
    failures: list[ModuleReport] = []

    for info in pkgutil.walk_packages(peat.modules.__path__, prefix="peat.modules."):
        try:
            pymod = importlib.import_module(info.name)
        except Exception as ex:
            report = ModuleReport(name=info.name, source=info.name)
            report.add("error", "import", f"Import failed: {ex!r}")
            failures.append(report)
            continue

        for _, obj in inspect.getmembers(pymod, inspect.isclass):
            if obj.__module__ == info.name and issubclass(obj, DeviceModule):
                found[f"{obj.__module__}.{obj.__qualname__}"] = obj

    return sorted(found.values(), key=lambda m: m.__name__), failures


def _defined_under(mod: type, path: Path) -> bool:
    """
    If a class is defined in a file, or in a file in a directory.
    """
    try:
        source = Path(inspect.getfile(mod)).resolve()
    except (TypeError, OSError):
        return False
    return source == path or path in source.parents


def import_external(path: Path) -> tuple[list[type[DeviceModule]], ModuleReport | None]:
    """
    Import modules from a file or directory the same way as "peat -I".

    Returns:
        The imported module classes, and a report if the import failed
    """
    report = ModuleReport(name=path.name, source=_display_path(path))

    if not path.exists():
        report.add("error", "import", f"Path does not exist: {path}")
        return [], report

    before = dict(module_api.modules)
    messages: list[str] = []
    sink = log.add(lambda m: messages.append(m.record["message"]), level="WARNING")

    try:
        imported = module_api.import_module(path)
    except Exception as ex:
        report.add(
            "error",
            "import",
            f"Import raised an exception: {ex!r}\n{traceback.format_exc()}",
        )
        return [], report
    finally:
        log.remove(sink)

    if not imported:
        details = "".join(f"\n  {m}" for m in messages)
        report.add("error", "import", f"PEAT couldn't import any modules from {path}{details}")
        return [], report

    # Modules defined in the path. Not a diff of module_api.modules, since
    # importing a path that was already imported doesn't create new classes.
    new = [m for m in module_api.modules.values() if _defined_under(m, path)]
    if not new:
        report.add(
            "error",
            "import",
            f"PEAT imported {path}, but none of the modules defined in it. Python "
            f"imports each module name once, so this happens when a different "
            f"file with the same name was imported first.",
        )
        return [], report

    for mod in new:
        replaced = before.get(mod.__name__.lower())
        if replaced is not None and replaced is not mod and not _defined_under(replaced, path):
            report.add(
                "warning",
                "import",
                f"{mod.__name__} replaces the module with the same name "
                f"from {replaced.__module__}",
            )

    return sorted(new, key=lambda m: m.__name__), report if report.findings else None


def resolve_targets(
    targets: list[str],
) -> tuple[list[type[DeviceModule]], list[ModuleReport]]:
    """
    Resolve command line arguments into module classes.
    """
    if not targets:
        return find_bundled_modules()

    modules: list[type[DeviceModule]] = []
    reports: list[ModuleReport] = []

    for target in targets:
        path = Path(target)
        looks_like_path = path.suffix == ".py" or "/" in target or "\\" in target
        found = [] if looks_like_path else module_api.lookup_types(target)
        report = None

        if found:
            pass
        elif looks_like_path or path.exists():
            found, report = import_external(path.resolve())
        else:
            report = ModuleReport(name=target, source=target)
            report.add("error", "import", f"No module or alias named '{target}'")

        # The same module can be found with more than one argument,
        # e.g. a file and the directory it's in
        seen = {(m.__name__, _source(m)) for m in modules}
        modules.extend(m for m in found if (m.__name__, _source(m)) not in seen)
        if report:
            reports.append(report)

    return modules, reports


def run_checks(
    modules: list[type[DeviceModule]], parse_file: Path | None = None
) -> list[ModuleReport]:
    """
    Run all checks on modules, including checks that compare modules.
    """
    reports: list[ModuleReport] = []
    all_modules = {*module_api.modules.values(), *modules}

    module_reports: dict[type, ModuleReport] = {}
    for mod in modules:
        module_reports[mod] = check_module(mod, all_modules, parse_file)

    try:
        check_vendors(all_modules, module_reports)
    except Exception as ex:
        report = ModuleReport(name="vendors", source="all modules")
        _crashed(report, "check_vendors", ex)
        reports.append(report)

    # A module that changes these changes them for every module
    for attr in (*LIST_ATTRS, *DICT_ATTRS):
        if DeviceModule.__dict__[attr]:
            report = ModuleReport(name="DeviceModule", source="peat/device.py")
            report.add(
                "error",
                "shared-default",
                f"DeviceModule.{attr} was changed by a module (e.g. with .append() "
                f"or .update()) and is no longer empty: {DeviceModule.__dict__[attr]!r}",
            )
            reports.append(report)

    return reports + list(module_reports.values())


def print_reports(reports: list[ModuleReport], verbose: bool) -> None:
    shown = SEVERITIES if verbose else ("error", "warning")

    for report in reports:
        findings = [f for f in report.findings if f.severity in shown]
        status = "OK" if not report.count("error") else "FAILED"
        print(f"{report.name} ({report.source}): {status}")
        for f in findings:
            lines = f.message.rstrip().splitlines()
            print(f"  {f.severity.upper():8} {f.check:18} {lines[0]}")
            for line in lines[1:]:
                print(f"  {'':27} {line}")

    totals = {s: sum(r.count(s) for r in reports) for s in SEVERITIES}
    print(
        f"\nChecked {len(reports)} modules: {totals['error']} errors, "
        f"{totals['warning']} warnings, {totals['info']} suggestions"
        + ("" if verbose or not totals["info"] else " (show them with --verbose)")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that PEAT device modules correctly implement the module API.",
    )
    parser.add_argument(
        "modules",
        nargs="*",
        help="Module names, aliases, or paths to Python files or directories "
        "with modules (as used with 'peat -I'). Default: all modules included with PEAT.",
    )
    parser.add_argument(
        "--parse",
        type=Path,
        metavar="PATH",
        help="Real file (or directory) to parse with the module, to check that "
        "parsing works. Requires exactly one module.",
    )
    parser.add_argument(
        "--strict", action="store_true", help="Fail if there are warnings, not only errors"
    )
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show optional suggestions")
    args = parser.parse_args(argv)

    if args.parse:
        if not args.parse.exists():
            parser.error(f"--parse path does not exist: {args.parse}")
        if not args.modules:
            parser.error("--parse requires a module")

    modules, reports = resolve_targets(args.modules)
    if any(r.count("error") for r in reports):
        args.parse = None  # Report why the import failed instead
    elif args.parse and len(modules) != 1:
        parser.error(
            f"--parse requires exactly one module, found {len(modules)}: "
            f"{', '.join(m.__name__ for m in modules)}"
        )
    elif args.parse and args.parse.is_dir() and not modules[0].can_parse_dir:
        parser.error(
            f"--parse got a directory, but {modules[0].__name__} can't parse "
            f"directories (can_parse_dir is False). Give it a file instead."
        )

    reports += run_checks(modules, args.parse)

    if args.json:
        print(json.dumps([asdict(r) for r in reports], indent=2))
    else:
        print_reports(reports, args.verbose)

    failing = ("error", "warning") if args.strict else ("error",)
    return 1 if any(r.count(s) for r in reports for s in failing) else 0


if __name__ == "__main__":
    sys.exit(main())
