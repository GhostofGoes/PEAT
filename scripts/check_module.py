#!/usr/bin/env python3
"""
Verify that a PEAT device module is implemented correctly.

Checks a module class against the PEAT module API (:class:`peat.device.DeviceModule`)
and reports problems in three levels:

- ``ERROR``: the module is broken or will not work as intended with PEAT
- ``WARNING``: the module will probably work, but something is likely wrong
- ``SUGGESTION``: improvements to bring the module in line with current conventions

This is intended to help developers writing new modules, as well as for updating
older modules to the current API. Refer to the "Module developer guide" in the
PEAT documentation for details on writing modules.

Usage:

    # Check a module in a Python file (same as the "-I" argument to PEAT)
    pdm run python scripts/check_module.py examples/example_peat_module/awesome_module.py

    # Check a module included with PEAT, by name or alias
    pdm run python scripts/check_module.py SELRelay
    pdm run python scripts/check_module.py sel

    # Check all modules included with PEAT
    pdm run python scripts/check_module.py --all

    # Treat warnings as errors (exit code 1 if there are any)
    pdm run python scripts/check_module.py --strict ./my_module.py

Exit code is 1 if there are any errors (or warnings with ``--strict``), otherwise 0.
"""

import argparse
import importlib
import inspect
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from peat import DeviceData, DeviceModule, IPMethod, SerialMethod, module_api, utils
from peat.data.default_options import DEFAULT_OPTIONS

Level = Literal["error", "warning", "suggestion"]

LEVELS: tuple[Level, ...] = ("error", "warning", "suggestion")

# Root of the PEAT repository (this file is in <repo>/scripts/)
REPO_ROOT = Path(__file__).resolve().parent.parent

# Methods that modules implement, and the wrapper methods that call them.
# The wrappers should NOT be overridden by modules.
IMPLEMENTABLE_METHODS = {
    "_pull": "pull",
    "_push": "push",
    "_parse": "parse",
}

# How PEAT calls each implementable method, as (positional args, keyword args).
# These are used to check that the method signatures are compatible.
METHOD_CALLS: dict[str, tuple[tuple, dict]] = {
    "_pull": (("dev",), {}),
    "_push": (("dev", "to_push", "push_type"), {}),
    "_parse": ((), {"file": "file", "dev": None}),
}

STR_ATTRS = ["device_type", "vendor_id", "vendor_name", "brand", "model"]
STR_LIST_ATTRS = ["supported_models", "filename_patterns", "module_aliases"]
MUTABLE_ATTRS = [
    "ip_methods",
    "serial_methods",
    "supported_models",
    "filename_patterns",
    "module_aliases",
    "annotate_fields",
    "default_options",
]


@dataclass
class Finding:
    level: Level
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.level.upper():<10} [{self.code}] {self.message}"


@dataclass
class ModuleReport:
    module: type[DeviceModule] | None
    name: str
    source: str = ""
    findings: list[Finding] = field(default_factory=list)

    def add(self, level: Level, code: str, message: str) -> None:
        self.findings.append(Finding(level, code, message))

    def count(self, level: Level) -> int:
        return sum(1 for f in self.findings if f.level == level)

    @property
    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    def render(self, min_level: Level = "suggestion") -> str:
        allowed = LEVELS[: LEVELS.index(min_level) + 1]
        lines = [f"{self.name}" + (f" ({self.source})" if self.source else "")]
        shown = [f for f in self.findings if f.level in allowed]
        shown.sort(key=lambda f: LEVELS.index(f.level))

        if not shown:
            lines.append("  No problems found")
        lines.extend(f"  {f}" for f in shown)

        return "\n".join(lines)


def _defining_class(cls: type, name: str) -> type | None:
    """Class in the MRO of ``cls`` where attribute ``name`` is defined."""
    for klass in cls.__mro__:
        if name in klass.__dict__:
            return klass
    return None


def _is_overridden(cls: type[DeviceModule], name: str) -> bool:
    definer = _defining_class(cls, name)
    return definer is not None and definer is not DeviceModule


def _source_file(cls: type) -> Path | None:
    try:
        return Path(inspect.getfile(cls)).resolve()
    except (TypeError, OSError):
        return None


def _is_builtin(cls: type) -> bool:
    """If the module is included with PEAT (lives in ``peat/modules/``)."""
    return cls.__module__.startswith("peat.modules.")


def _other_modules(cls: type[DeviceModule]) -> list[type[DeviceModule]]:
    return [m for m in module_api.classes if m is not cls and m.__name__ != cls.__name__]


def check_class_basics(cls: type[DeviceModule], report: ModuleReport) -> None:
    if not module_api.is_valid_module(cls):
        report.add("error", "invalid-class", "Not a subclass of peat.DeviceModule")
        return

    if not cls.__name__.isidentifier() or not cls.__name__[0].isupper():
        report.add(
            "suggestion",
            "class-name",
            f"Class name '{cls.__name__}' should be CamelCase, e.g. 'SELRelay'",
        )

    if not inspect.getdoc(cls) or cls.__doc__ is None:
        report.add(
            "suggestion",
            "class-docstring",
            "Add a docstring to the module class describing the device(s) it supports",
        )

    pymod = sys.modules.get(cls.__module__)
    if pymod is not None and not pymod.__doc__:
        report.add(
            "suggestion",
            "file-docstring",
            "Add a docstring at the top of the Python file describing "
            "the module, including an 'Authors' section",
        )

    builtin = module_api.get_module(cls.__name__)
    if builtin is not None and builtin is not cls and not _is_builtin(cls):
        report.add(
            "warning",
            "name-conflict",
            f"Module name '{cls.__name__}' conflicts with the existing module "
            f"'{builtin.__name__}' ({builtin.__module__}), which it will overwrite "
            f"when imported",
        )


def check_shared_attributes(cls: type[DeviceModule], report: ModuleReport) -> None:  # noqa: ARG001
    """Catch modules that modify the base class attributes (e.g. ``.append()``)."""
    for attr in MUTABLE_ATTRS:
        base_value = DeviceModule.__dict__[attr]
        if base_value:
            report.add(
                "error",
                "base-mutated",
                f"DeviceModule.{attr} is not empty, something modified the base "
                f"class attribute instead of defining it on the module class "
                f"(e.g. using '{attr}.append()' instead of '{attr} = [...]')",
            )


def check_attribute_types(cls: type[DeviceModule], report: ModuleReport) -> None:
    for attr in STR_ATTRS:
        value = getattr(cls, attr, None)
        if not isinstance(value, str):
            report.add(
                "error",
                "attr-type",
                f"'{attr}' should be a str, not {type(value).__name__}",
            )
        elif value != value.strip():
            report.add(
                "warning", "attr-whitespace", f"'{attr}' has leading or trailing whitespace"
            )

    for attr in STR_LIST_ATTRS:
        value = getattr(cls, attr, None)
        if not isinstance(value, list):
            report.add(
                "error",
                "attr-type",
                f"'{attr}' should be a list of str, not {type(value).__name__}",
            )
        elif not all(isinstance(v, str) and v.strip() for v in value):
            report.add("error", "attr-type", f"'{attr}' should only contain non-empty strings")
        elif len({v.lower() for v in value}) != len(value):
            report.add("warning", "attr-duplicates", f"'{attr}' has duplicate values")

    for attr in ["ip_methods", "serial_methods"]:
        if not isinstance(getattr(cls, attr, None), list):
            report.add("error", "attr-type", f"'{attr}' should be a list")

    for attr in ["annotate_fields", "default_options"]:
        if not isinstance(getattr(cls, attr, None), dict):
            report.add("error", "attr-type", f"'{attr}' should be a dict")

    if not isinstance(cls.can_parse_dir, bool):
        report.add("error", "attr-type", "'can_parse_dir' should be a bool")


def check_description(cls: type[DeviceModule], report: ModuleReport) -> None:
    """Check the attributes that describe the device (vendor, type, etc.)."""
    for attr in ["device_type", "vendor_id", "vendor_name"]:
        if isinstance(getattr(cls, attr), str) and not getattr(cls, attr):
            report.add(
                "warning",
                "missing-description",
                f"'{attr}' is not set, it's used to annotate device results and "
                f"to look up the module (e.g. with '-d')",
            )

    if not cls.supported_models and not cls.model:
        report.add(
            "suggestion",
            "missing-models",
            "Set 'supported_models' and/or 'model' with the device model(s) the module supports",
        )

    others = _other_modules(cls)
    if not others or not isinstance(cls.device_type, str):
        return

    # Consistency with other modules, which helps catch typos and case mismatches
    if cls.device_type:
        known_types = {m.device_type for m in others if m.device_type}
        if cls.device_type not in known_types:
            matches = [t for t in known_types if t.lower() == cls.device_type.lower()]
            if matches:
                report.add(
                    "warning",
                    "device-type-case",
                    f"device_type '{cls.device_type}' differs in case from "
                    f"the existing type '{matches[0]}'",
                )
            elif not _is_builtin(cls):
                report.add(
                    "suggestion",
                    "device-type-new",
                    f"device_type '{cls.device_type}' isn't used by any other module, "
                    f"check if one of these fits: {', '.join(sorted(known_types))}",
                )

    if cls.vendor_id and isinstance(cls.vendor_id, str):
        for other in others:
            if not isinstance(other.vendor_id, str) or other.vendor_id.lower() != (
                cls.vendor_id.lower()
            ):
                continue
            if other.vendor_id != cls.vendor_id:
                report.add(
                    "warning",
                    "vendor-mismatch",
                    f"vendor_id '{cls.vendor_id}' differs in case from "
                    f"'{other.vendor_id}' used by {other.__name__}",
                )
                break
            if cls.vendor_name and other.vendor_name and other.vendor_name != cls.vendor_name:
                report.add(
                    "warning",
                    "vendor-mismatch",
                    f"vendor_name '{cls.vendor_name}' differs from '{other.vendor_name}' "
                    f"used by {other.__name__} with the same vendor_id '{cls.vendor_id}'",
                )
                break


def check_methods(cls: type[DeviceModule], report: ModuleReport) -> None:
    implemented = []

    for method, wrapper in IMPLEMENTABLE_METHODS.items():
        if _is_overridden(cls, wrapper):
            report.add(
                "error",
                "wrapper-override",
                f"'{wrapper}()' is overridden, implement '{method}()' instead. "
                f"DeviceModule.{wrapper}() handles common logic before and "
                f"after calling {method}()",
            )

        if not _is_overridden(cls, method):
            continue

        implemented.append(method)
        definer = _defining_class(cls, method)
        raw = definer.__dict__[method]

        if not isinstance(raw, classmethod):
            report.add(
                "error",
                "not-classmethod",
                f"'{method}()' must be a @classmethod, not "
                f"{'a regular method' if inspect.isfunction(raw) else type(raw).__name__}",
            )
            continue

        args, kwargs = METHOD_CALLS[method]
        try:
            inspect.signature(getattr(cls, method)).bind(*args, **kwargs)
        except TypeError as ex:
            base_sig = inspect.signature(getattr(DeviceModule, method))
            report.add(
                "error",
                "bad-signature",
                f"'{method}()' signature is incompatible with how PEAT calls it "
                f"({ex}). Expected: {method}{base_sig}",
            )

    # Custom method used by some older modules
    for name in ["_identify", "identify", "identify_ip", "identify_serial"]:
        if name in cls.__dict__:
            report.add(
                "warning",
                "legacy-identify",
                f"'{name}()' isn't used by PEAT, add identification functions to "
                f"'ip_methods' or 'serial_methods' as IPMethod or SerialMethod objects",
            )

    if not implemented and not cls.ip_methods and not cls.serial_methods:
        report.add(
            "error",
            "no-functionality",
            "Module doesn't implement any functionality. Implement at least one of "
            "_pull(), _push(), or _parse(), or define 'ip_methods' or 'serial_methods'",
        )

    if implemented and "_pull" in implemented and not (cls.ip_methods or cls.serial_methods):
        report.add(
            "warning",
            "pull-without-identify",
            "_pull() is implemented but no 'ip_methods' or 'serial_methods' are "
            "defined, so PEAT can't discover devices to pull from",
        )


def check_identify_methods(cls: type[DeviceModule], report: ModuleReport) -> None:
    for attr, method_type in [("ip_methods", IPMethod), ("serial_methods", SerialMethod)]:
        methods = getattr(cls, attr)
        if not isinstance(methods, list):
            continue

        names = []

        for i, method in enumerate(methods):
            label = f"{attr}[{i}]"

            if not isinstance(method, method_type):
                report.add(
                    "error",
                    "identify-type",
                    f"{label} should be a {method_type.__name__}, not {type(method).__name__}",
                )
                continue

            label = f"{attr}[{i}] ('{method.name}')"
            names.append(method.name)

            func = method.identify_function
            if func is None:
                report.add(
                    "error",
                    "identify-function",
                    f"{label} has no identify_function, PEAT will raise an error "
                    f"when attempting to use it",
                )
            elif not callable(func):
                report.add(
                    "error", "identify-function", f"{label} identify_function isn't callable"
                )
            else:
                try:
                    inspect.signature(func).bind("dev")
                except TypeError:
                    report.add(
                        "error",
                        "identify-function",
                        f"{label} identify_function must accept a single argument "
                        f"(the DeviceData object, or the target for broadcasts)",
                    )
                except ValueError:
                    pass  # Signature can't be inspected (builtins, etc.)

            if not method.description:
                report.add("suggestion", "identify-description", f"{label} has no description")

            if method.reliability == 0:
                report.add(
                    "suggestion",
                    "identify-reliability",
                    f"{label} has a reliability of 0 (unknown), set it to a value "
                    f"from 1-10 so PEAT can prioritize methods",
                )

        if len(set(names)) != len(names):
            report.add(
                "warning", "identify-duplicates", f"'{attr}' has methods with duplicate names"
            )


def check_parsing(cls: type[DeviceModule], report: ModuleReport) -> None:
    has_parse = _is_overridden(cls, "_parse")

    if cls.filename_patterns and not has_parse:
        report.add(
            "error",
            "patterns-without-parse",
            "'filename_patterns' is set but _parse() isn't implemented",
        )

    if cls.can_parse_dir and not has_parse:
        report.add(
            "error",
            "parse-dir-without-parse",
            "'can_parse_dir' is True but _parse() isn't implemented",
        )

    if has_parse and not cls.filename_patterns and not cls.can_parse_dir:
        report.add(
            "warning",
            "parse-without-patterns",
            "_parse() is implemented but 'filename_patterns' is empty, "
            "so PEAT can't find files for the module to parse in a directory",
        )


def check_aliases(cls: type[DeviceModule], report: ModuleReport) -> None:
    if not isinstance(cls.module_aliases, list):
        return

    other_names = {m.__name__.lower(): m.__name__ for m in _other_modules(cls)}

    for alias in cls.module_aliases:
        if not isinstance(alias, str):
            continue
        norm = module_api._norm_name(alias)

        if norm == cls.__name__.lower():
            report.add(
                "suggestion",
                "alias-redundant",
                f"Alias '{alias}' is redundant, modules can already be referred to by name",
            )
        elif norm in other_names:
            report.add(
                "warning",
                "alias-shadowed",
                f"Alias '{alias}' is the same as the name of module "
                f"'{other_names[norm]}', and will never resolve to this module",
            )


def check_annotate_fields(cls: type[DeviceModule], report: ModuleReport) -> None:
    if not isinstance(cls.annotate_fields, dict) or not cls.annotate_fields:
        return

    dev = DeviceData()
    missing = object()

    for key in cls.annotate_fields:
        if not isinstance(key, str) or utils.rgetattr(dev, key, missing) is missing:
            report.add(
                "error",
                "annotate-field",
                f"annotate_fields key '{key}' isn't a valid DeviceData field "
                f"(e.g. 'os.name' or 'description.vendor.id')",
            )


def check_options(cls: type[DeviceModule], report: ModuleReport) -> None:
    if not isinstance(cls.default_options, dict):
        return

    for key, value in cls.default_options.items():
        if not isinstance(key, str):
            report.add("error", "options-key", f"default_options key {key!r} should be a str")
        elif key not in DEFAULT_OPTIONS and not isinstance(value, dict):
            report.add(
                "warning",
                "options-not-nested",
                f"default_options '{key}' should be nested under a key for the module "
                f"(e.g. '{cls.__name__.lower()}': {{'{key}': ...}}), or a protocol key "
                f"(e.g. 'http')",
            )
        elif key in DEFAULT_OPTIONS and isinstance(DEFAULT_OPTIONS[key], dict):
            if not isinstance(value, dict):
                report.add(
                    "error",
                    "options-type",
                    f"default_options '{key}' should be a dict, like the global default",
                )


def check_builtin_integration(cls: type[DeviceModule], report: ModuleReport) -> None:
    """Checks for modules included with PEAT (see "Adding a module to PEAT" in the docs)."""
    if not _is_builtin(cls):
        return

    import peat.modules

    if getattr(peat.modules, cls.__name__, None) is not cls:
        report.add(
            "error",
            "not-exported",
            f"'{cls.__name__}' isn't imported in peat/modules/__init__.py, so PEAT won't load it",
        )

    source = _source_file(cls)
    if source is not None and source.stem.replace("_", "") != cls.__name__.lower():
        report.add(
            "suggestion",
            "file-name",
            f"Module file '{source.name}' should be named after the class "
            f"('{cls.__name__.lower()}.py')",
        )

    name = cls.__name__
    cli_args = REPO_ROOT / "peat" / "cli_args.py"
    if cli_args.exists():
        names = {name.lower()} | {a.lower() for a in cls.module_aliases if isinstance(a, str)}
        text = cli_args.read_text(encoding="utf-8").lower()
        if not any(f"-d {n}" in text for n in names):
            report.add(
                "suggestion",
                "cli-examples",
                f"Add command line usage examples for '{name}' to peat/cli_args.py",
            )

    repo_files = {
        "no-tests": (
            REPO_ROOT / "tests",
            f"No tests reference '{name}', add tests in tests/modules/",
        ),
        "not-documented": (
            REPO_ROOT / "docs" / "supported_devices.csv",
            f"'{name}' isn't listed in docs/supported_devices.csv",
        ),
    }

    for code, (path, message) in repo_files.items():
        if not path.exists():
            continue  # Not running from a repo checkout
        files = path.rglob("*.py") if path.is_dir() else [path]
        if not any(_file_mentions(f, name) for f in files):
            report.add("suggestion", code, message)

    module_keys = [
        k for k in cls.default_options if isinstance(k, str) and k not in DEFAULT_OPTIONS
    ]
    config_example = REPO_ROOT / "examples" / "peat-config.yaml"
    if module_keys and config_example.exists():
        text = config_example.read_text(encoding="utf-8")
        for key in module_keys:
            if f"{key}:" not in text:
                report.add(
                    "suggestion",
                    "options-undocumented",
                    f"default_options '{key}' isn't documented in examples/peat-config.yaml",
                )


def _file_mentions(path: Path, text: str) -> bool:
    try:
        return text in path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False


CHECKS = [
    check_class_basics,
    check_shared_attributes,
    check_attribute_types,
    check_description,
    check_methods,
    check_identify_methods,
    check_parsing,
    check_aliases,
    check_annotate_fields,
    check_options,
    check_builtin_integration,
]


def check_module(cls: type[DeviceModule]) -> ModuleReport:
    """
    Run all checks on a PEAT module class.

    Args:
        cls: the module class to check

    Returns:
        Report with the problems found
    """
    source = _source_file(cls)
    if source is not None:
        try:
            source_str = source.relative_to(Path.cwd()).as_posix()
        except ValueError:
            source_str = source.as_posix()
    else:
        source_str = ""

    report = ModuleReport(module=cls, name=getattr(cls, "__name__", str(cls)), source=source_str)

    for check in CHECKS:
        check(cls, report)
        # Don't bother with the rest of the checks if it's not a module
        if "invalid-class" in report.codes:
            break

    return report


def load_from_path(path: Path) -> tuple[list[type[DeviceModule]], list[ModuleReport]]:
    """
    Import the PEAT module classes defined in a Python file or directory.

    Returns:
        Tuple of module classes found and reports for any import failures
    """
    path = path.resolve()
    files = sorted(path.glob("*.py")) if path.is_dir() else [path]
    found: list[type[DeviceModule]] = []
    failures: list[ModuleReport] = []

    if path.is_dir():
        sys.path.insert(0, path.parent.as_posix())
        prefix = f"{path.name}."
    else:
        sys.path.insert(0, path.parent.as_posix())
        prefix = ""

    for file in files:
        if file.name == "__init__.py":
            continue
        name = f"{prefix}{file.stem}"

        try:
            importlib.invalidate_caches()
            pymod = importlib.import_module(name)
        except Exception as ex:
            report = ModuleReport(module=None, name=file.name, source=file.as_posix())
            report.add(
                "error",
                "import-failed",
                f"Failed to import: {type(ex).__name__}: {ex}",
            )
            failures.append(report)
            continue

        found.extend(
            m
            for _, m in inspect.getmembers(pymod, inspect.isclass)
            if m.__module__ == pymod.__name__ and module_api.is_valid_module(m)
        )

    return found, failures


def resolve_targets(targets: Iterable[str]) -> tuple[list[type[DeviceModule]], list[ModuleReport]]:
    modules: list[type[DeviceModule]] = []
    reports: list[ModuleReport] = []

    for target in targets:
        path = Path(target)

        if path.suffix == ".py" or path.is_dir():
            if not path.exists():
                report = ModuleReport(module=None, name=target)
                report.add("error", "not-found", f"Path doesn't exist: {target}")
                reports.append(report)
                continue

            found, failures = load_from_path(path)
            reports.extend(failures)

            if not found and not failures:
                report = ModuleReport(module=None, name=target, source=path.as_posix())
                report.add(
                    "error",
                    "no-modules",
                    "No subclasses of peat.DeviceModule found. Note that modules "
                    "can't be defined in __init__.py files",
                )
                reports.append(report)

            modules.extend(found)
        else:
            found = module_api.get_modules(target)
            if not found:
                report = ModuleReport(module=None, name=target)
                report.add(
                    "error",
                    "not-found",
                    f"No module or alias named '{target}'. "
                    f"Available modules: {', '.join(module_api.names)}",
                )
                reports.append(report)
            modules.extend(found)

    # Deduplicate while preserving order
    unique = list(dict.fromkeys(modules))
    return unique, reports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify that a PEAT device module is implemented correctly",
        epilog=(
            "Examples:\n"
            "  check_module.py ./my_module.py\n"
            "  check_module.py ./my_modules/\n"
            "  check_module.py SELRelay\n"
            "  check_module.py --all --level warning\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="MODULE",
        help="Path to a Python file or directory with PEAT module(s), "
        "or the name or alias of a module included with PEAT",
    )
    parser.add_argument(
        "-a", "--all", action="store_true", help="Check all modules included with PEAT"
    )
    parser.add_argument(
        "-l",
        "--level",
        choices=LEVELS,
        default="suggestion",
        help="Minimum level of findings to show (default: %(default)s)",
    )
    parser.add_argument(
        "-s", "--strict", action="store_true", help="Exit with an error if there are warnings"
    )
    args = parser.parse_args(argv)

    if not args.targets and not args.all:
        parser.error("specify a module to check, or --all")

    modules, reports = resolve_targets(args.targets)
    if args.all:
        modules = list(dict.fromkeys([*modules, *module_api.classes]))

    reports.extend(check_module(m) for m in modules)

    for report in reports:
        print(report.render(args.level), end="\n\n")

    errors = sum(r.count("error") for r in reports)
    warnings = sum(r.count("warning") for r in reports)
    suggestions = sum(r.count("suggestion") for r in reports)
    print(
        f"Checked {len(modules)} module(s): {errors} error(s), "
        f"{warnings} warning(s), {suggestions} suggestion(s)"
    )

    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
