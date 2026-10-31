"""
Listings of device modules and their capabilities for the command line
interface (``--list-modules``, ``--list-all``, ``--module-info``, etc.).
Used by cli_main.py.

.. note::
   Listings are printed before logging is configured, so errors are
   printed to standard error (stderr) instead of being logged.
"""

import json
import sys
import textwrap
from collections.abc import Iterable
from pprint import pformat
from typing import Any

from humanfriendly.tables import format_pretty_table
from humanfriendly.terminal import ansi_strip
from humanfriendly.text import pluralize

from peat import DeviceModule, PeatError, config, consts, module_api
from peat.module_protocol import PROTOCOL_OPERATIONS, parse_protocol_filter

#: Operation performed by each CLI command that uses device modules.
#: Listings for other commands (e.g. ``pillage`` or ``heat``) include all modules.
COMMAND_OPERATIONS: dict[str, consts.OperationType] = {
    "scan": "scan",
    "pull": "pull",
    "push": "push",
    "parse": "parse",
}

# Width used to wrap long values in --module-info output
_WRAP_WIDTH = 100


def handle_list_args(args: dict[str, Any]) -> int | None:
    """
    Handle the module listing arguments (``--list-modules``, ``--list-aliases``,
    ``--list-alias-mappings``, ``--list-all``, and ``--module-info``).

    JSON is printed instead of text if ``-E/--print-results/--json``
    (:attr:`~peat.settings.Configuration.PRINT_RESULTS`) is set.

    Args:
        args: Raw CLI arguments

    Returns:
        Exit code if a listing argument was handled, or :obj:`None` if not
    """
    try:
        if args.get("list_modules"):
            return _list_modules(args)

        if args.get("list_aliases"):
            _print(json.dumps(list(module_api.module_aliases.keys())))
            return 0

        if args.get("list_alias_mappings"):
            _print(json.dumps(module_api.alias_mappings))
            return 0

        if args.get("list_all"):
            return _list_all()

        if args.get("module_info"):
            return _module_info(args["module_info"])
    except PeatError as ex:
        _error(str(ex))
        return 1

    return None


def get_protocol_filter() -> list[str]:
    """
    The protocol filter (``-p``/``--protocols`` or
    :attr:`~peat.settings.Configuration.PROTOCOL_FILTER`).

    Returns:
        The filter values. If empty, modules aren't filtered by protocol.

    Raises:
        PeatError: If the ``PROTOCOL_FILTER`` option failed to load, e.g. a
            malformed ``PEAT_PROTOCOL_FILTER`` environment variable. The filter
            restricts which modules communicate with devices, so PEAT refuses
            to run instead of silently using all of the modules.
    """
    error = config["load_errors"].get("PROTOCOL_FILTER")
    if error:
        raise PeatError(
            f"Failed to load the protocol filter ('protocol_filter' option or "
            f"PEAT_PROTOCOL_FILTER environment variable): {error}. Refusing to "
            f"run without it, fix the value or use -p instead."
        )
    return list(config.PROTOCOL_FILTER or [])


def args_comm_type(args: dict[str, Any]) -> consts.AllowedCommTypes | None:
    """
    Communication type of the targets in CLI arguments, if known.

    Args:
        args: Raw CLI arguments

    Returns:
        ``unicast_ip`` (``-i``), ``broadcast_ip`` (``-b``), ``serial`` (``-s``),
        or :obj:`None` if no targets are given (e.g. ``--list-modules`` without
        targets) or they're in a host file (``-f``)
    """
    if args.get("host_list"):
        return "unicast_ip"
    if args.get("broadcast_list"):
        return "broadcast_ip"
    if args.get("port_list"):
        return "serial"
    return None


def command_modules(args: dict[str, Any]) -> list[type[DeviceModule]]:
    """
    Modules that the command in ``args`` can use.

    This includes modules selected by ``-d`` (or all modules if it isn't set)
    and modules imported with ``-I``. Modules that don't support the command
    (e.g. ``pull``) are excluded, as are modules that don't match the protocol
    filter (``-p`` or :attr:`~peat.settings.Configuration.PROTOCOL_FILTER`),
    for commands that use it (``scan``, ``pull``, and ``push``). If targets
    are given (e.g. ``-b`` for a broadcast scan), only protocols used with
    their communication type are considered by the protocol filter.

    Args:
        args: Raw CLI arguments

    Returns:
        Sorted list of module classes

    Raises:
        PeatError: If the protocol filter is invalid or failed to load,
            or if the filters excluded all of the modules
    """
    func = args.get("func") or ""
    dev_types = list(args.get("device_types") or ["all"])
    dev_types.extend(sorted(module_api.runtime_imports))
    protocols = get_protocol_filter() if func in PROTOCOL_OPERATIONS else None

    return module_api.select_modules(
        dev_types,
        operation=COMMAND_OPERATIONS.get(func),
        protocols=protocols or None,
        comm_type=args_comm_type(args) if protocols else None,
    )


def format_modules_table(mods: Iterable[type[DeviceModule]]) -> str:
    """
    Table of modules with their type, vendor, operations, and protocols.
    """
    rows = [
        [
            m.__name__,
            m.device_type,
            m.vendor_id,
            ", ".join(m.get_operations()),
            ", ".join(m.get_protocols()),
        ]
        for m in sorted(mods, key=lambda x: x.__name__)
    ]
    return format_pretty_table(
        rows, column_names=["Module", "Type", "Vendor", "Operations", "Protocols"]
    )


def format_module_info(mod: type[DeviceModule]) -> str:
    """
    Human-readable details about a module, for ``--module-info``.
    """
    caps = mod.get_capabilities()
    parse_info = caps["parse"]

    vendor = caps["vendor_name"]
    if caps["vendor_id"] and caps["vendor_id"] != vendor:
        vendor = f"{vendor} ({caps['vendor_id']})" if vendor else caps["vendor_id"]

    lines = [f"{mod.__name__} ({mod.__module__})"]
    if caps["description"]:
        lines.append(f"  {caps['description']}")
    lines.append("")

    fields = [
        ("Device type", caps["device_type"]),
        ("Vendor", vendor),
        ("Brand", caps["brand"]),
        ("Default model", caps["model"]),
        ("Supported models", ", ".join(caps["supported_models"])),
        ("Aliases", ", ".join(caps["module_aliases"])),
        ("Operations", ", ".join(caps["operations"]) or "none"),
        ("Communication", ", ".join(caps["comm_types"])),
        ("Ports", ", ".join(str(p) for p in caps["ports"])),
        ("Parse patterns", ", ".join(parse_info["filename_patterns"])),
        ("Parse signatures", ", ".join(parse_info["file_signatures"])),
        ("Parses directories", "yes" if parse_info["can_parse_dir"] else ""),
        (
            "Imported at runtime",
            "yes" if mod.__name__.lower() in module_api.runtime_imports else "",
        ),
    ]
    label_width = max(len(label) for label, _ in fields) + 2
    for label, value in fields:
        if value:
            lines.append(_wrap_field(label, value, label_width))

    lines.append("")
    lines.append("  Protocols")
    protocols = mod.get_protocol_details()
    if protocols:
        rows = [
            [
                p.name,
                p.transport,
                ", ".join(str(x) for x in p.ports),
                ", ".join(p.operations),
                (
                    f"{p.description} (options: {p.options_key})".strip()
                    if p.options_key
                    else p.description
                ),
            ]
            for p in protocols
        ]
        cols = ["Protocol", "Transport", "Ports", "Operations", "Description"]
        lines.append(textwrap.indent(format_pretty_table(rows, column_names=cols), "  "))

        declared = {op for p in mod.protocols for op in p.operations}
        for op in ("pull", "push"):
            if mod.supports(op) and op not in declared:
                lines.append(
                    f"  Note: the module doesn't declare the protocols it uses "
                    f"for {op}, they're assumed to be the same as for scan."
                )
    else:
        lines.append("  None (the module doesn't communicate with devices)")

    if mod.ip_methods or mod.serial_methods:
        lines.append("")
        lines.append("  Identification methods (scan)")
        rows = [
            [
                m["name"],
                m["type"],
                m["protocol"],
                m["transport"],
                m["default_port"] if m["default_port"] is not None else "",
                m["reliability"],
            ]
            for m in caps["identify_methods"]
        ]
        cols = ["Method", "Type", "Protocol", "Transport", "Port", "Reliability"]
        lines.append(textwrap.indent(format_pretty_table(rows, column_names=cols), "  "))

    return "\n".join(lines)


def _list_modules(args: dict[str, Any]) -> int:
    func = args.get("func") or ""
    mods = command_modules(args)
    if not mods:
        _error(
            f"No device modules found for: {', '.join(args.get('device_types') or [])}. "
            f"Run 'peat {_cmd(func)} --list-all' to list modules and aliases."
        )
        return 1

    if config.PRINT_RESULTS:
        _print(json.dumps(module_api.get_capabilities(mods), indent=4))
        return 0

    if func in COMMAND_OPERATIONS:
        summary = f"{pluralize(len(mods), 'module')} can be used with 'peat {func}'"
    else:
        summary = f"{pluralize(len(mods), 'module')} imported"

    protocols = get_protocol_filter() if func in PROTOCOL_OPERATIONS else []
    if protocols:
        terms = ", ".join(t.raw for t in parse_protocol_filter(protocols))
        comm_type = args_comm_type(args)
        summary += f" (protocol filter: {terms}" + (f", {comm_type})" if comm_type else ")")

    _print(
        f"{format_modules_table(mods)}\n{summary}. "
        f"Run 'peat {_cmd(func)} --module-info <module>' for details."
    )
    return 0


def _list_all() -> int:
    if config.PRINT_RESULTS:
        _print(
            json.dumps(
                {
                    "modules": module_api.get_capabilities(),
                    "aliases": list(module_api.module_aliases.keys()),
                    "alias_mappings": module_api.alias_mappings,
                },
                indent=4,
            )
        )
        return 0

    _print(
        f"** Modules **\n"
        f"{format_modules_table(module_api.classes)}"
        f"\n\n** Aliases **\n"
        f"{pformat(list(module_api.module_aliases.keys()), compact=True)}"
        f"\n\n** Alias Mappings **\n"
        f"{pformat(module_api.alias_mappings, compact=True)}"
    )
    return 0


def _module_info(names: list[str]) -> int:
    mods: list[type[DeviceModule]] = []
    unknown: list[str] = []

    for name in names:
        found = module_api.lookup_types(name)
        if not found:
            unknown.append(name)
        mods.extend(m for m in found if m not in mods)

    if unknown:
        _error(
            f"Unknown device module(s) or alias(es): {', '.join(unknown)}. "
            f"Run '--list-all' to list modules and aliases."
        )
        return 1

    if config.PRINT_RESULTS:
        _print(json.dumps(module_api.get_capabilities(mods), indent=4))
    else:
        _print("\n\n".join(format_module_info(m) for m in mods))

    return 0


def _wrap_field(label: str, value: str, label_width: int) -> str:
    """
    Format a "label: value" line, wrapping long values.
    """
    prefix = f"  {label}:".ljust(label_width + 3)
    return textwrap.fill(
        value,
        width=_WRAP_WIDTH,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_on_hyphens=False,
    )


def _cmd(func: str) -> str:
    """
    CLI command name for a "func" value, e.g. "encrypt_config" => "encrypt-config".
    """
    return func.replace("_", "-") if func else "scan"


def _print(text: str) -> None:
    if config.NO_COLOR:
        text = ansi_strip(text)
    print(text, flush=True)  # noqa: T201


def _error(message: str) -> None:
    # NOTE: logging isn't configured yet when listing modules
    print(f"ERROR: {message}", file=sys.stderr, flush=True)  # noqa: T201


__all__ = [
    "COMMAND_OPERATIONS",
    "command_modules",
    "format_module_info",
    "format_modules_table",
    "handle_list_args",
]
