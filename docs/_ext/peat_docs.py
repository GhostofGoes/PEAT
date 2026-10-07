"""
PEAT-specific Sphinx directives.

``peat-device-table``
    Renders a device support table (e.g. ``supported_devices.csv``) as a set of
    per-vendor tables that fit on the page, with the long "Notes" and "Firmware
    Versions" columns moved into collapsible dropdowns below each table. The CSV
    file stays the single source of truth (it is also offered as a download).

    Usage::

        .. peat-device-table:: supported_devices.csv
           :vendor-sections:

    Options:

    ``:vendor-sections:``
        Emit a section heading for each vendor (so vendors show up in the page's
        table of contents). Without it, a bold rubric is used instead.
    ``:no-dropdowns:``
        Put notes in a bulleted list below the table instead of dropdowns.

Columns are matched by a normalized header name (lowercase, letters only), so the
CSV headers may contain reStructuredText roles such as ``:term:`TRL```.

``:peat-icon:`name```
    Inline a monochrome icon from ``docs/images/icons/`` next to a product name, for
    example ``:peat-icon:`docker` Docker``. See the README in that directory for the
    icon sources.

The extension also resolves references to Python builtins in type annotations (such as
``type`` in ``type[DeviceModule]``) exactly, instead of letting Sphinx "fuzzy match" them
to PEAT attributes that happen to have the same name (``Interface.type``, ``File.type``,
...), which produced "more than one target found" warnings and wrong links.
"""

from __future__ import annotations

import builtins
import csv
import re
from pathlib import Path

from docutils import nodes
from docutils.parsers.rst import directives
from docutils.statemachine import StringList
from sphinx import addnodes
from sphinx.application import Sphinx
from sphinx.util.docutils import SphinxDirective
from sphinx.util.nodes import nested_parse_with_titles

__version__ = "1.0.0"

# Normalized header name -> canonical column key
COLUMN_KEYS = {
    "vendor": "vendor",
    "device": "device",
    "supportedfunctions": "functions",
    "functions": "functions",
    "protocols": "protocols",
    "firmwareversions": "firmware",
    "firmware": "firmware",
    "notes": "notes",
    "estimatedtrl": "trl",
    "trl": "trl",
}


def _normalize_header(name: str) -> str:
    return re.sub(r"[^a-z]", "", name.lower())


#: Vendor name (as written in the CSV files) -> icon file in docs/images/icons/ (see its README)
VENDOR_ICONS = {
    "abb": "abb",
    "allen-bradley": "rockwellautomation",
    "camlin": "camlin",
    "fortinet": "fortinet",
    "ge": "generalelectric",
    "idirect": "idirect",
    "openplc": "openplc",
    "rockwell": "rockwellautomation",
    "sandia": "sandia",
    "schneider electric": "schneiderelectric",
    "sel": "sel",
    "siemens": "siemens",
    "uefi": "uefi",
    "windows": "windows",
    "woodward": "woodward",
}


#: Wordmark icons whose viewBox is cropped to the lettering; they render wider than tall
WIDE_ICONS = {"siemens", "abb"}


def _icon_html(icons_dir: Path, vendor: str) -> str | None:
    """Inline SVG for a vendor's icon, or None if there is none.

    The icon is decorative (``aria-hidden``): the heading text carries the vendor name.
    """
    slug = VENDOR_ICONS.get(vendor.strip().lower())
    if not slug:
        return None
    path = icons_dir / f"{slug}.svg"
    if not path.is_file():
        return None
    svg = path.read_text(encoding="utf-8").strip()
    classes = "peat-vendor-icon"
    if slug in WIDE_ICONS:
        classes += " peat-icon-wide"
    attrs = f'class="{classes}" aria-hidden="true" focusable="false"'
    return svg.replace("<svg ", f"<svg {attrs} ", 1)


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fp:
        # skipinitialspace: the CSV files put a space after the separating comma, and
        # without it a quoted field such as ``, "Pull config, Pull firmware"`` would keep its
        # quotes and be split at the inner comma
        reader = csv.reader(fp, skipinitialspace=True)
        header = next(reader)
        keys = [COLUMN_KEYS.get(_normalize_header(h), _normalize_header(h)) for h in header]
        rows = []
        for raw in reader:
            if not any(cell.strip() for cell in raw):
                continue
            row = {key: (_unquote(raw[i]) if i < len(raw) else "") for i, key in enumerate(keys)}
            rows.append(row)
    return rows


def _unquote(cell: str) -> str:
    """Strip whitespace and a stray pair of surrounding quotes left by hand-edited CSV."""
    cell = cell.strip()
    if len(cell) >= 2 and cell[0] == cell[-1] == '"':
        cell = cell[1:-1].strip()
    return cell


def _cell(text: str) -> str:
    """Make a CSV cell safe for a single list-table cell (collapse newlines)."""
    text = text.replace("\\,", ",")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " ".join(lines) if lines else "—"


def _multiline(text: str) -> list[str]:
    """Split a CSV cell with newline-separated items into bullet lines."""
    text = text.replace("\\,", ",")
    items = [line.strip().rstrip(",") for line in text.splitlines() if line.strip()]
    return items


class DeviceTableDirective(SphinxDirective):
    required_arguments = 1
    optional_arguments = 0
    final_argument_whitespace = True
    option_spec = {
        "vendor-sections": directives.flag,
        "no-dropdowns": directives.flag,
    }

    def run(self) -> list[nodes.Node]:
        _, path = self.env.relfn2path(self.arguments[0])
        csv_path = Path(path)
        if not csv_path.is_file():
            raise self.error(f"peat-device-table: file not found: {self.arguments[0]}")
        self.env.note_dependency(str(csv_path))

        rows = _read_rows(csv_path)
        has_firmware = any(r.get("firmware") for r in rows)
        has_trl = any(r.get("trl") for r in rows)

        # Group by vendor, preserving the order of first appearance
        vendors: dict[str, list[dict[str, str]]] = {}
        for row in rows:
            vendors.setdefault(row.get("vendor", "").strip() or "Other", []).append(row)

        lines: list[str] = []
        for vendor, devices in vendors.items():
            if "vendor-sections" in self.options:
                lines += [vendor, "-" * max(len(vendor), 4), ""]
            else:
                lines += [f".. rubric:: {vendor}", ""]

            # Summary table: Device | Supported functions | Protocols | TRL
            headers = ["Device", "Supported functions", "Protocols"]
            widths = ["32", "34", "24"]
            if has_trl:
                headers.append("TRL")
                widths.append("10")
            lines += [
                ".. list-table::",
                "   :class: peat-device-table",
                "   :header-rows: 1",
                f"   :widths: {' '.join(widths)}",
                "",
            ]
            lines.append(f"   * - {headers[0]}")
            for header in headers[1:]:
                lines.append(f"     - {header}")
            for row in devices:
                lines.append(f"   * - {_cell(row.get('device', ''))}")
                lines.append(f"     - {_cell(row.get('functions', ''))}")
                lines.append(f"     - {_cell(row.get('protocols', ''))}")
                if has_trl:
                    lines.append(f"     - {_cell(row.get('trl', ''))}")
            lines.append("")

            # Details: notes and tested firmware versions
            for row in devices:
                notes = row.get("notes", "").replace("\\,", ",").strip()
                firmware = _multiline(row.get("firmware", "")) if has_firmware else []
                if not notes and not firmware:
                    continue
                device_name = _cell(row.get("device", ""))
                short_name = device_name.split(".")[0].split(" (")[0]
                if "no-dropdowns" in self.options:
                    lines += [f"**{short_name}**", ""]
                    indent = ""
                else:
                    lines += [
                        f".. dropdown:: {short_name}: notes and tested firmware",
                        "   :class-container: peat-device-notes",
                        "",
                    ]
                    indent = "   "
                if notes:
                    lines += [f"{indent}{notes}", ""]
                if firmware:
                    lines += [f"{indent}Firmware versions PEAT has been used with:", ""]
                    for item in firmware:
                        lines.append(f"{indent}- {item}")
                    lines.append("")
            lines.append("")

        container = nodes.container()
        container["classes"].append("peat-device-tables")
        content = StringList(lines, source=str(csv_path))
        if "vendor-sections" in self.options:
            nested_parse_with_titles(self.state, content, container)
        else:
            self.state.nested_parse(content, self.content_offset, container)
        self._add_vendor_icons(container)
        return [container]

    def _add_vendor_icons(self, container: nodes.container) -> None:
        """Prefix each vendor heading (section title or rubric) with its icon (HTML only)."""
        icons_dir = Path(self.env.srcdir) / "images" / "icons"
        headings: list[nodes.Element] = [
            section.next_node(nodes.title) for section in container.findall(nodes.section)
        ]
        headings += list(container.findall(nodes.rubric))
        for heading in headings:
            if heading is None:
                continue
            vendor = heading.astext()
            html = _icon_html(icons_dir, vendor)
            if html:
                slug = VENDOR_ICONS[vendor.strip().lower()]
                self.env.note_dependency(str(icons_dir / f"{slug}.svg"))
                heading.insert(0, nodes.raw("", html, format="html"))


#: Names of Python builtins that commonly appear in type annotations
_BUILTIN_NAMES = frozenset(name for name in dir(builtins) if not name.startswith("_"))


def resolve_builtins_exactly(_app: Sphinx, doctree: nodes.document) -> None:
    """
    Make cross-references to Python builtins in type annotations non-"refspecific".

    Sphinx marks the type references it generates from ``:type:``/``:rtype:`` fields as
    "refspecific", which enables a fuzzy search that matches any object whose name *ends*
    with the target, e.g. ``type`` matches ``peat.data.models.Interface.type``. Without the
    flag, an unqualified builtin is not found in the Python domain and intersphinx links it
    to the Python documentation instead.
    """
    for node in doctree.findall(addnodes.pending_xref):
        if (
            node.get("refdomain") == "py"
            and node.hasattr("refspecific")
            and node.get("reftarget") in _BUILTIN_NAMES
        ):
            del node["refspecific"]


def label_sidebar_captions(
    _app: Sphinx, _pagename: str, _templatename: str, context: dict, _doctree
) -> None:
    """
    Add the ``aria-level`` that the sidebar's ``role="heading"`` toctree captions require.

    Sphinx renders toctree captions as ``<p class="caption" role="heading">``; a heading
    role without a level is an ARIA error (axe rule ``aria-required-attr``). Furo computes
    the sidebar HTML in its own ``html-page-context`` handler, so this one runs after it.
    """
    tree = context.get("furo_navigation_tree")
    if tree:
        context["furo_navigation_tree"] = tree.replace(
            '<p class="caption" role="heading">',
            '<p class="caption" role="heading" aria-level="2">',
        )


def peat_icon_role(_name, rawtext, text, lineno, inliner, _options=None, _content=None):
    """
    ``:peat-icon:`docker``` inlines an icon from ``docs/images/icons/`` (HTML output only).

    The icon is decorative and follows the text color; put the product name next to it.
    """
    env = inliner.document.settings.env
    icons_dir = Path(env.srcdir) / "images" / "icons"
    path = icons_dir / f"{text.strip()}.svg"
    if not path.is_file():
        msg = inliner.reporter.error(f"peat-icon: no icon named {text.strip()!r}", line=lineno)
        return [inliner.problematic(rawtext, rawtext, msg)], [msg]
    env.note_dependency(str(path))
    svg = path.read_text(encoding="utf-8").strip()
    attrs = 'class="peat-inline-icon" aria-hidden="true" focusable="false"'
    return [nodes.raw("", svg.replace("<svg ", f"<svg {attrs} ", 1), format="html")], []


def setup(app: Sphinx) -> dict:
    app.add_directive("peat-device-table", DeviceTableDirective)
    app.add_role("peat-icon", peat_icon_role)
    app.connect("doctree-read", resolve_builtins_exactly)
    app.connect("html-page-context", label_sidebar_captions, priority=600)
    return {
        "version": __version__,
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
