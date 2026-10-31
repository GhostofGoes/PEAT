"""
Render the HTML report from a :class:`~peat.report.context.ReportContext`.

The report is a single self-contained HTML file: the stylesheet and script
are inlined, and nothing is loaded from the network. A strict
``Content-Security-Policy`` (hash-based) is included as defense in depth:
only the report's own inline stylesheet and script can run, and no network
requests can be made, even if escaping were ever to fail.

Jinja2 is imported lazily, so importing :mod:`peat.report` stays cheap.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from peat.consts import PeatError

from .context import ReportContext
from .sanitize import neutralize

#: Directory with the templates, stylesheet and script.
#: PyInstaller sets ``__file__`` relative to the bundle, so this works in executables.
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

_CLOSING_TAG_RE = re.compile(r"</(style|script)", re.IGNORECASE)


class ReportError(PeatError):
    """The HTML report couldn't be rendered."""


def csp_source(text: str) -> str:
    """
    CSP hash source for the text of an inline element.

    >>> csp_source("")
    "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='"
    """
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


def build_csp(css: str, js: str) -> str:
    """
    Content Security Policy allowing only the report's own inline
    stylesheet and script, and no network access.
    """
    return (
        f"default-src 'none'; style-src {csp_source(css)}; script-src {csp_source(js)}; "
        "img-src data:; base-uri 'none'; form-action 'none'"
    )


def load_asset(name: str) -> str:
    """
    Read a static asset (``report.css`` or ``report.js``) from :data:`TEMPLATE_DIR`.

    Raises:
        ReportError: the asset couldn't be read, or contains a closing
            ``style``/``script`` tag (which could break out of its element)
    """
    try:
        text = (TEMPLATE_DIR / name).read_text(encoding="utf-8")
    except OSError as ex:
        raise ReportError(f"Failed to read report asset '{name}': {ex}") from ex
    if _CLOSING_TAG_RE.search(text):
        raise ReportError(f"Report asset '{name}' contains a closing style or script tag")
    return text


def render_report(ctx: ReportContext) -> str:
    """
    Render the report.

    Raises:
        ReportError: Jinja2 isn't available, or the templates are missing or broken
    """
    try:
        import jinja2
        from markupsafe import Markup
    except ImportError as ex:
        raise ReportError(f"Jinja2 is required to generate HTML reports: {ex}") from ex

    def _finalize(value: object) -> object:
        # Backstop for EVERY {{ }} expression: neutralize control and bidi
        # characters. Markup is ONLY used for the static stylesheet and script.
        if isinstance(value, Markup):
            return value
        return "" if value is None else neutralize(str(value))

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,  # Explicit: everything rendered here is HTML
        undefined=jinja2.StrictUndefined,
        finalize=_finalize,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        auto_reload=False,
    )
    css = load_asset("report.css")
    js = load_asset("report.js")
    try:
        template = env.get_template("report.html.j2")
        return template.render(ctx=ctx, css=Markup(css), js=Markup(js), csp=build_csp(css, js))
    except jinja2.TemplateError as ex:
        raise ReportError(f"Failed to render HTML report: {ex}") from ex


__all__ = ["TEMPLATE_DIR", "ReportError", "build_csp", "csp_source", "render_report"]
