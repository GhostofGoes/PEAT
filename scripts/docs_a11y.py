#!/usr/bin/env python3
"""
Accessibility checks for the built PEAT documentation.

Runs axe-core (https://github.com/dequelabs/axe-core) against pages of the HTML
documentation in headless Chromium using Playwright, in both the light and dark color
schemes, and reports WCAG violations. Exits non-zero if any violation at or above the
failure threshold is found.

Usage::

    pdm run docs-a11y                       # Checks a representative set of pages
    python scripts/docs_a11y.py _docs_html --all
    python scripts/docs_a11y.py _docs_html --fail-on moderate --json report.json

Requires the "docs" dependency group (playwright, axe-playwright-python) and a Chromium
that Playwright can find: run "playwright install chromium" once, or point
--executable-path (or the CHROMIUM_PATH environment variable) at an existing browser.
"""

# ruff: noqa: T201  (a command line tool: printing is its output)
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import sync_playwright

# Pages that cover every kind of content: landing page, generated API docs, tables,
# tabs and cards, inline SVG diagrams, the CLI reference, the glossary, and search.
DEFAULT_PAGES = [
    "index.html",
    "getting_started/introduction.html",
    "getting_started/supported_devices.html",
    "getting_started/install.html",
    "getting_started/quickstart.html",
    "user_guide/scan.html",
    "user_guide/output.html",
    "reference/cli.html",
    "reference/database_schema.html",
    "developer/data_model.html",
    "developer/device_api.html",
    "design/architecture.html",
    "tutorials/openplc_lab.html",
    "glossary.html",
    "genindex.html",
    "search.html",
]

IMPACT_ORDER = ["minor", "moderate", "serious", "critical"]

# Rules that are not meaningful for a static documentation site and are excluded.
# Keep this list short and justified.
DISABLED_RULES = {
    # The pages are deliberately not inside a single landmark region in Furo's layout
    # of sidebar + article + table of contents; the main content is in <main>/<article>.
    # "region": "...",
}


def check_page(axe: Axe, page, url: str) -> dict:
    page.goto(url, wait_until="networkidle")
    options = {
        "runOnly": {
            "type": "tag",
            "values": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"],
        }
    }
    if DISABLED_RULES:
        options["rules"] = {rule: {"enabled": False} for rule in DISABLED_RULES}
    result = axe.run(page, options=options)
    return result.response


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("html_dir", type=Path, help="Directory with the built HTML documentation")
    parser.add_argument(
        "--all", action="store_true", help="Check every HTML page instead of the default set"
    )
    parser.add_argument(
        "--pages", nargs="*", help="Specific pages (relative to html_dir) to check"
    )
    parser.add_argument(
        "--fail-on",
        choices=IMPACT_ORDER,
        default="serious",
        help="Minimum violation impact that fails the run (default: serious)",
    )
    parser.add_argument("--json", type=Path, help="Write the full results to this JSON file")
    parser.add_argument(
        "--executable-path",
        default=os.environ.get("CHROMIUM_PATH"),
        help="Chromium executable to use instead of Playwright's bundled browser",
    )
    parser.add_argument("--light-only", action="store_true", help="Skip the dark color scheme")
    args = parser.parse_args()

    html_dir = args.html_dir.resolve()
    if not (html_dir / "index.html").is_file():
        print(
            f"error: {html_dir} does not contain index.html (build the docs first)",
            file=sys.stderr,
        )
        return 2

    if args.pages:
        pages = args.pages
    elif args.all:
        pages = sorted(
            str(p.relative_to(html_dir))
            for p in html_dir.rglob("*.html")
            if "_static" not in p.parts
        )
    else:
        pages = [p for p in DEFAULT_PAGES if (html_dir / p).is_file()]

    schemes = ["light"] if args.light_only else ["light", "dark"]
    threshold = IMPACT_ORDER.index(args.fail_on)
    axe = Axe()
    report: dict[str, dict] = {}
    failures = 0
    total_violations = 0

    with sync_playwright() as pw:
        launch_kwargs = {}
        if args.executable_path:
            launch_kwargs["executable_path"] = args.executable_path
        browser = pw.chromium.launch(**launch_kwargs)
        for scheme in schemes:
            context = browser.new_context(
                viewport={"width": 1280, "height": 900}, color_scheme=scheme
            )
            page = context.new_page()
            for rel in pages:
                url = (html_dir / rel).as_uri()
                try:
                    response = check_page(axe, page, url)
                except Exception as ex:
                    print(f"[{scheme}] {rel}: ERROR {ex}")
                    failures += 1
                    continue
                violations = response.get("violations", [])
                report[f"{scheme}:{rel}"] = violations
                total_violations += len(violations)
                failing = [
                    v
                    for v in violations
                    if IMPACT_ORDER.index(v.get("impact") or "minor") >= threshold
                ]
                failures += len(failing)
                status = "FAIL" if failing else ("warn" if violations else "ok")
                print(
                    f"[{scheme}] {rel}: {status} "
                    f"({len(violations)} violations, {len(failing)} at/above {args.fail_on})"
                )
                for v in violations:
                    nodes = v.get("nodes", [])
                    targets = "; ".join(" ".join(n.get("target", [])) for n in nodes[:3])
                    more = f" (+{len(nodes) - 3} more)" if len(nodes) > 3 else ""
                    print(f"    - {v.get('impact', '?'):8s} {v['id']}: {v['help']}")
                    print(f"               {v.get('helpUrl', '')}")
                    print(f"               nodes: {targets}{more}")
            context.close()
        browser.close()

    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
        print(f"wrote {args.json}")

    print(
        f"\nChecked {len(pages)} pages x {len(schemes)} color scheme(s): "
        f"{total_violations} violations, {failures} at or above '{args.fail_on}'"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
