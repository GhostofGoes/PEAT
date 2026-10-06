#!/usr/bin/env python3
"""
Create or update the "docs" virtualenv from pdm.docs.lock.

This is what ``pdm run docs-venv`` runs. The documentation builds in its own virtualenv
(named "docs") from its own lock file so that a current Sphinx can be used alongside
PEAT's pinned runtime dependencies; see docs/contributing/documentation.rst.

It is a Python script rather than a PDM "shell" script because shell scripts run under
cmd.exe on Windows, where POSIX quoting and tools such as grep aren't available.
"""

# ruff: noqa: T201  (a command line helper: printing is its output)
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

#: Minimum Python version for the documentation build (Sphinx 9 requires 3.12)
PYTHON_VERSION = "3.12"
VENV_NAME = "docs"
LOCKFILE = "pdm.docs.lock"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def pdm(*args: str, capture: bool = False) -> subprocess.CompletedProcess:
    exe = shutil.which("pdm") or "pdm"  # resolves pdm.exe/pdm.cmd on Windows
    return subprocess.run(
        [exe, *args], cwd=PROJECT_ROOT, capture_output=capture, text=True, check=False
    )


def venv_exists() -> bool:
    listing = pdm("venv", "list", capture=True)
    if listing.returncode != 0:
        sys.stderr.write(listing.stderr)
        sys.exit(listing.returncode)
    # Lines look like "*  in-project: /path/to/.venv" or "-  docs: /path/to/venv"
    return re.search(rf"^\S+\s+{VENV_NAME}:", listing.stdout, re.MULTILINE) is not None


def main() -> int:
    if not venv_exists():
        print(f"Creating the '{VENV_NAME}' virtualenv with Python {PYTHON_VERSION}")
        created = pdm("venv", "create", "--name", VENV_NAME, PYTHON_VERSION)
        if created.returncode != 0:
            print(
                f"error: could not create the '{VENV_NAME}' virtualenv. Install Python "
                f"{PYTHON_VERSION} or newer, create it with "
                f"'pdm venv create --name {VENV_NAME} {PYTHON_VERSION}', and re-run this.",
                file=sys.stderr,
            )
            return created.returncode
    print(f"Installing the documentation dependencies from {LOCKFILE}")
    synced = pdm("sync", "--venv", VENV_NAME, "--lockfile", LOCKFILE, "-G", "docs", "--clean")
    return synced.returncode


if __name__ == "__main__":
    sys.exit(main())
