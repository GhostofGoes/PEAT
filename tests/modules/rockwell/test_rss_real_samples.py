"""
Optional tests against real RSLogix 500 project files.

No real project files are included with PEAT. To run these tests, set the
``PEAT_TEST_RSS_DIR`` environment variable to a directory containing
``*.RSS`` files (searched recursively). Every file must decode without
errors and pass the self-checks. This is how the opcode table and the
format notes in :mod:`peat.modules.rockwell.rss_parse` should be validated
when new sample files become available.

.. code-block:: bash

    PEAT_TEST_RSS_DIR=/path/to/rss/files pytest tests/modules/rockwell/test_rss_real_samples.py
"""

import os
from pathlib import Path

import pytest

from peat.modules.rockwell.rss_parse import parse_rss, read_rss

RSS_DIR = os.environ.get("PEAT_TEST_RSS_DIR", "")


def _sample_files() -> list[Path]:
    if not RSS_DIR:
        return []
    return sorted(p for p in Path(RSS_DIR).rglob("*") if p.suffix.lower() == ".rss")


pytestmark = pytest.mark.skipif(not RSS_DIR, reason="PEAT_TEST_RSS_DIR is not set")


@pytest.mark.parametrize("path", _sample_files(), ids=lambda p: p.name)
def test_real_rss_file(path):
    result = parse_rss(read_rss(path))

    assert result["errors"] == []
    assert result["warnings"] == []
    assert result["processor"]

    files = result["program_files"]
    assert files
    assert len(files) == result["program_files_declared"]
    declared = result["summary_info"].get("num_program_files")
    if declared is not None:
        assert len(files) == declared
    for pfile in files:
        assert len(pfile["rungs"]) == pfile["declared_rungs"]
        for rung in pfile["rungs"]:
            assert rung["text"].startswith("SOR ")
            assert rung["text"].endswith(" EOR")


def test_real_rss_files_found():
    assert _sample_files(), f"no .RSS files found in {RSS_DIR}"
