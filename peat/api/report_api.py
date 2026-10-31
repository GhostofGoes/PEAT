"""
Generate HTML reports for existing PEAT run directories (``peat report``).
"""

from __future__ import annotations

import json
from pathlib import Path

from peat import config, log
from peat.report import generate_report
from peat.run_results import find_run_dirs


def report_api(run_dirs: list[str | Path], output_file: str | Path | None = None) -> bool:
    """
    Generate (or regenerate) the HTML report for PEAT run directories.

    Args:
        run_dirs: Run directories, or directories containing run directories
            (e.g. ``./peat_results/``). The run directory of the current PEAT
            run (:attr:`RUN_DIR <peat.settings.Configuration.RUN_DIR>`) is excluded.
        output_file: Write the report to this file instead of
            ``peat-report.html`` in the run directory. Only valid if
            ``run_dirs`` resolves to a single run directory.

    Returns:
        If reports were generated for all the run directories, and all
        the paths are (or contain) run directories
    """
    if not run_dirs:
        log.critical("No run directories specified (usage: peat report <run-dir> [<run-dir> ...])")
        return False

    # Each path is resolved separately, so that a path that's missing or has
    # no run directories (e.g. a typo) fails the command (after the others)
    current_run = Path(config.RUN_DIR).resolve() if config.RUN_DIR else None
    found: list[Path] = []
    bad_paths = []
    for raw in run_dirs:
        dirs = find_run_dirs([raw])
        if not dirs:
            bad_paths.append(str(raw))
        explicit = Path(raw).expanduser().resolve()
        for run_dir in dirs:
            if run_dir == current_run or run_dir in found:
                continue
            # When expanding a results directory, skip the run directories of previous
            # "peat report" commands (which only have logs). Explicit paths are kept.
            if run_dir != explicit and _is_report_command_run(run_dir):
                continue
            found.append(run_dir)
    if not found:
        log.critical("No PEAT run directories were found")
        return False

    if output_file and len(found) > 1:
        log.critical(
            f"-w/--write-file can only be used with a single run directory "
            f"(found {len(found)} run directories)"
        )
        return False

    written = []
    for run_dir in found:
        report = generate_report(run_dir, output_file=output_file)
        if report:
            written.append(report)

    if config.PRINT_RESULTS:
        print(  # noqa: T201
            json.dumps({"reports": [p.as_posix() for p in written]}, indent=4), flush=True
        )

    log.info(f"Generated {len(written)} of {len(found)} HTML reports")
    if bad_paths:
        log.error(f"Paths that aren't (and don't contain) PEAT run directories: {bad_paths}")
    return len(written) == len(found) and not bad_paths


def _is_report_command_run(run_dir: Path) -> bool:
    return run_dir.name.startswith("report_") and not any(
        (run_dir / name).is_dir() for name in ("devices", "summaries")
    )


__all__ = ["report_api"]
