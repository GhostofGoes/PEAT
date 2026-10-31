"""
Self-contained HTML report summarizing a PEAT run (``peat-report.html``).

The report is generated automatically in the run directory at the end of
``scan``, ``pull``, ``push``, ``parse``, ``pillage`` and ``heat`` runs on the
CLI (unless disabled with ``--no-html-report`` or ``html_report: false``),
and can be (re)generated for existing run directories with ``peat report``.

It's built only from the files in the run directory (read using
:mod:`peat.run_results`), plus information about the current process when
generated at the end of a run.

Usage:

.. code-block:: python

   from peat.report import generate_report

   generate_report("./peat_results/pull_default-config_<timestamp>_<run_id>/")
"""

from __future__ import annotations

import contextlib
import os
import secrets
import timeit
from pathlib import Path

import pathvalidate

from peat import log, state, utils
from peat.consts import PeatError
from peat.run_results import RunResults

from .consts import REPORT_COMMANDS, REPORT_FILENAME
from .context import LiveRunInfo, ReportContext, build_report_context


def generate_report(
    run_dir: str | Path,
    output_file: str | Path | None = None,
    live: LiveRunInfo | None = None,
) -> Path | None:
    """
    Generate and write the HTML report for a run directory.

    Args:
        run_dir: The run directory to report on
        output_file: Where to write the report. Defaults to
            ``peat-report.html`` in the run directory. An existing file
            is replaced (a symlink is replaced, not followed).
        live: Information about the current run, if the report is for the
            run that is finishing. If set, the directories and configuration
            of the current run (:data:`peat.settings.config`) are used.

    Returns:
        The path of the report, or :obj:`None` if it couldn't be generated
        (the reason is logged as an error). It never raises, and never
        changes :attr:`state.error <peat.settings.State.error>`.
    """
    start = timeit.default_timer()
    try:
        if live:
            results = RunResults.from_config()
        else:
            results = RunResults.open(run_dir)
        out = _output_path(output_file) if output_file else results.path / REPORT_FILENAME

        from .render import render_report  # Lazy import of Jinja2

        ctx = build_report_context(results, live, report_path=out)
        html_text = render_report(ctx)
        _write_report(html_text, out)
    except (PeatError, OSError) as ex:
        log.error(f"Failed to generate HTML report for '{run_dir}': {ex}")
        return None
    except Exception as ex:  # Bad content must never abort a batch of reports
        log.error(f"Failed to generate HTML report for '{run_dir}' (unexpected error): {ex!r}")
        log.opt(exception=True).debug("HTML report traceback")
        return None

    log.info(f"Generated HTML report: {out.as_posix()}")
    log.debug(f"HTML report generation took {utils.fmt_duration(timeit.default_timer() - start)}")
    return out


def _output_path(output_file: str | Path) -> Path:
    """
    Absolute path of a user-specified report file.

    Only the parent directory is resolved, so that a symlink at the path
    itself is replaced instead of followed (see :func:`_write_report`).
    """
    path = Path(output_file).expanduser()
    if not path.name or path.name in (".", ".."):
        raise PeatError(f"Invalid report file name: '{output_file}'")
    try:
        # Names must be valid on all platforms, like other files PEAT writes
        pathvalidate.validate_filename(path.name, platform="universal")
    except pathvalidate.ValidationError as ex:
        raise PeatError(f"Invalid report file name '{path.name}': {ex}") from None
    return path.parent.resolve() / path.name


def _write_report(text: str, out: Path) -> None:
    """
    Write the report to a temporary file in the same directory, then rename it.

    This never writes *through* an existing file: if ``out`` is a symlink
    (e.g. planted in a run directory from another system), the link itself
    is replaced, and its target is left untouched. A partially written
    report never replaces an existing one.

    It doesn't use :func:`peat.utils.write_file`, which sets
    :attr:`state.error <peat.settings.State.error>` on failures (a report
    failure must not change the exit status of a run) and silently renames
    invalid file names.

    Raises:
        PeatError: ``out`` is a directory
        OSError: The file couldn't be written
    """
    if out.is_dir() and not out.is_symlink():
        raise PeatError(f"Report output path is a directory: {out}")
    if out.is_symlink():
        log.warning(f"Replacing symlink '{out}' with the report (its target isn't modified)")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.parent / f".{out.name}.{secrets.token_hex(8)}.tmp"
    # O_EXCL: fail instead of following anything that already exists at the
    # temporary path. Mode 0o666 is reduced by the umask, like a normal file.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o666)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fp:
            fp.write(text)
        os.replace(tmp, out)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    state.written_files.add(out.as_posix())  # Like utils.write_file()


__all__ = [
    "REPORT_COMMANDS",
    "REPORT_FILENAME",
    "LiveRunInfo",
    "ReportContext",
    "generate_report",
]
