"""
Constants and limits for the HTML report.

These are module-level constants rather than configuration options. The
limits keep reports of very large runs usable (and bound the work done to
generate them).
"""

#: Name of the report file written to the run directory
REPORT_FILENAME = "peat-report.html"

#: CLI commands that automatically generate a report when they finish
REPORT_COMMANDS = frozenset({"scan", "pull", "push", "parse", "pillage", "heat"})

#: Maximum number of rows in a table (the total number of rows is still shown)
MAX_TABLE_ROWS = 5000

#: Maximum number of warning/error log messages shown
MAX_LOG_ENTRIES = 1000

#: Maximum length of a text value (longer values are truncated)
MAX_TEXT_LEN = 4000

#: Maximum size of a JSON block (e.g. a device's ``extra`` data), in characters
MAX_JSON_BLOCK = 64 * 1024

#: Files saved by PEAT that are larger than this aren't hashed (in bytes)
ARTIFACT_HASH_MAX_BYTES = 256 * 1024**2

#: Maximum total size of the files hashed for a report (in bytes).
#: Files after the limit is reached aren't hashed.
ARTIFACT_HASH_TOTAL_MAX_BYTES = 2 * 1024**3

#: Maximum number of device sections that are expanded by default
MAX_OPEN_DEVICES = 10

__all__ = [
    "ARTIFACT_HASH_MAX_BYTES",
    "ARTIFACT_HASH_TOTAL_MAX_BYTES",
    "MAX_JSON_BLOCK",
    "MAX_LOG_ENTRIES",
    "MAX_OPEN_DEVICES",
    "MAX_TABLE_ROWS",
    "MAX_TEXT_LEN",
    "REPORT_COMMANDS",
    "REPORT_FILENAME",
]
