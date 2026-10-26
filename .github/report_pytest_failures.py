"""
Report why pytest tests failed as GitHub Actions error annotations, so the
reasons are visible in the job summary and checks API without the full log.

Usage: python .github/report_pytest_failures.py PYTEST_OUTPUT_FILE
"""

import re
import sys
from pathlib import Path

# GitHub shows at most 10 error annotations per step
MAX_ANNOTATIONS = 9


def annotate(title: str, body: str) -> None:
    body = body.strip()[-8000:].replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::error title={title}::{body}")  # noqa: T201


def main(output_file: str) -> None:
    path = Path(output_file)
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

    # Each failure starts with a "____ test_name ____" header
    sections = re.split(r"\n_{3,} (\S.*?) _{3,}\n", text)
    failures = list(zip(sections[1::2], sections[2::2]))

    for name, body in failures[:MAX_ANNOTATIONS]:
        errors = "\n".join(line for line in body.splitlines() if line.startswith(("E ", ">")))
        log = body.split("Captured log call", 1)[1] if "Captured log call" in body else ""
        annotate(name, errors[:3000] + "\n...\n" + "\n".join(log.splitlines()[-60:]))

    if failures:
        annotate("pytest summary", text.split("short test summary info", 1)[-1])
    else:
        annotate("pytest output", text[-8000:])


if __name__ == "__main__":
    main(sys.argv[1])
