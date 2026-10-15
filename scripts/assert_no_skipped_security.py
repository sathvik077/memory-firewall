#!/usr/bin/env python3
"""Fail if any security-marked test was skipped or deselected.

`CLAUDE.md` MF-21/MF-22 and the acceptance matrix both treat a quietly skipped security test as a
release blocker, because "all tests passed" is meaningless if the ones that matter did not run.
This script re-runs the security suite and asserts a non-zero executed count with zero skips.

Counts come from a JUnit XML report rather than from scraping pytest's console output. That is
not a style preference: ``[tool.pytest.ini_options] addopts`` already contains ``-q``, so adding
``-q`` on the command line produced ``-qq``, which suppresses the "N passed" summary line
entirely. The old scraper then read zero executed tests out of a perfectly healthy run and this
check failed in CI while passing locally against the fallback runner. A machine-readable report
has no such coupling to verbosity.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]


def _counts_from_junit(xml_path: Path) -> tuple[int, int] | None:
    """Return ``(executed, skipped)`` from a JUnit report, or ``None`` if it is unreadable."""
    if not xml_path.exists():
        return None
    try:
        root = ElementTree.parse(xml_path).getroot()  # noqa: S314 - our own pytest output
    except ElementTree.ParseError:
        return None
    suites = root.iter("testsuite")
    total = skipped = 0
    for suite in suites:
        total += int(suite.get("tests", 0))
        skipped += int(suite.get("skipped", 0))
    return (total - skipped, skipped)


def _counts_from_text(output: str) -> tuple[int, int]:
    """Best-effort parse of console output, for the no-pytest fallback runner."""
    match = re.search(
        r"selected=(\d+) passed=(\d+) failed=(\d+) errors=(\d+) skipped=(\d+)", output
    )
    if match:
        return int(match.group(2)), int(match.group(5))
    m_pass = re.search(r"(\d+) passed", output)
    m_skip = re.search(r"(\d+) skipped", output)
    return (int(m_pass.group(1)) if m_pass else 0, int(m_skip.group(1)) if m_skip else 0)


def main() -> int:
    try:
        import pytest  # noqa: F401

        have_pytest = True
    except ModuleNotFoundError:
        have_pytest = False

    with tempfile.TemporaryDirectory() as tmp:
        xml_path = Path(tmp) / "security-junit.xml"
        if have_pytest:
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                "tests/security",
                "-rs",
                f"--junit-xml={xml_path}",
            ]
        else:
            cmd = [sys.executable, "scripts/pytest_fallback.py", "tests/security"]

        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
        print(output[-4000:])

        counts = _counts_from_junit(xml_path) if have_pytest else None

    executed, skipped = counts if counts is not None else _counts_from_text(output)

    source = "junit xml" if counts is not None else "console output"
    print(
        f"\nsecurity suite: executed={executed} skipped={skipped} exit={proc.returncode} ({source})"
    )
    if proc.returncode != 0:
        print("FAIL: the security suite did not pass.", file=sys.stderr)
        return 1
    if executed == 0:
        print("FAIL: no security tests executed at all.", file=sys.stderr)
        return 1
    if skipped:
        print(
            f"FAIL: {skipped} security test(s) were skipped. A skipped security test is a release "
            "blocker, not a pass.",
            file=sys.stderr,
        )
        return 1
    print("OK: every security test executed and passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
