#!/usr/bin/env python3
"""Fail if any security-marked test was skipped or deselected.

`CLAUDE.md` MF-21/MF-22 and the acceptance matrix both treat a quietly skipped security test as a
release blocker, because "all tests passed" is meaningless if the ones that matter did not run.
This script re-runs the security suite and asserts a non-zero executed count with zero skips.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    try:
        import pytest  # noqa: F401

        cmd = [sys.executable, "-m", "pytest", "tests/security", "-q", "-rs"]
    except ModuleNotFoundError:
        cmd = [sys.executable, "scripts/pytest_fallback.py", "tests/security"]

    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    output = proc.stdout + proc.stderr
    print(output[-4000:])

    skipped = 0
    executed = 0
    match = re.search(
        r"selected=(\d+) passed=(\d+) failed=(\d+) errors=(\d+) skipped=(\d+)", output
    )
    if match:
        executed = int(match.group(2))
        skipped = int(match.group(5))
    else:
        m_pass = re.search(r"(\d+) passed", output)
        m_skip = re.search(r"(\d+) skipped", output)
        executed = int(m_pass.group(1)) if m_pass else 0
        skipped = int(m_skip.group(1)) if m_skip else 0

    print(f"\nsecurity suite: executed={executed} skipped={skipped} exit={proc.returncode}")
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
