"""Browser end-to-end, as a test.

The flows live in `scripts/browser_e2e.py` so that `make screenshots` and `make test-e2e` share one
implementation. This wraps them so `tests/e2e/` is a real suite rather than an empty directory, and
so a normal `pytest tests` run exercises the browser when the stack happens to be up.

It is skipped — loudly, with the reason — when Playwright is unavailable or the stack is not
running, because a browser test cannot be run against nothing. A skip here is reported by
`make verify` as BLOCKED rather than counted as a pass.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

WEB_PORT = 5174
URL = f"http://127.0.0.1:{WEB_PORT}"


def _stack_is_up() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.4)
        return probe.connect_ex(("127.0.0.1", WEB_PORT)) == 0


def _playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


@pytest.mark.slow
def test_dashboard_end_to_end() -> None:
    if not _playwright_available():
        pytest.skip(
            "playwright is not installed; retry: pip install playwright && "
            "playwright install chromium"
        )
    if not _stack_is_up():
        pytest.skip(f"no dashboard on {URL}; retry: ./scripts/devstack.sh start (or `make dev`)")

    from browser_e2e import run

    report = run(URL, capture=False)
    failed = [c for c in report.checks if not c.passed]
    assert report.checks, "the browser run asserted nothing"
    assert not failed, "browser checks failed: " + "; ".join(
        f"{c.name} ({c.detail})" for c in failed
    )
