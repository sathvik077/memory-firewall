#!/usr/bin/env python3
"""`make test-e2e` — browser assertions against the live app (no screenshots written)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browser_e2e import main

if __name__ == "__main__":
    raise SystemExit(main(["--json", "docs/assets/e2e-report.json"]))
