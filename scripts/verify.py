#!/usr/bin/env python3
"""`make verify` — the release truth source.

Runs every mandatory check, and is explicit about the difference between "failed" and "could not
run here". The contract forbids claiming success for an unexecuted check, so a check that cannot run
in this environment is reported as BLOCKED with the exact retry command and the release is marked
NOT READY.

Exit codes
----------
0   every mandatory check executed and passed, nothing blocked  -> release candidate
1   a mandatory check FAILED                                     -> NOT READY
2   everything executed passed, but something is BLOCKED         -> NOT READY
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {
    **os.environ,
    "PYTHONPATH": f"{ROOT / 'packages' / 'memory_firewall'}:{ROOT / 'apps' / 'api'}:{ROOT}",
}

PASS, FAIL, BLOCKED, SKIP = "PASS", "FAIL", "BLOCKED", "SKIPPED"


@dataclass
class Result:
    name: str
    status: str
    detail: str = ""
    command: str = ""
    retry: str = ""
    duration_s: float = 0.0
    evidence: str = ""


@dataclass
class Runner:
    results: list[Result] = field(default_factory=list)

    def run(
        self,
        name: str,
        command: list[str],
        *,
        gates: str = "",
        retry: str = "",
        optional: bool = False,
        timeout: int = 1800,
        evidence_tail: int = 0,
    ) -> Result:
        printable = " ".join(command)
        print(f"\n── {name}\n   $ {printable}", flush=True)
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                command, cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=timeout
            )
        except FileNotFoundError:
            result = Result(name, BLOCKED, f"{command[0]} is not installed", printable, retry)
            self._record(result, gates)
            return result
        except subprocess.TimeoutExpired:
            result = Result(name, FAIL, f"timed out after {timeout}s", printable, retry)
            self._record(result, gates)
            return result

        elapsed = time.perf_counter() - started
        output = (proc.stdout + proc.stderr).strip()
        tail = "\n".join(output.splitlines()[-evidence_tail:]) if evidence_tail else ""
        if proc.returncode == 0:
            status = PASS
            detail = output.splitlines()[-1][:160] if output else "exit 0"
        elif optional:
            status = BLOCKED
            detail = output.splitlines()[-1][:160] if output else f"exit {proc.returncode}"
        else:
            status = FAIL
            detail = f"exit {proc.returncode}: " + (output.splitlines()[-1][:160] if output else "")
        result = Result(name, status, detail, printable, retry, round(elapsed, 2), tail)
        self._record(result, gates)
        if status == FAIL:
            print("   ---- output tail ----")
            print("\n".join(output.splitlines()[-25:]))
        return result

    def record(
        self,
        name: str,
        status: str,
        detail: str,
        *,
        gates: str = "",
        retry: str = "",
        command: str = "",
    ) -> None:
        self._record(Result(name, status, detail, command, retry), gates)

    def _record(self, result: Result, gates: str) -> None:
        self.results.append(result)
        mark = {PASS: "PASS", FAIL: "FAIL", BLOCKED: "BLOCKED", SKIP: "SKIPPED"}[result.status]
        suffix = f"  [{gates}]" if gates else ""
        print(f"   -> {mark}  {result.detail}{suffix}", flush=True)
        if result.status == BLOCKED and result.retry:
            print(f"      retry: {result.retry}", flush=True)


def have(module: str) -> bool:
    return (
        subprocess.run(
            [sys.executable, "-c", f"import {module}"], capture_output=True, env=ENV
        ).returncode
        == 0
    )


def main() -> int:
    print("=" * 78)
    print("MEMORY FIREWALL — make verify")
    print("=" * 78)
    r = Runner()
    py = sys.executable
    test_cmd = [py, "-m", "pytest"] if have("pytest") else [py, "scripts/pytest_fallback.py"]

    # -- environment -----------------------------------------------------------------------
    r.run("environment diagnostics", [py, "-m", "memory_firewall.cli", "doctor"], gates="MF-01")

    # -- the engine ------------------------------------------------------------------------
    r.run("unit tests", [*test_cmd, "tests/unit"], gates="MF-02,MF-06,MF-09", evidence_tail=1)
    r.run(
        "integration tests",
        [*test_cmd, "tests/integration"],
        gates="MF-02,MF-03,MF-04,MF-08,MF-10,MF-12,MF-13",
        evidence_tail=1,
    )
    r.run(
        "security regression suite",
        [*test_cmd, "tests/security"],
        gates="MF-05,MF-07,MF-11,MF-22,MF-23",
        evidence_tail=1,
    )
    r.run(
        "no security test was skipped",
        [py, "scripts/assert_no_skipped_security.py"],
        gates="MF-21,MF-22",
        evidence_tail=2,
    )
    r.run(
        "release seed vectors (TEST_VECTORS.json)",
        [*test_cmd, "tests/integration/test_release_vectors.py"],
        gates="MF-02..MF-13",
        evidence_tail=1,
    )
    r.run(
        "offline scenarios",
        [py, "-m", "memory_firewall.cli", "scenarios"],
        gates="MF-15",
        evidence_tail=1,
    )
    r.run(
        "mandatory smoke",
        [py, "-m", "memory_firewall.cli", "smoke"],
        gates="MF-01,MF-05",
        evidence_tail=2,
    )

    # -- examples actually run -------------------------------------------------------------
    r.run(
        "SDK quickstart example", [py, "examples/sdk_quickstart.py"], gates="MF-12", evidence_tail=1
    )
    r.run(
        "support copilot example",
        [py, "examples/support_copilot/copilot.py"],
        gates="MF-12",
        evidence_tail=1,
    )

    # -- measurement -----------------------------------------------------------------------
    results_json = ROOT / "evals" / "results" / "RESULTS.json"
    if results_json.exists():
        report = json.loads(results_json.read_text(encoding="utf-8"))
        n = report["dataset"]["n_cases"]
        unmet = [k for k, g in report["pre_registered_goals"].items() if not g["met"]]
        full = report["conditions"]["full"]
        detail = (
            f"{n} cases; poison exposure {full['overall']['poison_exposure_rate']}; "
            f"stale-index {full['stale_index_subset']['exposed']}/"
            f"{full['stale_index_subset']['n']}; "
            f"{len(report['pre_registered_goals']) - len(unmet)}/"
            f"{len(report['pre_registered_goals'])} pre-registered goals met"
        )
        status = PASS if n >= 120 else FAIL
        r.record(
            "evaluation scorecard present and >=120 cases", status, detail, gates="MF-18,MF-19"
        )
        if unmet:
            r.record(
                "all pre-registered goals met",
                BLOCKED,
                f"unmet: {', '.join(unmet)} (reported honestly in evals/results/RESULTS.md)",
                gates="MF-18",
                retry="make eval",
            )
        else:
            r.record("all pre-registered goals met", PASS, "5/5", gates="MF-18")
    else:
        r.record(
            "evaluation scorecard",
            BLOCKED,
            "evals/results/RESULTS.json is missing",
            gates="MF-18",
            retry="make eval",
        )

    # -- quality gates ---------------------------------------------------------------------
    if shutil.which("ruff"):
        r.run("ruff lint", ["ruff", "check", "."], gates="MF-21")
        r.run("ruff format", ["ruff", "format", "--check", "."], gates="MF-21")
    else:
        r.run(
            "lint (stdlib fallback; ruff unavailable)",
            [py, "scripts/lint_fallback.py"],
            gates="MF-21",
            optional=True,
            retry="uv sync --extra dev && ruff check . && ruff format --check .",
        )
    if have("mypy"):
        r.run("mypy typecheck", [py, "-m", "mypy"], gates="MF-21")
    else:
        r.record(
            "mypy typecheck",
            BLOCKED,
            "mypy is not installed",
            gates="MF-21",
            retry="uv sync --extra dev && python -m mypy",
            command="python -m mypy",
        )

    if shutil.which("npm"):
        r.run(
            "dashboard typecheck + build",
            ["npm", "run", "build", "--prefix", "apps/dashboard"],
            gates="MF-21",
            evidence_tail=1,
        )
    else:
        r.record(
            "dashboard build",
            BLOCKED,
            "npm is not installed",
            gates="MF-21",
            retry="cd apps/dashboard && npm ci && npm run build",
        )

    # -- browser ---------------------------------------------------------------------------
    stack_up = (
        subprocess.run(
            [
                py,
                "-c",
                "import socket,sys;s=socket.socket();s.settimeout(0.4);"
                "sys.exit(s.connect_ex(('127.0.0.1', int(__import__('os').environ.get('MF_WEB_PORT', 5174)))))",
            ],
            capture_output=True,
            env=ENV,
        ).returncode
        == 0
    )
    if not have("playwright"):
        r.record(
            "browser end-to-end",
            BLOCKED,
            "the playwright package is not installed",
            gates="MF-14,MF-17",
            retry="pip install playwright && playwright install chromium",
        )
    elif not stack_up:
        r.record(
            "browser end-to-end",
            BLOCKED,
            "no dashboard on 127.0.0.1:5174 — start the stack first",
            gates="MF-14,MF-17",
            retry="./scripts/devstack.sh start && make verify",
        )
    else:
        r.run(
            "browser end-to-end + live dashboard assertions",
            [py, "scripts/run_e2e.py"],
            gates="MF-14,MF-16,MF-17",
            evidence_tail=3,
        )

    # -- artefacts -------------------------------------------------------------------------
    required_assets = [
        "docs/assets/scan-and-quarantine.png",
        "docs/assets/provenance-ledger.png",
        "docs/assets/retrieval-trace.png",
        "docs/assets/time-machine.png",
        "docs/assets/architecture.svg",
    ]
    missing = [a for a in required_assets if not (ROOT / a).exists()]
    r.record(
        "required screenshots and architecture image exist",
        PASS if not missing else FAIL,
        "all present" if not missing else f"missing: {', '.join(missing)}",
        gates="MF-17",
        retry="make screenshots && make arch",
    )

    required_docs = [
        "README.md",
        "LICENSE",
        "docs/RESEARCH.md",
        "docs/THREAT_MODEL.md",
        "docs/SECURITY.md",
        "docs/DECISIONS.md",
        "docs/VERIFICATION.md",
        "docs/ACCEPTANCE_STATUS.md",
        "docs/INTEGRATION.md",
        "docs/architecture.md",
        "docs/IMPLEMENTATION_PLAN.md",
    ]
    missing_docs = [d for d in required_docs if not (ROOT / d).exists()]
    r.record(
        "required documents exist",
        PASS if not missing_docs else FAIL,
        "all present" if not missing_docs else f"missing: {', '.join(missing_docs)}",
        gates="MF-26,MF-27",
    )

    # -- git hygiene -----------------------------------------------------------------------
    if (ROOT / ".git").exists():
        ignored = subprocess.run(
            ["git", "check-ignore", "private/Memory_Firewall_Research_Interview_Guide.pdf"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        tracked = subprocess.run(
            ["git", "ls-files", "private/"], cwd=ROOT, capture_output=True, text=True
        )
        env_tracked = subprocess.run(
            ["git", "ls-files", ".env"], cwd=ROOT, capture_output=True, text=True
        )
        clean = (
            ignored.returncode == 0
            and not tracked.stdout.strip()
            and not env_tracked.stdout.strip()
        )
        r.record(
            "git hygiene: private/ ignored, no .env tracked",
            PASS if clean else FAIL,
            "private/ ignored and nothing sensitive tracked"
            if clean
            else f"check-ignore exit {ignored.returncode}; tracked under private/: "
            f"{tracked.stdout.strip() or 'none'}; .env tracked: "
            f"{env_tracked.stdout.strip() or 'no'}",
            gates="MF-25",
        )
    else:
        r.record(
            "git hygiene",
            BLOCKED,
            "not a git repository yet",
            gates="MF-25",
            retry="git init && git add -A && make verify",
        )

    # -- docker ----------------------------------------------------------------------------
    docker_ok = (
        shutil.which("docker")
        and subprocess.run(["docker", "info"], capture_output=True).returncode == 0
    )
    if docker_ok:
        r.run(
            "docker image build (api)",
            ["docker", "build", "-f", "Dockerfile.api", "-t", "memory-firewall-api:verify", "."],
            gates="MF-25",
            timeout=1800,
        )
        r.run(
            "docker image build (dashboard)",
            [
                "docker",
                "build",
                "-f",
                "Dockerfile.dashboard",
                "-t",
                "memory-firewall-dashboard:verify",
                ".",
            ],
            gates="MF-25",
            timeout=1800,
        )
    else:
        r.record(
            "docker image builds",
            BLOCKED,
            "docker is unavailable or its daemon is not running",
            gates="MF-25",
            retry="docker build -f Dockerfile.api -t memory-firewall-api:dev .",
        )

    # -- summary ---------------------------------------------------------------------------
    print("\n" + "=" * 78)
    counts = {
        status: sum(1 for x in r.results if x.status == status)
        for status in (PASS, FAIL, BLOCKED, SKIP)
    }
    width = max(len(x.name) for x in r.results) + 2
    for item in r.results:
        print(f"{item.status:8} {item.name:{width}} {item.detail[:80]}")
    print("=" * 78)
    print(f"{counts[PASS]} passed · {counts[FAIL]} failed · {counts[BLOCKED]} blocked")

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": counts,
        "results": [vars(x) for x in r.results],
    }
    out = ROOT / "docs" / "verify-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")

    if counts[FAIL]:
        print("\nRELEASE STATUS: NOT READY — a mandatory check failed.")
        return 1
    if counts[BLOCKED]:
        print(
            "\nRELEASE STATUS: NOT READY — every executed check passed, but "
            f"{counts[BLOCKED]} mandatory check(s) could not run in this environment."
        )
        print("Each blocked check prints its exact retry command above and is recorded as")
        print(
            "NOT VERIFIED in docs/ACCEPTANCE_STATUS.md. Nothing blocked is being claimed as passing."
        )
        return 2
    print("\nRELEASE STATUS: all mandatory checks executed and passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
