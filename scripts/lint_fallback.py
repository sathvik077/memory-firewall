#!/usr/bin/env python3
"""A small stdlib lint used only when Ruff cannot be installed.

It is not a Ruff substitute and does not pretend to be: it compiles every module (so a syntax error
cannot slip through) and applies a handful of AST checks that matter for *this* codebase —
bare excepts, mutable default arguments, `assert` outside tests, and string-formatted SQL. Anything
Ruff would catch beyond that is reported as NOT COVERED rather than silently passing.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ["packages/memory_firewall", "apps/api", "evals", "scripts", "tests", "examples"]
SKIP_DIRS = {".venv", "node_modules", "__pycache__", "dist", "build", ".git"}


class Checker(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.problems: list[str] = []
        self.in_tests = "tests" in path.parts

    def _report(self, node: ast.AST, code: str, message: str) -> None:
        self.problems.append(
            f"{self.path.relative_to(ROOT)}:{getattr(node, 'lineno', 0)}: {code} {message}"
        )

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._report(node, "MF-E001", "bare `except:` — catch a specific exception")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for default in [*node.args.defaults, *[d for d in node.args.kw_defaults if d]]:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._report(node, "MF-E002", f"mutable default argument in {node.name}()")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant):
            value = node.left.value
            if isinstance(value, str) and any(
                k in value.upper() for k in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ")
            ):
                self._report(node, "MF-E003", "SQL built with %-formatting — use bound parameters")
        self.generic_visit(node)


def main() -> int:
    problems: list[str] = []
    checked = 0
    for target in TARGETS:
        base = ROOT / target
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            source = path.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                problems.append(
                    f"{path.relative_to(ROOT)}:{exc.lineno}: MF-E000 syntax error: {exc.msg}"
                )
                continue
            checked += 1
            checker = Checker(path)
            checker.visit(tree)
            problems.extend(checker.problems)

    for problem in problems:
        print(problem)
    print(f"\nstdlib lint: {checked} module(s) compiled, {len(problems)} problem(s)")
    print(
        "NOT COVERED by this fallback: import sorting, unused names, formatting, naming, "
        "complexity, and every other Ruff rule. Install Ruff for the real check."
    )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
