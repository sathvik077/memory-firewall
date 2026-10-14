#!/usr/bin/env python3
"""A minimal, honest stand-in for ``pytest`` — used **only** when pytest cannot be installed.

Why this exists
---------------
The release contract requires the test suites to be *executed*, not merely written. In an
environment whose egress policy blocks PyPI, pytest cannot be installed, and asserting "tests
written" with no observed result would be exactly the false completion the contract forbids. So this
runner executes the real test files unchanged, and ``docs/VERIFICATION.md`` records which runner
produced which numbers.

What it supports (deliberately a subset)
---------------------------------------
* discovery of ``tests/**/test_*.py`` and ``test_*`` functions, plus ``unittest.TestCase`` classes
* ``conftest.py`` fixtures, function-scoped, including ``yield`` fixtures and fixtures that request
  other fixtures; the ``tmp_path`` builtin
* ``pytest.fixture``, ``pytest.raises``, ``pytest.skip``, ``pytest.fail``, ``pytest.approx``
* ``@pytest.mark.<anything>`` and ``@pytest.mark.parametrize``
* ``-k`` substring selection, ``-m`` marker selection, ``-q``/``-v``

What it does NOT support: plugins, coverage, xdist, module/session-scoped fixture caching
semantics beyond a simple cache, monkeypatch, capsys, assertion rewriting (so failure output is the
plain ``AssertionError``). Anything it cannot honour it reports as an ERROR rather than skipping
silently.

Tests written for this runner are plain pytest tests; running them under real pytest requires no
change, which is the whole point.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import inspect
import sys
import tempfile
import traceback
import types
import unittest
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------------------- shim


class _Mark:
    def __init__(self, name: str) -> None:
        self.name = name

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # Bare marker used as @pytest.mark.foo
        if len(args) == 1 and not kwargs and callable(args[0]):
            fn = args[0]
            marks = getattr(fn, "_mf_marks", set())
            fn._mf_marks = marks | {self.name}
            return fn

        # Parametrised marker used as @pytest.mark.foo(...)
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            marks = getattr(fn, "_mf_marks", set())
            fn._mf_marks = marks | {self.name}
            if self.name == "parametrize":
                names = args[0]
                values = args[1]
                existing = getattr(fn, "_mf_parametrize", [])
                fn._mf_parametrize = [*existing, (names, list(values))]
            return fn

        return decorator


class _MarkRegistry:
    def __getattr__(self, name: str) -> _Mark:
        return _Mark(name)


class _Skipped(Exception):
    pass


class _Failed(AssertionError):
    pass


class _Approx:
    def __init__(self, expected: Any, rel: float = 1e-6, abs: float = 1e-12) -> None:  # noqa: A002
        self.expected = expected
        self.rel = rel
        self.abs = abs

    def __eq__(self, other: Any) -> bool:
        try:
            return abs(float(other) - float(self.expected)) <= max(
                self.abs, self.rel * abs(float(self.expected))
            )
        except (TypeError, ValueError):
            return NotImplemented

    def __repr__(self) -> str:
        return f"approx({self.expected!r})"


@dataclass
class _ExcInfo:
    value: BaseException | None = None

    @property
    def type(self) -> type[BaseException] | None:
        return type(self.value) if self.value else None

    def match(self, pattern: str) -> bool:
        import re

        return bool(re.search(pattern, str(self.value)))


def _build_pytest_module() -> types.ModuleType:
    module = types.ModuleType("pytest")

    def fixture(*fargs: Any, **fkwargs: Any) -> Any:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            fn._mf_fixture = True
            fn._mf_fixture_scope = fkwargs.get("scope", "function")
            fn._mf_fixture_name = fkwargs.get("name", fn.__name__)
            return fn

        if len(fargs) == 1 and callable(fargs[0]) and not fkwargs:
            return decorator(fargs[0])
        return decorator

    @contextmanager
    def raises(expected: Any, match: str | None = None) -> Iterator[_ExcInfo]:
        info = _ExcInfo()
        try:
            yield info
        except BaseException as exc:
            if not isinstance(exc, expected):
                raise
            info.value = exc
            if match is not None and not info.match(match):
                raise AssertionError(
                    f"exception message {str(exc)!r} does not match {match!r}"
                ) from exc
            return
        raise AssertionError(f"DID NOT RAISE {expected!r}")

    def skip(reason: str = "") -> None:
        raise _Skipped(reason)

    def fail(reason: str = "") -> None:
        raise _Failed(reason)

    module.fixture = fixture
    module.raises = raises
    module.skip = skip
    module.fail = fail
    module.approx = _Approx
    module.mark = _MarkRegistry()
    module.__mf_fallback__ = True
    return module


# --------------------------------------------------------------------------------------- runner


@dataclass
class Result:
    passed: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    selected: int = 0
    marks_seen: dict[str, int] = field(default_factory=dict)


class Runner:
    def __init__(
        self, rootdir: Path, *, keyword: str | None, marker: str | None, verbose: bool
    ) -> None:
        self.rootdir = rootdir
        self.keyword = keyword
        self.marker = marker
        self.verbose = verbose
        self.result = Result()
        self.fixtures: dict[str, Callable[..., Any]] = {}
        self._finalizers: list[Callable[[], None]] = []

    # -- fixtures ------------------------------------------------------------------------
    def _load_module(self, path: Path) -> types.ModuleType:
        name = "mf_" + "_".join(path.relative_to(self.rootdir).with_suffix("").parts)
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def collect_fixtures(self, module: types.ModuleType) -> None:
        for _, obj in inspect.getmembers(module, inspect.isfunction):
            if getattr(obj, "_mf_fixture", False):
                self.fixtures[getattr(obj, "_mf_fixture_name", obj.__name__)] = obj

    def resolve(self, name: str, cache: dict[str, Any]) -> Any:
        if name in cache:
            return cache[name]
        if name == "tmp_path":
            value = Path(tempfile.mkdtemp(prefix="mf-tmp-"))
            cache[name] = value
            return value
        if name == "tmp_path_factory":

            class _Factory:
                def mktemp(self, prefix: str = "mf") -> Path:
                    return Path(tempfile.mkdtemp(prefix=f"{prefix}-"))

            cache[name] = _Factory()
            return cache[name]
        if name not in self.fixtures:
            raise KeyError(f"fixture '{name}' not found")
        fn = self.fixtures[name]
        kwargs = {p: self.resolve(p, cache) for p in inspect.signature(fn).parameters}
        if inspect.isgeneratorfunction(fn):
            gen = fn(**kwargs)
            value = next(gen)

            def finalize(g: Any = gen) -> None:
                with contextlib.suppress(StopIteration):
                    next(g)

            self._finalizers.append(finalize)
        else:
            value = fn(**kwargs)
        cache[name] = value
        return value

    # -- selection -----------------------------------------------------------------------
    def _selected(self, test_id: str, marks: set[str]) -> bool:
        if self.keyword and self.keyword not in test_id:
            return False
        return not (self.marker and self.marker not in marks)

    # -- execution -----------------------------------------------------------------------
    def _run_one(self, test_id: str, fn: Callable[..., Any], params: dict[str, Any]) -> None:
        cache: dict[str, Any] = dict(params)
        self._finalizers = []
        try:
            kwargs = {
                p: self.resolve(p, cache) for p in inspect.signature(fn).parameters if p != "self"
            }
            fn(**kwargs)
        except _Skipped as exc:
            self.result.skipped.append((test_id, str(exc)))
            if self.verbose:
                print(f"  SKIP {test_id}: {exc}")
            return
        except AssertionError:
            self.result.failed.append((test_id, traceback.format_exc()))
            print(f"  FAIL {test_id}")
            return
        except Exception:
            self.result.errors.append((test_id, traceback.format_exc()))
            print(f"  ERROR {test_id}")
            return
        finally:
            for finalize in reversed(self._finalizers):
                with contextlib.suppress(Exception):  # a teardown failure must not mask a result
                    finalize()
        self.result.passed += 1
        if self.verbose:
            print(f"  ok   {test_id}")

    def run_file(self, path: Path) -> None:
        module = self._load_module(path)
        self.collect_fixtures(module)
        rel = str(path.relative_to(self.rootdir))

        # plain test functions
        for name, fn in sorted(inspect.getmembers(module, inspect.isfunction)):
            if not name.startswith("test_"):
                continue
            if fn.__module__ != module.__name__:
                continue
            marks: set[str] = set(getattr(fn, "_mf_marks", set()))
            for m in marks:
                self.result.marks_seen[m] = self.result.marks_seen.get(m, 0) + 1
            params_sets: list[dict[str, Any]] = [{}]
            for names, values in getattr(fn, "_mf_parametrize", []):
                keys = (
                    [k.strip() for k in names.split(",")] if isinstance(names, str) else list(names)
                )
                expanded: list[dict[str, Any]] = []
                for base in params_sets:
                    for value in values:
                        tup = value if isinstance(value, tuple) else (value,)
                        expanded.append({**base, **dict(zip(keys, tup, strict=False))})
                params_sets = expanded
            for index, params in enumerate(params_sets):
                suffix = f"[{index}]" if len(params_sets) > 1 else ""
                test_id = f"{rel}::{name}{suffix}"
                if not self._selected(test_id, marks):
                    continue
                self.result.selected += 1
                self._run_one(test_id, fn, params)

        # unittest.TestCase classes
        for cls_name, cls in sorted(inspect.getmembers(module, inspect.isclass)):
            if not issubclass(cls, unittest.TestCase) or cls is unittest.TestCase:
                continue
            if cls.__module__ != module.__name__:
                continue
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(cls)
            for case in suite:
                test_id = f"{rel}::{cls_name}::{case._testMethodName}"
                if not self._selected(test_id, set()):
                    continue
                self.result.selected += 1
                outcome = unittest.TestResult()
                case.run(outcome)
                if outcome.failures:
                    self.result.failed.append((test_id, outcome.failures[0][1]))
                    print(f"  FAIL {test_id}")
                elif outcome.errors:
                    self.result.errors.append((test_id, outcome.errors[0][1]))
                    print(f"  ERROR {test_id}")
                elif outcome.skipped:
                    self.result.skipped.append((test_id, outcome.skipped[0][1]))
                else:
                    self.result.passed += 1
                    if self.verbose:
                        print(f"  ok   {test_id}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="pytest fallback runner (subset)")
    parser.add_argument("paths", nargs="*", default=["tests"])
    parser.add_argument("-k", dest="keyword", default=None)
    parser.add_argument("-m", dest="marker", default=None)
    parser.add_argument("-q", dest="quiet", action="store_true")
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("--rootdir", default=".")
    args = parser.parse_args(argv)

    if "pytest" not in sys.modules:
        try:
            import pytest  # noqa: F401

            print("NOTE: real pytest is importable; prefer `python -m pytest`.", file=sys.stderr)
        except ModuleNotFoundError:
            sys.modules["pytest"] = _build_pytest_module()

    rootdir = Path(args.rootdir).resolve()
    sys.path.insert(0, str(rootdir / "packages" / "memory_firewall"))
    sys.path.insert(0, str(rootdir / "apps" / "api"))
    sys.path.insert(0, str(rootdir))

    banner = (
        "=" * 78
        + "\nFALLBACK TEST RUNNER (pytest unavailable in this environment).\n"
        + "Executes the same unmodified test files; supports a documented subset of pytest.\n"
        + "Re-run with `python -m pytest` once dependencies can be installed.\n"
        + "=" * 78
    )
    print(banner)

    runner = Runner(rootdir, keyword=args.keyword, marker=args.marker, verbose=args.verbose)

    files: list[Path] = []
    loaded_conftests: set[str] = set()
    for raw in args.paths:
        p = (rootdir / raw).resolve() if not Path(raw).is_absolute() else Path(raw)
        # conftest.py files apply from the rootdir downwards, exactly as pytest resolves them, so
        # `tests/integration` must still pick up `tests/conftest.py`.
        anchor = p if p.is_dir() else p.parent
        ancestors: list[Path] = []
        for parent in [anchor, *anchor.parents]:
            ancestors.append(parent)
            if parent == rootdir:
                break
        for parent in reversed(ancestors):
            candidate = parent / "conftest.py"
            if candidate.exists() and str(candidate) not in loaded_conftests:
                loaded_conftests.add(str(candidate))
                runner.collect_fixtures(runner._load_module(candidate))
        if p.is_dir():
            for conftest in sorted(p.rglob("conftest.py")):
                if str(conftest) not in loaded_conftests:
                    loaded_conftests.add(str(conftest))
                    runner.collect_fixtures(runner._load_module(conftest))
            files.extend(sorted(p.rglob("test_*.py")))
        elif p.is_file():
            files.append(p)

    for f in sorted(set(files)):
        if not args.quiet:
            print(f"\n{f.relative_to(rootdir)}")
        try:
            runner.run_file(f)
        except Exception:
            runner.result.errors.append((str(f), traceback.format_exc()))
            print(f"  COLLECTION ERROR {f}")

    r = runner.result
    print("\n" + "-" * 78)
    for test_id, tb in r.failed + r.errors:
        print(f"\n### {test_id}\n{tb}")
    print("-" * 78)
    print(
        f"selected={r.selected} passed={r.passed} failed={len(r.failed)} "
        f"errors={len(r.errors)} skipped={len(r.skipped)}"
    )
    if r.marks_seen:
        print("markers: " + ", ".join(f"{k}={v}" for k, v in sorted(r.marks_seen.items())))
    if r.skipped:
        print("SKIPPED TESTS (a skipped security test is a release blocker):")
        for test_id, reason in r.skipped:
            print(f"  - {test_id}: {reason}")
    return 0 if not r.failed and not r.errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
