"""Local directory importer.

The contract calls for "a concrete local ``.md`` directory importer with ignore/symlink checks"
(``CLAUDE.md`` §4A) and a path-traversal regression test (MF-22). The checks are therefore the point
of this module, not a nicety:

* The root is resolved once. Every candidate file is resolved and must still be *inside* the
  resolved root, which defeats ``../`` components and absolute-path tricks.
* Symlinks are skipped by default — both symlinked files and symlinked directories — because a
  symlink inside an otherwise innocuous folder is the standard way to make an importer read
  ``/etc/passwd`` or a credential file.
* Only an allow-list of suffixes is read, each file is size-capped, and common dependency, VCS and
  secret directories are ignored.
* Nothing is fetched over the network. There is no URL ingestion path anywhere in this product, so
  there is no SSRF surface to defend.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ..errors import ValidationError

__all__ = ["DEFAULT_IGNORED_DIRS", "DirectoryAdapter", "DirectoryDocument"]

DEFAULT_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".next",
        ".cache",
        "private",
        ".ssh",
        ".aws",
        ".gnupg",
        "site-packages",
    }
)


@dataclass(slots=True)
class DirectoryDocument:
    path: Path
    relative_path: str
    title: str
    text: str
    size_bytes: int


class DirectoryAdapter:
    """Walk a directory safely and yield importable text documents."""

    def __init__(
        self,
        root: str | Path,
        *,
        suffixes: tuple[str, ...] = (".md", ".txt"),
        max_files: int = 500,
        max_bytes_per_file: int = 256 * 1024,
        follow_symlinks: bool = False,
        ignored_dirs: frozenset[str] = DEFAULT_IGNORED_DIRS,
    ) -> None:
        root_path = Path(root).expanduser()
        if not root_path.exists() or not root_path.is_dir():
            raise ValidationError(f"import root '{root}' is not an existing directory")
        # Resolve once; every later comparison is against this canonical path.
        self.root = root_path.resolve(strict=True)
        self.suffixes = tuple(s.lower() for s in suffixes)
        self.max_files = max_files
        self.max_bytes_per_file = max_bytes_per_file
        self.follow_symlinks = follow_symlinks
        self.ignored_dirs = ignored_dirs
        self.skipped: list[dict[str, str]] = []

    def _is_inside_root(self, candidate: Path) -> bool:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        return resolved == self.root or self.root in resolved.parents

    def iter_documents(self) -> Iterator[DirectoryDocument]:
        count = 0
        for path in sorted(self.root.rglob("*")):
            if count >= self.max_files:
                self.skipped.append({"path": str(path), "reason": "max_files_reached"})
                break

            relative_parts = path.relative_to(self.root).parts
            if any(part in self.ignored_dirs for part in relative_parts[:-1]):
                continue
            if path.name in self.ignored_dirs:
                continue

            if path.is_symlink() and not self.follow_symlinks:
                self.skipped.append({"path": str(path), "reason": "symlink_skipped"})
                continue
            if (
                any(
                    (self.root / Path(*relative_parts[: i + 1])).is_symlink()
                    for i in range(len(relative_parts) - 1)
                )
                and not self.follow_symlinks
            ):
                self.skipped.append({"path": str(path), "reason": "symlinked_parent_skipped"})
                continue
            if not path.is_file():
                continue
            if path.suffix.lower() not in self.suffixes:
                self.skipped.append({"path": str(path), "reason": "suffix_not_allowed"})
                continue
            if not self._is_inside_root(path):
                self.skipped.append({"path": str(path), "reason": "resolved_outside_root"})
                continue

            size = path.stat().st_size
            if size > self.max_bytes_per_file:
                self.skipped.append({"path": str(path), "reason": "file_too_large"})
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError) as exc:
                self.skipped.append(
                    {"path": str(path), "reason": f"unreadable: {type(exc).__name__}"}
                )
                continue
            if not text.strip():
                continue

            relative = "/".join(path.relative_to(self.root).parts)
            count += 1
            yield DirectoryDocument(
                path=path,
                relative_path=relative,
                title=path.stem.replace("-", " ").replace("_", " ").strip() or relative,
                text=text,
                size_bytes=size,
            )
