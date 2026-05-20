"""Unified-diff parser. Just enough to map each added line back to its
line number in the post-change file, so inline comments land correctly.

We do NOT use a third-party diff lib — keeping the dependency surface
small matters in a tool that may be installed into CI images."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch

_FILE_HEADER_RE = re.compile(r"^diff --git a/(?P<old>.+?) b/(?P<new>.+?)$")
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


@dataclass
class DiffLine:
    new_lineno: int | None  # None for deletions
    old_lineno: int | None  # None for additions
    kind: str  # "+", "-", " "
    content: str


@dataclass
class DiffHunk:
    new_start: int
    new_count: int
    old_start: int
    old_count: int
    lines: list[DiffLine] = field(default_factory=list)


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False
    hunks: list[DiffHunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path if not self.is_deleted else self.old_path

    def added_line_numbers(self) -> list[int]:
        return [
            ln.new_lineno
            for h in self.hunks
            for ln in h.lines
            if ln.kind == "+" and ln.new_lineno is not None
        ]

    def added_lines(self) -> list[tuple[int, str]]:
        return [
            (ln.new_lineno, ln.content)
            for h in self.hunks
            for ln in h.lines
            if ln.kind == "+" and ln.new_lineno is not None
        ]


def _strip_prefix(path: str) -> str:
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def parse_unified_diff(diff: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    current_hunk: DiffHunk | None = None
    new_lineno = 0
    old_lineno = 0

    for raw in diff.splitlines():
        # --- file header ---
        m = _FILE_HEADER_RE.match(raw)
        if m:
            if current is not None:
                files.append(current)
            current = FileDiff(
                old_path=_strip_prefix(m.group("old")),
                new_path=_strip_prefix(m.group("new")),
            )
            current_hunk = None
            continue

        if current is None:
            continue

        if raw.startswith("new file mode"):
            current.is_new = True
            continue
        if raw.startswith("deleted file mode"):
            current.is_deleted = True
            continue
        if raw.startswith("Binary files") or raw.startswith("GIT binary patch"):
            current.is_binary = True
            continue
        if raw.startswith(("--- ", "+++ ", "index ", "similarity ", "rename ")):
            continue

        # --- hunk header ---
        m = _HUNK_HEADER_RE.match(raw)
        if m:
            current_hunk = DiffHunk(
                new_start=int(m.group("new_start")),
                new_count=int(m.group("new_count") or 1),
                old_start=int(m.group("old_start")),
                old_count=int(m.group("old_count") or 1),
            )
            current.hunks.append(current_hunk)
            new_lineno = current_hunk.new_start
            old_lineno = current_hunk.old_start
            continue

        if current_hunk is None:
            continue

        if not raw:
            # blank line inside hunk is a context line with empty content
            current_hunk.lines.append(DiffLine(
                new_lineno=new_lineno, old_lineno=old_lineno, kind=" ", content=""
            ))
            new_lineno += 1
            old_lineno += 1
            continue

        kind = raw[0]
        content = raw[1:]
        if kind == "+":
            current_hunk.lines.append(DiffLine(
                new_lineno=new_lineno, old_lineno=None, kind="+", content=content
            ))
            new_lineno += 1
        elif kind == "-":
            current_hunk.lines.append(DiffLine(
                new_lineno=None, old_lineno=old_lineno, kind="-", content=content
            ))
            old_lineno += 1
        elif kind == " ":
            current_hunk.lines.append(DiffLine(
                new_lineno=new_lineno, old_lineno=old_lineno, kind=" ", content=content
            ))
            new_lineno += 1
            old_lineno += 1
        elif kind == "\\":
            # "\ No newline at end of file" — ignore.
            continue

    if current is not None:
        files.append(current)
    return files


def filter_files(files: list[FileDiff], ignore_globs: list[str]) -> list[FileDiff]:
    if not ignore_globs:
        return files
    kept: list[FileDiff] = []
    for f in files:
        path = f.path
        if any(fnmatch(path, g) for g in ignore_globs):
            continue
        kept.append(f)
    return kept
