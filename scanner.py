"""Walk a tree and collect secret-shaped findings."""

import fnmatch
import os
from typing import Iterator, List, Optional

import patterns

Finding = dict


def _load_ignore(root: str) -> List[str]:
    path = os.path.join(root, ".keyshapeignore")
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def _is_ignored(rel: str, ignore_globs: List[str]) -> bool:
    for g in ignore_globs:
        if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(os.path.basename(rel), g):
            return True
        # support directory globs like "tests/**"
        if g.endswith("**") and rel.startswith(g[:-2]):
            return True
    return False


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 4)


def iter_files(root: str, ignore_globs: List[str]) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        # prune ignored dirs
        dirnames[:] = [d for d in dirnames if d not in patterns.SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if _is_ignored(rel, ignore_globs):
                continue
            if fn in patterns.LOCK_NAMES:
                continue
            ext = os.path.splitext(fn)[1].lower()
            if ext in patterns.SKIP_EXT:
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > 1_000_000:
                continue
            yield full, rel


def scan_file(path: str, rel: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings
    for i, line in enumerate(lines, 1):
        if patterns.IGNORE_MARKER in line:
            continue
        # collect matches, dedupe overlapping spans (keep first pattern)
        matches = []
        for name, rx in patterns.PATTERNS:
            for m in rx.finditer(line):
                matches.append((m.start(), m.end(), name, m))
        matches.sort(key=lambda x: (x[0], -x[1]))
        chosen = []
        for start, end, name, m in matches:
            if any(not (end <= s or start >= e) for s, e, _, _ in chosen):
                continue
            chosen.append((start, end, name, m))
        for start, end, name, m in chosen:
            secret = m.group(1) if m.lastindex else m.group(0)
            findings.append({
                "file": rel,
                "line": i,
                "pattern": name,
                "snippet": _redact(secret),
                "context": line.strip()[:120],
            })
        # high-entropy check for keyword assignments not already caught
        # (covered by generic pattern; nothing extra)
    return findings


def scan(root: str, extra_ignore: Optional[List[str]] = None) -> List[Finding]:
    root = os.path.abspath(root)
    ignore_globs = _load_ignore(root)
    if extra_ignore:
        ignore_globs.extend(extra_ignore)
    results: List[Finding] = []
    for full, rel in iter_files(root, ignore_globs):
        results.extend(scan_file(full, rel))
    return results
