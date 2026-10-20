"""Regex patterns for secret-shaped strings."""

import re
from typing import List, Tuple

# (name, compiled regex). Each regex should capture the secret in group 0 or a
# named group "secret". We record the full match span for redaction.
PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws-secret-access-key", re.compile(
        r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("stripe-secret-key", re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("generic-secret-assignment", re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
            ".tar", ".gz", ".lock", ".woff", ".woff2", ".ttf", ".eot",
            ".pyc", ".so", ".dylib", ".exe", ".bin"}
LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "Pipfile.lock", "Cargo.lock", "Gemfile.lock", "composer.lock"}

IGNORE_MARKER = "keyshape:ignore"


def shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent
