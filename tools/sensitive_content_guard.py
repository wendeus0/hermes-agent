#!/usr/bin/env python3
"""Sensitive content scanner for staged files or explicit paths.

Usage:
  python tools/sensitive_content_guard.py --staged
  python tools/sensitive_content_guard.py path/to/file [path/to/file2 ...]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from typing import Iterable

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("ghp_token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    (
        "api_key_assignment",
        re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"][^'\"]{16,}['\"]"),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._-]{16,}"),
    ),
    ("private_key_block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----")),
    (
        "sensitive_pem_path",
        re.compile(
            r"(?i)\b(identityfile|ssl[_-]?key|private[_-]?key|client[_-]?key|tls[_-]?key|keyfile)\b[^\n]{0,120}\.pem\b"
        ),
    ),
]

ALLOWLIST_PREFIXES = (
    "docs/examples/",
    "tests/fixtures/",
    ".github/workflows/",
)


def staged_files() -> list[pathlib.Path]:
    out = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"], text=True
    )
    result: list[pathlib.Path] = []
    for line in out.splitlines():
        p = pathlib.Path(line.strip())
        if p.exists() and p.is_file():
            result.append(p)
    return result


def iter_lines(path: pathlib.Path) -> Iterable[tuple[int, str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    return enumerate(text.splitlines(), start=1)


def allowlisted(path: pathlib.Path) -> bool:
    norm = str(path).replace("\\", "/")
    return any(norm.startswith(prefix) or f"/{prefix}" in norm for prefix in ALLOWLIST_PREFIXES)


def scan(paths: list[pathlib.Path]) -> list[dict]:
    findings: list[dict] = []
    for path in paths:
        if allowlisted(path):
            continue
        for line_no, line in iter_lines(path):
            for rule_name, rx in PATTERNS:
                if rx.search(line):
                    findings.append(
                        {
                            "file": str(path),
                            "line": line_no,
                            "pattern": rule_name,
                            "snippet": line[:220],
                        }
                    )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--staged", action="store_true")
    args = parser.parse_args()

    if args.staged:
        paths = staged_files()
    else:
        paths = [pathlib.Path(p) for p in args.paths]

    findings = scan(paths)
    if not findings:
        print("sensitive-content-guard: ok")
        return 0

    print("sensitive-content-guard: blocked")
    for f in findings:
        print(f"- {f['file']}:{f['line']} [{f['pattern']}] {f['snippet']}")
    print("\nRemova/mascare conteúdos sensíveis ou ajuste allowlist com parcimônia.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
