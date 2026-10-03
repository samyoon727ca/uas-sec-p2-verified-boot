#!/usr/bin/env python3
"""Check that data/p1/*.csv are byte-for-byte copies of P1 at the pinned commit.

Reads the repo and commit from data/p1/pin.txt and fetches each CSV from
raw.githubusercontent.com at that commit. Needs network access; CI runs it.
Exits 1 on any mismatch. Standard library only.

Usage:
    python tools/check_p1_snapshot.py
"""
from __future__ import annotations

import hashlib
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
P1_DIR = ROOT / "data" / "p1"
FILES = ["requirements.csv", "threats.csv", "trace.csv", "verification.csv"]
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def read_pin(path: Path) -> tuple[str, str]:
    fields = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    repo, commit = fields.get("repo", ""), fields.get("commit", "")
    if not re.match(r"^[\w.-]+/[\w.-]+$", repo) or not COMMIT.match(commit):
        raise SystemExit(f"{path.name}: needs 'repo: owner/name' and a full 40-character 'commit'")
    return repo, commit


def main() -> int:
    repo, commit = read_pin(P1_DIR / "pin.txt")
    bad = 0
    for name in FILES:
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/data/{name}"
        with urllib.request.urlopen(url, timeout=30) as resp:
            upstream = resp.read()
        local = (P1_DIR / name).read_bytes()
        same = upstream == local
        bad += not same
        print(f"{'OK   ' if same else 'DIFF '} {name} sha256 {hashlib.sha256(local).hexdigest()[:16]}"
              + ("" if same else f" (P1 {commit[:7]}: {hashlib.sha256(upstream).hexdigest()[:16]})"))
    print(f"{'PASS' if not bad else 'FAIL'}: data/p1 vs {repo}@{commit[:7]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
