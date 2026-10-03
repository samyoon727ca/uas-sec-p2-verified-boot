#!/usr/bin/env python3
"""Fail if any tracked or untracked, non-ignored file contains private key material.

P2 uses dev/test keys that are generated per run or held locally; none may be
committed. This catches PEM/OpenSSH/TSS private keys and PX4 secure-boot key
files (JSON with a 32-byte hex "private" value). Standard library only.

Usage:
    python tools/check_no_secrets.py [--root .]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Built from parts so this file does not match itself.
PATTERNS = {
    "PEM private key": re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*" + rb"PRIVATE KEY-----"),
    "PX4 secure-boot private key": re.compile(rb'"priv' + rb'ate"\s*:\s*"[0-9a-fA-F]{64}'),
}


def tracked_files(root: Path) -> list[Path]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"], check=True,
                             capture_output=True).stdout
        return [root / p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        return [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]


def scan(root: Path) -> list[str]:
    findings = []
    for path in tracked_files(root):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(data):
                findings.append(f"{path.relative_to(root)}: {label}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    findings = scan(args.root)
    for f in findings:
        print(f"ERROR   {f}")
    print(f"{'FAIL' if findings else 'PASS'}: {len(findings)} file(s) with private key material")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
