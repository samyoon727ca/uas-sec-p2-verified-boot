#!/usr/bin/env python3
"""Fail if any tracked or untracked, non-ignored file contains private key material.

Outside a git checkout it scans every file under --root except .git and
Python's compiled caches.

P2 uses dev/test keys that are generated per run or held locally; none may be
committed. This catches PEM/OpenSSH/TSS private keys, PX4 secure-boot key
files (JSON with a 32-byte hex "private" value) and WireGuard private keys in
wg-quick form ("PrivateKey = <base64>"). It cannot recognize raw key bytes,
such as a MAVLink signing key; harnesses record only their SHA-256.
Standard library only.

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
    # wg-quick configuration: a 32-byte key in base64 is 43 characters and one "=".
    "WireGuard private key": re.compile(rb"Private" + rb"Key\s*=\s*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]="),
}


SKIPPED_OUTSIDE_GIT = {".git", "__pycache__"}


def tracked_files(root: Path) -> list[Path]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"], check=True,
                             capture_output=True).stdout
        return [root / p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        # Not a git checkout: an exported tree, or an evidence folder a harness just wrote. Everything
        # is scanned, a local keys/ folder included, except Python's compiled caches: the compiled
        # unit test of this scanner holds the very patterns it searches for.
        return [p for p in root.rglob("*") if p.is_file() and not SKIPPED_OUTSIDE_GIT.intersection(p.parts)
                and p.suffix != ".pyc"]


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
