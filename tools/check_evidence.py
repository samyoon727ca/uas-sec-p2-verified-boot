#!/usr/bin/env python3
"""Check that the committed evidence is byte for byte what evidence/SHA256SUMS records.

A run folder is committed once, as the run produced it, and never edited
afterwards (docs/06 section 6.4). evidence/SHA256SUMS lists the SHA-256 of
every file in every run folder, in sha256sum's format with paths relative to
evidence/. This check fails if a listed file is missing or changed, or if a
run folder holds a file that is not listed.

    python tools/check_evidence.py                              # check
    python tools/check_evidence.py --add ve07-ci/20261013-d9149f6   # list a new run folder

--add appends the files of one run folder and refuses to touch a folder that
is already listed, so existing entries are never rewritten.

Exits 1 on any difference. Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "SHA256SUMS"
LINE = re.compile(r"^([0-9a-f]{64})  (\S.*)$")
RUN_FOLDER = re.compile(r"^ve\d{2}-(ci|hw)/\d{8}-[0-9a-f]{7,40}$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_files(evidence: Path) -> list[str]:
    """Every file in a run folder (evidence/<event>-<kind>/<run>/...), relative to evidence/."""
    return sorted(p.relative_to(evidence).as_posix() for p in evidence.glob("*/*/**/*") if p.is_file())


def read_manifest(evidence: Path) -> tuple[dict[str, str], list[str]]:
    listed: dict[str, str] = {}
    errors = []
    path = evidence / MANIFEST
    if not path.is_file():
        return listed, [f"{MANIFEST}: file not found"]
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        m = LINE.match(line)
        if not m:
            errors.append(f"{MANIFEST}:{n}: not a sha256sum line")
        elif m.group(2) in listed:
            errors.append(f"{MANIFEST}:{n}: {m.group(2)} is listed twice")
        else:
            listed[m.group(2)] = m.group(1)
    return listed, errors


def check(evidence: Path) -> list[str]:
    listed, errors = read_manifest(evidence)
    present = set(run_files(evidence))
    for rel, want in listed.items():
        if rel not in present:
            errors.append(f"{rel}: listed in {MANIFEST} but missing")
        elif sha256(evidence / rel) != want:
            errors.append(f"{rel}: changed since it was recorded in {MANIFEST}")
    errors += [f"{rel}: not listed in {MANIFEST}" for rel in sorted(present - set(listed))]
    return errors


def add(evidence: Path, folder: str) -> list[str]:
    folder = folder.strip("/")
    if not RUN_FOLDER.match(folder):
        return [f"{folder}: not a run folder (<event>-<ci|hw>/<YYYYMMDD>-<commit>)"]
    listed, errors = read_manifest(evidence) if (evidence / MANIFEST).is_file() else ({}, [])
    if errors:
        return errors
    if any(rel.startswith(folder + "/") for rel in listed):
        return [f"{folder}: already listed in {MANIFEST}; existing entries are never rewritten"]
    new = [rel for rel in run_files(evidence) if rel.startswith(folder + "/")]
    if not new:
        return [f"{folder}: no files found"]
    with (evidence / MANIFEST).open("a", encoding="utf-8", newline="\n") as f:
        for rel in new:
            f.write(f"{sha256(evidence / rel)}  {rel}\n")
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--add", metavar="FOLDER", help="append one new run folder, relative to evidence/")
    args = parser.parse_args(argv)
    evidence = args.root / "evidence"
    errors = add(evidence, args.add) if args.add else check(evidence)
    for e in errors:
        print(f"ERROR   {e}")
    listed, _ = read_manifest(evidence)
    if args.add:
        folder = args.add.strip("/")
        print(f"{'FAIL' if errors else 'added'}: {sum(rel.startswith(folder + '/') for rel in listed)} "
              f"file(s) of {folder} listed")
    else:
        print(f"{'FAIL' if errors else 'PASS'}: {len(listed)} evidence file(s) listed, {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
