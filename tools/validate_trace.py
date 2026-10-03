#!/usr/bin/env python3
"""Validate P2 traceability data against the pinned P1 snapshot.

P2 adds child requirements (refinements of P1 requirements whose evidence
repo is P2), traces each child to its parent's P1 threats, and defines the
test cases that produce evidence for P1's verification events. Every ID that
P2 cites from P1 must exist in data/p1/, a byte-for-byte copy of P1 at the
commit named in data/p1/pin.txt (tools/check_p1_snapshot.py checks the copy).

Exits 1 if any error is found. Standard library only.

Usage:
    python tools/validate_trace.py [--root .]
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCHEMAS = {
    "requirements.csv": [
        "req_id", "parent_req", "statement", "rationale", "allocated_to", "verification",
    ],
    "trace.csv": ["req_id", "threat_id"],
    "testcases.csv": [
        "tc_id", "ve_id", "title", "verifies", "procedure", "pass_criteria",
        "ci_status", "hw_status", "ci_evidence", "hw_evidence",
    ],
}

# Columns P2 reads from each P1 file. P1 may add columns; it may not drop these.
P1_COLUMNS = {
    "requirements.csv": ["req_id", "statement", "allocated_to", "verification", "evidence_repo"],
    "threats.csv": ["threat_id", "title"],
    "trace.csv": ["threat_id", "req_id"],
    "verification.csv": ["ve_id", "title", "method", "evidence_repo", "req_ids", "status"],
}

THIS_REPO = "P2"
CHILD_ID = re.compile(r"^(SR-\d{3})\.\d+$")
TC_ID = re.compile(r"^TC-\d{2}$")
SHALL = re.compile(r"\bshall\b", re.IGNORECASE)
TC_STATUS = {"planned", "passed", "failed", "n/a"}
EVIDENCE_DIR = "evidence/"


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.summary = ""

    def error(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")


def split_multi(value: str) -> list[str]:
    """Split a semicolon-separated cell into trimmed, non-empty values."""
    return [v.strip() for v in value.split(";") if v.strip()]


def load(path: Path, columns: list[str], exact: bool, report: Report) -> list[dict] | None:
    """Load a CSV as dicts with a '_where' locator. None if unusable."""
    label = f"{path.parent.name}/{path.name}" if path.parent.name == "p1" else path.name
    if not path.is_file():
        report.error(label, "file not found")
        return None
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        if exact and fields != columns:
            report.error(label, f"header must be exactly: {','.join(columns)}")
            return None
        missing = [c for c in columns if c not in fields]
        if missing:
            report.error(label, f"missing columns: {', '.join(missing)}")
            return None
        rows = []
        for line, row in enumerate(reader, start=2):
            if None in row:
                report.error(f"{label}:{line}", "more cells than header columns")
                continue
            clean = {k: (v or "").strip() for k, v in row.items()}
            clean["_where"] = f"{label}:{line}"
            rows.append(clean)
        return rows


def index_unique(rows: list[dict], key: str, pattern, report: Report) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for row in rows:
        rid = row[key]
        if pattern is not None and not pattern.match(rid):
            report.error(row["_where"], f"malformed {key} '{rid}'")
            continue
        if rid in index:
            report.error(row["_where"], f"duplicate {key} '{rid}' (first at {index[rid]['_where']})")
            continue
        index[rid] = row
    return index


class P1:
    """The pinned P1 snapshot, indexed."""

    def __init__(self, rows: dict[str, list[dict]]) -> None:
        self.reqs = {r["req_id"]: r for r in rows["requirements.csv"]}
        self.threats = {t["threat_id"]: t for t in rows["threats.csv"]}
        self.parents: dict[str, set[str]] = {}
        for link in rows["trace.csv"]:
            self.parents.setdefault(link["req_id"], set()).add(link["threat_id"])
        self.events = {v["ve_id"]: v for v in rows["verification.csv"]}
        self.own_reqs = {rid for rid, r in self.reqs.items() if r["evidence_repo"] == THIS_REPO}
        self.own_events = {vid for vid, v in self.events.items() if v["evidence_repo"] == THIS_REPO}

    def event_reqs(self, ve_id: str) -> set[str]:
        return set(split_multi(self.events[ve_id]["req_ids"]))


def check_requirements(rows: list[dict], p1: P1, report: Report) -> dict[str, dict]:
    index = index_unique(rows, "req_id", CHILD_ID, report)
    for rid, row in index.items():
        where = row["_where"]
        for name in ("statement", "rationale"):
            if not row[name]:
                report.error(where, f"'{name}' is required")
        shalls = len(SHALL.findall(row["statement"]))
        if row["statement"] and shalls != 1:
            report.error(where, f"statement must contain exactly one 'shall' (found {shalls})")
        parent_id = row["parent_req"]
        parent = p1.reqs.get(parent_id)
        if parent is None:
            report.error(where, f"parent_req '{parent_id}' is not a P1 requirement")
            continue
        if CHILD_ID.match(rid).group(1) != parent_id:
            report.error(where, f"{rid} must be numbered under its parent {parent_id}")
        if parent["evidence_repo"] != THIS_REPO:
            report.error(where, f"parent {parent_id} has evidence repo {parent['evidence_repo']}, not {THIS_REPO}")
        if row["allocated_to"] != parent["allocated_to"]:
            report.error(where, f"allocated_to '{row['allocated_to']}' must match parent {parent_id} "
                                f"({parent['allocated_to']})")
        if row["verification"] != parent["verification"]:
            report.error(where, f"verification '{row['verification']}' must match parent {parent_id} "
                                f"({parent['verification']})")
    return index


def check_trace(rows: list[dict], children: dict, p1: P1, report: Report) -> set[tuple[str, str]]:
    links: dict[tuple[str, str], str] = {}
    for row in rows:
        where, rid, tid = row["_where"], row["req_id"], row["threat_id"]
        if rid not in children:
            report.error(where, f"req_id '{rid}' is not a P2 child requirement")
            continue
        if tid not in p1.threats:
            report.error(where, f"threat_id '{tid}' is not a P1 threat")
            continue
        parent_id = children[rid]["parent_req"]
        if tid not in p1.parents.get(parent_id, set()):
            report.error(where, f"{tid} is not a parent threat of {parent_id} in P1; "
                                f"propose the change in P1 instead of diverging")
            continue
        if (rid, tid) in links:
            report.error(where, f"duplicate link {rid} -> {tid} (first at {links[(rid, tid)]})")
            continue
        links[(rid, tid)] = where
    traced = {rid for rid, _ in links}
    for rid, row in children.items():
        if rid not in traced:
            report.error(row["_where"], f"{rid} has no parent threat in trace.csv")
    return set(links)


def check_testcases(rows: list[dict], children: dict, p1: P1, root: Path, report: Report) -> dict[str, dict]:
    index = index_unique(rows, "tc_id", TC_ID, report)
    covered: set[str] = set()
    hw_events: set[str] = set()
    for row in index.values():
        where, ve_id = row["_where"], row["ve_id"]
        for name in ("title", "procedure", "pass_criteria"):
            if not row[name]:
                report.error(where, f"'{name}' is required")
        if ve_id not in p1.own_events:
            report.error(where, f"ve_id '{ve_id}' is not a P1 verification event with evidence repo {THIS_REPO}")
            continue
        ve_reqs = p1.event_reqs(ve_id)
        ids = split_multi(row["verifies"])
        if not ids:
            report.error(where, "'verifies' is required")
        for rid in ids:
            if rid in children:
                parent_id = children[rid]["parent_req"]
                if parent_id not in ve_reqs:
                    report.error(where, f"{rid} refines {parent_id}, which {ve_id} does not verify")
                    continue
            elif rid in p1.reqs:
                if rid not in ve_reqs:
                    report.error(where, f"{rid} is not verified by {ve_id} in P1")
                    continue
            else:
                report.error(where, f"'{rid}' is neither a P2 child nor a P1 requirement")
                continue
            covered.add(rid)
        statuses = {}
        for env in ("ci", "hw"):
            status, evidence = row[f"{env}_status"], row[f"{env}_evidence"]
            statuses[env] = status
            if status not in TC_STATUS:
                report.error(where, f"{env}_status '{status}' must be one of {sorted(TC_STATUS)}")
                continue
            if status in ("passed", "failed"):
                if not evidence:
                    report.error(where, f"{env}_status is {status} but {env}_evidence is empty")
                elif not evidence.startswith(EVIDENCE_DIR):
                    report.error(where, f"{env}_evidence '{evidence}' must be under {EVIDENCE_DIR}")
                elif not (root / evidence).exists():
                    report.error(where, f"{env}_evidence '{evidence}' does not exist")
            elif evidence:
                report.error(where, f"{env}_evidence must be empty while {env}_status is {status}")
        if statuses.get("ci") == "n/a" and statuses.get("hw") == "n/a":
            report.error(where, "a test case must run in CI, on hardware, or both")
        if statuses.get("hw") in TC_STATUS - {"n/a"}:
            hw_events.add(ve_id)

    for rid, row in children.items():
        if rid not in covered:
            report.error(row["_where"], f"{rid} is not verified by any test case")
    for rid in sorted(p1.own_reqs - covered):
        report.error("testcases.csv", f"P1 requirement {rid} (evidence repo {THIS_REPO}) is not verified by any test case")
    for ve_id in sorted(p1.own_events - hw_events):
        report.error("testcases.csv", f"{ve_id} has no hardware test case; P1 verifies it on the device")
    return index


def validate(root: Path) -> Report:
    report = Report()
    data = root / "data"
    p1_rows = {name: load(data / "p1" / name, cols, False, report) for name, cols in P1_COLUMNS.items()}
    p2_rows = {name: load(data / name, cols, True, report) for name, cols in SCHEMAS.items()}
    if any(rows is None for rows in (*p1_rows.values(), *p2_rows.values())):
        return report

    p1 = P1(p1_rows)
    if not p1.own_reqs:
        report.error("p1/requirements.csv", f"no P1 requirement names {THIS_REPO} as its evidence repo")
    children = check_requirements(p2_rows["requirements.csv"], p1, report)
    links = check_trace(p2_rows["trace.csv"], children, p1, report)
    cases = check_testcases(p2_rows["testcases.csv"], children, p1, root, report)

    report.summary = (
        f"P1 parents {', '.join(sorted(p1.own_reqs))} ({', '.join(sorted(p1.own_events))}); "
        f"{len(children)} child requirements, {len(links)} trace links, {len(cases)} test cases"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    args = parser.parse_args(argv)

    report = validate(args.root)
    for e in report.errors:
        print(f"ERROR   {e}")
    if report.summary:
        print(report.summary)
    print(f"{'FAIL' if report.errors else 'PASS'}: {len(report.errors)} error(s)")
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
