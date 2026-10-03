#!/usr/bin/env python3
"""Render generated Markdown views from data/*.csv into the README and docs.

Views are written between marker comments:
    <!-- BEGIN GENERATED: <name> -->  ...  <!-- END GENERATED: <name> -->

    python tools/render_views.py           # rewrite the views in place
    python tools/render_views.py --check   # exit 1 if any view is out of date

Standard library only.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
sys.path.insert(0, str(ROOT / "tools"))
from validate_trace import THIS_REPO, split_multi  # noqa: E402

STATUS_LABEL = {"passed": "passed", "failed": "**failed**", "planned": "planned", "n/a": "–"}


def read(name: str) -> list[dict]:
    with (DATA / name).open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def cell(text: str) -> str:
    return text.replace("|", "\\|")


def link(status: str, evidence: str, depth: str) -> str:
    label = STATUS_LABEL.get(status, status)
    return f"[{label}]({depth}{evidence})" if evidence else label


def rollup(cases: list[dict]) -> dict:
    """Combine test-case results into one status per verification event.

    An event is passed only when every applicable CI and hardware run has
    passed, failed if any run failed, in progress if some have passed, and
    planned otherwise.
    """
    counts = {}
    for env in ("ci", "hw"):
        runs = [c[f"{env}_status"] for c in cases if c[f"{env}_status"] != "n/a"]
        counts[env] = (sum(s == "passed" for s in runs), len(runs), sum(s == "failed" for s in runs))
    passed = sum(c[0] for c in counts.values())
    total = sum(c[1] for c in counts.values())
    failed = sum(c[2] for c in counts.values())
    if failed:
        status = "failed"
    elif total and passed == total:
        status = "passed"
    elif passed:
        status = "in progress"
    else:
        status = "planned"
    return {"status": status, **counts}


def ve_status() -> str:
    events = [e for e in read("p1/verification.csv") if e["evidence_repo"] == THIS_REPO]
    cases = read("testcases.csv")
    lines = [
        "| Event | Verifies (P1) | CI runs passed | Hardware runs passed | P2 status | P1 status |",
        "|---|---|---|---|---|---|",
    ]
    for e in events:
        r = rollup([c for c in cases if c["ve_id"] == e["ve_id"]])
        lines.append(
            f"| {e['ve_id']} {cell(e['title'])} | {', '.join(split_multi(e['req_ids']))} | "
            f"{r['ci'][0]} of {r['ci'][1]} | {r['hw'][0]} of {r['hw'][1]} | {r['status']} | {e['status']} |"
        )
    return "\n".join(lines)


def child_requirements() -> str:
    reqs = read("requirements.csv")
    threats: dict[str, list[str]] = {}
    for t in read("trace.csv"):
        threats.setdefault(t["req_id"], []).append(t["threat_id"])
    cases: dict[str, list[str]] = {}
    for c in read("testcases.csv"):
        for rid in split_multi(c["verifies"]):
            cases.setdefault(rid, []).append(c["tc_id"])
    lines = [
        f"{len(reqs)} child requirements.",
        "",
        "| ID | Requirement | Parent | Parent threats | Verified by |",
        "|---|---|---|---|---|",
    ]
    for r in reqs:
        lines.append(
            f"| {r['req_id']} | {cell(r['statement'])} | {r['parent_req']} | "
            f"{', '.join(threats.get(r['req_id'], []))} | {', '.join(cases.get(r['req_id'], []))} |"
        )
    return "\n".join(lines)


def test_cases() -> str:
    cases = read("testcases.csv")
    lines = [
        f"{len(cases)} test cases. Status links point to the evidence.",
        "",
        "| ID | Event | Test case | Verifies | CI | Hardware | Pass criteria |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in cases:
        lines.append(
            f"| {c['tc_id']} | {c['ve_id']} | {cell(c['title'])} | {', '.join(split_multi(c['verifies']))} | "
            f"{link(c['ci_status'], c['ci_evidence'], '../')} | {link(c['hw_status'], c['hw_evidence'], '../')} | "
            f"{cell(c['pass_criteria'])} |"
        )
    return "\n".join(lines)


VIEWS = {
    "ve-status": [ROOT / "README.md", ROOT / "docs/06-verification.md"],
    "child-requirements": [ROOT / "docs/01-scope-and-trace.md"],
    "test-cases": [ROOT / "docs/06-verification.md"],
}
RENDER = {"ve-status": ve_status, "child-requirements": child_requirements, "test-cases": test_cases}


def splice(text: str, name: str, body: str) -> str:
    pattern = re.compile(
        rf"(<!-- BEGIN GENERATED: {re.escape(name)} -->\n)(?:.*?\n)?(<!-- END GENERATED: {re.escape(name)} -->)",
        re.S,
    )
    if not pattern.search(text):
        raise SystemExit(f"markers for view '{name}' not found")
    return pattern.sub(lambda m: m.group(1) + body + "\n" + m.group(2), text, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if any generated view is out of date")
    args = parser.parse_args(argv)

    stale = []
    for name, paths in VIEWS.items():
        body = RENDER[name]()
        for path in paths:
            text = path.read_text(encoding="utf-8")
            new = splice(text, name, body)
            if new != text:
                stale.append(f"{path.relative_to(ROOT)} ({name})")
                if not args.check:
                    path.write_text(new, encoding="utf-8")
    if args.check and stale:
        for s in stale:
            print(f"STALE   {s}: run python tools/render_views.py")
        return 1
    print("views up to date" if args.check else f"rendered {len(VIEWS)} view(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
