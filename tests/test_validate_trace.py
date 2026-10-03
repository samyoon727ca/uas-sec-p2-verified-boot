"""Unit tests for tools/validate_trace.py. Run: python -m unittest discover -s tests"""
from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import validate_trace as vt  # noqa: E402

P1_HEADERS = {
    "requirements.csv": ["req_id", "statement", "rationale", "allocated_to", "verification",
                         "evidence_repo", "resiliency_approach"],
    "threats.csv": ["threat_id", "title", "element_id", "stride"],
    "trace.csv": ["threat_id", "req_id"],
    "verification.csv": ["ve_id", "title", "method", "evidence_repo", "req_ids", "procedure",
                         "pass_criteria", "status"],
}


def p1_baseline():
    """A small P1 snapshot: SR-005 and SR-018 belong to P2, SR-001 to P3."""
    def req(rid, alloc, repo):
        return {"req_id": rid, "statement": "s", "rationale": "r", "allocated_to": alloc,
                "verification": "T", "evidence_repo": repo, "resiliency_approach": ""}
    return {
        "requirements.csv": [req("SR-005", "CMP-CC", "P2"), req("SR-018", "CMP-FC", "P2"),
                             req("SR-001", "CMP-CC", "P3")],
        "threats.csv": [{"threat_id": t, "title": t, "element_id": "CMP-CC", "stride": "T"}
                        for t in ("THR-008", "THR-030", "THR-001")],
        "trace.csv": [{"threat_id": "THR-008", "req_id": "SR-005"},
                      {"threat_id": "THR-030", "req_id": "SR-018"},
                      {"threat_id": "THR-001", "req_id": "SR-001"}],
        "verification.csv": [
            {"ve_id": "VE-07", "title": "t", "method": "T", "evidence_repo": "P2", "req_ids": "SR-005",
             "procedure": "p", "pass_criteria": "c", "status": "planned"},
            {"ve_id": "VE-08", "title": "t", "method": "T", "evidence_repo": "P2", "req_ids": "SR-018",
             "procedure": "p", "pass_criteria": "c", "status": "planned"},
            {"ve_id": "VE-01", "title": "t", "method": "T", "evidence_repo": "P3", "req_ids": "SR-001",
             "procedure": "p", "pass_criteria": "c", "status": "planned"},
        ],
    }


def child(rid, parent="SR-005", **kw):
    row = {"req_id": rid, "parent_req": parent, "statement": "The CC shall do X.", "rationale": "r",
           "allocated_to": "CMP-CC", "verification": "T"}
    row.update(kw)
    return row


def case(tcid, ve, verifies, **kw):
    row = {c: "" for c in vt.SCHEMAS["testcases.csv"]}
    row.update(tc_id=tcid, ve_id=ve, title="t", verifies=verifies, procedure="p", pass_criteria="c",
               ci_status="planned", hw_status="planned")
    row.update(kw)
    return row


def p2_baseline():
    return {
        "requirements.csv": [child("SR-005.1")],
        "trace.csv": [{"req_id": "SR-005.1", "threat_id": "THR-008"}],
        "testcases.csv": [case("TC-01", "VE-07", "SR-005; SR-005.1"),
                          case("TC-02", "VE-08", "SR-018", ci_status="n/a")],
    }


def write(path: Path, header: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)


class ValidatorTest(unittest.TestCase):
    def run_validator(self, p2=None, p1=None, files=()):
        p2 = p2 if p2 is not None else p2_baseline()
        p1 = p1 if p1 is not None else p1_baseline()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, rows in p1.items():
                write(root / "data" / "p1" / name, P1_HEADERS[name], rows)
            for name, rows in p2.items():
                write(root / "data" / name, vt.SCHEMAS[name], rows)
            for rel in files:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("log\n")
            return vt.validate(root)

    def assertError(self, fragment, **kw):
        report = self.run_validator(**kw)
        self.assertTrue(any(fragment in e for e in report.errors),
                        f"expected error containing {fragment!r}, got {report.errors}")

    # --- baseline -------------------------------------------------------
    def test_baseline_is_valid(self):
        self.assertEqual(self.run_validator().errors, [])

    def test_p1_may_add_columns(self):
        p1 = p1_baseline()
        for row in p1["verification.csv"]:
            row["evidence"] = ""
        P1_HEADERS["verification.csv"].append("evidence")
        try:
            self.assertEqual(self.run_validator(p1=p1).errors, [])
        finally:
            P1_HEADERS["verification.csv"].remove("evidence")

    def test_p1_missing_column_is_rejected(self):
        p1 = p1_baseline()
        for row in p1["requirements.csv"]:
            del row["evidence_repo"]
        P1_HEADERS["requirements.csv"].remove("evidence_repo")
        try:
            self.assertError("missing columns: evidence_repo", p1=p1)
        finally:
            P1_HEADERS["requirements.csv"].insert(5, "evidence_repo")

    # --- child requirements --------------------------------------------
    def test_child_must_be_numbered_under_parent(self):
        p2 = p2_baseline()
        p2["requirements.csv"] = [child("SR-018.1", parent="SR-005")]
        p2["trace.csv"] = [{"req_id": "SR-018.1", "threat_id": "THR-008"}]
        p2["testcases.csv"][0]["verifies"] = "SR-005; SR-018.1"
        self.assertError("must be numbered under its parent SR-005", p2=p2)

    def test_malformed_child_id(self):
        p2 = p2_baseline()
        p2["requirements.csv"] = [child("SR-005a")]
        self.assertError("malformed req_id 'SR-005a'", p2=p2)

    def test_parent_must_belong_to_p2(self):
        p2 = p2_baseline()
        p2["requirements.csv"].append(child("SR-001.1", parent="SR-001"))
        self.assertError("parent SR-001 has evidence repo P3", p2=p2)

    def test_unknown_parent(self):
        p2 = p2_baseline()
        p2["requirements.csv"].append(child("SR-099.1", parent="SR-099"))
        self.assertError("parent_req 'SR-099' is not a P1 requirement", p2=p2)

    def test_exactly_one_shall(self):
        p2 = p2_baseline()
        p2["requirements.csv"][0]["statement"] = "The CC shall do X and shall do Y."
        self.assertError("exactly one 'shall' (found 2)", p2=p2)

    def test_component_must_match_parent(self):
        p2 = p2_baseline()
        p2["requirements.csv"][0]["allocated_to"] = "CMP-FC"
        self.assertError("allocated_to 'CMP-FC' must match parent SR-005", p2=p2)

    def test_method_must_match_parent(self):
        p2 = p2_baseline()
        p2["requirements.csv"][0]["verification"] = "I"
        self.assertError("verification 'I' must match parent SR-005", p2=p2)

    def test_duplicate_child(self):
        p2 = p2_baseline()
        p2["requirements.csv"].append(child("SR-005.1"))
        self.assertError("duplicate req_id 'SR-005.1'", p2=p2)

    # --- trace ----------------------------------------------------------
    def test_threat_outside_parent_set_is_rejected(self):
        p2 = p2_baseline()
        p2["trace.csv"].append({"req_id": "SR-005.1", "threat_id": "THR-030"})
        self.assertError("THR-030 is not a parent threat of SR-005", p2=p2)

    def test_unknown_threat(self):
        p2 = p2_baseline()
        p2["trace.csv"].append({"req_id": "SR-005.1", "threat_id": "THR-999"})
        self.assertError("threat_id 'THR-999' is not a P1 threat", p2=p2)

    def test_child_without_trace(self):
        p2 = p2_baseline()
        p2["trace.csv"] = []
        self.assertError("SR-005.1 has no parent threat", p2=p2)

    def test_duplicate_trace(self):
        p2 = p2_baseline()
        p2["trace.csv"].append({"req_id": "SR-005.1", "threat_id": "THR-008"})
        self.assertError("duplicate link SR-005.1 -> THR-008", p2=p2)

    # --- test cases -----------------------------------------------------
    def test_event_must_belong_to_p2(self):
        p2 = p2_baseline()
        p2["testcases.csv"].append(case("TC-03", "VE-01", "SR-001"))
        self.assertError("ve_id 'VE-01' is not a P1 verification event with evidence repo P2", p2=p2)

    def test_requirement_must_be_in_event(self):
        p2 = p2_baseline()
        p2["testcases.csv"][1]["verifies"] = "SR-018; SR-005"
        self.assertError("SR-005 is not verified by VE-08 in P1", p2=p2)

    def test_child_parent_must_be_in_event(self):
        p2 = p2_baseline()
        p2["testcases.csv"][1]["verifies"] = "SR-018; SR-005.1"
        self.assertError("SR-005.1 refines SR-005, which VE-08 does not verify", p2=p2)

    def test_passed_needs_evidence(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0]["ci_status"] = "passed"
        self.assertError("ci_status is passed but ci_evidence is empty", p2=p2)

    def test_evidence_must_exist(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0].update(ci_status="passed", ci_evidence="evidence/ve07-ci/run1")
        self.assertError("ci_evidence 'evidence/ve07-ci/run1' does not exist", p2=p2)

    def test_evidence_must_be_under_evidence_dir(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0].update(hw_status="failed", hw_evidence="logs/run1.log")
        self.assertError("must be under evidence/", p2=p2, files=["logs/run1.log"])

    def test_existing_evidence_is_accepted(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0].update(ci_status="passed", ci_evidence="evidence/ve07-ci/run1/summary.json")
        report = self.run_validator(p2=p2, files=["evidence/ve07-ci/run1/summary.json"])
        self.assertEqual(report.errors, [])

    def test_planned_with_evidence_is_rejected(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0]["ci_evidence"] = "evidence/x"
        self.assertError("ci_evidence must be empty while ci_status is planned", p2=p2)

    def test_bad_status(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0]["hw_status"] = "done"
        self.assertError("hw_status 'done' must be one of", p2=p2)

    def test_runs_nowhere(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0].update(ci_status="n/a", hw_status="n/a")
        self.assertError("must run in CI, on hardware, or both", p2=p2)

    def test_uncovered_child(self):
        p2 = p2_baseline()
        p2["testcases.csv"][0]["verifies"] = "SR-005"
        self.assertError("SR-005.1 is not verified by any test case", p2=p2)

    def test_uncovered_parent(self):
        p2 = p2_baseline()
        p2["testcases.csv"] = [case("TC-01", "VE-07", "SR-005; SR-005.1")]
        self.assertError("P1 requirement SR-018 (evidence repo P2) is not verified by any test case", p2=p2)

    def test_event_needs_hardware_case(self):
        p2 = p2_baseline()
        p2["testcases.csv"][1].update(ci_status="planned", hw_status="n/a")
        self.assertError("VE-08 has no hardware test case", p2=p2)

    def test_malformed_tc_id(self):
        p2 = p2_baseline()
        p2["testcases.csv"].append(case("TC-3", "VE-07", "SR-005"))
        self.assertError("malformed tc_id 'TC-3'", p2=p2)

    def test_wrong_header_is_rejected(self):
        p2 = p2_baseline()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, rows in p1_baseline().items():
                write(root / "data" / "p1" / name, P1_HEADERS[name], rows)
            for name, rows in p2.items():
                header = vt.SCHEMAS[name][::-1] if name == "trace.csv" else vt.SCHEMAS[name]
                write(root / "data" / name, header, rows)
            report = vt.validate(root)
        self.assertTrue(any("header must be exactly" in e for e in report.errors), report.errors)


class RepoDataTest(unittest.TestCase):
    def test_repository_data_is_valid(self):
        report = vt.validate(Path(__file__).resolve().parent.parent)
        self.assertEqual(report.errors, [])


if __name__ == "__main__":
    unittest.main()
