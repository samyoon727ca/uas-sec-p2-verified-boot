"""Unit tests for tools/check_evidence.py."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import check_evidence as ce  # noqa: E402

RUN = "ve07-ci/20261013-d9149f6"


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.evidence = Path(self.tmp.name) / "evidence"
        self.write(f"{RUN}/summary.json", b"{}\n")
        self.write(f"{RUN}/TC-01.log", b"U-Boot\r\n")   # raw console output keeps its CRLF
        self.write("README.md", b"# Evidence\n")         # not in a run folder: not listed
        self.assertEqual(ce.add(self.evidence, RUN), [])

    def write(self, rel: str, data: bytes) -> None:
        path = self.evidence / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def assertError(self, fragment: str) -> None:
        errors = ce.check(self.evidence)
        self.assertTrue(any(fragment in e for e in errors), f"expected {fragment!r} in {errors}")

    def test_recorded_folder_passes(self):
        self.assertEqual(ce.check(self.evidence), [])
        listed, errors = ce.read_manifest(self.evidence)
        self.assertEqual((sorted(listed), errors), ([f"{RUN}/TC-01.log", f"{RUN}/summary.json"], []))

    def test_manifest_is_written_with_lf(self):
        self.assertNotIn(b"\r", (self.evidence / ce.MANIFEST).read_bytes())

    def test_changed_file_is_found(self):
        self.write(f"{RUN}/TC-01.log", b"U-Boot\n")
        self.assertError(f"{RUN}/TC-01.log: changed since it was recorded")

    def test_missing_file_is_found(self):
        (self.evidence / RUN / "TC-01.log").unlink()
        self.assertError(f"{RUN}/TC-01.log: listed in SHA256SUMS but missing")

    def test_unlisted_file_is_found(self):
        self.write(f"{RUN}/TC-99.log", b"added later\n")
        self.assertError(f"{RUN}/TC-99.log: not listed in SHA256SUMS")
        self.write("ve07-hw/20261120-0123abc/summary.json", b"{}\n")
        self.assertError("ve07-hw/20261120-0123abc/summary.json: not listed in SHA256SUMS")

    def test_missing_manifest_is_an_error(self):
        (self.evidence / ce.MANIFEST).unlink()
        self.assertError("SHA256SUMS: file not found")

    def test_malformed_and_duplicate_lines(self):
        manifest = self.evidence / ce.MANIFEST
        first = manifest.read_text().splitlines()[0]
        manifest.write_text(manifest.read_text() + "not a line\n" + first + "\n")
        self.assertError("SHA256SUMS:3: not a sha256sum line")
        self.assertError("is listed twice")

    def test_add_never_rewrites_a_listed_folder(self):
        self.write(f"{RUN}/TC-01.log", b"edited\n")
        self.assertIn("already listed", ce.add(self.evidence, RUN)[0])
        self.assertError("changed since it was recorded")

    def test_add_appends_a_new_folder(self):
        new = "ve08-ci/20261013-aac4299"
        self.write(f"{new}/summary.json", b"{}\n")
        self.assertEqual(ce.add(self.evidence, new + "/"), [])
        self.assertEqual(ce.check(self.evidence), [])

    def test_add_rejects_other_paths(self):
        self.assertIn("not a run folder", ce.add(self.evidence, "README.md")[0])
        self.assertIn("no files found", ce.add(self.evidence, "ve07-ci/20261011-7bc523b")[0])


class RepoEvidenceTest(unittest.TestCase):
    def test_repository_evidence_matches_its_manifest(self):
        self.assertEqual(ce.check(Path(__file__).resolve().parent.parent / "evidence"), [])


if __name__ == "__main__":
    unittest.main()
