"""Unit tests for tools/render_views.py."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import render_views as rv  # noqa: E402

B, E = "<!-- BEGIN GENERATED: v -->", "<!-- END GENERATED: v -->"


def tc(ci, hw):
    return {"ci_status": ci, "hw_status": hw}


class SpliceTest(unittest.TestCase):
    def test_fills_empty_block(self):
        self.assertEqual(rv.splice(f"a\n{B}\n{E}\nz", "v", "body"), f"a\n{B}\nbody\n{E}\nz")

    def test_replaces_existing_block_and_is_idempotent(self):
        once = rv.splice(f"{B}\nold\nlines\n{E}", "v", "new")
        self.assertEqual(once, f"{B}\nnew\n{E}")
        self.assertEqual(rv.splice(once, "v", "new"), once)

    def test_missing_markers_fail(self):
        with self.assertRaises(SystemExit):
            rv.splice("no markers", "v", "body")


class RollupTest(unittest.TestCase):
    def test_all_planned(self):
        self.assertEqual(rv.rollup([tc("planned", "planned")])["status"], "planned")

    def test_ci_only_pass_is_in_progress(self):
        r = rv.rollup([tc("passed", "planned"), tc("n/a", "planned")])
        self.assertEqual(r["status"], "in progress")
        self.assertEqual(r["ci"], (1, 1, 0))
        self.assertEqual(r["hw"], (0, 2, 0))

    def test_passes_only_when_every_applicable_run_passed(self):
        self.assertEqual(rv.rollup([tc("passed", "passed"), tc("n/a", "passed")])["status"], "passed")

    def test_any_failure_fails(self):
        self.assertEqual(rv.rollup([tc("passed", "passed"), tc("failed", "n/a")])["status"], "failed")


class RepoViewsTest(unittest.TestCase):
    def test_views_are_current(self):
        self.assertEqual(rv.main(["--check"]), 0)


if __name__ == "__main__":
    unittest.main()
