"""Unit tests for model/run_tlc.py and model/ci.py. No network and no Java: TLC's output is canned."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "model"))
import ci as model_ci  # noqa: E402
import run_tlc  # noqa: E402

VIOLATION = 'Error: Invariant NoOldReleaseUnseals is violated.\nState 1: <Initial predicate>\n"CounterExample written: x"\n'


class ToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_pins_are_parsed_and_malformed_ones_refused(self):
        url, sha = run_tlc.read_pin()
        self.assertTrue(url.startswith("https://github.com/tlaplus/tlaplus/releases/download/") and len(sha) == 64)
        s = "\nsha256: " + "a" * 64
        for text in ("url: http://h/tla2tools.jar" + s, "url: https://h/x.jar" + s, "url: https://h/tla2tools.jar",
                     "url: https://h/tla2tools.jar" + s.upper(), "url: https://h/tla2tools.jar\n" + "a" * 64):
            (self.tmp / "p.pin").write_text("# comment\nversion: 1\n" + text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                run_tlc.read_pin(self.tmp / "p.pin")

    def test_jar_is_kept_only_if_its_hash_matches(self):
        (self.tmp / "tla2tools.jar").write_bytes(b"jar")
        url, cache = (self.tmp / "tla2tools.jar").as_uri(), self.tmp / "cache"
        with self.assertRaisesRegex(SystemExit, "refusing"):
            run_tlc.jar(url, "0" * 64, cache)
        self.assertEqual(list(cache.iterdir()), [])
        self.assertEqual(run_tlc.jar(url, hashlib.sha256(b"jar").hexdigest(), cache).read_bytes(), b"jar")
        (cache / f"tla2tools-{'0' * 16}.jar").write_bytes(b"jar")   # cached, so no download: no URLError
        with self.assertRaisesRegex(SystemExit, "refusing"):
            run_tlc.jar("https://invalid.invalid/tla2tools.jar", "0" * 64, cache)
        self.assertFalse((cache / f"tla2tools-{'0' * 16}.jar").exists())

    def test_tlc_outcomes(self):
        self.assertEqual(run_tlc.outcome(VIOLATION, 12), "NoOldReleaseUnseals")
        self.assertEqual(run_tlc.outcome("Error: Action property EpochMonotonic is violated.\n", 13), "EpochMonotonic")
        self.assertEqual(run_tlc.outcome("Error: Invariant Inv is violated by the initial state:\nx = 0\n", 12), "Inv")
        self.assertEqual(run_tlc.outcome(run_tlc.PASSED + "\n11749 distinct states found\n", 0), "pass")
        for stdout, rc in (("Parsing or semantic analysis failed.\n", 255), (run_tlc.PASSED, 1), (VIOLATION, 0),
                           (VIOLATION + VIOLATION.replace("NoOld", "Other"), 12)):
            with self.subTest(stdout=stdout, rc=rc), self.assertRaises(RuntimeError):
                run_tlc.outcome(stdout, rc)

    def test_configs_are_checked(self):
        self.assertEqual(model_ci.load_configs()[0], {"spec": "Epoch.tla", "cfg": "Epoch.cfg", "expect": "NoOldReleaseUnseals"})
        (self.tmp / "M.tla").write_text("")
        (self.tmp / "M.cfg").write_text("INVARIANT Inv\n")
        good = {"spec": "M.tla", "cfg": "M.cfg", "expect": "Inv"}
        for entries, ok in (([good], True), ([dict(good, expect="pass")], True), ({}, False), ([], False),
                            ([dict(good, extra="x")], False), ([dict(good, expect=1)], False), ([good, good], False),
                            ([dict(good, spec="../M.tla")], False), ([dict(good, cfg="N.cfg")], False),
                            ([dict(good, cfg=["M.cfg"])], False)):
            (self.tmp / "configs.json").write_text(json.dumps(entries))
            with self.subTest(entries=entries):
                if ok:
                    self.assertEqual(model_ci.load_configs(self.tmp / "configs.json"), entries)
                else:
                    self.assertRaises(ValueError, model_ci.load_configs, self.tmp / "configs.json")


if __name__ == "__main__":
    unittest.main()
