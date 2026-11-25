"""Unit tests for model/run_tlc.py, model/ci.py and model/trace_to_tpm2.py. No network, Java or swtpm: TLC's output
is canned, and traces are the committed A-01 fixture or edits of it."""
from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "model"))
import ci as model_ci  # noqa: E402
import run_tlc  # noqa: E402
import trace_to_tpm2  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "model" / "fixtures" / "a01-trace.json"
VIOLATION = 'Error: Invariant NoOldReleaseUnseals is violated.\nState 1: <Initial predicate>\n"CounterExample written: x"\n'


class ToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_pins_are_parsed_and_malformed_ones_refused(self):
        url, sha = run_tlc.read_pin()
        self.assertRegex(url, r"^https://\S+/[^/]*[0-9a-f]{7,40}/tla2tools\.jar$")   # names one commit's build
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


class TraceToTpm2Test(unittest.TestCase):
    def setUp(self):
        self.trace = json.loads(FIXTURE.read_text())

    def test_every_action_of_the_spec_has_a_mapping(self):
        spec = (run_tlc.ROOT / "model" / "Epoch.tla").read_text()
        actions = set(re.findall(r"(?:\\/|:)\s*([A-Za-z_]\w*)", spec[spec.index("\nNext =="):spec.index("\nSpec ==")]))
        self.assertEqual(actions, set(trace_to_tpm2.COMMANDS))

    def test_unknown_action_is_rejected_by_name(self):
        with self.assertRaisesRegex(trace_to_tpm2.TraceError, "no tpm2-tools mapping for action PCR_Extend"):
            trace_to_tpm2.commands("PCR_Extend", self.trace[0], self.trace[1], [])

    def test_step_no_action_explains_is_rejected(self):
        unexplained = dict(self.trace[1], ownerAuth="set")   # no action changes ownerAuth
        other = dict(self.trace[6], session=dict(self.trace[6]["session"], digest=["other"]))
        for trace, error in (([self.trace[0], unexplained], "state 2: no action .* changes committed, nv, ownerAuth"),
                             (self.trace[:6] + [other], "state 7: PolicyNV to a digest no release signs"),
                             ([self.trace[0], dict(self.trace[1], pcrs=[])], "state 2: not a state of"),
                             ([self.trace[0], {**self.trace[1], "nv": {}}], "state 2: not a state of"),
                             ([self.trace[0], dict(self.trace[0], session=[])], "state 2: malformed")):
            with self.subTest(error=error), self.assertRaisesRegex(trace_to_tpm2.TraceError, error):
                trace_to_tpm2.translate(trace)

    def test_empty_trace_is_rejected(self):
        for trace in ([], self.trace[:1], {}, {"counterexample": self.trace}):
            with self.subTest(trace=trace), self.assertRaisesRegex(trace_to_tpm2.TraceError, "at least one step"):
                trace_to_tpm2.translate(trace)
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "t.json"
        path.write_text("[]")
        with self.assertRaisesRegex(SystemExit, "at least one step"):
            trace_to_tpm2.main([str(path)])

    def test_placeholders_are_filled(self):
        self.assertEqual(trace_to_tpm2.fill(["-i", "{policy_dir_1}/approved", "o"], {"policy_dir_1": "/p"}),
                         ["-i", "/p/approved", "o"])
        with self.assertRaises(KeyError):
            trace_to_tpm2.fill(["{owner_auth}"], {})


if __name__ == "__main__":
    unittest.main()
