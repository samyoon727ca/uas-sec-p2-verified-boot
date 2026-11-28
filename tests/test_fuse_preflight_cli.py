"""Tests for the tools/fuse_preflight.py command line and its fuse-burn record, on the synthetic images of
test_fuse_preflight_images.py. Nothing here touches hardware."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fuse_preflight as fp  # noqa: E402
from test_fuse_preflight_gates import CLEAN, EVENT, RECOVERY  # noqa: E402
from test_fuse_preflight_images import OTHER, TABLE, csf, flash_bin, u_boot_itb  # noqa: E402

COMMANDS = fp.render_srk_commands(fp.fuse_words(fp.srk_fuse_hash(TABLE)))
CLOSE = "fuse prog 1 3 0x2000000"


class CliTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)      # stands in for the repo root
        record = self.root / "evidence" / RECOVERY
        record.parent.mkdir(parents=True)
        record.write_text("uuu recovery run\n")
        (self.root / "evidence/SHA256SUMS").write_text(f"{fp.check_evidence.sha256(record)}  {RECOVERY}\n")
        self.inputs = self.root / "in|puts`"       # a '|' and a backtick the markdown table must escape
        self.inputs.mkdir()
        flash, itb = flash_bin(csf(TABLE, index=2), csf(TABLE, index=2)), u_boot_itb(csf(TABLE, index=2))
        for name, blob in (("table.bin", TABLE), ("flash.bin", flash), ("u-boot.itb", itb)):
            self.write(name, blob)
        self.write("plan.txt", "\n".join(COMMANDS) + "\n")
        self.headers = (f"# flash.bin sha256: {hashlib.sha256(flash).hexdigest()}\n"
                        f"# u-boot.itb sha256: {hashlib.sha256(itb).hexdigest()}\n")
        self.out = self.root / "out"

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.inputs / name
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def run_cli(self, *extra: str, recovery: str | None = "evidence/" + RECOVERY) -> tuple[int, str]:
        argv = ["--srk-table", str(self.inputs / "table.bin"), "--flash-bin", str(self.inputs / "flash.bin"),
                "--uboot-itb", str(self.inputs / "u-boot.itb"), "--plan", str(self.inputs / "plan.txt"),
                "--out", str(self.out), *extra]
        if recovery is not None:
            argv += ["--recovery-evidence", recovery]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = fp.main(argv, root=self.root)
        return code, out.getvalue()

    def passed(self, *extra: str) -> tuple[dict, str]:
        code, output = self.run_cli(*extra)
        self.assertEqual(code, 0, output)
        return json.loads((self.out / f"{fp.RECORD}.json").read_text()), (self.out / f"{fp.RECORD}.md").read_text()

    def assert_refused(self, code: int, output: str = "") -> str:
        self.assertEqual(code, 1)
        self.assertFalse(self.out.exists())
        return output

    def test_passing_run_writes_both_records(self):
        with mock.patch.object(Path, "read_bytes", autospec=True, side_effect=Path.read_bytes) as read:
            data, md = self.passed()
        names = sorted(path.name for (path,), _ in read.call_args_list if path.parent == self.inputs)
        self.assertEqual(names, ["flash.bin", "plan.txt", "table.bin", "u-boot.itb"])   # each input read once
        self.assertEqual((data["schema"], data["tool_version"]), ("fuse-burn-record/1", "unknown"))   # not a git repo
        self.assertRegex(data["created_utc"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(data["srk_fuse_hash"], fp.srk_fuse_hash(TABLE).hex())
        self.assertEqual(data["fuse_words"], [fp.hexword(w) for w in fp.fuse_words(fp.srk_fuse_hash(TABLE))])
        self.assertEqual(data["steps"], [{"step": "A", "title": "burn the SRK hash", "commands": COMMANDS}])
        self.assertEqual([c.split()[2] for c in COMMANDS], ["6"] * 4 + ["7"] * 4)
        self.assertEqual(data["images"], {"flash.bin": {"srk_index": 2, "ivt_offsets": ["0x400", "0x3000"]},
                                          "u-boot.itb": {"srk_index": 2, "ivt_offsets": ["0x2000"]}})
        for key, name in (("srk_table", "table.bin"), ("flash_bin", "flash.bin"), ("plan", "plan.txt")):
            self.assertEqual(data["inputs"][key]["sha256"],
                             hashlib.sha256((self.inputs / name).read_bytes()).hexdigest())
        self.assertIsNone(data["inputs"]["hab_log"])
        warning = "no --dev-inventory given: dev-key check not run, so this SRK hash may be a dev key (docs/05 rule 5)"
        self.assertIn(warning, data["warnings"])                # no --dev-inventory: warned in both files
        self.assertIn(f"- {warning}", md)
        self.assertEqual(data["inputs"]["recovery_evidence"]["path"], "evidence/" + RECOVERY)
        plan = str(self.inputs / "plan.txt").replace("|", "\\|")
        self.assertIn(f"| plan | `` {plan} `` | `{data['inputs']['plan']['sha256']}` |", md)
        # The markdown carries the same commands, hashes and links.
        self.assertEqual(re.findall(r"```\n(.*?)\n```", md, re.S), ["\n".join(COMMANDS)])
        self.assertIn("## Step A: burn the SRK hash", md)
        self.assertNotIn("## Step B", md)
        for text in (data["srk_fuse_hash"], data["inputs"]["flash_bin"]["sha256"], data["tool_version"],
                     "permanent", "explicit go-ahead", "docs/05 rule 5", "OI2-02", "OI2-07", "#27-open-items"):
            self.assertIn(text, md)

    def test_close_step_only_behind_its_gate(self):
        self.write("plan.txt", "\n".join(COMMANDS + [CLOSE]) + "\n")
        self.assert_refused(*self.run_cli())
        self.write("hab.log", self.headers + EVENT)
        output = self.assert_refused(*self.run_cli("--hab-log", str(self.inputs / "hab.log")))
        self.assertIn("ERROR: close gate: line 9: close command refused: HAB log: event block 1", output)
        self.write("hab.log", self.headers + CLEAN)
        data, md = self.passed("--hab-log", str(self.inputs / "hab.log"))
        self.assertEqual([s["commands"] for s in data["steps"]], [COMMANDS, [CLOSE]])
        self.assertEqual(re.findall(r"```\n(.*?)\n```", md, re.S), ["\n".join(COMMANDS), CLOSE])
        self.assertLess(md.index("## Step A"), md.index("## Step B: close the chip"))
        self.assertIn("If the SRK hash was already burned in an earlier run, do not type Step A again", md)
        self.assertTrue(any("closes the chip" in w for w in data["warnings"]))

    def test_refusing_run_prints_every_finding_and_writes_nothing(self):
        swapped = COMMANDS[:]
        swapped[1] = swapped[1][:-1] + ("0" if swapped[1][-1] != "0" else "1")
        self.write("plan.txt", "\n".join(swapped[:-1]) + "\n")
        output = self.assert_refused(*self.run_cli(recovery=None))
        for kind in ("mismatch", "missing", "recovery evidence"):
            self.assertIn(f"ERROR: {kind}:", output)
        self.assertIn("REFUSED: 3 blocking finding(s); no record written", output)

    def test_bad_inputs_are_findings(self):
        self.write("u-boot.itb", u_boot_itb(csf(OTHER)))
        output = self.assert_refused(*self.run_cli())
        self.assertIn("ERROR: table mismatch: u-boot.itb", output)
        (self.inputs / "table.bin").unlink()
        self.write("plan.txt", "reset\n")
        output = self.assert_refused(*self.run_cli(recovery=None))
        self.assertRegex(output, r"ERROR: input: --srk-table .*table.bin: cannot read")
        self.assertIn("ERROR: input: plan line 1: not a fuse prog command", output)
        self.assertIn("ERROR: recovery evidence: fuse burn refused: no --recovery-evidence given", output)
        output = self.assert_refused(*self.run_cli("--hab-log", str(self.write("hab.log", b"\xff")),
                                                   recovery="nowhere/run.log"))
        for text in ("input: a text input is not UTF-8", "recovery evidence: fuse burn refused: nowhere/run.log"):
            self.assertIn(f"ERROR: {text}", output)

    def test_hab_log_for_srk_only_plan_is_checked_as_warnings(self):
        other = f"# flash.bin sha256: {'0' * 64}\n"            # a log captured for another flash.bin
        self.write("hab.log", other + self.headers.splitlines()[1] + "\n" + EVENT)
        data, md = self.passed("--hab-log", str(self.inputs / "hab.log"))
        hab = [w for w in data["warnings"] if w.startswith("HAB log:")]
        self.assertEqual([("sha256 mismatch" in w, "event block 1" in w) for w in hab], [(True, False), (False, True)])
        self.assertTrue(all(w.endswith("(not a gate: this plan does not close the chip)") for w in hab))
        self.assertIn(f"- {hab[0]}", md)
        first, *block = hab[1].split("\n")                      # the event block: a code block in its list item
        self.assertIn("\n".join([f"- {first}", ""] + [f"      {line}" for line in block]), md)

    def test_dev_board_warning_in_both_files(self):
        self.write("dev.txt", f"{fp.srk_fuse_hash(TABLE).hex()} k-cc-root-dev\n")
        output = self.assert_refused(*self.run_cli("--dev-inventory", str(self.inputs / "dev.txt")))
        self.assertIn("ERROR: dev key: SRK hash to burn: dev key 'k-cc-root-dev'", output)
        data, md = self.passed("--dev-inventory", str(self.inputs / "dev.txt"), "--dev-board")
        self.assertTrue(data["dev_board"])
        warning = "SRK hash to burn: dev key 'k-cc-root-dev': allowed for a dev board only"
        self.assertIn(warning, data["warnings"])
        self.assertIn(f"- {warning}", md)
        self.assertTrue(any(w.startswith("--dev-board:") for w in data["warnings"]))
        self.assertIn("- --dev-board:", md)

    def test_existing_record_is_not_overwritten(self):
        self.out.mkdir()
        for old in ("fuse-burn-record.md", "fuse-burn-record.json"):       # either one alone
            (self.out / old).write_text("earlier\n")
            code, output = self.run_cli()
            self.assertEqual((code, (self.out / old).read_text()), (1, "earlier\n"))
            self.assertIn(f"{self.out / old} already exists", output)
            self.assertEqual(list(self.out.iterdir()), [self.out / old])    # nothing of this run is left
            (self.out / old).unlink()

    def test_out_file_or_failed_write_leaves_no_record(self):
        self.out.write_text("not a folder\n")
        code, output = self.run_cli()
        self.assertEqual((code, self.out.read_text()), (1, "not a folder\n"))
        self.assertIn("is not a directory", output)
        self.out.unlink()
        self.out = self.root / "out" / "sub"         # mkdir makes both folders; the rollback removes both
        real = Path.open

        def full_disk(path, *args, **kwargs):       # the .md is created, then its write fails: both files go
            f = real(path, *args, **kwargs)
            f.write = mock.Mock(side_effect=OSError(28, "No space left on device")) if path.suffix == ".md" else f.write
            return f
        with mock.patch.object(Path, "open", full_disk):
            code, output = self.run_cli()
        self.assertEqual((code, (self.root / "out").exists(), "cannot write in" in output), (1, False, True))


if __name__ == "__main__":
    unittest.main()
