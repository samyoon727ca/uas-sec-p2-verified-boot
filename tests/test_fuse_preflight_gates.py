"""Unit tests for the dev-key, HAB-log and close gates in tools/fuse_preflight.py (OI2-02, OI2-07)."""
from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import fuse_preflight as fp  # noqa: E402


def srk_table(*seeds: int) -> bytes:
    """parse_srk_table reads only the headers, so each key is a stand-in: tag 0xE1, length, 0x21, 64 seed bytes."""
    keys = b"".join(struct.pack(">BHB", 0xE1, 68, 0x21) + bytes([seed]) * 64 for seed in seeds)
    return struct.pack(">BHB", 0xD7, 4 + len(keys), 0x43) + keys


TABLE = srk_table(1, 2, 3, 4)
DIGEST = fp.srk_fuse_hash(TABLE)
KEY_2 = hashlib.sha256(fp.parse_srk_table(TABLE).keys[2]).digest()
FLASH, ITB = hashlib.sha256(b"flash.bin").hexdigest(), hashlib.sha256(b"u-boot.itb").hexdigest()
IMAGES = {"flash.bin": FLASH, "u-boot.itb": ITB}
HEADERS = f"# flash.bin sha256: {FLASH}\n# u-boot.itb sha256: {ITB}\n"
# hab_status output on an open chip, as U-Boot's arch/arm/mach-imx/hab.c prints it.
CLEAN = "=> hab_status\n\nSecure boot disabled\n\nHAB Configuration: 0xf0, HAB State: 0x66\nNo HAB Events Found!\n\n"
EVENT = ("=> hab_status\n\nSecure boot disabled\n\nHAB Configuration: 0xf0, HAB State: 0x66\n\n"
         "--------- HAB Event 1 -----------------\nevent data:\n\t0xdb 0x00 0x14 0x41 0x33 0x18 0xc0 0x00\n"
         "\nSTS = HAB_FAILURE (0x33)\nRSN = HAB_INV_SIGNATURE (0x18)\n\n=> ")
SRK_PLAN = "".join(f"fuse prog {cmd[10:]}\n" for cmd in fp.render_srk_commands(fp.fuse_words(DIGEST)))
CLOSE_PLAN = SRK_PLAN + "fuse prog 1 3 0x2000000\n"
RECOVERY = "ve07-hw/20261201-abcdef0/recovery.log"


class DevKeyTest(unittest.TestCase):
    def inventory(self, digest: bytes, label: str = "k-cc-root-dev") -> dict[bytes, str]:
        return fp.parse_dev_inventory(f"# dev keys\n\n{digest.hex()} {label}  # bench board\n")

    def test_parse(self):
        self.assertEqual(self.inventory(DIGEST), {DIGEST: "k-cc-root-dev"})
        self.assertEqual(fp.parse_dev_inventory(DIGEST.hex().upper() + " a-dev"), {DIGEST: "a-dev"})

    def test_dev_match_is_an_error_without_the_flag(self):
        for name, digest in (("fuse hash", DIGEST), ("key entry", KEY_2)):
            with self.subTest(name):
                findings = fp.check_dev_keys(TABLE, DIGEST, self.inventory(digest), dev_board=False)
                self.assertEqual(len(findings), 1)
                self.assertTrue(findings[0].error)
                self.assertRegex(findings[0].message, r"dev key 'k-cc-root-dev': expected no dev key .* rule 5")
        self.assertIn("SRK table key 2", fp.check_dev_keys(TABLE, DIGEST, self.inventory(KEY_2), False)[0].message)

    def test_dev_match_is_a_warning_with_the_flag(self):
        findings = fp.check_dev_keys(TABLE, DIGEST, self.inventory(DIGEST), dev_board=True)
        self.assertEqual(findings, [fp.Finding("dev key", "SRK hash to burn: dev key 'k-cc-root-dev': allowed for "
                                                          "a dev board only", error=False)])

    def test_no_match(self):
        other = hashlib.sha256(b"other").digest()
        self.assertEqual(fp.check_dev_keys(TABLE, DIGEST, self.inventory(other), dev_board=False), [])

    def test_bad_inventories_are_refused(self):
        h = DIGEST.hex()
        cases = {
            "label without -dev": (f"{h} k-cc-root\n", r"line 1: label 'k-cc-root' does not end in '-dev'"),
            "bare -dev": (f"{h} -dev\n", r"label '-dev' does not end in '-dev'"),
            "short hash": (f"{h[:-2]} a-dev\n", r"line 1: malformed"),
            "no label": (f"# c\n{h}\n", r"line 2: malformed"),
            "extra field": (f"{h} a-dev b-dev\n", r"line 1: malformed"),
            "listed twice": (f"{h} a-dev\n{h} b-dev\n", r"line 2: hash .* already listed as 'a-dev'"),
        }
        for name, (text, message) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(fp.PreflightError, message):
                fp.parse_dev_inventory(text)


class HabLogTest(unittest.TestCase):
    def test_clean_log(self):
        log = fp.parse_hab_log(HEADERS + CLEAN)
        self.assertEqual(log, fp.HabLog({"flash.bin": FLASH, "u-boot.itb": ITB}, True, ()))
        self.assertEqual(fp.check_hab_log(HEADERS + CLEAN, IMAGES), [])
        self.assertEqual(fp.check_hab_log(HEADERS.replace(FLASH, FLASH.upper()) + CLEAN, IMAGES), [])

    def test_log_with_one_event(self):
        log = fp.parse_hab_log(HEADERS + EVENT)
        self.assertFalse(log.clean)
        self.assertEqual(len(log.events), 1)
        self.assertTrue(log.events[0].startswith("--------- HAB Event 1 "))
        self.assertIn("RSN = HAB_INV_SIGNATURE (0x18)", log.events[0])
        findings = fp.check_hab_log(HEADERS + EVENT, IMAGES)
        self.assertEqual([f.kind for f in findings], ["hab event"])
        self.assertRegex(findings[0].message, r"event block 1 of 1: expected none, got:\n-+ HAB Event 1")

    def test_log_for_other_images(self):
        other = dict(IMAGES, **{"u-boot.itb": "0" * 64})
        findings = fp.check_hab_log(HEADERS + CLEAN, other)
        self.assertEqual(len(findings), 1)
        self.assertRegex(findings[0].message, rf"u-boot.itb sha256 mismatch: .* expected 0{{64}}, got {ITB}")

    def test_log_without_digest_headers(self):
        findings = fp.check_hab_log(CLEAN, IMAGES)
        self.assertEqual([f.message for f in findings],
                         [f"HAB log: flash.bin sha256 header missing: expected '# flash.bin sha256: {FLASH}'",
                          f"HAB log: u-boot.itb sha256 header missing: expected '# u-boot.itb sha256: {ITB}'"])
        only_flash = fp.check_hab_log(HEADERS.splitlines()[0] + "\n" + CLEAN, IMAGES)
        self.assertEqual(len(only_flash), 1)
        self.assertIn("u-boot.itb sha256 header missing", only_flash[0].message)

    def test_no_image_digest_given(self):
        findings = fp.check_hab_log(HEADERS + CLEAN, {"flash.bin": FLASH})
        self.assertEqual([f.message for f in findings], ["HAB log: no u-boot.itb sha256 given to check the log against"])

    def test_unparseable_logs(self):
        cases = {
            "empty": ("", r"got 0 of the first"),
            "no status": (HEADERS + "=> hab_status\n", r"got 0 of the first"),
            "clean only in a note": (HEADERS + "# No HAB Events Found!\n", r"got 0 of the first"),
            "two outputs": (HEADERS + CLEAN + CLEAN, r"got 2 of the first"),
            "clean and event": (HEADERS + CLEAN + EVENT, r"both .* and 1 HAB Event blocks"),
            "bad digest": (f"# flash.bin sha256: {FLASH[:-1]}\n" + CLEAN, r"line 1: flash.bin sha256 '[0-9a-f]+' "
                                                                          r"is not 64 hex digits"),
            "digest twice": (HEADERS + f"# flash.bin sha256: {FLASH}\n" + CLEAN, r"line 3: flash.bin sha256 "
                                                                                 r"given twice"),
        }
        for name, (text, message) in cases.items():
            with self.subTest(name):
                with self.assertRaisesRegex(fp.PreflightError, message):
                    fp.parse_hab_log(text)
                findings = fp.check_hab_log(text, IMAGES)
                self.assertEqual([f.kind for f in findings], ["hab log unparseable"])


class CloseGateTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)     # stands in for the repo root
        self.record = self.root / "evidence" / RECOVERY
        self.record.parent.mkdir(parents=True)
        self.record.write_text("uuu recovery run\n")
        self.manifest(hashlib.sha256(self.record.read_bytes()).hexdigest())

    def manifest(self, digest: str, path: str = RECOVERY):
        (self.root / "evidence" / "SHA256SUMS").write_text(f"{digest}  {path}\n")

    def close(self, plan: str = CLOSE_PLAN, hab_log: str | None = HEADERS + CLEAN,
              recovery: str | None = "evidence/" + RECOVERY) -> list[fp.Finding]:
        return fp.check_close(fp.parse_fuse_plan(plan), hab_log, recovery, IMAGES, root=self.root)

    def test_close_with_clean_log_and_recovery_evidence_passes(self):
        self.assertEqual(self.close(), [])
        self.assertEqual(self.close(recovery=str(self.record)), [])
        self.assertEqual(fp.check_close([], None, None, IMAGES, root=self.root), [])

    def test_close_without_a_log(self):
        findings = self.close(hab_log=None)
        self.assertEqual([f.kind for f in findings], ["close gate"])
        self.assertRegex(findings[0].message, r"^line 9: close command refused: no HAB log given; .* \(OI2-02\)$")

    def test_close_with_a_bad_log(self):
        for name, log in (("event", HEADERS + EVENT), ("no headers", CLEAN), ("unparseable", HEADERS)):
            with self.subTest(name):
                findings = self.close(hab_log=log)
                self.assertTrue(findings)
                for f in findings:
                    self.assertEqual(f.kind, "close gate")
                    self.assertRegex(f.message, r"(?s)^line 9: close command refused: HAB log: .*\(OI2-02\)$")

    def test_close_without_recovery_evidence(self):
        for recovery in (None, ""):
            findings = self.close(recovery=recovery)
            self.assertEqual([f.kind for f in findings], ["recovery evidence"])
            self.assertRegex(findings[0].message, r"no --recovery-evidence given; .*\(OI2-07\)$")

    def test_recovery_evidence_not_listed(self):
        self.manifest("0" * 64, "ve07-hw/20261201-abcdef0/other.log")
        self.assertRegex(self.close()[0].message, rf"evidence/{RECOVERY} is not listed in evidence/SHA256SUMS; "
                                                  r".*\(OI2-07\)$")

    def test_recovery_evidence_hash_mismatch(self):
        self.manifest("0" * 64)
        findings = self.close()
        self.assertEqual(len(findings), 1)
        self.assertRegex(findings[0].message, rf"evidence/{RECOVERY} hash mismatch: SHA256SUMS records 0{{64}}")

    def test_recovery_evidence_outside_evidence_or_missing(self):
        (self.root / "notes.txt").write_text("x")
        cases = {"outside": ("notes.txt", r"notes.txt is not under evidence/"),
                 "escapes": ("evidence/../notes.txt", r"is not under evidence/"),
                 "the folder": ("evidence", r"evidence is not under evidence/"),
                 "missing": ("evidence/ve07-hw/none.log", r"evidence/ve07-hw/none.log is not a file"),
                 "a directory": ("evidence/ve07-hw", r"is not a file")}
        for name, (recovery, message) in cases.items():
            with self.subTest(name):
                findings = self.close(recovery=recovery)
                self.assertEqual(len(findings), 1)
                self.assertRegex(findings[0].message, f"fuse burn refused: .*{message}.*OI2-07")
        (self.root / "evidence" / "SHA256SUMS").write_text("not a sum line\n")
        self.assertRegex(self.close()[0].message, r"evidence/SHA256SUMS unreadable: SHA256SUMS:1")

    def test_srk_only_plan_needs_no_log_but_needs_recovery_evidence(self):
        self.assertEqual(self.close(plan=SRK_PLAN, hab_log=None), [])
        self.assertEqual(self.close(plan=SRK_PLAN, hab_log=HEADERS + EVENT), [])
        findings = self.close(plan=SRK_PLAN, hab_log=None, recovery=None)
        self.assertEqual([f.kind for f in findings], ["recovery evidence"])
        self.assertIn("OI2-07", findings[0].message)

    def test_close_with_neither_reports_both(self):
        self.assertEqual([f.kind for f in self.close(hab_log=None, recovery=None)],
                         ["recovery evidence", "close gate"])


if __name__ == "__main__":
    unittest.main()
