"""Unit tests for the VE-07 harness helpers in tests/ve07/boot_cases.py."""
from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "ve07"))
import boot_cases as bc  # noqa: E402
import check_config  # noqa: E402  (cc/uboot, put on the path by boot_cases)


def make_fdt(tree: dict) -> bytes:
    """Build a minimal flattened devicetree from nested dicts (bytes values are properties)."""
    structure, strings, offsets = bytearray(), bytearray(), {}

    def pad():
        structure.extend(b"\0" * (-len(structure) % 4))

    def name_off(name):
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(name.encode() + b"\0")
        return offsets[name]

    def emit(name, node):
        structure.extend(struct.pack(">I", 1) + name.encode() + b"\0")
        pad()
        for key, value in node.items():
            if isinstance(value, bytes):
                structure.extend(struct.pack(">III", 3, len(value), name_off(key)) + value)
                pad()
        for key, value in node.items():
            if isinstance(value, dict):
                emit(key, value)
        structure.extend(struct.pack(">I", 2))

    emit("", tree)
    structure.extend(struct.pack(">I", 9))
    off_rsv, off_struct = 40, 56
    off_strings = off_struct + len(structure)
    total = off_strings + len(strings)
    header = struct.pack(">10I", 0xD00DFEED, total, off_struct, off_strings, off_rsv, 17, 16, 0,
                         len(strings), len(structure))
    return header + b"\0" * 16 + bytes(structure) + bytes(strings)


TREE = {"description": b"fit\0",
        "images": {"kernel": {"data": b"KERNELDATA", "type": b"kernel\0"},
                   "fdt": {"data": b"DTB!"}}}


class FdtTest(unittest.TestCase):
    def test_finds_property_value(self):
        blob = make_fdt(TREE)
        off, length = bc.fdt_prop(blob, "/images/kernel", "data")
        self.assertEqual(blob[off:off + length], b"KERNELDATA")
        off, length = bc.fdt_prop(blob, "/images/fdt", "data")
        self.assertEqual(blob[off:off + length], b"DTB!")

    def test_missing_property(self):
        with self.assertRaises(KeyError):
            bc.fdt_prop(make_fdt(TREE), "/images/ramdisk", "data")

    def test_rejects_non_fdt(self):
        with self.assertRaises(ValueError):
            bc.fdt_prop(b"\0" * 64, "/", "x")

    def test_flip_byte_changes_exactly_one_byte_in_the_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "a.itb", Path(tmp) / "b.itb"
            src.write_bytes(make_fdt(TREE))
            at = bc.flip_byte(src, dst, "/images/kernel")
            a, b = src.read_bytes(), dst.read_bytes()
            self.assertEqual([i for i in range(len(a)) if a[i] != b[i]], [at])
            off, length = bc.fdt_prop(a, "/images/kernel", "data")
            self.assertTrue(off <= at < off + length)


class EvaluateTest(unittest.TestCase):
    def case(self, **kw):
        return bc.Case("X", "TC-00", "test", "t", **kw)

    def test_expect_and_forbid(self):
        checks = bc.evaluate(self.case(expect=["good"], forbid=["bad"]), "all good here", "exited")
        self.assertTrue(all(c["ok"] for c in checks))
        checks = bc.evaluate(self.case(expect=["good"], forbid=["bad"]), "good but bad", "exited")
        self.assertFalse(all(c["ok"] for c in checks))

    def test_timeout_fails(self):
        checks = bc.evaluate(self.case(expect=["x"]), "x", "timeout")
        self.assertFalse(all(c["ok"] for c in checks))

    def test_stop_case_must_stop(self):
        case = self.case(expect=["=> "], stop="=> ")
        self.assertTrue(all(c["ok"] for c in bc.evaluate(case, "=> ", "stopped")))
        self.assertFalse(all(c["ok"] for c in bc.evaluate(case, "=> ", "exited")))

    def test_prompt_pattern_needs_line_start(self):
        self.assertIsNone(__import__("re").search(bc.PROMPT, "a => b"))
        self.assertIsNotNone(__import__("re").search(bc.PROMPT, "x\n=> "))


    def test_counted_expect(self):
        case = self.case(expect=[("boot", 3)])
        self.assertTrue(all(c["ok"] for c in bc.evaluate(case, "boot boot boot", "exited")))
        self.assertFalse(all(c["ok"] for c in bc.evaluate(case, "boot boot", "exited")))

    def test_ansi_sequences_are_ignored(self):
        checks = bc.evaluate(self.case(expect=[bc.PROMPT]), "x\r\n\x1b[2K=> ", "exited")
        self.assertTrue(all(c["ok"] for c in checks))

    def test_keystroke_case_needs_enough_keys(self):
        case = self.case(keys_from="go")
        self.assertFalse(all(c["ok"] for c in bc.evaluate(case, "go", "exited", bc.MIN_KEYS - 1)))
        self.assertTrue(all(c["ok"] for c in bc.evaluate(case, "go", "exited", bc.MIN_KEYS)))


class ConfigCheckTest(unittest.TestCase):
    def write(self, tmp, name, text):
        path = Path(tmp) / name
        path.write_text(text)
        return path

    def test_reports_missing_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            frag = self.write(tmp, "f.config", "# comment\nCONFIG_A=y\n# CONFIG_B is not set\n")
            cfg = self.write(tmp, ".config", "CONFIG_A=y\nCONFIG_B=y\n")
            checks = check_config.check(cfg, [frag])
        self.assertEqual([(c["pattern"], c["ok"]) for c in checks],
                         [("CONFIG_A=y", True), ("# CONFIG_B is not set", False)])

    def test_later_fragment_overrides_earlier(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = self.write(tmp, "a.config", "CONFIG_BOOTDELAY=-2\nCONFIG_A=y\n")
            b = self.write(tmp, "b.config", "CONFIG_BOOTDELAY=2\n")
            cfg = self.write(tmp, ".config", "CONFIG_A=y\nCONFIG_BOOTDELAY=2\n")
            self.assertTrue(all(c["ok"] for c in check_config.check(cfg, [a, b])))

    def test_diff_lists_changed_added_and_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self.write(tmp, "base", "CONFIG_A=y\nCONFIG_B=1\n# CONFIG_C is not set\n")
            cfg = self.write(tmp, "cfg", "CONFIG_A=y\nCONFIG_B=2\n# CONFIG_C is not set\nCONFIG_D=y\n")
            self.assertEqual(check_config.diff(cfg, base), ["CONFIG_B=2", "CONFIG_D=y"])
            self.assertEqual(check_config.diff(base, cfg), ["CONFIG_B=1", "# CONFIG_D removed"])

    def test_each_control_fragment_changes_one_setting(self):
        for variant, frag in bc.CONTROL_FRAGMENTS.items():
            self.assertEqual(len(check_config.expected([frag])), 1, variant)


class ProvenanceTest(unittest.TestCase):
    def test_only_github_actions_counts_as_ci(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": ""}):
            self.assertEqual(bc.environment(), {"kind": "local"})
        ci = {"GITHUB_ACTIONS": "true", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
              "GITHUB_RUN_ID": "42", "ImageOS": "ubuntu24", "ImageVersion": "20261004.327"}
        with mock.patch.dict(os.environ, ci):
            env = bc.environment()
        self.assertEqual(env["kind"], "ci")
        self.assertEqual(env["run_url"], "https://github.com/o/r/actions/runs/42")
        self.assertEqual(env["runner_image"], "ubuntu24 20261004.327")


if __name__ == "__main__":
    unittest.main()
