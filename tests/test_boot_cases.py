"""Unit tests for the VE-07 harness helpers in tests/ve07/boot_cases.py."""
from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "ve07"))
import boot_cases as bc  # noqa: E402


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


class ConfigCheckTest(unittest.TestCase):
    def test_reports_missing_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            frag, cfg = Path(tmp) / "f.config", Path(tmp) / ".config"
            frag.write_text("# comment\nCONFIG_A=y\n# CONFIG_B is not set\n")
            cfg.write_text("CONFIG_A=y\nCONFIG_B=y\n")
            saved = bc.FRAGMENTS
            bc.FRAGMENTS = [frag]
            try:
                checks = bc.check_config(cfg)
            finally:
                bc.FRAGMENTS = saved
        self.assertEqual([(c["pattern"], c["ok"]) for c in checks],
                         [("CONFIG_A=y", True), ("# CONFIG_B is not set", False)])


if __name__ == "__main__":
    unittest.main()
