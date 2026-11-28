"""Unit tests for tools/fuse_preflight.py."""
from __future__ import annotations

import ast
import hashlib
import random
import re
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import fuse_preflight as fp  # noqa: E402

RNG = random.Random(27)     # public test data: random moduli with no private key behind them

# [NXP-FUSE] section 1.7: the guide's hexdump of SRK_1_2_3_4_fuse.bin, and the commands that burn it.
GUIDE_WORDS = [0x20593752, 0x6ACE6962, 0x26E0D06C, 0xFC600661, 0x1240E88F, 0x1209F144, 0x831C8117, 0x1190FD4D]
GUIDE_COMMANDS = ["fuse prog 6 0 0x20593752", "fuse prog 6 1 0x6ACE6962", "fuse prog 6 2 0x26E0D06C",
                  "fuse prog 6 3 0xFC600661", "fuse prog 7 0 0x1240E88F", "fuse prog 7 1 0x1209F144",
                  "fuse prog 7 2 0x831C8117", "fuse prog 7 3 0x1190FD4D"]


def rsa_entry(bits: int = 4096) -> bytes:
    """By hand: tag 0xE1, length, PKCS#1 (0x21), 3 zero bytes, flags, both lengths, random modulus, exponent."""
    modulus = bytes([0x80 | RNG.randrange(256)]) + RNG.randbytes(bits // 8 - 1)
    exponent = b"\x01\x00\x01"
    body = bytes(3) + b"\x80" + struct.pack(">HH", len(modulus), len(exponent)) + modulus + exponent
    return struct.pack(">BHB", 0xE1, 4 + len(body), 0x21) + body


def srk_table(entries: list[bytes], version: int = 0x43) -> bytes:
    return struct.pack(">BHB", 0xD7, 4 + sum(map(len, entries)), version) + b"".join(entries)


class SrkTableTest(unittest.TestCase):
    def test_one_two_and_four_keys_parse_and_hash(self):
        for n in (1, 2, 4):
            with self.subTest(keys=n):
                entries = [rsa_entry() for _ in range(n)]
                self.assertEqual(fp.parse_srk_table(srk_table(entries)), fp.SrkTable(0x43, tuple(entries)))
                # Known answer, from hashlib over the hand-built entries: SHA-256 over the keys' SHA-256 hashes.
                key_hashes = b"".join(hashlib.sha256(e).digest() for e in entries)
                self.assertEqual(fp.srk_fuse_hash(srk_table(entries)), hashlib.sha256(key_hashes).digest())

    def test_bad_tables_are_refused(self):
        one, two = rsa_entry(), rsa_entry()
        good = srk_table([one, two])
        cases = {
            "truncated header": (good[:3], r"SRK table: 3 bytes, too short for its 4-byte HAB header"),
            "bad tag": (b"\xd8" + good[1:], r"SRK table: header tag 0xd8, expected 0xd7"),
            "not HABv4": (srk_table([one], version=0x30), r"SRK table: version 0x30 is not HABv4"),
            "length mismatch": (good[:-1], rf"length mismatch: header says {len(good)} bytes, the data has "
                                           rf"{len(good) - 1}"),
            "trailing bytes": (good + b"\0\0", rf"SRK table: 2 trailing bytes after the {len(good)}-byte table"),
            "bad entry tag": (srk_table([one, b"\xe2" + two[1:]]),
                              rf"entry 2 at offset {4 + len(one)}: tag 0xe2, expected 0xe1 \(public key\)"),
            "entry too long": (srk_table([one[:1] + struct.pack(">H", len(one) + 1) + one[3:]]),
                               rf"entry 1 at offset 4: length mismatch: entry says {len(one) + 1} bytes, "
                               rf"expected 5 to the {len(one)} left"),
            "entry header only": (srk_table([b"\xe1\x00\x04\x21", one]), r"entry 1 at offset 4: length mismatch: "
                                                                         r"entry says 4 bytes"),
            "entry cut short": (srk_table([one, b"\xe1\x00"]), r"entry 2 at offset \d+: 2 bytes left, too short"),
            "no keys": (srk_table([]), r"SRK table: 0 key entries, expected 1 to 4"),
            "five keys": (srk_table([one, two, one, two, one]), r"SRK table: 5 key entries, expected 1 to 4"),
        }
        for name, (data, message) in cases.items():
            for check in (fp.parse_srk_table, fp.srk_fuse_hash):
                with self.subTest(name, check=check.__name__), self.assertRaisesRegex(fp.PreflightError, message):
                    check(data)


class FuseWordsTest(unittest.TestCase):
    def test_words_are_little_endian_reads(self):
        self.assertEqual(fp.fuse_words(bytes(range(32))), [0x03020100 + 0x04040404 * i for i in range(8)])

    def test_guide_example_renders_as_the_guide_writes_it(self):
        digest = b"".join(struct.pack("<I", w) for w in GUIDE_WORDS)    # SRK_1_2_3_4_fuse.bin bytes
        self.assertEqual(digest[:4], b"\x52\x37\x59\x20")
        self.assertEqual(fp.fuse_words(digest), GUIDE_WORDS)
        self.assertEqual(fp.render_srk_commands(GUIDE_WORDS), GUIDE_COMMANDS)
        # No leading zeros, as the guide's hexdump prints them.
        self.assertEqual(fp.render_srk_commands([0xABCD] + [0] * 7)[:2], ["fuse prog 6 0 0xABCD", "fuse prog 6 1 0x0"])

    def test_bad_inputs_are_refused(self):
        with self.assertRaisesRegex(fp.PreflightError, "SRK hash: 31 bytes, expected 32"):
            fp.fuse_words(bytes(31))
        for words in ([0] * 7, [0] * 9, [0] * 7 + [1 << 32], [0] * 7 + [-1]):
            with self.subTest(words=words), self.assertRaisesRegex(fp.PreflightError, "expected 8 words of 32 bits"):
                fp.render_srk_commands(words)


class ParsePlanTest(unittest.TestCase):
    def test_commands_comments_and_blank_lines(self):
        plan = fp.parse_fuse_plan("# SRK hash\n\nfuse prog 6 0 0x20593752\n  fuse prog -y 7 3 0xabc  # last word\r\n"
                                  "fuse  prog\t1 3 0x2000000\n")
        self.assertEqual(plan, [fp.FuseWrite(3, 6, 0, 0x20593752, False), fp.FuseWrite(4, 7, 3, 0xABC, True),
                                fp.FuseWrite(5, 1, 3, 0x2000000, False)])

    def test_other_commands_are_refused(self):
        for line in ("fuse override 6 0 0x1", "fuse read 6 0", "mw.l 0x30350000 0x1", "=> fuse prog 6 0 0x1", "fuse"):
            with self.subTest(line), self.assertRaisesRegex(fp.PreflightError, "plan line 2: not a fuse prog command"):
                fp.parse_fuse_plan("fuse prog 6 0 0x1\n" + line)

    def test_malformed_lines_are_refused(self):
        for line in ("fuse prog 6 0", "fuse prog 6 0 20593752", "fuse prog 6 0 0x1 0x2", "fuse prog 06 0 0x1",
                     "fuse prog 6 0x0 0x1", "fuse prog 6 0 0x123456789", "fuse prog -y -y 6 0 0x1",
                     "fuse prog 6 0 0xG", "fuse prog 6 \u0660 0x1", "fuse prog"):
            with self.subTest(line), self.assertRaisesRegex(fp.PreflightError, "plan line 1: malformed, expected "
                                                                               r"'fuse prog \[-y\] <bank> <word>"):
                fp.parse_fuse_plan(line)


class CheckPlanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digest = fp.srk_fuse_hash(srk_table([rsa_entry() for _ in range(4)]))
        cls.words = fp.fuse_words(cls.digest)
        cls.commands = fp.render_srk_commands(cls.words)

    def check(self, lines: list[str]) -> list[fp.Finding]:
        return fp.check_plan(fp.parse_fuse_plan("\n".join(lines)), self.digest)

    def assertOnly(self, findings: list[fp.Finding], kind: str, messages: list[str]):
        self.assertEqual([(f.kind, f.error) for f in findings], [(kind, True)] * len(messages))
        self.assertEqual([f.message for f in findings], messages)

    def test_rendered_plan_passes(self):
        self.assertEqual(self.check(self.commands), [])

    def test_close_is_reported_as_its_own_step(self):
        findings = self.check(self.commands + ["fuse prog 1 3 0x2000000"])
        self.assertEqual([(f.kind, f.error) for f in findings], [("close step", False)])
        self.assertIn("line 9: bank 1 word 3: closes the chip", findings[0].message)

    def test_word_swap(self):
        lines = list(self.commands)
        lines[4], lines[5] = lines[4].replace("7 0 ", "7 1 "), lines[5].replace("7 1 ", "7 0 ")
        w = [fp.hexword(v) for v in self.words]
        self.assertOnly(self.check(lines), "word swap", [
            f"line 5: bank 7 word 1: word swap: expected {w[5]}, got {w[4]}, the word for bank 7 word 0",
            f"line 6: bank 7 word 0: word swap: expected {w[4]}, got {w[5]}, the word for bank 7 word 1"])

    def test_byte_swap(self):
        swapped = struct.unpack(">8I", self.digest)     # a big-endian read of SRK_1_2_3_4_fuse.bin
        self.assertOnly(self.check(fp.render_srk_commands(list(swapped))), "byte swap", [
            f"line {i + 1}: bank {b} word {w}: byte swap: expected {fp.hexword(self.words[i])}, "
            f"got {fp.hexword(swapped[i])}, its bytes reversed" for i, (b, w) in enumerate(fp.SRK_FUSES)])

    def test_mismatch(self):
        wrong = self.words[2] ^ 0x10
        lines = self.commands[:2] + [f"fuse prog 6 2 {fp.hexword(wrong)}"] + self.commands[3:]
        self.assertOnly(self.check(lines), "mismatch", [
            f"line 3: bank 6 word 2: mismatch: expected {fp.hexword(self.words[2])}, got {fp.hexword(wrong)}"])

    def test_duplicate_srk_word(self):
        # A repeated SRK word line passes if it repeats the right value; a wrong value is a mismatch at its own line,
        # even after the right one.
        self.assertEqual(self.check(self.commands[:3] + [self.commands[2]] + self.commands[3:]), [])
        wrong = self.words[2] ^ 0x10
        lines = self.commands[:3] + [f"fuse prog 6 2 {fp.hexword(wrong)}"] + self.commands[3:]
        self.assertOnly(self.check(lines), "mismatch", [
            f"line 4: bank 6 word 2: mismatch: expected {fp.hexword(self.words[2])}, got {fp.hexword(wrong)}"])

    def test_missing_word(self):
        self.assertOnly(self.check(self.commands[:6] + self.commands[7:]), "missing", [
            f"bank 7 word 2: SRK hash word missing: expected {fp.hexword(self.words[6])}, got no write"])

    def test_unknown_fuse_write(self):
        lines = self.commands + ["fuse prog 9 3 0x1", "fuse prog 6 4 0x5", "fuse prog 1 2 0x2000000"]
        where = "expected none outside bank 6/7 words 0-3 and bank 1 word 3"
        self.assertOnly(self.check(lines), "unknown fuse write", [
            f"line 9: bank 9 word 3: unknown fuse write: {where}, got 0x00000001",
            f"line 10: bank 6 word 4: unknown fuse write: {where}, got 0x00000005",
            f"line 11: bank 1 word 2: unknown fuse write: {where}, got 0x02000000"])

    def test_wrong_close_value_is_refused(self):
        self.assertOnly(self.check(self.commands + ["fuse prog 1 3 0x2000001", "fuse prog -y 1 3 0x200"]),
                        "close value", [
                            "line 9: bank 1 word 3: close command refused: expected 0x02000000, got 0x02000001",
                            "line 10: bank 1 word 3: close command refused: expected 0x02000000, got 0x00000200"])

    def test_close_before_the_srk_hash_is_refused(self):
        findings = self.check(self.commands[:7] + ["fuse prog 1 3 0x2000000", self.commands[7]])
        errors = [f for f in findings if f.error]
        self.assertOnly(errors, "close order", [
            "line 8: bank 1 word 3: close command before the SRK hash is complete: expected after line 9, got line 8"])


class NoDeviceAccessTest(unittest.TestCase):
    def test_imports_nothing_that_reaches_a_device_or_network(self):
        tree = ast.parse(Path(fp.__file__).read_text())
        imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                    for alias in node.names}
        imported |= {node.module.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imported & {"socket", "ssl", "http", "urllib", "asyncio", "subprocess", "serial", "termios",
                                     "tty", "fcntl", "pty", "ctypes", "mmap"}, set())

    def test_names_no_device_path(self):
        # test_fuse_preflight_cli.py checks that no CLI run opens a path under /dev or /sys; this also covers code
        # no test runs, for a path written in the source.
        tree = ast.parse(Path(fp.__file__).read_text())
        texts = [node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
                 for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))]
        self.assertEqual([text for text in texts if re.search(r"(?<!\w)/(dev|sys)\b", text)], [])


if __name__ == "__main__":
    unittest.main()
