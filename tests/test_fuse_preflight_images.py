"""Unit tests for the signed-image checks in tools/fuse_preflight.py, on synthetic images built here.

CST needs an NXP account, so no real signed image can be made in CI. The builders below lay out flash.bin and
u-boot.itb as the module docstring describes; their addresses are notional. No binary is committed.
"""
from __future__ import annotations

import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import fuse_preflight as fp  # noqa: E402

SPL_BASE = 0x920000         # notional CONFIG_SPL_TEXT_BASE; SPL's IVT loads 0x40 below it
FIT_BASE = 0x40480000       # notional CONFIG_SPL_LOAD_FIT_ADDRESS
SPL_PAYLOAD = b"SPL and DDR firmware stand-in.\0\0" * 0x2E                  # 0x5C0 bytes
FIT = b"\xd0\x0d\xfe\xed" + b"FIT tree with U-Boot, BL31, DTB." * 0x90      # 0x1204 bytes, padded to 0x2000


def srk_table(*seeds: int) -> bytes:
    """parse_srk_table reads only the headers, so each key is a stand-in: tag 0xE1, length, 0x21, 64 seed bytes."""
    keys = b"".join(struct.pack(">BHB", 0xE1, 68, 0x21) + bytes([seed]) * 64 for seed in seeds)
    return struct.pack(">BHB", 0xD7, 4 + len(keys), 0x43) + keys


TABLE, OTHER = srk_table(1, 2, 3, 4), srk_table(5, 6, 7, 8)


def install_key(flags: int, protocol: int, source: int, target: int, location: int) -> bytes:
    return struct.pack(">BHB4BI", 0xBE, 12, flags, protocol, 0x17, source, target, location)


def csf(table: bytes, index: int = 0, flags: int = 0, protocol: int = 0x03, offset: int | None = None,
        extra: bytes = b"") -> bytes:
    """Header, Install SRK, Install CSFK, Authenticate CSF and any extra commands; then the SRK table, at the
    offset Install SRK gives, and stand-in certificate and signature bytes."""
    length = 4 + 36 + len(extra)
    commands = (install_key(flags, protocol, index, 0, length if offset is None else offset)
                + install_key(0x02, 0x09, 0, 1, length + len(table))
                + struct.pack(">BHB4BI", 0xCA, 12, 0, 1, 0xC5, 0, 0, length + len(table) + 8) + extra)
    return struct.pack(">BHB", 0xD4, length, 0x43) + commands + table + bytes(16)


def ivt(entry: int, boot_data: int, self_addr: int, csf_addr: int) -> bytes:
    return bytes([0xD1, 0x00, 0x20, 0x41]) + struct.pack("<7I", entry, 0, 0, boot_data, self_addr, csf_addr, 0)


def u_boot_itb(fit_csf: bytes) -> bytes:
    """The FIT padded to 4 KiB, then its IVT at 0x2000 and its CSF at 0x2020."""
    self_addr = FIT_BASE + 0x2000
    return FIT.ljust(0x2000, b"\0") + ivt(self_addr, 0, self_addr, self_addr + 0x20) + fit_csf


def flash_bin(spl_csf: bytes, fit_csf: bytes) -> bytes:
    """Padding, SPL's IVT at 0x400, boot data, SPL payload, SPL's CSF at 0xA00; then u-boot.itb from 0x1000, so its
    IVT is at 0x3000."""
    self_addr = SPL_BASE - 0x40
    spl = ivt(SPL_BASE, self_addr + 0x20, self_addr, SPL_BASE + len(SPL_PAYLOAD)) + bytes(0x20) + SPL_PAYLOAD
    return (bytes(0x400) + spl + spl_csf).ljust(0x1000, b"\0") + u_boot_itb(fit_csf)


def plan_for(table: bytes, *extra: str) -> list[fp.FuseWrite]:
    return fp.parse_fuse_plan("\n".join(fp.render_srk_commands(fp.fuse_words(fp.srk_fuse_hash(table))) + list(extra)))


class ImageTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = Path(folder.name)

    def extract(self, data: bytes, name: str = "flash.bin"):
        (self.dir / name).write_bytes(data)
        return fp.extract_srk(self.dir / name)

    def test_good_images(self):
        flash, itb = self.extract(flash_bin(csf(TABLE, 2), csf(TABLE, 2))), self.extract(u_boot_itb(csf(TABLE, 2)))
        self.assertEqual(flash, [(0x400, TABLE, 2), (0x3000, TABLE, 2)])
        self.assertEqual(itb, [(0x2000, TABLE, 2)])
        self.assertEqual(fp.check_images({"flash.bin": flash, "u-boot.itb": itb}, fp.srk_fuse_hash(TABLE),
                                         plan_for(TABLE, "fuse prog 1 3 0x2000000")), [])

    def test_ivt_fields_and_file_offsets(self):
        spl, fit = fp.find_ivts(flash_bin(csf(TABLE), csf(TABLE)))
        self.assertEqual(spl, fp.Ivt(0x400, 0x41, SPL_BASE, 0, SPL_BASE - 0x20, SPL_BASE - 0x40, SPL_BASE + 0x5C0))
        self.assertEqual((spl.file_offset(spl.csf), fit.file_offset(fit.csf)), (0xA00, 0x3020))
        self.assertEqual(fp.parse_csf(csf(TABLE, 3)), (3, 40))

    def test_bad_images_are_refused(self):
        good = u_boot_itb(csf(TABLE))
        too_far = bytearray(good)
        struct.pack_into("<I", too_far, 0x2018, FIT_BASE + len(good))
        before = bytearray(good)
        struct.pack_into("<I", before, 0x2018, FIT_BASE - 0x20)
        no_csf = bytearray(good)
        struct.pack_into("<I", no_csf, 0x2018, 0)
        overrun = bytearray(good)
        overrun[0x2025:0x2027] = b"\x01\x00"
        short = bytearray(good)
        short[0x2025:0x2027] = b"\x00\x08"
        ivt_at = r"flash.bin: IVT at offset 0x2000: "
        at = ivt_at + r"CSF at offset 0x2020: "
        cases = {
            "missing IVT": (good[:0x2000] + b"\xd0" + good[0x2001:], r"flash.bin: no IVT \(tag 0xd1, length 0x0020"),
            "IVT version 0x30": (good[:0x2003] + b"\x30" + good[0x2004:], r"flash.bin: no IVT"),
            "IVT header cut at the end": (good[:0x2003], r"flash.bin: no IVT"),
            "truncated IVT": (good[:0x2010], r"flash.bin: IVT at offset 0x2000: truncated: 16 bytes left, expected 32"),
            "no CSF": (bytes(no_csf), ivt_at + r"no CSF: its csf pointer is 0"),
            "CSF pointer past the end": (bytes(too_far), ivt_at + rf"CSF pointer {FIT_BASE + len(good):#010x} is "
                                                                  rf"outside the file: offset {len(good):#x}, the "
                                                                  rf"file has {len(good):#x} bytes"),
            "CSF pointer before the start": (bytes(before), ivt_at + r"CSF pointer 0x4047ffe0 is outside the file: "
                                                                     r"offset -0x20"),
            "truncated CSF": (good[:0x2034], at + r"CSF: length mismatch: header says 40 bytes, only 20 left in the "
                                                  r"file"),
            "truncated SRK table": (good[:0x2100], at + r"SRK table: length mismatch: header says 276 bytes, the data "
                                                        r"has 184"),
            "SRK table offset past the end": (u_boot_itb(csf(TABLE, offset=0x10000)),
                                              at + r"SRK table offset 0x10000 is outside the file: 0x14c bytes from "
                                                   r"the CSF"),
            "SRK table offset into the commands": (u_boot_itb(csf(TABLE, offset=4)),
                                                   at + r"SRK table: header tag 0xbe, expected 0xd7"),
            "bad CSF tag": (u_boot_itb(b"\xd5" + csf(TABLE)[1:]), at + r"CSF: header tag 0xd5, expected 0xd4"),
            "command overrun": (bytes(overrun), at + r"CSF: command at offset 4: length mismatch: command says 256 "
                                                     r"bytes, expected 4 to the 36 left in the CSF"),
            "short Install Key": (bytes(short), at + r"CSF: command at offset 4: Install Key of 8 bytes, expected at "
                                                      r"least 12"),
            "no Install SRK": (u_boot_itb(csf(TABLE, protocol=0x09)), at + r"CSF: no Install SRK command"),
            "two Install SRK": (u_boot_itb(csf(TABLE, extra=install_key(0, 0x03, 1, 0, 52))),
                                at + r"CSF: 2 Install SRK commands, expected 1"),
            "absolute SRK address": (u_boot_itb(csf(TABLE, flags=0x01)),
                                     at + r"CSF: command at offset 4: Install SRK flags 0x01 give an absolute address"),
            "wrong SRK index": (u_boot_itb(csf(srk_table(1, 2), index=2)),
                                ivt_at + r"SRK index 2 is not in the SRK table: expected 0 to 1"),
            "CSFs install different tables": (flash_bin(csf(TABLE), csf(OTHER)),
                                              r"flash.bin: IVTs at offsets 0x400 and 0x3000 disagree: their CSFs "
                                              r"install different SRK tables"),
            "CSFs install different indexes": (flash_bin(csf(TABLE, 0), csf(TABLE, 1)),
                                               r"IVTs at offsets 0x400 and 0x3000 disagree: their CSFs install "
                                               r"different SRK indexes 0 and 1"),
        }
        for name, (data, message) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(fp.PreflightError, message):
                self.extract(data)

    def test_unreadable_image_is_refused(self):
        with self.assertRaisesRegex(fp.PreflightError, r"missing.bin: cannot read: No such file"):
            fp.extract_srk(self.dir / "missing.bin")

    def test_table_that_differs_from_the_planned_hash(self):
        digest, other = fp.srk_fuse_hash(TABLE), fp.srk_fuse_hash(OTHER)
        findings = fp.check_images({"u-boot.itb": self.extract(u_boot_itb(csf(OTHER)))}, digest, plan_for(TABLE))
        self.assertEqual(findings, [fp.Finding("table mismatch", f"u-boot.itb: IVT at offset 0x2000: SRK table "
                                                                 f"mismatch: expected hash {digest.hex()}, got "
                                                                 f"{other.hex()}")])

    def test_write_that_may_revoke_the_srk_index_in_use(self):
        images = {"flash.bin": self.extract(flash_bin(csf(TABLE, 1), csf(TABLE, 1))),
                  "u-boot.itb": self.extract(u_boot_itb(csf(TABLE, 3)))}
        findings = fp.check_images(images, fp.srk_fuse_hash(TABLE), plan_for(TABLE, "fuse prog 9 3 0x2"))
        self.assertEqual(findings, [fp.Finding("revocation unchecked", "line 9: bank 9 word 3: revocation unchecked: "
                                               "expected no write that may revoke SRK index 1, 3, got 0x00000002; "
                                               "neither guide states where SRK_REVOKE is")])

    def test_no_images_is_a_finding(self):
        self.assertEqual([f.kind for f in fp.check_images({}, fp.srk_fuse_hash(TABLE), plan_for(TABLE))], ["no image"])

    def test_damaged_images_raise_only_preflight_errors(self):
        rng, good = random.Random(29), flash_bin(csf(TABLE, 1), csf(TABLE, 1))
        structure = [range(0x400, 0x420), range(0xA00, 0xA00 + 0x14C), range(0x3000, 0x3020 + 0x14C)]
        digest, outcomes = fp.srk_fuse_hash(TABLE), set()
        for i in range(200):
            data = bytearray(good)
            if i % 2:
                del data[rng.randrange(len(data)):]
            else:
                for _ in range(rng.randint(1, 4)):  # in the IVTs and CSFs, where a flip reaches the parser
                    data[rng.choice(rng.choice(structure))] ^= 1 << rng.randrange(8)
            with self.subTest(i):
                try:
                    fp.check_images({"flash.bin": self.extract(bytes(data))}, digest, [])
                    outcomes.add("extracted")
                except fp.PreflightError:
                    outcomes.add("refused")
        self.assertEqual(outcomes, {"extracted", "refused"})


if __name__ == "__main__":
    unittest.main()
