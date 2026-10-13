"""Unit tests for the VE-08 host harness, tests/ve08/image_cases.py."""
from __future__ import annotations

import base64
import json
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "ve08"))
import image_cases as ic  # noqa: E402

APP = ic.APP_LOAD_ADDRESS


def app_image(size: int = 4096) -> bytes:
    """An image laid out like px4_fmu-v6x_secureboot: vectors, the TOC at +0x800, then code."""
    app = bytearray(b"\x5a" * size)
    end = APP + ((size + 3) & ~3)
    entries = [(b"BOOT", APP, end, 1, 0, 0x5), (b"SIG1", end, end + 64, 0, 0, 0)]
    toc = struct.pack("<II", 0x00434F54, 1)
    for name, start, stop, sig, key, flags in entries:
        toc += name + struct.pack("<IIIBBBBI", start, stop, 0, sig, key, 0, flags, 0)
    app[ic.TOC_OFFSET:ic.TOC_OFFSET + len(toc) + 4] = toc + struct.pack("<I", 0x00444E45)
    return bytes(app)


def c_array(key: bytes) -> str:
    return "// Public key to verify signed binaries\n" + "".join(
        ", ".join(f"0x{b:x}" for b in key[i:i + 8]) + ",\n" for i in range(0, 32, 8))


class ParseTest(unittest.TestCase):
    def test_public_key_from_c_array(self):
        key = bytes(range(32))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "k.pub"
            path.write_text(c_array(key))
            self.assertEqual(ic.public_key(path), key)
            path.write_text(c_array(key)[:-6])
            with self.assertRaises(ValueError):
                ic.public_key(path)

    def test_px4_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.px4"
            path.write_text(json.dumps({"board_id": 53, "image": base64.b64encode(zlib.compress(b"IMG")).decode(),
                                        "image_size": 3, "image_signed": True, "parameter_xml": "x"}))
            image, desc = ic.px4_image(path)
        self.assertEqual((image, desc), (b"IMG", {"board_id": 53, "image_size": 3, "image_signed": True}))

    def test_flip_lands_in_the_signed_range_past_the_toc(self):
        signed = app_image() + bytes(64)
        modified, at = ic.flip_in_app(signed)
        self.assertTrue(ic.TOC_OFFSET < at < len(signed) - ic.SIGNATURE_SIZE)
        self.assertEqual([i for i in range(len(signed)) if signed[i] != modified[i]], [at])


class EvaluateTest(unittest.TestCase):
    TOC0 = "P2-FC toc 0: BOOT 0x08020000-0x08021000 signature=1 key=0 flags=0x05\n"

    def case(self, starts):
        return ic.Case("X", "TC-11", "test", "t", "signed", "run-key", starts)

    def test_starts_and_stays(self):
        out = self.TOC0 + "P2-FC result: starts the application at 0x08020000\n"
        self.assertTrue(all(c["ok"] for c in ic.evaluate(self.case(True), out, 0, 4096 + 64)))
        self.assertFalse(all(c["ok"] for c in ic.evaluate(self.case(False), out, 0, 4096 + 64)))
        out = self.TOC0 + "P2-FC result: stays in the boot loader: TOC entry 0 does not verify\n"
        self.assertTrue(all(c["ok"] for c in ic.evaluate(self.case(False), out, 1, 4096 + 64)))
        self.assertFalse(all(c["ok"] for c in ic.evaluate(self.case(False), out, 2, 4096 + 64)))

    def test_toc_must_end_at_the_signature(self):
        out = self.TOC0 + "P2-FC result: starts the application at 0x08020000\n"
        self.assertFalse(all(c["ok"] for c in ic.evaluate(self.case(True), out, 0, 4100 + 64)))
        wrong_slot = out.replace("key=0", "key=1")
        self.assertFalse(all(c["ok"] for c in ic.evaluate(self.case(True), wrong_slot, 0, 4096 + 64)))


class StaticChecksTest(unittest.TestCase):
    def fc(self, tmp: Path, **over) -> Path:
        run_key, built = bytes(range(32)), app_image(4094)
        signed = built + b"\xff\xff" + bytes(64)
        files = {"bootloader.bin": b"\0" * 100 + run_key + b"\0" * 100, "firmware.bin": built,
                 "firmware-signed.bin": signed,
                 "firmware.px4": json.dumps({"image": base64.b64encode(zlib.compress(signed)).decode(),
                                             "image_signed": True}).encode()}
        files.update(over)
        if "firmware-signed.bin" in over and "firmware.px4" not in over:   # keep the envelope consistent
            files["firmware.px4"] = json.dumps({"image": base64.b64encode(zlib.compress(over["firmware-signed.bin"])).decode(),
                                                "image_signed": True}).encode()
        for name, data in files.items():
            (tmp / name).write_bytes(data)
        return tmp

    def test_all_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = ic.static_checks(self.fc(Path(tmp)), bytes(range(32)), bytes([7]) * 32)
        self.assertTrue(all(c["ok"] for c in checks), [c for c in checks if not c["ok"]])

    def test_each_check_can_fail(self):
        test_key = bytes([7]) * 32
        bad = {
            "the boot loader holds the run key once": {"bootloader.bin": b"\0" * 64},
            "the boot loader does not hold PX4's public test key": {"bootloader.bin": bytes(range(32)) + test_key},
            "the signed image is the built image, padded to 4 bytes, plus a 64-byte signature":
                {"firmware-signed.bin": app_image(4094) + b"\xff\xff" + bytes(63)},
            "the .px4 envelope carries the signed image and marks it signed":
                {"firmware.px4": json.dumps({"image": base64.b64encode(zlib.compress(b"x")).decode()}).encode()},
        }
        for pattern, over in bad.items():
            with self.subTest(pattern), tempfile.TemporaryDirectory() as tmp:
                checks = ic.static_checks(self.fc(Path(tmp), **over), bytes(range(32)), test_key)
                self.assertEqual([c["pattern"] for c in checks if not c["ok"]], [pattern])


if __name__ == "__main__":
    unittest.main()
