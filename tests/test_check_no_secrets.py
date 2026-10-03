"""Unit tests for tools/check_no_secrets.py."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import check_no_secrets as cs  # noqa: E402

# Assembled at runtime so this file does not trip the scanner itself.
PEM_HEADER = "-----BEGIN " + "EC PRIVATE KEY-----"
PX4_KEY = '{"public": "' + "ab" * 32 + '", "priv' + 'ate": "' + "cd" * 32 + '"}'


class ScanTest(unittest.TestCase):
    def scan(self, files: dict[str, str]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in files.items():
                (root / name).write_text(text)
            return cs.scan(root)

    def test_pem_private_key_is_found(self):
        self.assertEqual(self.scan({"k.txt": PEM_HEADER + "\nAAAA\n"}), ["k.txt: PEM private key"])

    def test_px4_key_file_is_found(self):
        self.assertEqual(self.scan({"key.json": PX4_KEY}), ["key.json: PX4 secure-boot private key"])

    def test_public_material_is_allowed(self):
        self.assertEqual(self.scan({"pub.pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n",
                                    "key0.pub": "0x01, 0x02"}), [])


if __name__ == "__main__":
    unittest.main()
