"""Unit tests for tools/check_no_secrets.py."""
from __future__ import annotations

import base64
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import check_no_secrets as cs  # noqa: E402


def joined(*parts: str) -> str:
    """Assemble a sample at run time, so that neither this file nor its compiled .pyc trips the scanner.

    Literals joined with "+" would not do: CPython folds them into one constant in the .pyc.
    """
    return "".join(parts)


PEM_HEADER = joined("-----BEGIN ", "EC PRIVATE KEY-----")
PX4_KEY = joined('{"public": "', "ab" * 32, '", "priv', 'ate": "', "cd" * 32, '"}')
WG_KEY = base64.b64encode(bytes(range(32))).decode()   # 43 characters and one "="
WG_CONF = joined("[Interface]\n", "Private", "Key = ", WG_KEY, "\nListenPort = 51820\n")


class ScanTest(unittest.TestCase):
    def scan(self, files: dict[str, str]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text)
            return sorted(Path(f.split(": ")[0]).as_posix() + ": " + f.split(": ")[1] for f in cs.scan(root))

    def test_pem_private_key_is_found(self):
        self.assertEqual(self.scan({"k.txt": PEM_HEADER + "\nAAAA\n"}), ["k.txt: PEM private key"])

    def test_px4_key_file_is_found(self):
        self.assertEqual(self.scan({"key.json": PX4_KEY}), ["key.json: PX4 secure-boot private key"])

    def test_wireguard_private_key_is_found(self):
        self.assertEqual(self.scan({"wg0.conf": WG_CONF}), ["wg0.conf: WireGuard private key"])
        self.assertEqual(self.scan({"wg0.conf": WG_CONF.replace(" = ", "=")}), ["wg0.conf: WireGuard private key"])

    def test_public_material_is_allowed(self):
        self.assertEqual(self.scan({"pub.pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n",
                                    "key0.pub": "0x01, 0x02",
                                    "peer.conf": "[Peer]\nPublicKey = " + WG_KEY + "\n",
                                    "notes.md": joined("Set Private", "Key = <base64> in wg0.conf.\n")}), [])

    def test_outside_git_compiled_caches_are_skipped_and_a_keys_folder_is_not(self):
        # These temporary folders are not git checkouts, just as an evidence folder in CI is not.
        self.assertEqual(self.scan({"tests/__pycache__/test_x.cpython-312.pyc": PEM_HEADER + PX4_KEY,
                                    "stray.pyc": WG_CONF,
                                    "keys/k-cc-os.key": PEM_HEADER + "\nAAAA\n"}),
                         ["keys/k-cc-os.key: PEM private key"])

    def test_this_test_does_not_trip_the_scanner(self):
        # The source, and every string constant its compiled form holds (what a .pyc stores).
        source = Path(__file__).read_bytes()
        self.assertEqual([label for label, p in cs.PATTERNS.items() if p.search(source)], [])
        constants, todo = [], [compile(source, __file__, "exec")]
        while todo:
            for c in todo.pop().co_consts:
                if hasattr(c, "co_consts"):
                    todo.append(c)
                elif isinstance(c, str):
                    constants.append(c.encode())
        compiled = b"\n".join(constants)
        self.assertEqual([label for label, p in cs.PATTERNS.items() if p.search(compiled)], [])


if __name__ == "__main__":
    unittest.main()
