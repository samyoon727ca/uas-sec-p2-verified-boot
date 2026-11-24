"""Cross-check tools/fuse_preflight.py's SRK fuse hash against NXP's SPSDK, an independent HABv4 implementation.

The unit tests in test_fuse_preflight.py build their SRK tables by hand from the same reading of the format as the
tool, so a misreading would match itself there. Here SPSDK builds each table and its fuse values from certificates.
SPSDK is test-only (requirements-spsdk.txt); without it these tests skip, unless P2_REQUIRE_SPSDK=1 (set in CI)
makes a missing or changed SPSDK an error instead of a skip.
"""
from __future__ import annotations

import datetime
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import fuse_preflight as fp  # noqa: E402

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from spsdk.crypto.certificate import Certificate
    from spsdk.image.hab.hab_srk import SrkItem, SrkTable
except ImportError as exc:
    if os.environ.get("P2_REQUIRE_SPSDK") == "1":
        raise
    SPSDK_MISSING = f"SPSDK not importable ({exc}); install requirements-spsdk.txt"
else:
    SPSDK_MISSING = ""


def srk_certificate(n: int) -> "Certificate":
    """A self-signed RSA-4096 SRK CA certificate, as CST's hab4_pki_tree.sh makes them: a fresh key per run, kept
    only in memory, and CA key usage, which gives the table entry flag 0x80."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"P2 test SRK{n}")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return Certificate(cert)


@unittest.skipUnless(not SPSDK_MISSING, SPSDK_MISSING)
class SpsdkSrkReferenceTest(unittest.TestCase):
    def test_hash_and_words_match_spsdk_for_one_two_and_four_keys(self):
        for n in (1, 2, 4):
            with self.subTest(keys=n):
                table = SrkTable()
                for i in range(n):
                    table.append(SrkItem.from_certificate(srk_certificate(i + 1)))
                data = table.export()

                parsed = fp.parse_srk_table(data)
                self.assertEqual(parsed.keys, tuple(srk.export() for srk in table))
                self.assertTrue(all(entry[7] == 0x80 for entry in parsed.keys))    # CA flag, as CST sets it
                digest = fp.srk_fuse_hash(data)
                self.assertEqual(digest, table.export_fuses())
                self.assertEqual(fp.fuse_words(digest), [table.get_fuse(i) for i in range(8)])
                # And SPSDK reads the table as the tool does: same fuse hash from SPSDK's own parse of the bytes.
                self.assertEqual(SrkTable.parse(data).export_fuses(), digest)


if __name__ == "__main__":
    unittest.main()
