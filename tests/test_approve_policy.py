"""Unit tests for tools/approve_policy.py and the TC-05 parts of the VE-07 harness."""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "ve07"))
import approve_policy as ap  # noqa: E402
import boot_cases as bc  # noqa: E402
import provision  # noqa: E402

# Known answers from tpm2-tools 5.6 on swtpm 0.7.3 (trial sessions, nvreadpublic, loadexternal -n),
# for a K-CC-POL public key loaded with "tpm2_loadexternal -C o -G ecc".
KPOL_PUB = bytes.fromhex(
    "00560023000b00060040000000100010000300100020"
    "5758893289ffff4a140d6866d7cc11b096d4b8279fefe0dec429fbee02b699d6"
    "0020d1fdf972aaadd7912d888e06a831415d483f7316c1dc75275bb29c4e6b688061")
KPOL_NAME = "000b4d913dc3c48e5016ab1856be51d98e2250f61533e108ab3d651347c06ba7dff9"
NV_NAME = "000b4e4310ce5717f2559389029b6820ccb55eaf00dc3bf868b64ff885b7b8c0171c"
SEAL_POLICY = "272e5231683f84c429bcfc6b9b9d760ffd227ce7fea0c1a9b4040c862663a4ea"   # PolicyAuthorize(KPOL, "p2/cc-keys")
PCRS = {0: "01" * 32, 1: "02" * 32, 8: "08" * 32, 9: "09" * 32}
POLICY_PCR = "5ac525dc85eb0fb44a4ee57cfe9809e7a272a75cb13ef9bed2301083c87ae02c"
APPROVED_E0 = "83b0066c89bc2d086e704f4fcea289eb4303b45df7fe65650447fe3f3e32fee0"   # + PolicyNV(epoch 0)


def der_int(n: bytes) -> bytes:
    n = n.lstrip(b"\0") or b"\0"
    if n[0] & 0x80:
        n = b"\0" + n
    return bytes([0x02, len(n)]) + n


def der_sig(r: bytes, s: bytes) -> bytes:
    body = der_int(r) + der_int(s)
    return bytes([0x30, len(body)]) + body


class KnownAnswerTest(unittest.TestCase):
    def test_epoch_index_name(self):
        self.assertEqual(ap.nv_name().hex(), NV_NAME)

    def test_public_area_and_name(self):
        pub = ap.parse_public(KPOL_PUB)
        self.assertEqual(pub["name"].hex(), KPOL_NAME)
        self.assertEqual((pub["type"], pub["attributes"], pub["auth_policy"]), (0x0023, 0x00060040, b""))

    def test_seal_policy(self):
        self.assertEqual(ap.policy_authorize(bytes.fromhex(KPOL_NAME)).hex(), SEAL_POLICY)

    def test_policy_pcr(self):
        self.assertEqual(ap.policy_pcr(bytes(32), PCRS).hex(), POLICY_PCR)

    def test_approved_policy(self):
        self.assertEqual(ap.approved_policy(PCRS, 0).hex(), APPROVED_E0)


class PolicyTest(unittest.TestCase):
    def test_pcr_selection_bitmap(self):
        self.assertEqual(ap.pcr_selection().hex(), "00000001" "000b" "03" "030300")

    def test_epoch_operand_sets_every_bit_above_the_epoch(self):
        self.assertEqual(ap.epoch_operand(0).hex(), "fffffffffffffffe")
        self.assertEqual(ap.epoch_operand(5).hex(), "ffffffffffffffc0")
        self.assertEqual(ap.epoch_operand(63).hex(), "0000000000000000")
        for bad in (-1, 64):
            with self.subTest(bad), self.assertRaises(ValueError):
                ap.epoch_operand(bad)

    def test_each_input_changes_the_approved_policy(self):
        base = ap.approved_policy(PCRS, 0)
        self.assertNotEqual(ap.approved_policy({**PCRS, 9: "00" * 32}, 0), base)
        self.assertNotEqual(ap.approved_policy(PCRS, 1), base)
        self.assertNotEqual(ap.approved_policy(PCRS, 0, ap.nv_name(index=0x01000002)), base)

    def test_parse_public_rejects_garbage(self):
        for blob in (b"\x00\x05abc", KPOL_PUB[:-1], KPOL_PUB.replace(b"\x00\x0b", b"\x00\x04", 1)):
            with self.subTest(blob[:6].hex()), self.assertRaises(ValueError):
                ap.parse_public(blob)


class SignatureTest(unittest.TestCase):
    def test_der_to_tpmt_signature(self):
        r, s = bytes([0x80]) + bytes(range(31)), bytes(range(1, 31))   # high bit set; short
        sig = ap.der_to_tpmt_signature(der_sig(r, s))
        self.assertEqual(sig[:6], struct.pack(">HHH", 0x0018, 0x000B, 32))
        self.assertEqual(sig[6:38], r)
        self.assertEqual(sig[38:40], struct.pack(">H", 32))
        self.assertEqual(sig[40:], s.rjust(32, b"\0"))

    def test_der_errors(self):
        good = der_sig(b"\x01" * 32, b"\x02" * 32)
        for bad in (good + b"\0", b"\x31" + good[1:], der_sig(b"\x01" * 33, b"\x02" * 32)):
            with self.subTest(bad[:4].hex()), self.assertRaises(ValueError):
                ap.der_to_tpmt_signature(bad)

    @unittest.skipUnless(shutil.which("openssl"), "openssl not on PATH")
    def test_sign_verifies_with_openssl(self):
        with tempfile.TemporaryDirectory() as tmp:
            key, pub, sig_der, msg = (Path(tmp) / n for n in ("k.pem", "p.pem", "s.der", "m.bin"))
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-out", str(key)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True,
                           capture_output=True)
            approved = bytes.fromhex(APPROVED_E0)
            sig = ap.sign(key, approved)
            sig_der.write_bytes(der_sig(sig[6:38], sig[40:]))
            msg.write_bytes(approved + ap.POLICY_REF)
            ok = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig_der),
                                 str(msg)], capture_output=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)


class SharedConstantsTest(unittest.TestCase):
    """The C agent, the MSS tool and the provisioning must agree."""

    def test_agent_constants(self):
        src = (ROOT / "cc/initramfs/p2-unseal.c").read_text()
        define = dict(re.findall(r"(?m)^#define (\w+) (\S+)$", src))
        self.assertEqual(int(define["PARENT_HANDLE"], 16), ap.PARENT_HANDLE)
        self.assertEqual(int(define["EPOCH_NV_INDEX"], 16), ap.EPOCH_NV_INDEX)
        self.assertEqual(define["POLICY_REF"].strip('"').encode(), ap.POLICY_REF)
        bitmap = re.search(r"\.pcrSelect = \{ (0x\w+), (0x\w+), (0x\w+) \}", src).groups()
        self.assertEqual(bytes(int(b, 16) for b in bitmap), ap.pcr_selection()[-3:])
        self.assertIn("TPM2_EO_BITCLEAR", src)

    def test_provisioned_nv_attributes(self):
        bits = {"ownerwrite": ap.TPMA_NV_OWNERWRITE, "nt=bits": ap.TPM_NT_BITS, "authread": ap.TPMA_NV_AUTHREAD,
                "no_da": ap.TPMA_NV_NO_DA}
        value = sum(bits[a] for a in provision.EPOCH_NV_ATTRIBUTES.split("|"))
        self.assertEqual(value | ap.TPMA_NV_WRITTEN, ap.EPOCH_NV_ATTRIBUTES)   # nvsetbits sets WRITTEN

    def test_sealed_attributes(self):
        self.assertEqual(sorted(provision.SEALED_ATTRIBUTES.split("|")), ["adminwithpolicy", "fixedparent", "fixedtpm"])


class HarnessTest(unittest.TestCase):
    def test_tar_folder_is_reproducible_and_padded(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "policy").mkdir()
            (d / "policy/epoch").write_text("0\n")
            (d / "parent.name").write_bytes(b"\x00\x0b" + bytes(32))
            first = provision.tar_folder(d)
            (d / "policy/epoch").touch()
            self.assertEqual(provision.tar_folder(d), first)
            self.assertEqual(len(first), provision.DATA_DISK_BYTES)

    def test_wireguard_key_is_clamped(self):
        k = provision.wireguard_key()
        self.assertEqual((len(k), k[0] & 7, k[31] & 0xC0), (32, 0, 0x40))

    def record(self, **over):
        sealed = {"flags": ["adminwithpolicy", "fixedparent", "fixedtpm"], "auth_policy": SEAL_POLICY}
        r = {"epoch_nv_name": {"tpm": NV_NAME, "computed": NV_NAME},
             "kpol_name": {"tpm": KPOL_NAME, "computed": KPOL_NAME}, "seal_policy": SEAL_POLICY,
             "sealed_objects": {"wireguard": dict(sealed), "mavlink": dict(sealed)}}
        r.update(over)
        return provision.Provisioned(Path("."), Path("."), b"", {"wireguard": "aa" * 32, "mavlink": "bb" * 32}, r)

    def test_unseal_checks(self):
        text = "P2-UNSEAL wireguard ok\r\nP2-KEY wireguard sha256 " + "aa" * 32 + "\r\nP2-KEY mavlink sha256 " \
            + "bb" * 32 + "\r\n"
        self.assertTrue(all(c["ok"] for c in bc.unseal_checks(self.record(), text)))
        wrong = text.replace("bb" * 32, "cc" * 32)
        failed = [c["pattern"] for c in bc.unseal_checks(self.record(), wrong) if not c["ok"]]
        self.assertEqual(failed, ["mavlink: SHA-256 of the unsealed key equals the key sealed"])

    def test_provisioning_checks_catch_a_user_auth_object(self):
        rec = self.record()
        rec.record["sealed_objects"]["mavlink"]["flags"] = ["adminwithpolicy", "fixedparent", "fixedtpm",
                                                            "userwithauth"]
        failed = [c["pattern"] for c in provision.provisioning_checks(rec) if not c["ok"]]
        self.assertEqual(len(failed), 1)
        self.assertTrue(failed[0].startswith("mavlink: fixedtpm"))

    def test_data_disk_comes_before_the_boot_slot(self):
        m = bc.Machine(Path("u.bin"), Path("slot.img"), Path("f.img"), None, Path("sock"), data=Path("cc.img"))
        argv = m.argv()
        drives = [a for a in argv if a.startswith("if=none")]
        self.assertTrue(drives[0].startswith("if=none,id=data") and drives[1].startswith("if=none,id=slot"))
        self.assertFalse(any("id=data" in a for a in bc.Machine(Path("u"), Path("s"), Path("f"), None,
                                                                 Path("k")).argv()))


if __name__ == "__main__":
    unittest.main()
