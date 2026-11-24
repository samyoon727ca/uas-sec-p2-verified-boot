"""Replay of the A-01 counterexample TLC finds on model/Epoch.cfg, by hand, on swtpm with tpm2-tools.

The weakness is expected on today's recorded design (the epoch index of tests/ve07/provision.py, empty owner
auth), so the test passes when release 1 unseals after epoch 2 is committed. Each step and the TLC trace action
it replays (model/Epoch.tla; the trace's states 2 to 9):

  setup, not in the trace   provision.provision: parent, epoch index (docs/03 section 3.2, no bits set) and a
                            sealed key under PolicyAuthorize(K-CC-POL, policyRef); tools/approve_policy.py signs
                            releases 1 and 2 with a throwaway K-CC-POL in a temp dir
  Commit(2)                 tpm2_nvsetbits -C o -i 0x4 (section 3.5, step 4)
  baseline (TC-08)          release 1: tpm2_startauthsession, tpm2_policypcr, then tpm2_policynv is refused;
                            release 2, the committed one, still unseals in the same steps as below
  NV_UndefineSpace          tpm2_nvundefine -C o, with the empty owner auth
  NV_DefineSpace            tpm2_nvdefine -C o with the provisioned attributes and size
  NV_SetBits({})            tpm2_nvsetbits -C o -i 0: written, no bits set, so the name is the provisioned one
  StartAuthSession          tpm2_startauthsession --policy-session
  PolicyNV                  tpm2_policypcr (PCR stages are abstracted away in the model), tpm2_policynv with
                            release 1's operand, TPM_EO_BITCLEAR
  PolicyAuthorize           tpm2_loadexternal and tpm2_verifysignature of release 1's signed policy, then
                            tpm2_policyauthorize
  Unseal                    tpm2_load, tpm2_unseal: the key's SHA-256 is compared, the key is never printed

Release 1's policy is approved for the PCRs of a freshly reset swtpm (all zero); the test checks they are.
Runs in the model job (model/ci.py); skips where swtpm or tpm2-tools is not on the PATH, as in the validate job.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ve07"))
import provision  # noqa: E402
from provision import EPOCH_NV, ap  # noqa: E402

TOOLS = ("swtpm", "swtpm_ioctl", "openssl", *(f"tpm2_{c}" for c in (
    "createprimary", "evictcontrol", "flushcontext", "readpublic", "nvdefine", "nvsetbits", "nvreadpublic",
    "loadexternal", "create", "nvundefine", "pcrread", "startauthsession", "policypcr", "policynv",
    "verifysignature", "policyauthorize", "load", "unseal")))
MISSING = [t for t in TOOLS if not shutil.which(t)]
KEY = "wireguard"   # the sealed object the replay unseals
PCRS = {i: "00" * 32 for i in ap.POLICY_PCRS}
PCR_SELECTION = "sha256:" + ",".join(map(str, ap.POLICY_PCRS))


@unittest.skipUnless(not MISSING, f"not on PATH: {', '.join(MISSING)}")
class ReplayA01Test(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="p2a01-")))
        self.wd = self.tmp / "replay"
        self.wd.mkdir()
        kpol = self.tmp / "k-cc-pol.pem"   # throwaway K-CC-POL, deleted with the temp dir
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-out", str(kpol)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(kpol), "-pubout", "-out", str(self.wd / "kpol.pem")],
                       check=True, capture_output=True)
        self.prov = provision.provision(self.tmp, self.tmp, kpol, PCRS, epoch=1)   # writes release 1's policy
        self.release = {1: self.prov.data / "policy", 2: self.tmp / "release2" / "policy"}
        approved = ap.approved_policy(PCRS, 2)
        ap.write_policy(self.release[2].parent, approved, ap.sign(kpol, approved), 2)
        self.tpm = provision.TcpSwtpm(self.prov.state)
        self.addCleanup(self.tpm.stop)

    def tpm2(self, *args: str) -> str:
        return self.tpm.tpm2(*args, cwd=self.wd)

    def start_session(self) -> None:
        self.tpm2("startauthsession", "--policy-session", "-S", "session.ctx")
        self.tpm2("policypcr", "-Q", "-S", "session.ctx", "-l", PCR_SELECTION)

    def policy_nv(self, epoch: int) -> None:
        (self.wd / "operand.bin").write_bytes(ap.epoch_operand(epoch))
        self.tpm2("policynv", "-Q", "-S", "session.ctx", "-i", "operand.bin", EPOCH_NV, "bc")

    def authorize_and_unseal(self, policy: Path) -> str:
        """PolicyAuthorize with the TPM's ticket for this release's signed policy, then Unseal; the key's SHA-256."""
        (self.wd / "signed.bin").write_bytes((policy / "approved").read_bytes() + ap.POLICY_REF)
        (self.wd / "policy-ref.bin").write_bytes(ap.POLICY_REF)
        self.tpm2("loadexternal", "-Q", "-C", "o", "-G", "ecc", "-u", "kpol.pem", "-c", "kpol.ctx", "-n", "kpol.name")
        self.tpm2("verifysignature", "-Q", "-c", "kpol.ctx", "-g", "sha256", "-m", "signed.bin",
                  "-s", str(policy / "approved.sig"), "-t", "ticket.bin")
        self.tpm2("flushcontext", "-t")   # swtpm has no resource manager
        self.tpm2("policyauthorize", "-Q", "-S", "session.ctx", "-i", str(policy / "approved"),
                  "-q", "policy-ref.bin", "-n", "kpol.name", "-t", "ticket.bin")
        sealed = self.prov.data / "sealed"
        self.tpm2("load", "-Q", "-C", provision.PARENT, "-u", str(sealed / f"{KEY}.pub"),
                  "-r", str(sealed / f"{KEY}.priv"), "-c", "sealed.ctx")
        secret = subprocess.run(["tpm2_unseal", "-c", "sealed.ctx", "-p", "session:session.ctx"], cwd=self.wd,
                                env=self.tpm.env, check=True, capture_output=True).stdout   # kept in memory only
        self.tpm2("flushcontext", "-t")
        self.tpm2("flushcontext", "-s")
        return hashlib.sha256(secret).hexdigest()

    def test_a01_old_release_unseals_after_redefine_on_recorded_design(self):
        pcrs = self.tpm2("pcrread", PCR_SELECTION, "-o", "pcrs.bin")
        self.assertEqual((self.wd / "pcrs.bin").read_bytes(), bytes(32 * len(PCRS)), f"PCRs not zero: {pcrs}")

        # Commit(2), then the baseline: release 1 is refused at PolicyNV (TC-08).
        self.tpm2("nvsetbits", "-Q", EPOCH_NV, "-C", "o", "-i", f"{1 << 2:#x}")
        self.start_session()
        with self.assertRaises(subprocess.CalledProcessError, msg="release 1 passed PolicyNV after epoch 2"):
            self.policy_nv(1)
        self.tpm2("flushcontext", "-s")
        self.start_session()
        self.policy_nv(2)
        self.assertEqual(self.authorize_and_unseal(self.release[2]), self.prov.secrets_sha256[KEY])

        # NV_UndefineSpace and NV_DefineSpace with the empty owner auth, then NV_SetBits({}).
        self.tpm2("nvundefine", "-Q", EPOCH_NV, "-C", "o")
        self.tpm2("nvdefine", "-Q", EPOCH_NV, "-C", "o", "-s", str(ap.EPOCH_NV_SIZE),
                  "-a", provision.EPOCH_NV_ATTRIBUTES)
        self.tpm2("nvsetbits", "-Q", EPOCH_NV, "-C", "o", "-i", "0")
        name = re.search(r"name:\s*([0-9a-f]+)", self.tpm2("nvreadpublic", EPOCH_NV)).group(1)
        self.assertEqual(name, ap.nv_name().hex(), "the redefined index's name differs from the one policies bind")

        # StartAuthSession, PolicyNV, PolicyAuthorize and Unseal under release 1's policy.
        self.start_session()
        self.policy_nv(1)
        self.assertEqual(self.authorize_and_unseal(self.release[1]), self.prov.secrets_sha256[KEY],
                         "release 1 unsealed something other than the sealed key")


if __name__ == "__main__":
    unittest.main()
