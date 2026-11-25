"""Replay of the A-01 counterexample TLC finds on model/Epoch.cfg, on swtpm with tpm2-tools.

The trace, tests/model/fixtures/a01-trace.json (TLC's counterexample on Epoch.cfg, states 1 to 9), is translated by
model/trace_to_tpm2.py; A01 below is the replay of it written by hand, the oracle the translation must equal. The
weakness is expected on today's recorded design (the epoch index of tests/ve07/provision.py, empty owner auth), so
the test passes when release 1 unseals after epoch 2 is committed. Around the generated commands the test adds:

  setup, not in the trace   provision.provision: parent, epoch index (docs/03 section 3.2, no bits set) and a
                            sealed key under PolicyAuthorize(K-CC-POL, policyRef); tools/approve_policy.py signs
                            releases 1 and 2 with a throwaway K-CC-POL in a temp dir
  baseline (TC-08)          after Commit(2), release 1: tpm2_startauthsession, tpm2_policypcr, then tpm2_policynv
                            is refused; release 2, the committed one, still unseals
  name check                after NV_SetBits({}), the index has the provisioned name, which the policies bind
  Unseal                    the key's SHA-256 is compared; the key is never printed

Release 1's policy is approved for the PCRs of a freshly reset swtpm (all zero); the test checks they are.
Runs in the model job (model/ci.py), and fails there without swtpm or tpm2-tools; elsewhere, as in the validate
job, it skips without them.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ve07"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "model"))
import provision  # noqa: E402
import trace_to_tpm2  # noqa: E402
from provision import EPOCH_NV, ap  # noqa: E402

TOOLS = ("swtpm", "swtpm_ioctl", "openssl", *(f"tpm2_{c}" for c in (
    "createprimary", "evictcontrol", "flushcontext", "readpublic", "nvdefine", "nvsetbits", "nvreadpublic",
    "loadexternal", "create", "nvundefine", "pcrread", "startauthsession", "policypcr", "policynv",
    "verifysignature", "policyauthorize", "load", "unseal")))
MISSING = [t for t in TOOLS if not shutil.which(t)]
KEY = "wireguard"   # the sealed object the replay unseals
PCRS = {i: "00" * 32 for i in ap.POLICY_PCRS}
PCR_SELECTION = "sha256:" + ",".join(map(str, ap.POLICY_PCRS))
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "a01-trace.json"
S = ["-S", "session.ctx"]
# The A-01 trace's actions (model/Epoch.tla) and their replay, by hand; {placeholders} as in model/README.md.
A01 = [
    ("Commit", [["tpm2_nvsetbits", "-Q", "{epoch_index}", "-C", "o", "-i", f"{1 << 2:#x}"]]),   # section 3.5, step 4
    ("NV_UndefineSpace", [["tpm2_nvundefine", "-Q", "{epoch_index}", "-C", "o"]]),   # with the empty owner auth
    ("NV_DefineSpace", [["tpm2_nvdefine", "-Q", "{epoch_index}", "-C", "o", "-s", str(ap.EPOCH_NV_SIZE),
                         "-a", provision.EPOCH_NV_ATTRIBUTES]]),   # the provisioned attributes and size
    ("NV_SetBits", [["tpm2_nvsetbits", "-Q", "{epoch_index}", "-C", "o", "-i", "0x0"]]),   # written, no bits set
    ("StartAuthSession", [["tpm2_startauthsession", "--policy-session", *S]]),
    ("PolicyNV", [["tpm2_policypcr", "-Q", *S, "-l", "{pcr_selection}"],   # PCR stages are not in the model
                  ["tpm2_policynv", "-Q", *S, "-i", "{operand_1}", "{epoch_index}", "bc"]]),   # release 1's operand
    ("PolicyAuthorize", [["tpm2_loadexternal", "-Q", "-C", "o", "-G", "ecc", "-u", "{kpol_pub}", "-c", "kpol.ctx",
                          "-n", "kpol.name"],
                         ["tpm2_verifysignature", "-Q", "-c", "kpol.ctx", "-g", "sha256", "-m", "{signed_1}",
                          "-s", "{policy_dir_1}/approved.sig", "-t", "ticket.bin"],
                         ["tpm2_flushcontext", "-t"],
                         ["tpm2_policyauthorize", "-Q", *S, "-i", "{policy_dir_1}/approved", "-q", "{policy_ref}",
                          "-n", "kpol.name", "-t", "ticket.bin"]]),
    ("Unseal", [["tpm2_load", "-Q", "-C", "{parent}", "-u", "{sealed_pub}", "-r", "{sealed_priv}", "-c", "sealed.ctx"],
                ["tpm2_unseal", "-c", "sealed.ctx", "-p", "session:session.ctx"],
                ["tpm2_flushcontext", "-t"], ["tpm2_flushcontext", "-s"]]),
]


def translated(trace: Path) -> list[tuple[str, list[list[str]]]]:
    return [(s["action"], s["argv"]) for s in trace_to_tpm2.translate(json.loads(trace.read_text()))]


class TranslateA01Test(unittest.TestCase):
    """No swtpm or Java needed."""

    def test_fixture_translates_to_the_hand_written_replay(self):
        self.assertEqual(translated(FIXTURE), A01)

    @unittest.skipUnless(os.environ.get("P2_MODEL_TRACES"), "P2_MODEL_TRACES not set (model/ci.py sets it)")
    def test_tlc_counterexample_still_replays_as_the_fixture(self):
        self.assertEqual(translated(Path(os.environ["P2_MODEL_TRACES"]) / "Epoch.json"), A01)


# Skips without the tools, except under model/ci.py (P2_MODEL_TRACES set), which must not pass without the replay.
@unittest.skipIf(MISSING and not os.environ.get("P2_MODEL_TRACES"), f"not on PATH: {', '.join(MISSING)}")
class ReplayA01Test(unittest.TestCase):
    def setUp(self):
        self.assertFalse(MISSING, "model/ci.py needs swtpm and tpm2-tools on the PATH")
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

    def placeholders(self) -> dict[str, str]:
        """Values for model/trace_to_tpm2.py's placeholders; writes each release's operand and signed message."""
        sealed = self.prov.data / "sealed"
        values = {"epoch_index": EPOCH_NV, "pcr_selection": PCR_SELECTION, "parent": provision.PARENT,
                  "kpol_pub": "kpol.pem", "policy_ref": "policy-ref.bin",
                  "sealed_pub": str(sealed / f"{KEY}.pub"), "sealed_priv": str(sealed / f"{KEY}.priv")}
        (self.wd / "policy-ref.bin").write_bytes(ap.POLICY_REF)
        for e, policy in self.release.items():
            (self.wd / f"operand-{e}.bin").write_bytes(ap.epoch_operand(e))
            (self.wd / f"signed-{e}.bin").write_bytes((policy / "approved").read_bytes() + ap.POLICY_REF)
            values |= {f"operand_{e}": f"operand-{e}.bin", f"signed_{e}": f"signed-{e}.bin",
                       f"policy_dir_{e}": str(policy)}
        return values

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

        steps = trace_to_tpm2.translate(json.loads(FIXTURE.read_text()))
        self.assertEqual([(s["action"], s["argv"]) for s in steps], A01)
        values, unsealed = self.placeholders(), []
        for step in steps:
            for argv in step["argv"]:
                out = subprocess.run(trace_to_tpm2.fill(argv, values), cwd=self.wd, env=self.tpm.env, check=True,
                                     capture_output=True).stdout
                if argv[0] == "tpm2_unseal":
                    unsealed.append(hashlib.sha256(out).hexdigest())   # the key is kept in memory only
            if step["action"] == "Commit":   # the baseline: release 1 is refused at PolicyNV (TC-08)
                self.start_session()
                with self.assertRaises(subprocess.CalledProcessError, msg="release 1 passed PolicyNV after epoch 2"):
                    self.policy_nv(1)
                self.tpm2("flushcontext", "-s")
                self.start_session()
                self.policy_nv(2)
                self.assertEqual(self.authorize_and_unseal(self.release[2]), self.prov.secrets_sha256[KEY])
            elif step["action"] == "NV_SetBits":
                name = re.search(r"name:\s*([0-9a-f]+)", self.tpm2("nvreadpublic", EPOCH_NV)).group(1)
                self.assertEqual(name, ap.nv_name().hex(),
                                 "the redefined index's name differs from the one policies bind")
        self.assertEqual(unsealed, [self.prov.secrets_sha256[KEY]], "release 1 did not unseal the sealed key once")

if __name__ == "__main__":
    unittest.main()
