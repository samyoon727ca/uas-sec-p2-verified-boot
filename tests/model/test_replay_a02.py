"""Replay of the counterexample TLC finds on model/Boot.cfg, on swtpm with tpm2-tools.

The trace, tests/model/fixtures/a02-trace.json (TLC's counterexample on Boot.cfg), is translated by
model/trace_to_tpm2.py; A02 below is its actions, written by hand. The test plays each stage: U-Boot's measurements,
then the initramfs, which unseals and caps PCRs 0, 1, 8 and 9 (docs/03 section 3.3, step 4). It first checks
TC-05b's baseline: as userspace, after the cap, a new session is refused at PolicyAuthorize. Then the TPM alone is
reset (swtpm_ioctl -i, tpm2_startup -c), and userspace replays the predicted measurements and unseals. That is
expected on today's recorded design for an attacker who can reset the TPM alone (A2-02, THR-034's residual risk),
so the test passes when the second unseal succeeds. The release is approved for epoch 2, as in Boot.tla.

Runs in the model job (model/ci.py), and fails there without swtpm or tpm2-tools; elsewhere it skips without them.
"""
from __future__ import annotations

import hashlib
import json
import os
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
    "createprimary", "evictcontrol", "flushcontext", "readpublic", "nvdefine", "nvsetbits", "loadexternal", "create",
    "pcrextend", "pcrevent", "startauthsession", "policypcr", "policynv", "verifysignature", "policyauthorize",
    "load", "unseal", "shutdown", "startup")))
MISSING = [t for t in TOOLS if not shutil.which(t)]
KEY = "wireguard"   # the sealed object the replay unseals
CAP_EVENT = b"p2/cc-keys released"   # cc/initramfs/p2-unseal.c
# One digest per PCR stands for what U-Boot measures of the release into it; the policy covers the result.
MEASURED = {p: hashlib.sha256(f"p2-a02/pcr{p}".encode()).digest() for p in ap.POLICY_PCRS}
PCRS = {p: hashlib.sha256(bytes(32) + d).hexdigest() for p, d in MEASURED.items()}
PCR_SELECTION = "sha256:" + ",".join(map(str, ap.POLICY_PCRS))
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "a02-trace.json"
MEASURE = [("Extend", [str(p), "release"]) for p in ap.POLICY_PCRS]
UNSEAL = [("StartAuthSession", []), ("PolicyPCR", []), ("PolicyNV", ["0x01000001", [3]]),
          ("PolicyAuthorize", [2]), ("Unseal", [])]
A02 = [("Handover", ["uboot"]), *MEASURE, ("Handover", ["kernel"]), ("Handover", ["initramfs"]), *UNSEAL,
       *[("Extend", [str(p), "cap"]) for p in ap.POLICY_PCRS], ("Handover", ["userspace"]),
       ("TPMReset", []), *MEASURE, *UNSEAL]


def actions(trace: Path) -> list[tuple[str, list]]:
    return [(s["action"], s["args"]) for s in trace_to_tpm2.translate(json.loads(trace.read_text()))]


class TranslateA02Test(unittest.TestCase):
    """No swtpm or Java needed."""

    def test_fixture_translates_to_the_hand_written_actions(self):
        self.assertEqual(actions(FIXTURE), A02)

    @unittest.skipUnless(os.environ.get("P2_MODEL_TRACES"), "P2_MODEL_TRACES not set (model/ci.py sets it)")
    def test_tlc_counterexample_still_replays_as_the_fixture(self):
        self.assertEqual(actions(Path(os.environ["P2_MODEL_TRACES"]) / "Boot.json"), A02)


# Skips without the tools, except under model/ci.py (P2_MODEL_TRACES set), which must not pass without the replay.
@unittest.skipIf(MISSING and not os.environ.get("P2_MODEL_TRACES"), f"not on PATH: {', '.join(MISSING)}")
class ReplayA02Test(unittest.TestCase):
    def setUp(self):
        self.assertFalse(MISSING, "model/ci.py needs swtpm and tpm2-tools on the PATH")
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="p2a02-")))
        self.wd = self.tmp / "replay"
        self.wd.mkdir()
        kpol = self.tmp / "k-cc-pol.pem"   # throwaway K-CC-POL, deleted with the temp dir
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-out", str(kpol)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(kpol), "-pubout", "-out", str(self.wd / "kpol.pem")],
                       check=True, capture_output=True)
        self.prov = provision.provision(self.tmp, self.tmp, kpol, PCRS, epoch=2)   # release 2's policy
        self.tpm = provision.TcpSwtpm(self.prov.state)
        self.addCleanup(self.tpm.stop)

    def placeholders(self) -> dict[str, str]:
        """Values for model/trace_to_tpm2.py's placeholders; writes the operand, signed message and cap event."""
        sealed, policy = self.prov.data / "sealed", self.prov.data / "policy"
        (self.wd / "policy-ref.bin").write_bytes(ap.POLICY_REF)
        (self.wd / "operand-2.bin").write_bytes(ap.epoch_operand(2))
        (self.wd / "signed-2.bin").write_bytes((policy / "approved").read_bytes() + ap.POLICY_REF)
        (self.wd / "cap-event.bin").write_bytes(CAP_EVENT)
        return {"epoch_index": EPOCH_NV, "pcr_selection": PCR_SELECTION, "parent": provision.PARENT,
                "kpol_pub": "kpol.pem", "policy_ref": "policy-ref.bin", "operand_2": "operand-2.bin",
                "signed_2": "signed-2.bin", "policy_dir_2": str(policy), "cap_event": "cap-event.bin",
                "sealed_pub": str(sealed / f"{KEY}.pub"), "sealed_priv": str(sealed / f"{KEY}.priv"),
                "swtpm_ctrl": f"127.0.0.1:{self.tpm.port + 1}", **{f"release_{p}": d.hex() for p, d in MEASURED.items()}}

    def run_step(self, step: dict, values: dict[str, str]) -> list[str]:
        """Runs a step's commands; the SHA-256 of what tpm2_unseal returns, which is kept in memory only."""
        unsealed = []
        for argv in step["argv"]:
            out = subprocess.run(trace_to_tpm2.fill(argv, values), cwd=self.wd, env=self.tpm.env, check=True,
                                 capture_output=True).stdout
            if argv[0] == "tpm2_unseal":
                unsealed.append(hashlib.sha256(out).hexdigest())
        return unsealed

    def test_a02_userspace_unseals_after_tpm_reset_on_recorded_design(self):
        steps = trace_to_tpm2.translate(json.loads(FIXTURE.read_text()))
        self.assertEqual([(s["action"], s["args"]) for s in steps], A02)
        values, unsealed = self.placeholders(), []
        reset, session = A02.index(("TPMReset", [])), A02.index(("StartAuthSession", []))
        for step in steps[:reset]:   # U-Boot, the kernel and the initramfs, then userspace starts
            unsealed += self.run_step(step, values)
        self.assertEqual(unsealed, [self.prov.secrets_sha256[KEY]], "the initramfs did not unseal the key")
        for step in steps[session:session + 3]:   # TC-05b: after the cap, the initramfs's session is refused
            self.run_step(step, values)
        with self.assertRaises(subprocess.CalledProcessError, msg="PolicyAuthorize passed after the cap"):
            self.run_step(steps[session + 3], values)
        self.tpm.tpm2("flushcontext", "-s", cwd=self.wd)
        for step in steps[reset:]:   # the TPM alone resets; userspace replays the measurements and unseals
            unsealed += self.run_step(step, values)
        self.assertEqual(unsealed, [self.prov.secrets_sha256[KEY]] * 2, "userspace did not unseal after the reset")


if __name__ == "__main__":
    unittest.main()
