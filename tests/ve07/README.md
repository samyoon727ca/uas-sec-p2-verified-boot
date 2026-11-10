# VE-07 emulated harness

Runs the CC boot chain on QEMU `virt` with swtpm and checks the VE-07 test cases that emulation can prove ([docs/06](../../docs/06-verification.md)).

| Script | Covers |
|---|---|
| [`boot_cases.py`](boot_cases.py), [`provision.py`](provision.py) | TC-01 signed chain boots; TC-03 modified kernel, initramfs or devicetree refused; TC-04 modified boot configuration refused, with control runs on stock U-Boot and on the P2 build with one console setting relaxed; TC-05 keys unseal in the measured, unmodified boot state, and a second attempt in the same boot is refused, with a control run on an agent build that does not cap the PCRs; TC-06 keys do not unseal from a modified boot state; TC-07 keys do not unseal on another CC's TPM; TC-08 rollback and a rogue-signed policy refused; TC-09 unseal traffic holds neither key and comes from salted sessions, with control runs on the agent's two control builds: one leaves the response in the clear, the other encrypts it in a session that is not salted; TC-10 predicted PCRs equal the measured PCRs and the event-log replay |

## Run

Ubuntu 24.04 (the same image as the CI runner):

```sh
cc/emu/install-host-packages.sh           # pinned host packages from the Ubuntu snapshot (sudo)
cc/build.sh                               # six U-Boot variants (hardened, stock, two control, two TC-06 test builds), kernel, initramfs -> build/
python3 tests/ve07/boot_cases.py --build build --out /tmp/ve07
```

A run on your own machine is marked `local` in its summary and is not CI evidence, so write it outside `evidence/ve07-ci/`: that folder holds only the artifacts of GitHub Actions runs.

These host packages cannot share a machine with the VE-08 ones. [`fc/host-packages.txt`](../../fc/host-packages.txt) brings in `gcc-multilib`, and installing it removes the arm64 cross compiler that `cc/build.sh` needs. CI uses separate runners. On one machine, re-run `cc/emu/install-host-packages.sh` before returning to VE-07.

The harness:
- generates a dev K-CC-OS key and a rogue key in a temporary directory, and deletes both on exit;
- dumps QEMU's devicetree with the exact command line it boots with;
- signs the FIT and builds each tampered variant *after* signing, as an attacker with storage access would;
- predicts PCRs 0, 1, 8 and 9 for the signed FIT and the hardened U-Boot with [`tools/predict_pcrs.py`](../../tools/predict_pcrs.py) before anything boots;
- provisions a TPM with tpm2-tools, as a factory would: a persistent parent, the epoch NV index, and a WireGuard key and a MAVLink key it generates and seals (`provision.py`). It keeps only the keys' SHA-256 values;
- approves the release as the MSS would, with a K-CC-POL dev key generated for the run (`tools/approve_policy.py`), and packs the CC data as a tar for a second virtio disk;
- builds what the refusal cases need: chains signed like a release but with one measured item changed (TC-06, with two one-setting U-Boot test builds from `cc/build.sh`, and the kernel changed once at each end of its stored image), a second CC's TPM provisioned the same way (TC-07), a release 2 that the MSS approves at epoch 1, a copy of the TPM with epoch 1 committed, CC data carrying policies signed by a rogue key, and CC data carrying release 2's policy signed by the real K-CC-POL under another `policyRef` and under none (TC-08);
- for TC-05's second-unseal case and its control, signs a chain for each of the agent's two builds that try to unseal again (with the cap, and without it) and approves each with its own policy;
- for TC-09's two controls, signs a chain for each of the agent's control builds (response in the clear; session not salted) and approves each with its own policy;
- boots each case with a fresh swtpm, or with a copy of the provisioned, second or committed TPM. For TC-09, swtpm logs every TPM command and response (log level 20), and the harness searches them for the sealed keys, which it keeps in memory only. It also reads from them how each `TPM2_Unseal` session was started (salted to the parent or not), and tries to decrypt each answer with the key an unsalted session would have, which needs nothing but the recorded nonces. It writes each I/O log in swtpm's layout with any key bytes replaced by `--`, whether in the clear or decryptable that way, and records where and the SHA-256 of what it replaced.

A refusal case (TC-06 to TC-08) counts only if TC-05, its positive control, passed in the same run. `summary.md` lists what `p2-unseal` reported for every sealing run.

The initramfs ([`cc/initramfs/init`](../../cc/initramfs/init)) prints the SHA-256 PCRs 0 to 9 from sysfs and the TPM event log Linux received, base64-encoded between `P2-EVENTLOG-BEGIN` and `P2-EVENTLOG-END`. TC-10 compares both with the prediction. Every run that reads the PCRs also checks that the digests U-Boot logged for the kernel and the initramfs are the SHA-256 of each whole image in the FIT, computed by the harness without the predictor. Otherwise a mistake that U-Boot and the predictor shared, such as measuring only the start of an image, would pass as agreement. If the CC data disk is attached, the initramfs then runs [`p2-unseal`](../../cc/initramfs/p2-unseal.c) and prints each unsealed key's SHA-256; TC-05 compares those with the keys sealed.

It writes one console log per case and `summary.json`/`summary.md`, and exits non-zero if any case fails. A negative case counts only if the positive control (TC-01) passed in the same run.

`summary.json` records where the run happened. Only a GitHub Actions run, with its run ID and runner image, counts as CI evidence; a run anywhere else is marked `local`. A CI run also fails if any host package differs from its pin.

## What a pass does and does not show

It shows that the hardened U-Boot configuration boots only the signed configuration and refuses every tamper and configuration change tried. It also shows that U-Boot measures what [docs/03 §3.1](../../docs/03-measured-boot-sealing.md#31-measurements-sr-0101) says, so the PCRs a sealing policy names can be computed before a release boots. TC-05 to TC-08 show, on swtpm (A2-04), that the CC's keys unseal through the MSS-approved policy for that boot, and that the TPM refuses them to a changed boot state, another TPM, an older epoch and a rogue-signed policy. TC-09 shows that the unsealed keys cross swtpm's interface only encrypted. Its record is swtpm's own log of each command and response, not a capture of a bus. That the same bytes cross SPI on the DEBIX is an assumption: TC-09 has no hardware run. The limits of these results are listed in [docs/06 §6.6](../../docs/06-verification.md#66-limits-of-the-ci-evidence). A pass does not show measurement into a real TPM over SPI; that is OI2-01, on the DEBIX. Nor does it show a hardware root of trust. In emulation, QEMU loads `u-boot.bin` and supplies the control devicetree that holds K-CC-OS (A2-03). TC-02, on the DEBIX hardware, covers that.
