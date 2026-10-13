# VE-07 emulated harness

Runs the CC boot chain on QEMU `virt` with swtpm and checks the VE-07 test cases that emulation can prove ([docs/06](../../docs/06-verification.md)).

| Script | Covers |
|---|---|
| [`boot_cases.py`](boot_cases.py), [`provision.py`](provision.py) | TC-01 signed chain boots; TC-03 modified kernel, initramfs or devicetree refused; TC-04 modified boot configuration refused, with control runs on stock U-Boot and on the P2 build with one console setting relaxed; TC-05 keys unseal in the measured, unmodified boot state; TC-06 keys do not unseal from a modified boot state; TC-07 keys do not unseal on another CC's TPM; TC-08 rollback and a rogue-signed policy refused; TC-09 unseal traffic holds neither key, with a control run on the agent's control build, which leaves the response in the clear; TC-10 predicted PCRs equal the measured PCRs and the event-log replay |

## Run

Ubuntu 24.04 (the same image as the CI runner):

```sh
cc/emu/install-host-packages.sh           # pinned host packages from the Ubuntu snapshot (sudo)
cc/build.sh                               # U-Boot hardened, stock and two control variants, kernel, initramfs -> build/
python3 tests/ve07/boot_cases.py --build build --out evidence/ve07-ci/$(date -u +%Y%m%d)-$(git rev-parse --short HEAD)
```

The harness:
- generates a dev K-CC-OS key and a rogue key in a temporary directory, and deletes both on exit;
- dumps QEMU's devicetree with the exact command line it boots with;
- signs the FIT and builds each tampered variant *after* signing, as an attacker with storage access would;
- predicts PCRs 0, 1, 8 and 9 for the signed FIT and the hardened U-Boot with [`tools/predict_pcrs.py`](../../tools/predict_pcrs.py) before anything boots;
- provisions a TPM with tpm2-tools, as a factory would: a persistent parent, the epoch NV index, and a WireGuard key and a MAVLink key it generates and seals (`provision.py`). It keeps only the keys' SHA-256 values;
- approves the release as the MSS would, with a K-CC-POL dev key generated for the run (`tools/approve_policy.py`), and packs the CC data as a tar for a second virtio disk;
- builds what the refusal cases need: chains signed like a release but with one measured item changed (TC-06, with two one-setting U-Boot test builds from `cc/build.sh`), a second CC's TPM provisioned the same way (TC-07), a release 2 that the MSS approves at epoch 1, a copy of the TPM with epoch 1 committed, and CC data carrying policies signed by a rogue key (TC-08);
- for TC-09's control, signs a chain whose initramfs has the agent's control build and approves it with its own policy;
- boots each case with a fresh swtpm, or with a copy of the provisioned, second or committed TPM. For TC-09, swtpm logs every TPM command and response (log level 20), and the harness searches them for the sealed keys, which it keeps in memory only. It writes each I/O log in swtpm's layout with any key bytes replaced by `--`, and records where and the SHA-256 of what it replaced.

A refusal case (TC-06 to TC-08) counts only if TC-05, its positive control, passed in the same run. `summary.md` lists what `p2-unseal` reported for every sealing run.

The initramfs ([`cc/initramfs/init`](../../cc/initramfs/init)) prints the SHA-256 PCRs 0 to 9 from sysfs and the TPM event log Linux received, base64-encoded between `P2-EVENTLOG-BEGIN` and `P2-EVENTLOG-END`. TC-10 compares both with the prediction. If the CC data disk is attached, the initramfs then runs [`p2-unseal`](../../cc/initramfs/p2-unseal.c) and prints each unsealed key's SHA-256; TC-05 compares those with the keys sealed.

It writes one console log per case and `summary.json`/`summary.md`, and exits non-zero if any case fails. A negative case counts only if the positive control (TC-01) passed in the same run.

`summary.json` records where the run happened. Only a GitHub Actions run, with its run ID and runner image, counts as CI evidence; a run anywhere else is marked `local`. A CI run also fails if any host package differs from its pin.

## What a pass does and does not show

It shows that the hardened U-Boot configuration boots only the signed configuration and refuses every tamper and configuration change tried. It also shows that U-Boot measures what [docs/03 §3.1](../../docs/03-measured-boot-sealing.md#31-measurements-sr-0101) says, so the PCRs a sealing policy names can be computed before a release boots. TC-05 to TC-08 show, on swtpm (A2-04), that the CC's keys unseal through the MSS-approved policy for that boot, and that the TPM refuses them to a changed boot state, another TPM, an older epoch and a rogue-signed policy. TC-09 shows that the unsealed keys cross the TPM interface only encrypted; on hardware the same bytes cross SPI. It does not show measurement into a real TPM over SPI; that is OI2-01, on the DEBIX. Nor does it show a hardware root of trust. In emulation, QEMU loads `u-boot.bin` and supplies the control devicetree that holds K-CC-OS (A2-03). TC-02, on the DEBIX hardware, covers that.
