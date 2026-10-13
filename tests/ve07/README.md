# VE-07 emulated harness

Runs the CC boot chain on QEMU `virt` with swtpm and checks the VE-07 test cases that emulation can prove ([docs/06](../../docs/06-verification.md)).

| Script | Covers |
|---|---|
| [`boot_cases.py`](boot_cases.py) | TC-01 signed chain boots; TC-03 modified kernel, initramfs or devicetree refused; TC-04 modified boot configuration refused, with control runs on stock U-Boot and on the P2 build with one console setting relaxed; TC-10 predicted PCRs equal the measured PCRs and the event-log replay |

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
- boots each case with a fresh swtpm.

The initramfs ([`cc/initramfs/init`](../../cc/initramfs/init)) prints the SHA-256 PCRs 0 to 9 from sysfs and the TPM event log Linux received, base64-encoded between `P2-EVENTLOG-BEGIN` and `P2-EVENTLOG-END`. TC-10 compares both with the prediction.

It writes one console log per case and `summary.json`/`summary.md`, and exits non-zero if any case fails. A negative case counts only if the positive control (TC-01) passed in the same run.

`summary.json` records where the run happened. Only a GitHub Actions run, with its run ID and runner image, counts as CI evidence; a run anywhere else is marked `local`. A CI run also fails if any host package differs from its pin.

## What a pass does and does not show

It shows that the hardened U-Boot configuration boots only the signed configuration and refuses every tamper and configuration change tried. It also shows that U-Boot measures what [docs/03 §3.1](../../docs/03-measured-boot-sealing.md#31-measurements-sr-0101) says, so the PCRs a sealing policy names can be computed before a release boots. It does not show measurement into a real TPM over SPI; that is OI2-01, on the DEBIX. Nor does it show a hardware root of trust. In emulation, QEMU loads `u-boot.bin` and supplies the control devicetree that holds K-CC-OS (A2-03). TC-02, on the DEBIX hardware, covers that.
