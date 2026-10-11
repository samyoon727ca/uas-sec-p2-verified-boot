# VE-07 emulated harness

Runs the CC boot chain on QEMU `virt` with swtpm and checks the VE-07 test cases that emulation can prove ([docs/06](../../docs/06-verification.md)).

| Script | Covers |
|---|---|
| [`boot_cases.py`](boot_cases.py) | TC-01 signed chain boots; TC-03 modified kernel, initramfs or devicetree refused; TC-04 modified boot configuration refused, with control runs on stock U-Boot and on the P2 build with one console setting relaxed |

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
- boots each case with a fresh swtpm.

It writes one console log per case and `summary.json`/`summary.md`, and exits non-zero if any case fails. A negative case counts only if the positive control (TC-01) passed in the same run.

`summary.json` records where the run happened. Only a GitHub Actions run, with its run ID and runner image, counts as CI evidence; a run anywhere else is marked `local`. A CI run also fails if any host package differs from its pin.

## What a pass does and does not show

It shows that the hardened U-Boot configuration boots only the signed configuration and refuses every tamper and configuration change tried. It does not show a hardware root of trust. In emulation, QEMU loads `u-boot.bin` and supplies the control devicetree that holds K-CC-OS (A2-03). TC-02, on the Raspberry Pi, covers that.
