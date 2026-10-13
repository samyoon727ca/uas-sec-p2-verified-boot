# VE-08 host harness

Builds the FC's secure-boot pair at the pinned PX4 commit with a per-run key, then checks the VE-08 case that needs no flight controller: TC-11, FC images signed and checked on the host ([docs/04 §4.4](../../docs/04-fc-secure-boot.md#44-what-ci-shows-and-what-only-the-board-shows)).

| File | Role |
|---|---|
| [`../../fc/clone-px4.sh`](../../fc/clone-px4.sh) | Clones PX4 at the tag in [`fc/px4/pin.txt`](../../fc/px4/pin.txt) and refuses any other commit |
| [`../../fc/build.sh`](../../fc/build.sh) | In the pinned PX4 container: generates K-FC-FW dev with PX4's `generate_signing_keys.py`, builds `px4_fmu-v6x_bootloader_secureboot` with it in key slot 0 (`PUBLIC_KEY0`) and `px4_fmu-v6x_secureboot` signed with it (`BOARD_SECUREBOOT_KEY`), and signs the built image again with PX4's public test key. Deletes the private key on exit |
| [`host/check_image.c`](host/check_image.c) | Says whether the boot loader would start an image. Built for a 32-bit host with PX4's own `find_toc()`, `verify_app()`, stub keystore and monocypher, so the TOC's 32-bit addresses need no translation; the image is mapped at its flash address `0x08020000` in otherwise erased flash. [`host/`](host/) also holds the three stand-ins it needs outside NuttX: `hw_config.h` (the board's values), `nuttx/arch.h` (`up_assert`) and the Ed25519 branch of PX4's `sw_crypto` |
| [`image_cases.py`](image_cases.py) | The cases below, the static checks, and the evidence |

## Cases

| Run | Image | Key in slot 0 | Expected |
|---|---|---|---|
| TC-11a (positive) | Signed by the build with the run key | run key | starts |
| TC-11b | As built, unsigned | run key | stays in the boot loader |
| TC-11c | Signed, then one byte changed past the TOC | run key | stays |
| TC-11d | Signed with PX4's public test key | run key | stays |
| TC-11d-control | The same image | PX4's test key | starts, so TC-11d fails on the key alone |

Static checks: the boot loader holds the run key once and not PX4's test key; the signed image is the built image padded to 4 bytes plus a 64-byte signature; the `.px4` upload envelope carries the signed image and marks it signed. A negative case counts only if TC-11a passed in the same run.

## Run

CI runs it on every change to `fc/` or `tests/ve08/` ([`ve08-host`](../../.github/workflows/ve08-host.yml)). Locally, with Docker and Ubuntu 24.04:

```sh
cc/emu/install-host-packages.sh fc/host-packages.txt
fc/clone-px4.sh /tmp/px4
docker run --rm -v "$PWD:/p2:ro" -v /tmp:/work -e PX4=/work/px4 -e KEYS=/work/keys -e OUT=/work/fc \
  "$(awk '$1 == "container:" {print $2}' fc/px4/pin.txt)" bash /p2/fc/build.sh
python3 tests/ve08/image_cases.py --px4 /tmp/px4 --fc /tmp/fc --out /tmp/ve08
```

## What a pass does and does not show

It shows that the pinned PX4 builds a boot loader trusting only the run key, that the build signs the firmware the way the boot loader checks it, and that PX4's verification code accepts only that image. It does not show the boot loader enforcing the check at reset on the STM32H753, or the upload and recovery paths: TC-12 to TC-14 on a Pixhawk 6X.
