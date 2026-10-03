# 4. FC secure boot

The FC uses PX4 Bootloader Secure Boot on a Holybro Pixhawk 6X (`px4_fmu-v6x`). At reset, the PX4 boot loader checks an Ed25519 signature over the firmware image. Firmware not signed with a key the boot loader trusts never starts. The project firmware key K-FC-FW sits in keystore slot 0; an offline recovery key K-FC-REC sits in slot 1. SWD is needed only to install or change the boot loader; firmware goes over USB (SR-018).

Status: design. Nothing here is shown working until its test case passes ([§6](06-verification.md)). PX4 is pinned at `v1.18.0-rc1`; `v1.18.0` had not been released on 2026-10-03 (P1 DD-06).

## 4.1 How the PX4 boot loader checks firmware

Checked in the source and docs at `v1.18.0-rc1` [PX4-SECBOOT], [PX4-BL]:

- **Algorithm.** Ed25519 via monocypher (submodule `baca5d31`): a 32-byte key and a 64-byte signature.
- **Layout.** A table of contents (TOC) at a fixed offset names a BOOT region and a SIG1 entry. At reset, the boot loader verifies the TOC's own entry, then each entry flagged `TOC_FLAG1_CHECK_SIGNATURE`. On failure it stays in the boot loader and waits for an upload.
- **Key slot.** Each TOC entry names the keystore slot that verifies it. The upstream `fmu-v6x` TOC names slot 0 for BOOT. The stub keystore compiles in up to four public keys, `PUBLIC_KEY0` to `PUBLIC_KEY3`; slot 0 is mandatory.
- **Uploader check.** `Tools/px4_uploader.py` asks the boot loader to check the signature (`VERIFY_SIG`) before rebooting, so a bad image is reported at upload.
- **Board support.** Only `px4_fmu-v6x` ships secure-boot variants: `px4_fmu-v6x_bootloader_secureboot` and `px4_fmu-v6x_secureboot`. Other boards need a port (TOC, linker script, board configs).
- **Lost key.** PX4 warns that if the private key for a boot loader's trusted key is lost, recovery needs a debug probe.

**Gaps relevant to SR-018:**
- **No anti-rollback.** The boot loader checks the signature only. `image_cert_t` carries creation and expiry dates, but the boot loader never reads them. An older signed image still boots (P1 change 2).
- **No write-protection.** The boot loader sets no flash write-protection or readout protection. Its integrity rests on the debug port being disabled or sealed (SR-024, P5; P1 change 3).
- **Raw-key signing.** `Tools/secure_bootloader/sign_firmware.py` reads the raw private key, in hex, from a JSON file (OI2-04).

## 4.2 Workflow

Hardware: Pixhawk 6X (STM32H753). SWD and the console are on the FMU Debug port (Pixhawk Debug Full, JST SM10B) [PX4-6X].

1. **Keys.** Generate K-FC-FW and K-FC-REC with PX4's `Tools/secure_bootloader/generate_signing_keys.py`. Each produces a private JSON file, kept outside the repo, and a public C-array file.
2. **Boot loader.** Build `px4_fmu-v6x_bootloader_secureboot` with `PUBLIC_KEY0` set to K-FC-FW and `PUBLIC_KEY1` set to K-FC-REC. Record its SHA-256. Flash it once over SWD.
3. **Firmware.** Build `px4_fmu-v6x_secureboot` with `BOARD_SECUREBOOT_KEY` pointing at K-FC-FW. The build signs the image and wraps it as a `.px4`.
4. **Load.** Upload over USB with `px4_uploader.py`, then power-cycle. The power cycle shows what the boot loader does at reset, not just what the uploader reports.

## 4.3 Recovery paths

| Situation | Path | Needs |
|---|---|---|
| A refused image is on the board | Upload a correctly signed image over USB; the boot loader is still running | USB |
| K-FC-FW lost | Sign with K-FC-REC. The firmware build's TOC must name slot 1, which needs a P2 variant of `toc.c` | USB; K-FC-REC from offline storage |
| Both private keys lost, or a key compromised | Flash a boot loader with new public keys over SWD | Debug probe |
| Return the board to stock | Flash the stock boot loader over SWD | Debug probe |

A slot-1 key protects against *loss*, not *compromise*. Firmware chooses its slot through the TOC, so anyone holding either private key can sign firmware that boots. Revoking a key means reflashing the boot loader over SWD.

## 4.4 What CI shows and what only the board shows

| | CI (TC-11) | Pixhawk 6X (TC-12 to TC-14) |
|---|---|---|
| Both targets build at the pinned tag with a per-run key | ✓ | — |
| Signed, unsigned, modified-signed and wrong-key images are told apart by PX4's verification code | ✓ planned: PX4's own `crypto.c`/TOC code and monocypher compiled for the host. Fallback: the same monocypher with a TOC parser written to PX4's header | — |
| The boot loader enforces the check at reset on the STM32H753 | — | ✓ |
| Recovery over USB and SWD | — | ✓ |

The wrong-key case uses PX4's committed test key (`Tools/test_keys/test_keys.json`). It is public, so it is a safe stand-in for "a key the boot loader does not trust."

## 4.5 Design decisions

| ID | Decision | Rationale | Alternative considered |
|---|---|---|---|
| DD2-13 | Pixhawk 6X (`px4_fmu-v6x`) | The only board with upstream secure-boot variants at `v1.18.0-rc1` | Another Pixhawk with a P2 port of the TOC and linker script |
| DD2-14 | K-FC-REC in slot 1, held offline | Recovery from losing K-FC-FW without a debug probe (P1 THR-040) | A single key, with SWD as the only recovery |
| DD2-15 | Host-side check of signed images in CI | Catches signing-pipeline faults without hardware | None: the board run is still required for VE-08 |

## 4.6 Open items

| ID | Item | Closed by |
|---|---|---|
| OI2-04 | PX4's signer needs the raw Ed25519 private key. SR-034 (P3) needs signing inside an HSM: a PKCS#11 Ed25519 signer that writes the same 64-byte signature PX4 appends | P3 |
| OI2-06 | PX4 `v1.18.0` not released; P2 is pinned to `v1.18.0-rc1` | P1 DD-06 re-pin |
