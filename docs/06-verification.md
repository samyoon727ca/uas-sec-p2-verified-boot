# 6. Verification

Fourteen test cases produce the evidence for P1's VE-07 and VE-08. Ten run in CI (emulated or on the host), and twelve run on owned hardware. A verification event passes only when every applicable CI and hardware run has passed. Only then does a P1 pull request set its status to `passed` and link the evidence. Until a test case passes, nothing it covers is called working.

## 6.1 Status

Generated from the CSVs by `tools/render_views.py`. CI fails if this view drifts from the data.

<!-- BEGIN GENERATED: ve-status -->
| Event | Verifies (P1) | CI runs passed | Hardware runs passed | P2 status | P1 status |
|---|---|---|---|---|---|
| VE-07 CC verified boot and key sealing | SR-005, SR-010 | 0 of 9 | 0 of 9 | planned | planned |
| VE-08 FC boots only signed firmware | SR-018 | 0 of 1 | 0 of 3 | planned | planned |
<!-- END GENERATED: ve-status -->

## 6.2 What emulation proves, and what only hardware proves

**CI runs prove:**
- the U-Boot configuration: signed configurations only, required key, no legacy images, no stored environment, no console after a failure;
- that tampered kernels, initramfs, devicetrees and configurations are refused;
- what U-Boot measures, and that the PCRs can be predicted from the release artifacts;
- the sealing policy logic: approved state only, signed approval, epoch anti-rollback, sealed objects bound to one TPM, encrypted unseal;
- the FC signing pipeline and the image format the PX4 boot loader checks;
- that each test detects the failure it looks for, through a positive control and, where useful, a control run against a weakened configuration.

**Only hardware runs prove:**
- a hardware root of trust: an immutable ROM and an OTP key that refuse a modified boot loader (TC-02);
- that U-Boot reaches a real TPM over `spi-gpio` and measures the same items (OI2-01);
- sealing on a real TPM rather than swtpm (A2-04), including removal of real storage;
- that the PX4 boot loader enforces signatures at reset on the STM32H753 (TC-12, TC-13), and the recovery paths (TC-14).

**Neither proves** resistance to physical attack: TPM bus interposers, TPM reset (A2-02), debug-port access or fault injection. Those belong to P5.

## 6.3 Test cases

<!-- BEGIN GENERATED: test-cases -->
14 test cases. Status links point to the evidence.

| ID | Event | Test case | Verifies | CI | Hardware | Pass criteria |
|---|---|---|---|---|---|---|
| TC-01 | VE-07 | Signed chain boots | SR-005, SR-005.1 | planned | planned | U-Boot verifies the FIT configuration signature with the required key and the kernel reaches the initramfs. |
| TC-02 | VE-07 | Modified boot loader refused by the hardware root of trust | SR-005 | – | planned | The Raspberry Pi boot loader refuses both images and U-Boot never runs. |
| TC-03 | VE-07 | Modified kernel, initramfs or devicetree refused | SR-005 | planned | planned | U-Boot reports a hash mismatch for the changed image, does not start the kernel and resets without offering a console. |
| TC-04 | VE-07 | Modified boot configuration refused | SR-005, SR-005.1 | planned | planned | Every attempt is refused or ignored and no console prompt appears. The control runs show the stock configuration accepts the injected environment and the legacy image. |
| TC-05 | VE-07 | Keys unseal in the measured, unmodified boot state | SR-010, SR-010.1, SR-010.2 | planned | planned | Both keys unseal and match the provisioned values. |
| TC-06 | VE-07 | Keys do not unseal from a modified boot state | SR-010, SR-010.1 | planned | planned | Unseal fails in every case. |
| TC-07 | VE-07 | Keys do not unseal from removed storage | SR-010 | planned | planned | The sealed objects do not load on the second TPM. |
| TC-08 | VE-07 | Rollback and unapproved policies refused | SR-010.2, SR-010.3 | planned | planned | Unseal fails in both cases and the current chain still unseals. |
| TC-09 | VE-07 | Unseal traffic is encrypted | SR-010.4 | planned | – | The unsealed key bytes never appear in the recorded traffic; in the control run they do. |
| TC-10 | VE-07 | Predicted PCRs match the measured PCRs and the event log | SR-010.1 | planned | planned | The predicted, measured and replayed values are equal. |
| TC-11 | VE-08 | FC images signed and checked on the host | SR-018 | planned | – | Only the image signed with the run key verifies. |
| TC-12 | VE-08 | Signed firmware starts PX4 | SR-018 | – | planned | The board leaves the boot loader and PX4 starts, shown by the console log and USB enumeration. |
| TC-13 | VE-08 | Unsigned, modified and wrong-key firmware stay in the boot loader | SR-018 | – | planned | The uploader reports a signature failure and, after each power cycle, the board stays in the boot loader. |
| TC-14 | VE-08 | Recovery paths work | SR-018 | – | planned | Each step returns the board to the intended state. |
<!-- END GENERATED: test-cases -->

## 6.4 Evidence rules

- **Location.** Evidence lives in `evidence/<event>-<ci|hw>/<YYYYMMDD>-<commit>/`. A test case's evidence column points at that folder.
- **Contents.** Each run folder holds:
  - `summary.json`: tool versions, pins, SHA-256 of every built artifact and public key, and each case's result;
  - one console log per case.
- **Scripted.** A harness exits non-zero if any case fails, and CI runs it on every change to `cc/` or the harness. VE-07's emulated harness is [`tests/ve07/boot_cases.py`](../tests/ve07/boot_cases.py), run by the [`ve07-emu`](../.github/workflows/ve07-emu.yml) workflow, which uploads its evidence as a build artifact.
- **Controls first.** A negative case counts only if the positive control passed in the same run. Where the attack would succeed against a weaker setup (for example stock `qemu_arm64_defconfig`), a control run shows it succeeding there, so the test can be seen to detect it.
- **Hardware runs** are run by the owner on owned devices with the scripts in this repo. Their logs are committed the same way.

## 6.5 Reporting to P1

When every case of an event has passed, a pull request to P1 sets the event's status in `data/verification.csv` to `passed` and links this repo's evidence. That uses the `evidence` column proposed as P1 change 1 ([§1.4](01-scope-and-trace.md)). P1's validator, generated views and SysML generator must stay green.
