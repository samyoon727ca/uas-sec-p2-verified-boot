# 6. Verification

Fourteen test cases produce the evidence for P1's VE-07 and VE-08. Ten run in CI (emulated or on the host), and twelve run on owned hardware. A verification event passes only when every applicable CI and hardware run has passed. Only then does a P1 pull request set its status to `passed` and link the evidence. Until a test case passes, nothing it covers is called working.

## 6.1 Status

Generated from the CSVs by `tools/render_views.py`. CI fails if this view drifts from the data.

<!-- BEGIN GENERATED: ve-status -->
| Event | Verifies (P1) | CI runs passed | Hardware runs passed | P2 status | P1 status |
|---|---|---|---|---|---|
| VE-07 CC verified boot and key sealing | SR-005, SR-010 | 9 of 9 | 0 of 9 | in progress | planned |
| VE-08 FC boots only signed firmware | SR-018 | 1 of 1 | 0 of 3 | in progress | planned |
<!-- END GENERATED: ve-status -->

## 6.2 What emulation can prove, and what only hardware can prove

Each list says what that kind of run is able to prove. So far CI has proved the first four CI items (§6.1): the boot-loader configuration and tamper refusal with controls (TC-01, TC-03, TC-04); predictable measurements (TC-10); and the sealing policy logic. For sealing, keys unseal in the approved state under the signed policy (TC-05); they are refused to a changed state, another TPM, an older epoch and a rogue-signed policy (TC-06 to TC-08), each refusal counted only when TC-05 passed in the same run; and they cross the TPM interface only encrypted, with a control run on a build that does not encrypt (TC-09). The fifth, the FC signing pipeline and image format, is proved by TC-11, with a control showing the wrong-key image fails on the key alone. Every CI item now has passing cases; the whole hardware list is planned. Three of the sealing results hold only under conditions the cases do not exercise; §6.6 lists them.

**CI runs can prove:**
- the U-Boot configuration: signed configurations only, required key, no legacy images, no stored environment, no console after a failure;
- that tampered kernels, initramfs, devicetrees and configurations are refused;
- what U-Boot measures, and that the PCRs can be predicted from the release artifacts;
- the sealing policy logic: approved state only, signed approval, epoch anti-rollback, sealed objects bound to one TPM, encrypted unseal;
- the FC signing pipeline and the image format the PX4 boot loader checks;
- that each test detects the failure it looks for, through a positive control and, where useful, a control run against a weakened configuration.

**Only hardware runs can prove:**
- a hardware root of trust: an immutable ROM and a fused key hash that refuse a modified boot loader once the chip is closed (TC-02);
- that U-Boot reaches a real TPM over ECSPI and measures the same items (OI2-01);
- sealing on a real TPM rather than swtpm (A2-04), including removal of real storage;
- that the PX4 boot loader enforces signatures at reset on the STM32H753 (TC-12, TC-13), and the recovery paths (TC-14).

**Neither can prove** resistance to physical attack: TPM bus interposers, TPM reset (A2-02), debug-port access or fault injection. Those belong to P5.

## 6.3 Test cases

<!-- BEGIN GENERATED: test-cases -->
14 test cases. Status links point to the evidence.

| ID | Event | Test case | Verifies | CI | Hardware | Pass criteria |
|---|---|---|---|---|---|---|
| TC-01 | VE-07 | Signed chain boots | SR-005, SR-005.1 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | U-Boot verifies the FIT configuration signature with the required key and the kernel reaches the initramfs. On hardware, HAB also reports no events. |
| TC-02 | VE-07 | Modified boot loader refused by the hardware root of trust | SR-005 | – | planned | On the closed chip, both images are refused and U-Boot never runs. The open-chip run is a check only: HAB logs a failure event for each image, and none for the correct one, but boots them anyway. |
| TC-03 | VE-07 | Modified kernel, initramfs or devicetree refused | SR-005 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | U-Boot reports a hash mismatch for the changed image, does not start the kernel and resets without offering a console. |
| TC-04 | VE-07 | Modified boot configuration refused | SR-005, SR-005.1 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | Every attempt is refused or ignored and no console prompt appears. The control runs show the stock configuration accepts the injected environment and the legacy image, and the same keystrokes reach a prompt when either console setting is relaxed. |
| TC-05 | VE-07 | Keys unseal in the measured, unmodified boot state | SR-010, SR-010.1, SR-010.2 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | Both keys unseal and match the provisioned values. The second attempt is refused; in the control run it releases both keys again. |
| TC-06 | VE-07 | Keys do not unseal from a modified boot state | SR-010, SR-010.1 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | Unseal fails in every case. |
| TC-07 | VE-07 | Keys do not unseal from removed storage | SR-010 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | The sealed objects do not load on the second TPM. |
| TC-08 | VE-07 | Rollback and unapproved policies refused | SR-010.2, SR-010.3 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | Unseal fails in every case and the current chain still unseals. |
| TC-09 | VE-07 | Unseal traffic is encrypted | SR-010.4 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | – | The unsealed key bytes never appear in the recorded traffic, every unseal session is salted to the parent, and no key decrypts from the traffic alone. In the first control run the key bytes appear; in the second they decrypt from the traffic alone. |
| TC-10 | VE-07 | Predicted PCRs match the measured PCRs and the event log | SR-010.1 | [passed](../evidence/ve07-ci/20261110-ad7482b/summary.md) | planned | The predicted, measured and replayed values are equal. |
| TC-11 | VE-08 | FC images signed and checked on the host | SR-018 | [passed](../evidence/ve08-ci/20261013-aac4299/summary.md) | – | Only the image signed with the run key verifies. |
| TC-12 | VE-08 | Signed firmware starts PX4 | SR-018 | – | planned | The board leaves the boot loader and PX4 starts, shown by the console log and USB enumeration. |
| TC-13 | VE-08 | Unsigned, modified and wrong-key firmware stay in the boot loader | SR-018 | – | planned | The uploader reports a signature failure and, after each power cycle, the board stays in the boot loader. |
| TC-14 | VE-08 | Recovery paths work | SR-018 | – | planned | Each step returns the board to the intended state. |
<!-- END GENERATED: test-cases -->

## 6.4 Evidence rules

- **Location.** Evidence lives in `evidence/<event>-<ci|hw>/<YYYYMMDD>-<commit>/`. A test case's evidence column points at that folder's `summary.md`. The validator accepts it only if the folder is for the same event and the same kind of run (`ci` or `hw`), and the `summary.json` beside it records that event, that kind of run and that test case with the same result.
- **Contents.** Each run folder holds:
  - `summary.json`: tool versions, pins, SHA-256 of every built artifact and public key, and each case's result;
  - one console log per case.
- **Scripted.** A harness exits non-zero if any case fails, and CI runs it on every change to `cc/` or the harness. VE-07's emulated harness is [`tests/ve07/boot_cases.py`](../tests/ve07/boot_cases.py), run by the [`ve07-emu`](../.github/workflows/ve07-emu.yml) workflow, which uploads its evidence as a build artifact.
- **Provenance.** A `ci` folder is the unchanged artifact of a GitHub Actions run; its `summary.json` records the run ID, runner image and installed host package versions. Runs anywhere else are marked `local` and are not CI evidence. GitHub deletes an artifact 90 days after its run, so [`evidence/README.md`](../evidence/README.md) records each artifact's ID and the digest GitHub reported for it, and [`evidence/SHA256SUMS`](../evidence/SHA256SUMS) records the SHA-256 of every file. A run folder is never edited after it is committed; [`tools/check_evidence.py`](../tools/check_evidence.py) fails the build if one is.
- **Controls first.** A negative case counts only if the positive control passed in the same run. Where the attack would succeed against a weaker setup (for example stock `qemu_arm64_defconfig`), a control run shows it succeeding there, so the test can be seen to detect it.
- **Hardware runs** are run by the owner on owned devices with the scripts in this repo. Their logs are committed the same way, in an `hw` folder whose `summary.json` records `environment.kind` as `hw`.

## 6.5 Reporting to P1

When every case of an event has passed, a pull request to P1 sets the event's status in `data/verification.csv` to `passed` and links this repo's evidence. That uses the `evidence` column P1 added as change 1 ([§1.4](01-scope-and-trace.md)). P1's validator, generated views and SysML generator must stay green.

## 6.6 Limits of the CI evidence

An audit of P1 and P2 on 2026-10-13 tried to break each test by breaking the thing it tests. Most changes turned a case red. The ones below did not, or showed that a stated property depends on something no case covers. Each stays open until a change closes it and a test case shows that. The full findings are in P1's [`overview/audit/findings.json`](https://github.com/samyoon727ca/uas-sec-p1-architecture/blob/main/overview/audit/findings.json); the IDs here are the audit's.

| Result | What the cases show | What they do not show |
|---|---|---|
| Epoch anti-rollback (TC-08, SR-010.3) | An older signed chain that leaves the TPM alone is refused its keys after a newer epoch is committed | That the epoch survives an attacker. The epoch index is defined under owner authorization, which P2 leaves empty, without protection against removal. Code with TPM access could remove it and define it again with no bits set; the index would have the same name, so every signed policy would accept it. The audit reasoned this from the TPM specification. A local run on 2026-11-09 then showed it on swtpm: after `TPM2_NV_UndefineSpace` and a new `TPM2_NV_DefineSpace` under owner authorization, the index had the same name with no bits set, and release 1 unsealed both keys with its epoch-0 policy although epoch 1 had been committed. That run is not CI evidence, and no fix is chosen yet (A-01) |
| Keys released only to the approved boot state (TC-05, TC-06, SR-010) | The TPM releases the keys in the approved state, refuses them in six changed states, and refuses a second release in the same boot, because the agent extends the policy PCRs after it runs (TC-05b). Without that cap the second release succeeds (control run) | That what runs after the initramfs can be trusted with the keys. They are in memory and go to the next stage, the root filesystem, which P4 is to verify (SR-006). Neither repo records yet that SR-010 depends on it ([§1.4](01-scope-and-trace.md#14-changes-proposed-to-p1), change 7; the rest of A-02) |
| Encrypted unseal (TC-09, SR-010.4) | Neither key appears in any TPM command or response swtpm recorded, each unseal session is salted to the parent, and no key decrypts from the recording alone. With encryption off both keys appear, and with the salt left out both decrypt (two control runs) | That the same holds on the SPI bus. The record is swtpm's own log, and TC-09 has no hardware run (A-10) |
| Policy bound to this use (SR-010.2) | A policy signed by another key is refused (TC-08c, TC-08d), and so is this release's policy when the real K-CC-POL signed it under another `policyRef` or under none (TC-08e, TC-08f) | That the TPM would refuse it too. The agent refuses at `TPM2_VerifySignature`, before the TPM is asked to authorize. The TPM's own binding, through the sealed objects' authPolicy, is not exercised separately |
| FC image check (TC-11) | PX4's own `find_toc()` and `verify_app()` accept only the image signed with the run key | That the boot loader's decision is the same. The harness re-implements the loop around those calls and fixes the flash size at 2 MiB; the copy already differs from PX4 for an image whose first word is `0xFFFFFFFF` (A-11). TC-12 and TC-13 on the board close this |

Closed since the audit, each by a change with a check that fails when the fault is put back: a second release of the keys in the same boot (A-02 in part: the cap, TC-05b and its control); a kernel measured only in part (A-03: TC-06f and the whole-image digest check); an unsalted unseal session (A-04: TC-09's session check and its second control); an emptied `policyRef` (A-05: TC-08e and TC-08f); a hardening line dropped from a configuration fragment (A-06: the fixed boot-loader policy in the build and in TC-04a); evidence that is not the run it claims to be (A-07: the validator); and evidence that cannot be compared with its artifact after GitHub deletes it (A-08 in part: recorded digests and a checked manifest).
