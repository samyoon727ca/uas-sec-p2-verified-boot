# 1. Scope and traceability

P2 produces the verification evidence for three P1 requirements. On the companion computer (CC) they are SR-005 (verified boot) and SR-010 (keys sealed to the TPM). On the flight controller (FC) it is SR-018 (PX4 Bootloader Secure Boot). Evidence is produced through two P1 verification events, VE-07 and VE-08. P2 adds five child requirements where a P1 requirement needs refinement to be testable. Every other P2 statement traces to the P1 baseline at commit `7aadc83` ([P1]).

## 1.1 P1 parents

| P1 requirement | Component | Parent threats (P1) | Verified by (P1) |
|---|---|---|---|
| SR-005: the CC shall boot only boot-chain components signed with the project boot key, verified from a hardware root of trust | CMP-CC | THR-008 persistent modification of CC software; THR-010 code execution on the CC yields full C2; THR-032 CC storage rewritten offline | VE-07 (Test) |
| SR-010: the CC shall seal its WireGuard private key and its copy of the signing key to its TPM, bound to the measured boot state | CMP-CC | THR-007 vehicle impersonated with a stolen CC WireGuard key; THR-034 keys extracted from a captured CC; THR-035 CC trust anchors replaced | VE-07 (Test) |
| SR-018: the FC shall boot only firmware signed with the project firmware key, using PX4 Bootloader Secure Boot | CMP-FC | THR-030 FC firmware modified through the boot loader or debug port; THR-041 release artifacts tampered before loading; THR-058 unsigned firmware loaded through the USB boot loader | VE-08 (Test) |

P1 also hands P2 these premises:
- **A-04:** the CC can carry a hardware root of trust and a TPM 2.0.
- **A-08:** three adversary tiers, including physical access to a captured vehicle.
- **A-14:** loads and provisioning happen on the ground over wired links.
- **DD-06:** the PX4 baseline is v1.18.

## 1.2 Child requirements

A child is added only where its parent cannot be tested as written. It keeps its parent's component and verification method, and it traces only to its parent's P1 threats. If P2 finds a threat P1 lacks, the fix goes to P1 (§1.4), not into a P2-only threat. The validator enforces all three rules.

Generated from the CSVs by `tools/render_views.py`. CI fails if this view drifts from the data.

<!-- BEGIN GENERATED: child-requirements -->
5 child requirements.

| ID | Requirement | Parent | Parent threats | Verified by |
|---|---|---|---|---|
| SR-005.1 | The CC shall take its boot-loader configuration only from the verified boot-loader image and from signed FIT configurations. | SR-005 | THR-008, THR-032 | TC-01, TC-04 |
| SR-010.1 | The CC shall bind its sealed keys to SHA-256 PCRs 0, 1, 8 and 9 as extended by the boot loader. | SR-010 | THR-007, THR-034 | TC-05, TC-06, TC-10 |
| SR-010.2 | The CC shall unseal its keys only under a PCR policy signed with the MSS policy key. | SR-010 | THR-034 | TC-05, TC-08 |
| SR-010.3 | The CC shall refuse to unseal its keys under a policy whose epoch is below the minimum epoch recorded in its TPM. | SR-010 | THR-034 | TC-08 |
| SR-010.4 | The CC shall unseal its keys only over a salted TPM session with response encryption. | SR-010 | THR-034 | TC-09 |
<!-- END GENERATED: child-requirements -->

**Considered and not adopted:** SR-005.2, "the CC boot loader shall refuse a FIT whose epoch is below the TPM minimum epoch." It would need a U-Boot patch to be maintained against every release. SR-010.3 already denies a rolled-back chain its keys, so it cannot join C2 (DD2-07).

SR-018 needs no child. Its gaps are P1-level and are proposed in §1.4.

## 1.3 Assumptions

Each of these is an **assumption**: accepted for analysis, not yet shown. Test cases or open items retire them.

| ID | Assumption | Why it matters |
|---|---|---|
| A2-01 | Every `boot.img` ever signed with K-CC-ROOT contains a U-Boot with measured boot enabled | A signed U-Boot that does not measure leaves PCRs 0–9 at their reset values. If it also had a verification flaw, the kernel it starts could extend the approved values itself and unseal the keys |
| A2-02 | The TPM's reset input follows the CC platform reset and cannot be driven by software | If the TPM can be reset on its own, its PCRs return to zero and approved measurements can be replayed. To check on the chosen module; P5 covers physical attack |
| A2-03 | In the emulated chain, QEMU loading `u-boot.bin` and its control devicetree stands in for the hardware root of trust | Emulation cannot show that a modified boot loader is refused (TC-02 is hardware only) |
| A2-04 | swtpm 0.7.3 implements the TPM 2.0 commands P2 uses as the TCG Library specifies | swtpm is not a certified TPM, and its state is a host file. Hardware runs repeat the sealing cases on a real TPM |
| A2-05 | PX4 Bootloader Secure Boot behaves the same at `v1.18.0` as at `v1.18.0-rc1` | Rechecked at the DD-06 re-pin |
| A2-06 | U-Boot's GPIO soft SPI can drive the chosen SPI TPM on a Raspberry Pi 4 | Measured boot on the hardware depends on it (OI2-01) |

## 1.4 Changes proposed to P1

P2 corrects P1 rather than diverging from it. Each item becomes a small P1 pull request; the P1 PR column is filled in when it is opened.

| # | Proposed change | Reason | P1 PR |
|---|---|---|---|
| 1 | Add an `evidence` column to `verification.csv`: required when the status is `passed` or `failed`, optional while `planned`. Keep the validator, generated views and SysML generator green | P1 has no place to link the evidence that P2–P6 produce | — |
| 2 | Add a threat: an older signed FC firmware is loaded over USB. Disposition to be decided in P1: accept with rationale, or mitigate by procedure | The PX4 boot loader checks the signature only; `image_cert_t` carries creation and expiry fields, but the boot loader never reads them [PX4-BL]. SR-018 as written does not cover rollback | — |
| 3 | Record that SR-018's root of trust is the FC boot-loader sector and depends on SR-024 | The PX4 boot loader sets no flash write-protection [PX4-BL]. Anyone with SWD access can replace it | — |
| 4 | Add to THR-034's residual risk: a TPM bus probe or a TPM reset with replayed measurements on a captured CC | SR-010.4 stops passive sniffing of unsealed keys; reset-and-replay depends on A2-02 | — |
| 5 | Reword A-04 to separate the two roots of trust: SoC secure boot verifies the chain (SR-005); the TPM measures and seals (SR-010) | A TPM does not verify boot. A-04 currently names TPM 2.0 as the example hardware root of trust | — |
| 6 | Record a residual risk: the CC root boot key is limited to 112-bit strength on the chosen hardware | The Pi boot loader fixes RSA-2048. NIST SP 800-57 disallows 112-bit strength for applying protection from 2031 ([§5.1](05-key-management.md)) | — |

## 1.5 Out of scope

- **Update signing and acceptance (SR-007)** belong to P3. P2 defines the signed PCR policy that an update carries.
- **PKI, HSM custody and certificates** belong to P3. P2 uses dev keys and documents the hand-off (§5).
- **Root filesystem integrity (SR-006)** and the hardened image belong to P4.
- **Physical attacks:** debug ports, bus interposers and glitching belong to P5.
- **Zynq UltraScale+ bitstream authentication** is out of scope: no Zynq hardware is owned.
