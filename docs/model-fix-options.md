# Candidate fixes for A-01 and A-02, as checked in the model

Four options for the owner to choose from, each checked by TLC on [`model/`](../model/README.md). Nothing here changes P2's recorded design: docs/03, docs/05 and the provisioning harness stay as they are until the owner decides. `python3 model/ci.py` runs every configuration below and fails unless TLC's outcome is the one `model/configs.json` records. Every result holds **in this model**, with its abstractions (model/README.md): a value the model does not have, an action it leaves out or an attacker it does not describe is outside what TLC checked.

The findings, as the model shows them: **A-01**, an epoch reset by `NV_UndefineSpace` and `NV_DefineSpace` under the empty owner auth (`Epoch.cfg` and `EpochMonotonic.cfg` fail). **A-02**, a second release of the keys after the initramfs: by root in userspace without the cap (`BootNoCap.cfg` fails), and, with the cap, by an attacker who resets the TPM alone and replays the measurements (`Boot.cfg` fails, A2-02).

Each `pass` has a witness on the same constants, expected violated, showing the legitimate path still works: `CommittedReleaseNeverUnseals` (after `Commit(2)`, release 2 still unseals) for options 1 and 2, `InitramfsNeverObtainsKeys` for options 3 and 4.

## Option 1: owner auth set, unknown to the attacker

**Changes.** Provisioning sets a random owner authValue (`TPM2_HierarchyChangeAuth`) and keeps it for the epoch commit of docs/03 §3.5 step 4, which already uses owner authorization. Config: `FixOwnerAuth.cfg` (`OwnerAuth = "set"`), witness `FixOwnerAuthWitness.cfg`.

**Closes, in this model:** A-01. With owner auth set and unknown to the attacker, `NV_UndefineSpace` and `NV_DefineSpace` are refused to it, and `NoOldReleaseUnseals` and `EpochMonotonic` hold. Its `NV_SetBits` is refused too, since the index is `ownerwrite` only. NV and owner auth survive a TPM reset, so the result holds for either tier.

**Remains.** The model takes "unknown" as given. The commit runs on the CC, in userspace, where the A-01 attacker runs. So the value would be stored on the CC, and root that reads it is back at A-01. Storing no long-lived secret on the CC is OI2-05, which docs/05 §5.3 hands to P3 (an MSS-signed epoch advance). Lockout and DA: the model has no DA counter and no guessing, so it says nothing about either. The value must therefore be random and full-length. `lockoutAuth` stays empty, so any caller can still `TPM2_Clear`: that deletes the epoch index and replaces the storage seed. That denies the keys but does not release them (not modeled). A-02 is unchanged.

**Operational cost.** One secret per CC, generated at provisioning and needed for every epoch advance. Losing it means no epoch advance until re-provisioning, which re-seals the keys. A value shared across the fleet would make one CC's compromise everyone's.

**Owner decision: pending.**

## Option 2: epoch index defined with `TPMA_NV_POLICY_DELETE`

**Changes.** Provisioning defines the epoch index with `TPMA_NV_POLICY_DELETE` (and `TPMA_NV_PLATFORMCREATE`, under platform authorization). Its authPolicy then permits only `TPM2_NV_UndefineSpaceSpecial`, under a condition the attacker cannot meet: none at all, which makes the index permanent, or a signature only the MSS can give. The index's name changes, so `tools/approve_policy.py` and `tests/ve07/provision.py` would change with it (not in this task). Config: `FixPolicyDelete.cfg` (`policy_delete` in `ProvAttrs`), witness `FixPolicyDeleteWitness.cfg`.

**Closes, in this model:** A-01. `NV_UndefineSpace` is refused on the index, and no caller can define a `POLICY_DELETE` index, since platform authorization is not modeled. `TPM2_NV_UndefineSpaceSpecial` is not modeled either, so the model assumes the delete policy cannot be satisfied. `NoOldReleaseUnseals` and `EpochMonotonic` hold for either tier.

**Remains.** Owner auth stays empty, so any caller can still set a higher bit with `NV_SetBits` and deny the keys to every release. That is availability, which the model does not check. The commit's authorization is still the open item OI2-05. Platform authorization is outside the model. On this CC, U-Boot owns the platform hierarchy. If it leaves the hierarchy enabled with an empty auth, root gains `TPM2_Clear` and hierarchy control, which deny the keys. A delete policy that needs only platform auth would also fail. So U-Boot would have to set a random platformAuth or disable the hierarchy each boot, which is a boot-loader change. A-02 is unchanged.

**Operational cost.** A provisioning step that runs while platform authorization is available, so in or before U-Boot. With an unsatisfiable delete policy, a provisioning mistake is permanent for that TPM. No secret has to be stored on the CC for this option.

**Owner decision: pending.**

## Option 3: PCR cap after unseal

**Changes.** None: this is already the recorded design (DD2-18, docs/03 §3.3 step 4, TC-05b). The initramfs extends the cap event into every policy PCR before it hands off. So its configs are the existing `BootRoot.cfg` (witness `BootRootWitness.cfg`) and `Boot.cfg`, against the control `BootNoCap.cfg`. A copy under a new name would check the same thing twice.

**Closes, in this model:** the second release by root in userspace, that is, A-02 as the audit wrote it. `OnlyInitramfsObtainsKeys` holds on `BootRoot.cfg` and fails on `BootNoCap.cfg`.

**Remains.** An attacker who can reset the TPM alone. `Boot.cfg` fails in 27 steps: reset, replay U-Boot's measurements, unseal. That rests on A2-02 and DD2-17, is THR-034's residual risk, and P5 owns it. The cap does not act on A-01: `Epoch.tla` has no PCRs, and `Epoch.cfg` still fails. Keys already handed to userspace depend on SR-006 (the rest of A-02, docs/06 §6.6).

**Operational cost.** None new. No program later in the same boot can unseal, by design.

**Owner decision: pending.**

## Option 4: options 2 and 3 combined

**Changes.** Option 2's epoch index, with option 3's cap kept. `Epoch.tla` has no PCRs and `Boot.tla` has no NV commands, so the combination is checked in two parts. `FixPolicyDelete.cfg` is the A-01 part, where the cap has nothing to act on. `FixCombined.cfg` (physical) and `FixCombinedRoot.cfg` (root, witness `FixCombinedRootWitness.cfg`) are `Boot.cfg` and `BootRoot.cfg` with option 2's `ProvAttrs`.

**Closes, in this model:** A-01, and the second release by root in userspace. The legitimate unseal stays reachable with the new index.

**Remains.** The TPM reset with replay: `FixCombined.cfg` fails in the same 27 steps as `Boot.cfg`. Option 2's residuals (higher bits set by any caller, platform hierarchy, OI2-05) also remain. The model has no single spec that holds both the NV commands and the boot stages, and `Boot.tla` boots only the newer release. So an attack that mixes the two, such as an epoch reset followed by booting an older signed release, is checked only as A-01 in `Epoch.tla`.

**Operational cost.** Option 2's.

**Owner decision: pending.**

## Results

From `python3 model/ci.py`: `pass` means the property holds on that configuration, and `fail` means TLC reports it violated. `—` means the configuration does not check it, either because it does not list it or because TLC stopped at an earlier violation. Witnesses are left out. `tests/test_model_fix_options.py` fails if this table and `model/configs.json` disagree.

| Option | Config | Attacker | NoOldReleaseUnseals | EpochMonotonic | OnlyInitramfsObtainsKeys |
|---|---|---|---|---|---|
| today | Epoch.cfg | any caller | fail | — | — |
| today | EpochMonotonic.cfg | any caller | — | fail | — |
| 1 | FixOwnerAuth.cfg | any caller | pass | pass | — |
| 2, 4 | FixPolicyDelete.cfg | any caller | pass | pass | — |
| control, no cap | BootNoCap.cfg | root | — | — | fail |
| 3 (today) | BootRoot.cfg | root | pass | pass | pass |
| 3 (today) | Boot.cfg | physical | — | — | fail |
| 4 | FixCombinedRoot.cfg | root | pass | pass | pass |
| 4 | FixCombined.cfg | physical | — | — | fail |
