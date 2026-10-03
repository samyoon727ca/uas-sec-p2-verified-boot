# 3. Measured boot and key sealing

U-Boot measures what it boots into four SHA-256 PCRs before running it. The CC's WireGuard private key and its copy of the MAVLink signing key are sealed once, to a policy that the MSS approves with a signature. Each release carries a signed policy covering its predicted PCR values and its anti-rollback epoch. A legitimate update therefore needs no re-sealing, and an older release cannot unseal once a newer epoch is committed (SR-010, SR-010.1 to SR-010.4).

Status: design, informed by a throwaway prototype (§3.7). Nothing here is shown working until its test case passes ([§6](06-verification.md)).

## 3.1 Measurements (SR-010.1)

| PCR | Measured by U-Boot | Event type | Changes when |
|---|---|---|---|
| 0 | U-Boot version string | `EV_S_CRTM_VERSION` | U-Boot is rebuilt or rolled back |
| 1 | Devicetree from the FIT; kernel command line | `EV_TABLE_OF_DEVICES`, `EV_PLATFORM_CONFIG_FLAGS` | Hardware description or boot arguments change |
| 8 | Kernel image as stored in the FIT | `EV_COMPACT_HASH` "linux" | Kernel changes |
| 9 | Initramfs | `EV_COMPACT_HASH` "initrd" | Initramfs changes, including the unseal logic |

Sources: `boot/bootm.c` and `lib/tpm_tcg2.c` at `v2026.07` [UBOOT]. Three properties follow.

- **Predictable.** `bootm` measures right after finding the images: before loading or decompressing them, and before any devicetree fixups. So the MSS can compute every PCR value from the release artifacts alone. `tools/predict_pcrs.py` does this, and TC-10 checks the prediction against the measured PCRs and the event log.
- **Logged.** The event log goes to Linux through `linux,sml-base`/`linux,sml-size` on the TPM node [UBOOT-MB], so the measurements can be replayed and checked.
- **Fails open for boot, closed for keys.** `bootm` ignores a measurement failure and boots anyway [UBOOT]. The PCRs then hold no approved values, so the keys stay sealed. The CC boots without them and cannot join C2.

PCRs from 10 up change at runtime (IMA, for example) and are not in the policy. Runtime integrity is P4's (SR-006).

## 3.2 Sealed objects

| Item | Choice |
|---|---|
| Contents | CC WireGuard private key; CC copy of the MAVLink signing key (P1 DS-CC-CRED) |
| Parent | ECC P-256 primary key in the owner hierarchy |
| Attributes | `fixedtpm`, `fixedparent`, `adminwithpolicy`; **no** `userwithauth`, so only the policy releases them |
| Auth policy | `TPM2_PolicyAuthorize(K-CC-POL, policyRef)`. `policyRef` names this use, so a policy the MSS signs for another purpose cannot be reused here |
| Where the blob lives | CC storage. It is useless away from its TPM (TC-07) |

## 3.3 Release policy (SR-010.2)

For each release the MSS builds and signs an **approved policy**:

```
PolicyPCR( sha256: 0, 1, 8, 9  =  predicted values )
PolicyNV ( epoch index, operandB = bits above E, TPM_EO_BITCLEAR )
```

To unseal, the initramfs:
1. checks the signature with `TPM2_VerifySignature` to get a ticket;
2. runs `PolicyPCR`, then `PolicyNV`, then `PolicyAuthorize` with the ticket, in a policy session;
3. unseals over a salted, encrypted session (§3.6).

This is the TCG's mechanism for avoiding PCR brittleness [TCG-P1, Figure 16]. Nothing on the CC can approve its own state: approval needs K-CC-POL, which lives on the MSS and in P3's HSM.

## 3.4 Anti-rollback epoch (SR-010.3)

The epoch is an **NV bit field** in the TPM. Committing epoch *k* sets bit *k*. The policy for a release at epoch *E* passes only if no bit above *E* is set (`TPM_EO_BITCLEAR`: all bits set in B are clear in A [TCG-P2]).

**Why a bit field, not a counter.** A bit field starts at zero and can only gain bits [TCG-P1 §37.2.6.4], so one signed policy works on every CC. A counter's first increment lands above any value that counter index has ever held on that TPM [TCG-P1 §37.2.6.3]. Its starting value would therefore differ per TPM, and the MSS would have to sign per-device policies.

**Limits.** 64 epochs. The epoch advances only for releases that fix a security flaw in the boot chain; other releases reuse the current epoch.

**Who may advance it.** In P2 the epoch bit is set with TPM owner authorization. A fielded CC needs an MSS-signed authorization instead (OI2-05, P3).

## 3.5 Legitimate update

1. **MSS:** build the release, predict PCRs 0, 1, 8 and 9, build the approved policy for epoch *E* and sign it with K-CC-POL. P3 moves the key into the HSM.
2. **CC:** install the new FIT, and a new `boot.img` if U-Boot changed, together with the signed policy. P3 owns update acceptance (SR-007).
3. **Reboot:** the new chain unseals with the new policy. The sealed objects are untouched.
4. **Commit:** if *E* is above the current epoch, set bit *E*. From then on, policies for older epochs fail.
5. **If the new chain cannot unseal,** do not commit, and boot the previous chain. The A/B layout belongs to P3 and P4.

Re-sealing on the CC during an update was rejected. It needs the keys in the clear on a running system, and it gives no rollback protection.

## 3.6 Session protection (SR-010.4)

A discrete TPM answers over SPI. Without parameter encryption, the unsealed key crosses the bus in the clear, where a probe on a captured vehicle can read it (P1 A-08, tier 2). The initramfs therefore unseals in a session that is:
- **salted** to a TPM key whose public part is recorded at provisioning;
- set to **encrypt the response.**

This stops passive sniffing. It does not stop an attacker who can reset the TPM alone and replay approved measurements (A2-02); that is P1 change 4 and P5's scope.

## 3.7 Prototype findings

A throwaway prototype ran on swtpm 0.7.3 and tpm2-tools 5.6 while the design was being chosen. Its results shaped the design. They are **not evidence**; TC-05 to TC-10 reproduce them in CI.

- The policy in §3.3 unsealed in the approved state.
- It unsealed for the next epoch before commit, and only for that epoch after commit.
- It refused a rogue-signed policy and a changed PCR 8.
- A second TPM refused to load the sealed blob.
- swtpm 0.7.3 rejected an RSA-3072 public key for `TPM2_LoadExternal`. K-CC-POL is therefore ECDSA P-256, which has the same 128-bit strength [SP800-57].
- Without a resource manager, swtpm runs out of object slots unless transient objects are flushed. The CC uses the kernel's `/dev/tpmrm0`.

## 3.8 Design decisions

| ID | Decision | Rationale | Alternative considered |
|---|---|---|---|
| DD2-08 | Seal to PCRs 0, 1, 8 and 9 | §3.1 | Adding IMA (PCR 10): changes at runtime |
| DD2-09 | `PolicyAuthorize` with an MSS-signed approved policy | Updates without re-sealing; no self-approval | PCR-only policy re-sealed on every update |
| DD2-10 | NV bit-field epoch in the approved policy | Same policy on every CC; bits can only be set | NV counter: per-device starting value |
| DD2-11 | K-CC-POL is ECDSA P-256 | Same strength as RSA-3072 [SP800-57]; loads in swtpm 0.7.3 | RSA-3072: rejected by swtpm 0.7.3 |
| DD2-12 | Salted session with response encryption for unseal | SR-010.4 | Unencrypted session (control run in TC-09) |

## 3.9 Open items

| ID | Item | Closed by |
|---|---|---|
| OI2-05 | Advancing the epoch uses TPM owner authorization in P2. A fielded CC needs an MSS-signed authorization so that no long-lived secret is stored on the CC | P3 |
