# VE-07 emulated run: TC-01, TC-03, TC-04, TC-05, TC-06, TC-07, TC-08, TC-10

- Date (UTC): 2026-10-13T04:49:45Z
- Where: GitHub Actions run [38347668352](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38347668352) (ubuntu24 20261004.327.1)
- Code commit: `cf388091c9236fff5ea0a0d45cb35ee3f661fb20` (cc/ or tests/ modified: false)
- Host packages match the pins (snapshot 20261002T000000Z): yes
- Result: **PASS**

| Test case | Result |
|---|---|
| TC-01 | passed |
| TC-03 | passed |
| TC-04 | passed |
| TC-05 | passed |
| TC-06 | passed |
| TC-07 | passed |
| TC-08 | passed |
| TC-10 | passed |

| Run | Role | What | Result | Seconds | Log |
|---|---|---|---|---|---|
| TC-04a | test | Built .config holds every P2 setting; each control build changes exactly one | pass | 0 | – |
| TC-01 | positive | Signed chain boots to the initramfs | pass | 9 | [TC-01.log](TC-01.log) |
| TC-03a | test | Kernel changed after signing | pass | 1 | [TC-03a.log](TC-03a.log) |
| TC-03b | test | Initramfs changed after signing | pass | 1 | [TC-03b.log](TC-03b.log) |
| TC-03c | test | Devicetree changed after signing | pass | 1 | [TC-03c.log](TC-03c.log) |
| TC-04b | test | Unsigned configuration added after signing and made default | pass | 0 | [TC-04b.log](TC-04b.log) |
| TC-04c | test | Unsigned FIT | pass | 0 | [TC-04c.log](TC-04c.log) |
| TC-04d | test | FIT signed by a rogue key with the same key name | pass | 0 | [TC-04d.log](TC-04d.log) |
| TC-04e | test | Legacy uImage in the boot slot | pass | 0 | [TC-04e.log](TC-04e.log) |
| TC-04e-control | control for TC-04e | Stock U-Boot boots the same legacy uImage (via injected environment) | pass | 4 | [TC-04e-control.log](TC-04e-control.log) |
| TC-04f | test | Environment injected into flash is ignored | pass | 9 | [TC-04f.log](TC-04f.log) |
| TC-04f-control | control for TC-04f | Stock U-Boot runs the injected environment | pass | 4 | [TC-04f-control.log](TC-04f-control.log) |
| TC-04g | test | Keystrokes from console start to the end of a good boot reach no prompt | pass | 9 | [TC-04g.log](TC-04g.log) |
| TC-04g-control | control for TC-04g | The same keystrokes stop autoboot when only the delay is restored | pass | 1 | [TC-04g-control.log](TC-04g-control.log) |
| TC-04h | test | Keystrokes after a refused boot reach no prompt; the board resets and refuses again | pass | 4 | [TC-04h.log](TC-04h.log) |
| TC-04h-control | control for TC-04h | The same keystrokes reach a prompt when only the reset is removed | pass | 1 | [TC-04h-control.log](TC-04h-control.log) |
| TC-05 | test | Keys unseal in the measured, unmodified boot state | pass | 10 | [TC-05.log](TC-05.log) |
| TC-06a | test | Boot loader with another version string (PCR 0) | pass | 10 | [TC-06a.log](TC-06a.log) |
| TC-06b | test | Kernel command line with one more argument (PCR 1) | pass | 10 | [TC-06b.log](TC-06b.log) |
| TC-06c | test | Devicetree with one more property, re-signed (PCR 1) | pass | 10 | [TC-06c.log](TC-06c.log) |
| TC-06d | test | Kernel image with other bytes, re-signed (PCR 8) | pass | 10 | [TC-06d.log](TC-06d.log) |
| TC-06e | test | Initramfs with one more file, re-signed (PCR 9) | pass | 10 | [TC-06e.log](TC-06e.log) |
| TC-07a | test | This CC's data on a second CC's TPM | pass | 9 | [TC-07a.log](TC-07a.log) |
| TC-07b | test | The same, with the parent name changed to the second TPM's | pass | 10 | [TC-07b.log](TC-07b.log) |
| TC-08a | test | Release 1 with its epoch-0 policy, after epoch 1 is committed | pass | 10 | [TC-08a.log](TC-08a.log) |
| TC-08b | test | Release 2 with its epoch-1 policy, after the commit, still unseals | pass | 10 | [TC-08b.log](TC-08b.log) |
| TC-08c | test | Release 2 with a policy signed by a rogue key, rogue public key on storage | pass | 10 | [TC-08c.log](TC-08c.log) |
| TC-08d | test | Release 2 with a policy signed by a rogue key, K-CC-POL public key on storage | pass | 10 | [TC-08d.log](TC-08d.log) |
| TC-10 | test | Predicted PCRs equal the measured PCRs and the event-log replay | pass | 9 | [TC-10.log](TC-10.log) |

TC-05, keys unsealed by `p2-unseal` under the approved policy for epoch 0 (`6a942643065afc6a…`). Keys are generated per run; only their SHA-256 is recorded.

| Key | SHA-256 sealed | Unsealed |
|---|---|---|
| wireguard | `c3357cf50b1fec92ae71c0736c8d0fb48208d38681a4c9c29b8d0a1577bc51a2` | equal |
| mavlink | `058368f15bea3138deb3401ff84bb8840bb746175e6588bd4910de55d28709fa` | equal |

Sealing runs: what `p2-unseal` reported for each key.

| Run | U-Boot | FIT | TPM | CC data | p2-unseal |
|---|---|---|---|---|---|
| TC-05 | hardened | good | provisioned | cc | ok |
| TC-06a | tc06-version | good | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context |
| TC-06b | tc06-bootargs | good | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context |
| TC-06c | hardened | tc06-devicetree | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context |
| TC-06d | hardened | tc06-kernel | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context |
| TC-06e | hardened | tc06-initramfs | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context |
| TC-07a | hardened | good | second | cc | refused at parent name: missing or wrong CC data |
| TC-07b | hardened | good | second | cc-moved | refused at Load: tpm:parameter(1):integrity check failed |
| TC-08a | hardened | good | committed | cc | refused at PolicyNV: tpm:error(2.0): policy failure in math operation or an invalid authPolicy value |
| TC-08b | hardened | r2 | committed | cc-r2 | ok |
| TC-08c | hardened | r2 | committed | cc-r2-rogue-key | refused at Unseal: tpm:session(1):a policy check failed |
| TC-08d | hardened | r2 | committed | cc-r2-rogue-sig | refused at VerifySignature: tpm:parameter(2):the signature is not valid |

TC-10, SHA-256 PCRs (predicted by `tools/predict_pcrs.py` from `good.itb` and `u-boot-hardened.bin`):

| PCR | Predicted | Measured | Event-log replay |
|---|---|---|---|
| 0 | `30c8a64625e906bd4cbb92442cbb825d80a4e91559aece4c5254e554a7fb54e0` | equal | equal |
| 1 | `a59fee377561a1ff23d7c9e6f1d6853f054269470832e5a0b0198c42f04e1dc6` | equal | equal |
| 8 | `872c40a29504ea646eae76dd60ff0a8078344d933f9c304cfeefb688ce0bb4e8` | equal | equal |
| 9 | `2e34bd575fc57407b450443791269d869fcd50fba28fa5352bc687aff9de8358` | equal | equal |

Every check behind each result is in `summary.json`. Logs are the raw console output; patterns are matched with ANSI escape sequences removed.
