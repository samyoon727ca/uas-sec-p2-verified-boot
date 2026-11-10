# VE-07 emulated run: TC-01, TC-03, TC-04, TC-05, TC-06, TC-07, TC-08, TC-09, TC-10

- Date (UTC): 2026-11-10T06:45:12Z
- Where: GitHub Actions run [42769477229](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42769477229) (ubuntu24 20261101.360.1)
- Code commit: `ec5ea720567f63146f5d7e12d9ece3e5e8b79259` (cc/ or tests/ modified: false)
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
| TC-09 | passed |
| TC-10 | passed |

| Run | Role | What | Result | Seconds | Log |
|---|---|---|---|---|---|
| TC-04a | test | Built .config holds every P2 setting; each control build changes exactly one | pass | 0 | – |
| TC-01 | positive | Signed chain boots to the initramfs | pass | 11 | [TC-01.log](TC-01.log) |
| TC-03a | test | Kernel changed after signing | pass | 1 | [TC-03a.log](TC-03a.log) |
| TC-03b | test | Initramfs changed after signing | pass | 1 | [TC-03b.log](TC-03b.log) |
| TC-03c | test | Devicetree changed after signing | pass | 1 | [TC-03c.log](TC-03c.log) |
| TC-04b | test | Unsigned configuration added after signing and made default | pass | 0 | [TC-04b.log](TC-04b.log) |
| TC-04c | test | Unsigned FIT | pass | 0 | [TC-04c.log](TC-04c.log) |
| TC-04d | test | FIT signed by a rogue key with the same key name | pass | 0 | [TC-04d.log](TC-04d.log) |
| TC-04e | test | Legacy uImage in the boot slot | pass | 0 | [TC-04e.log](TC-04e.log) |
| TC-04e-control | control for TC-04e | Stock U-Boot boots the same legacy uImage (via injected environment) | pass | 4 | [TC-04e-control.log](TC-04e-control.log) |
| TC-04f | test | Environment injected into flash is ignored | pass | 11 | [TC-04f.log](TC-04f.log) |
| TC-04f-control | control for TC-04f | Stock U-Boot runs the injected environment | pass | 5 | [TC-04f-control.log](TC-04f-control.log) |
| TC-04g | test | Keystrokes from console start to the end of a good boot reach no prompt | pass | 11 | [TC-04g.log](TC-04g.log) |
| TC-04g-control | control for TC-04g | The same keystrokes stop autoboot when only the delay is restored | pass | 1 | [TC-04g-control.log](TC-04g-control.log) |
| TC-04h | test | Keystrokes after a refused boot reach no prompt; the board resets and refuses again | pass | 5 | [TC-04h.log](TC-04h.log) |
| TC-04h-control | control for TC-04h | The same keystrokes reach a prompt when only the reset is removed | pass | 1 | [TC-04h-control.log](TC-04h-control.log) |
| TC-05 | test | Keys unseal in the measured, unmodified boot state | pass | 12 | [TC-05.log](TC-05.log) |
| TC-05b | test | A second unseal in the same boot is refused | pass | 12 | [TC-05b.log](TC-05b.log) |
| TC-05b-control | control for TC-05b | Without the cap, the second unseal releases both keys again | pass | 12 | [TC-05b-control.log](TC-05b-control.log) |
| TC-06a | test | Boot loader with another version string (PCR 0) | pass | 12 | [TC-06a.log](TC-06a.log) |
| TC-06b | test | Kernel command line with one more argument (PCR 1) | pass | 12 | [TC-06b.log](TC-06b.log) |
| TC-06c | test | Devicetree with one more property, re-signed (PCR 1) | pass | 12 | [TC-06c.log](TC-06c.log) |
| TC-06d | test | Kernel image with other bytes, re-signed (PCR 8) | pass | 12 | [TC-06d.log](TC-06d.log) |
| TC-06e | test | Initramfs with one more file, re-signed (PCR 9) | pass | 12 | [TC-06e.log](TC-06e.log) |
| TC-07a | test | This CC's data on a second CC's TPM | pass | 11 | [TC-07a.log](TC-07a.log) |
| TC-07b | test | The same, with the parent name changed to the second TPM's | pass | 12 | [TC-07b.log](TC-07b.log) |
| TC-08a | test | Release 1 with its epoch-0 policy, after epoch 1 is committed | pass | 12 | [TC-08a.log](TC-08a.log) |
| TC-08b | test | Release 2 with its epoch-1 policy, after the commit, still unseals | pass | 12 | [TC-08b.log](TC-08b.log) |
| TC-08c | test | Release 2 with a policy signed by a rogue key, rogue public key on storage | pass | 12 | [TC-08c.log](TC-08c.log) |
| TC-08d | test | Release 2 with a policy signed by a rogue key, K-CC-POL public key on storage | pass | 11 | [TC-08d.log](TC-08d.log) |
| TC-09 | test | Neither key appears in the TPM traffic of a TC-05 boot | pass | 12 | [TC-09.log](TC-09.log) |
| TC-09-control | control for TC-09 | Both keys appear in it when the agent leaves the response in the clear | pass | 12 | [TC-09-control.log](TC-09-control.log) |
| TC-10 | test | Predicted PCRs equal the measured PCRs and the event-log replay | pass | 11 | [TC-10.log](TC-10.log) |

TC-05, keys unsealed by `p2-unseal` under the approved policy for epoch 0 (`34ff1c1248ece97b…`). Keys are generated per run; only their SHA-256 is recorded.

| Key | SHA-256 sealed | Unsealed |
|---|---|---|
| wireguard | `a0d006e6361e57a1939a1af61f0ce7bf9ea7458e0206dbb92a14329769edba31` | equal |
| mavlink | `f5de4cb05e09fb0419e885e7d966440acdab24f4b6f7f3706db3404e7a1e10e5` | equal |

Sealing runs: what `p2-unseal` reported for each key, and after the release: the cap that extends the policy PCRs and, in the two second-unseal builds, a second attempt (`AGAIN`).

| Run | U-Boot | FIT | TPM | CC data | p2-unseal | After the release |
|---|---|---|---|---|---|---|
| TC-05 | hardened | good | provisioned | cc | ok | CAP ok |
| TC-05b | hardened | tc05-again | provisioned | cc-tc05-again | ok (agent build: a second attempt follows) | CAP ok; AGAIN refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context |
| TC-05b-control | hardened | ctl-nocap | provisioned | cc-ctl-nocap | ok (agent build: PCRs not capped; a second attempt follows) | AGAIN ok; AGAIN is the key released before |
| TC-06a | tc06-version | good | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context | CAP ok |
| TC-06b | tc06-bootargs | good | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context | CAP ok |
| TC-06c | hardened | tc06-devicetree | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context | CAP ok |
| TC-06d | hardened | tc06-kernel | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context | CAP ok |
| TC-06e | hardened | tc06-initramfs | provisioned | cc | refused at PolicyAuthorize: tpm:parameter(1):value is out of range or is not correct for the context | CAP ok |
| TC-07a | hardened | good | second | cc | refused at parent name: missing or wrong CC data | CAP ok |
| TC-07b | hardened | good | second | cc-moved | refused at Load: tpm:parameter(1):integrity check failed | CAP ok |
| TC-08a | hardened | good | committed | cc | refused at PolicyNV: tpm:error(2.0): policy failure in math operation or an invalid authPolicy value | CAP ok |
| TC-08b | hardened | r2 | committed | cc-r2 | ok | CAP ok |
| TC-08c | hardened | r2 | committed | cc-r2-rogue-key | refused at Unseal: tpm:session(1):a policy check failed | CAP ok |
| TC-08d | hardened | r2 | committed | cc-r2-rogue-sig | refused at VerifySignature: tpm:parameter(2):the signature is not valid | CAP ok |
| TC-09 | hardened | good | provisioned | cc | ok | CAP ok |
| TC-09-control | hardened | ctl-clear | provisioned | cc-ctl-clear | ok (agent build: response encryption off) | CAP ok |

TC-09: TPM commands and responses swtpm recorded during the boot, searched for each key. The I/O logs are swtpm's own layout with any key bytes replaced by `--`; `summary.json` gives the position and SHA-256 of every replacement.

| Run | Frames | Key bytes found | I/O log |
|---|---|---|---|
| TC-09 | 556 | none | [TC-09.swtpm-io.log](TC-09.swtpm-io.log) |
| TC-09-control | 556 | wireguard in frame 463 (rsp), mavlink in frame 523 (rsp) | [TC-09-control.swtpm-io.log](TC-09-control.swtpm-io.log) |

TC-10, SHA-256 PCRs (predicted by `tools/predict_pcrs.py` from `good.itb` and `u-boot-hardened.bin`):

| PCR | Predicted | Measured | Event-log replay |
|---|---|---|---|
| 0 | `30c8a64625e906bd4cbb92442cbb825d80a4e91559aece4c5254e554a7fb54e0` | equal | equal |
| 1 | `a59fee377561a1ff23d7c9e6f1d6853f054269470832e5a0b0198c42f04e1dc6` | equal | equal |
| 8 | `872c40a29504ea646eae76dd60ff0a8078344d933f9c304cfeefb688ce0bb4e8` | equal | equal |
| 9 | `5f9b447464bfa17cb55b3d6d39459c93010abdd5f6bf5f22cd13cc25ed26303c` | equal | equal |

Every check behind each result is in `summary.json`. Logs are the raw console output; patterns are matched with ANSI escape sequences removed.
