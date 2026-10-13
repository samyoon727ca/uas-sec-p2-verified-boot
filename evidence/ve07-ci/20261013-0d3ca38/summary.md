# VE-07 emulated run: TC-01, TC-03, TC-04, TC-05, TC-10

- Date (UTC): 2026-10-13T04:15:29Z
- Where: GitHub Actions run [38345035945](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38345035945) (ubuntu24 20261004.327.1)
- Code commit: `0d3ca389ee65ba4575c00aad9b5130c4c416c5e5` (cc/ or tests/ modified: false)
- Host packages match the pins (snapshot 20261002T000000Z): yes
- Result: **PASS**

| Test case | Result |
|---|---|
| TC-01 | passed |
| TC-03 | passed |
| TC-04 | passed |
| TC-05 | passed |
| TC-10 | passed |

| Run | Role | What | Result | Seconds | Log |
|---|---|---|---|---|---|
| TC-04a | test | Built .config holds every P2 setting; each control build changes exactly one | pass | 0 | – |
| TC-01 | positive | Signed chain boots to the initramfs | pass | 8 | [TC-01.log](TC-01.log) |
| TC-03a | test | Kernel changed after signing | pass | 1 | [TC-03a.log](TC-03a.log) |
| TC-03b | test | Initramfs changed after signing | pass | 1 | [TC-03b.log](TC-03b.log) |
| TC-03c | test | Devicetree changed after signing | pass | 1 | [TC-03c.log](TC-03c.log) |
| TC-04b | test | Unsigned configuration added after signing and made default | pass | 0 | [TC-04b.log](TC-04b.log) |
| TC-04c | test | Unsigned FIT | pass | 0 | [TC-04c.log](TC-04c.log) |
| TC-04d | test | FIT signed by a rogue key with the same key name | pass | 0 | [TC-04d.log](TC-04d.log) |
| TC-04e | test | Legacy uImage in the boot slot | pass | 0 | [TC-04e.log](TC-04e.log) |
| TC-04e-control | control for TC-04e | Stock U-Boot boots the same legacy uImage (via injected environment) | pass | 3 | [TC-04e-control.log](TC-04e-control.log) |
| TC-04f | test | Environment injected into flash is ignored | pass | 8 | [TC-04f.log](TC-04f.log) |
| TC-04f-control | control for TC-04f | Stock U-Boot runs the injected environment | pass | 3 | [TC-04f-control.log](TC-04f-control.log) |
| TC-04g | test | Keystrokes from console start to the end of a good boot reach no prompt | pass | 8 | [TC-04g.log](TC-04g.log) |
| TC-04g-control | control for TC-04g | The same keystrokes stop autoboot when only the delay is restored | pass | 1 | [TC-04g-control.log](TC-04g-control.log) |
| TC-04h | test | Keystrokes after a refused boot reach no prompt; the board resets and refuses again | pass | 3 | [TC-04h.log](TC-04h.log) |
| TC-04h-control | control for TC-04h | The same keystrokes reach a prompt when only the reset is removed | pass | 1 | [TC-04h-control.log](TC-04h-control.log) |
| TC-05 | test | Keys unseal in the measured, unmodified boot state | pass | 8 | [TC-05.log](TC-05.log) |
| TC-10 | test | Predicted PCRs equal the measured PCRs and the event-log replay | pass | 8 | [TC-10.log](TC-10.log) |

TC-05, keys unsealed by `p2-unseal` under the approved policy for epoch 0 (`6a942643065afc6a…`). Keys are generated per run; only their SHA-256 is recorded.

| Key | SHA-256 sealed | Unsealed |
|---|---|---|
| wireguard | `708e7d05bd875470ce8530cb433922021f971faa979af37378c85b0350b6bb9d` | equal |
| mavlink | `5057bbd7a00ae248801f97160ac72b151b2abb23c3c060a669a5f9f446e3278c` | equal |

TC-10, SHA-256 PCRs (predicted by `tools/predict_pcrs.py` from `good.itb` and `u-boot-hardened.bin`):

| PCR | Predicted | Measured | Event-log replay |
|---|---|---|---|
| 0 | `30c8a64625e906bd4cbb92442cbb825d80a4e91559aece4c5254e554a7fb54e0` | equal | equal |
| 1 | `a59fee377561a1ff23d7c9e6f1d6853f054269470832e5a0b0198c42f04e1dc6` | equal | equal |
| 8 | `872c40a29504ea646eae76dd60ff0a8078344d933f9c304cfeefb688ce0bb4e8` | equal | equal |
| 9 | `2e34bd575fc57407b450443791269d869fcd50fba28fa5352bc687aff9de8358` | equal | equal |

Every check behind each result is in `summary.json`. Logs are the raw console output; patterns are matched with ANSI escape sequences removed.
