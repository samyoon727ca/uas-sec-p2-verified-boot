# VE-07 emulated run: verified boot (TC-01, TC-03, TC-04)

- Date (UTC): 2026-10-11T07:11:04Z
- Where: GitHub Actions run [38120187352](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38120187352) (ubuntu24 20261004.327.1)
- Code commit: `7bc523b94355e4baf36528fbb9e0c6c2b0418f1c` (cc/ or tests/ modified: false)
- Host packages match the pins (snapshot 20261002T000000Z): yes
- Result: **PASS**

| Test case | Result |
|---|---|
| TC-01 | passed |
| TC-03 | passed |
| TC-04 | passed |

| Run | Role | What | Result | Seconds | Log |
|---|---|---|---|---|---|
| TC-04a | test | Built .config holds every P2 setting; each control build changes exactly one | pass | 0 | – |
| TC-01 | positive | Signed chain boots to the initramfs | pass | 10 | [TC-01.log](TC-01.log) |
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
| TC-04g | test | Keystrokes from console start to the end of a good boot reach no prompt | pass | 10 | [TC-04g.log](TC-04g.log) |
| TC-04g-control | control for TC-04g | The same keystrokes stop autoboot when only the delay is restored | pass | 1 | [TC-04g-control.log](TC-04g-control.log) |
| TC-04h | test | Keystrokes after a refused boot reach no prompt; the board resets and refuses again | pass | 5 | [TC-04h.log](TC-04h.log) |
| TC-04h-control | control for TC-04h | The same keystrokes reach a prompt when only the reset is removed | pass | 1 | [TC-04h-control.log](TC-04h-control.log) |

Every check behind each result is in `summary.json`. Logs are the raw console output; patterns are matched with ANSI escape sequences removed.
