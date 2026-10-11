# VE-07 emulated run: verified boot (TC-01, TC-03, TC-04)

- Date (UTC): 2026-10-03T16:50:59Z
- Code commit: `c87c3e98f3c73909e4c9a0471e57a6e7f606de15` (cc/ or tests/ modified: false)
- Result: **PASS**

| Test case | Result |
|---|---|
| TC-01 | passed |
| TC-03 | passed |
| TC-04 | passed |

| Run | Role | What | Result | Seconds | Log |
|---|---|---|---|---|---|
| TC-04a | test | Built .config holds every P2 setting | pass | 0 | – |
| TC-01 | positive | Signed chain boots to the initramfs | pass | 15 | [TC-01.log](TC-01.log) |
| TC-03a | test | Kernel changed after signing | pass | 2 | [TC-03a.log](TC-03a.log) |
| TC-03b | test | Initramfs changed after signing | pass | 2 | [TC-03b.log](TC-03b.log) |
| TC-03c | test | Devicetree changed after signing | pass | 2 | [TC-03c.log](TC-03c.log) |
| TC-04b | test | Unsigned configuration added after signing and made default | pass | 1 | [TC-04b.log](TC-04b.log) |
| TC-04c | test | Unsigned FIT | pass | 1 | [TC-04c.log](TC-04c.log) |
| TC-04d | test | FIT signed by a rogue key with the same key name | pass | 1 | [TC-04d.log](TC-04d.log) |
| TC-04e | test | Legacy uImage in the boot slot | pass | 1 | [TC-04e.log](TC-04e.log) |
| TC-04e-control | control | Stock U-Boot boots the same legacy uImage (via injected environment) | pass | 8 | [TC-04e-control.log](TC-04e-control.log) |
| TC-04f | test | Environment injected into flash is ignored | pass | 14 | [TC-04f.log](TC-04f.log) |
| TC-04f-control | control | Stock U-Boot runs the injected environment | pass | 8 | [TC-04f-control.log](TC-04f-control.log) |
| TC-04g | test | Keystrokes during a good boot do not interrupt it | pass | 14 | [TC-04g.log](TC-04g.log) |
| TC-04h | test | Keystrokes after a refused boot reach no prompt | pass | 2 | [TC-04h.log](TC-04h.log) |
| TC-04g-control | control | Keystrokes stop stock U-Boot at a prompt | pass | 5 | [TC-04g-control.log](TC-04g-control.log) |

Every check behind each result is in `summary.json`.
