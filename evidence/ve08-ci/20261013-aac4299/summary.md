# VE-08 host run: FC images checked with PX4's verification code (TC-11)

- Date (UTC): 2026-10-13T05:35:39Z
- Where: GitHub Actions run [38351585198](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38351585198) (ubuntu24 20261004.327.1)
- Code commit: `aac42999041002065a08c0735633be4155403467` (fc/ or tests/ modified: false)
- PX4: `fca3df865af36124a28c9d607e850f111dbaaea9` (v1.18.0-rc1), built in `ghcr.io/px4/px4-dev@sha256:5e7ad18c75c3a5a655d5adfde4ab1eb216dd4bee7710941b6cd122f3969a7fed`
- Host packages match the pins (snapshot 20261002T000000Z): yes
- Result: **PASS**

| Check | Result |
|---|---|
| the boot loader holds the run key once | pass |
| the boot loader does not hold PX4's public test key | pass |
| the signed image is the built image, padded to 4 bytes, plus a 64-byte signature | pass |
| the .px4 envelope carries the signed image and marks it signed | pass |

| Run | Role | Image | Checker key in slot 0 | Expected | Result | Log |
|---|---|---|---|---|---|---|
| TC-11a | positive | Image signed by the build with the run key | run-key | starts | pass | [TC-11a.log](TC-11a.log) |
| TC-11b | test | Image as built, unsigned | run-key | stays in boot loader | pass | [TC-11b.log](TC-11b.log) |
| TC-11c | test | Signed image with one byte changed after signing | run-key | stays in boot loader | pass | [TC-11c.log](TC-11c.log) |
| TC-11d | test | Image signed with PX4's public test key | run-key | stays in boot loader | pass | [TC-11d.log](TC-11d.log) |
| TC-11d-control | control for TC-11d | The same image starts when the test key is in slot 0 | test-key | starts | pass | [TC-11d-control.log](TC-11d-control.log) |

Every check is in `summary.json`. Each log is the checker's output for that image.
