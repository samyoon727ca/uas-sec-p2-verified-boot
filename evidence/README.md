# Evidence

One folder per run: `<event>-<ci|hw>/<YYYYMMDD>-<commit>/`, where `<commit>` is the code commit the run tested. Each folder holds `summary.md` (readable), `summary.json` (every check, tool versions, pins, artifact and public-key SHA-256) and one console log per case. Rules are in [docs/06 §6.4](../docs/06-verification.md#64-evidence-rules).

| Run | Event | Environment | Test cases | Result |
|---|---|---|---|---|
| [`ve07-ci/20261013-d9149f6`](ve07-ci/20261013-d9149f6/summary.md) | VE-07 | GitHub Actions run [38349138261](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38349138261), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 31 of 31 runs, including 5 control runs. TC-09's swtpm I/O logs have key bytes replaced by `--` |
| [`ve07-ci/20261013-cf38809`](ve07-ci/20261013-cf38809/summary.md) | VE-07 | GitHub Actions run [38347668352](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38347668352), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-08, TC-10 | Pass: 29 of 29 runs, including 4 control runs |
| [`ve07-ci/20261013-0d3ca38`](ve07-ci/20261013-0d3ca38/summary.md) | VE-07 | GitHub Actions run [38345035945](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38345035945), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03, TC-04, TC-05, TC-10 | Pass: 18 of 18 runs, including 4 control runs |
| [`ve07-ci/20261013-1c9867e`](ve07-ci/20261013-1c9867e/summary.md) | VE-07 | GitHub Actions run [38340963718](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38340963718), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 | TC-01, TC-03, TC-04, TC-10 | Pass: 17 of 17 runs, including 4 control runs |
| [`ve07-ci/20261011-7bc523b`](ve07-ci/20261011-7bc523b/summary.md) | VE-07 | GitHub Actions run [38120187352](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38120187352), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 | TC-01, TC-03, TC-04 | Pass: 16 of 16 runs, including 4 control runs |

Newest run first. A test case links to the newest run that covers it; older runs stay as the record of what passed at their commit.

The CI workflow [`ve07-emu`](../.github/workflows/ve07-emu.yml) re-runs the same harness on every change to `cc/` or `tests/ve07/` and uploads its output as the `ve07-ci-evidence` artifact. A `ci` folder is that artifact, downloaded unchanged.
