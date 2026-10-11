# Evidence

One folder per run: `<event>-<ci|hw>/<YYYYMMDD>-<commit>/`, where `<commit>` is the code commit the run tested. Each folder holds `summary.md` (readable), `summary.json` (every check, tool versions, pins, artifact and public-key SHA-256) and one console log per case. Rules are in [docs/06 §6.4](../docs/06-verification.md#64-evidence-rules).

| Run | Event | Environment | Test cases | Result |
|---|---|---|---|---|
| [`ve07-ci/20261003-c87c3e9`](ve07-ci/20261003-c87c3e9/summary.md) | VE-07 | QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3, Ubuntu 24.04 | TC-01, TC-03, TC-04 | Pass: 15 of 15 runs, including 3 control runs |

The CI workflow [`ve07-emu`](../.github/workflows/ve07-emu.yml) re-runs the same harness on every change to `cc/` or `tests/ve07/` and uploads its output as the `ve07-ci-evidence` artifact.
