# Evidence

One folder per run: `<event>-<ci|hw>/<YYYYMMDD>-<commit>/`, where `<commit>` is the code commit the run tested. Each folder holds `summary.md` (readable), `summary.json` (every check, tool versions, pins, artifact and public-key SHA-256) and one log per case: the console for VE-07, the image checker's output for VE-08. Rules are in [docs/06 §6.4](../docs/06-verification.md#64-evidence-rules).

| Run | Event | Environment | Test cases | Result |
|---|---|---|---|---|
| [`ve08-ci/20261013-aac4299`](ve08-ci/20261013-aac4299/summary.md) | VE-08 | GitHub Actions run [38351585198](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38351585198), runner image `ubuntu24` 20261004.327.1: PX4 `v1.18.0-rc1` built in `px4-dev` by digest; PX4's verification code on a 32-bit host | TC-11 | Pass: 5 of 5 runs, including 1 control run, and 4 of 4 static checks |
| [`ve07-ci/20261013-d9149f6`](ve07-ci/20261013-d9149f6/summary.md) | VE-07 | GitHub Actions run [38349138261](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38349138261), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 31 of 31 runs, including 5 control runs. TC-09's swtpm I/O logs have key bytes replaced by `--` |
| [`ve07-ci/20261013-cf38809`](ve07-ci/20261013-cf38809/summary.md) | VE-07 | GitHub Actions run [38347668352](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38347668352), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-08, TC-10 | Pass: 29 of 29 runs, including 4 control runs |
| [`ve07-ci/20261013-0d3ca38`](ve07-ci/20261013-0d3ca38/summary.md) | VE-07 | GitHub Actions run [38345035945](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38345035945), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03, TC-04, TC-05, TC-10 | Pass: 18 of 18 runs, including 4 control runs |
| [`ve07-ci/20261013-1c9867e`](ve07-ci/20261013-1c9867e/summary.md) | VE-07 | GitHub Actions run [38340963718](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38340963718), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 | TC-01, TC-03, TC-04, TC-10 | Pass: 17 of 17 runs, including 4 control runs |
| [`ve07-ci/20261011-7bc523b`](ve07-ci/20261011-7bc523b/summary.md) | VE-07 | GitHub Actions run [38120187352](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/38120187352), runner image `ubuntu24` 20261004.327.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 | TC-01, TC-03, TC-04 | Pass: 16 of 16 runs, including 4 control runs |

Newest run first. A test case links to the newest run that covers it; older runs stay as the record of what passed at their commit.

The CI workflow [`ve07-emu`](../.github/workflows/ve07-emu.yml) re-runs the same harness on every change to `cc/` or `tests/ve07/` and uploads its output as the `ve07-ci-evidence` artifact. A `ci` folder is that artifact, downloaded unchanged.

## Provenance

GitHub deletes an artifact, and its run's logs, 90 days after the run. Until then anyone can download the artifact and compare it with the folder here. After that, this table and [`SHA256SUMS`](SHA256SUMS) are the record.

| Run folder | Actions run | Artifact ID | Digest of the artifact zip, as GitHub reports it | GitHub deletes it |
|---|---|---|---|---|
| `ve08-ci/20261013-aac4299` | 38351585198 | 11790723761 | `sha256:9dcaa56deabbc280d28344d1f596d91cf95f0f7117487f8a00fae08f53b47ac0` | 2027-01-11 |
| `ve07-ci/20261013-d9149f6` | 38349138261 | 11791035439 | `sha256:953755016b7791871b6c0cf7b58d72fa36ac694c9f686b5bb292e798e71a77ab` | 2027-01-11 |
| `ve07-ci/20261013-cf38809` | 38347668352 | 11788788970 | `sha256:aca26b914abdddf0733d5bf1d7caede5e590962f3e0e2dea8116938a54e7a550` | 2027-01-11 |
| `ve07-ci/20261013-0d3ca38` | 38345035945 | 11788712833 | `sha256:20ec479368edfae5aeb08808de7c42c0bd7cd4c664f6c727424993916fd5f2ab` | 2027-01-11 |
| `ve07-ci/20261013-1c9867e` | 38340963718 | 11787081162 | `sha256:fde0587dd310ba5362a97f781dc0e287c5445a586d66acf4cbcab4e44b47f6c7` | 2027-01-11 |
| `ve07-ci/20261011-7bc523b` | 38120187352 | 11695296310 | `sha256:3301a9dda00161d2826dcd835e2adfaf63c462c841ef803daf2ac87d841fec2e` | 2027-01-09 |

Checked on 2026-11-09: each artifact was downloaded again, its SHA-256 equalled the digest above, and it unpacked to exactly the files of its folder.

To repeat the check while an artifact exists:

```sh
gh api repos/samyoon727ca/uas-sec-p2-verified-boot/actions/artifacts/<artifact ID>/zip > a.zip
sha256sum a.zip                      # the digest in the table
unzip -q a.zip -d a && diff -r a evidence/<run folder>
```

[`SHA256SUMS`](SHA256SUMS) lists the SHA-256 of every file in every run folder. A run folder is never edited after it is committed, and [`tools/check_evidence.py`](../tools/check_evidence.py) fails the build if a listed file changes or goes missing, or if a run folder gains a file that is not listed. A new run is added once with `python tools/check_evidence.py --add <event>-<ci|hw>/<run>`.

What this does not give: once GitHub has deleted an artifact, nothing outside this repo vouches for the digest in the table. Lasting, independent provenance needs the artifact attested at build time or attached to a release; neither is set up yet.
