# Evidence

One folder per run: `<event>-<ci|hw>/<YYYYMMDD>-<commit>/`, where `<commit>` is the code commit the run tested. Each folder holds `summary.md` (readable), `summary.json` (every check, tool versions, pins, artifact and public-key SHA-256) and one log per case: the console for VE-07, the image checker's output for VE-08. Rules are in [docs/06 §6.4](../docs/06-verification.md#64-evidence-rules).

| Run | Event | Environment | Test cases | Result |
|---|---|---|---|---|
| [`ve08-ci/20261110-5e7233a`](ve08-ci/20261110-5e7233a/summary.md) | VE-08 | GitHub Actions run [42879974766](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42879974766), runner image `ubuntu24` 20261101.360.1: PX4 `v1.18.0-rc1` built in `px4-dev` by digest; PX4's verification code on a 32-bit host | TC-11 | Pass: 5 of 5 runs, including 1 control run, and 4 of 4 static checks. First run whose summary names the inputs its "modified" flag covers |
| [`ve07-ci/20261110-5e7233a`](ve07-ci/20261110-5e7233a/summary.md) | VE-07 | GitHub Actions run [42879974771](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42879974771), runner image `ubuntu24` 20261101.360.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 37 of 37 runs, including 7 control runs. No case changed; first run whose summary names the inputs its "modified" flag covers (`cc`, `tests`, `tools`). TC-09's swtpm I/O logs have key bytes replaced by `--`, in the clear or decryptable from the traffic |
| [`ve07-ci/20261110-ae3149e`](ve07-ci/20261110-ae3149e/summary.md) | VE-07 | GitHub Actions run [42876292325](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42876292325), runner image `ubuntu24` 20261101.360.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 37 of 37 runs, including 7 control runs. First run in which the build and TC-04a check the hardened configuration against the fixed boot-loader policy; each control build breaks exactly the rule its fragment relaxes. TC-09's swtpm I/O logs have key bytes replaced by `--`, in the clear or decryptable from the traffic |
| [`ve07-ci/20261110-ad7482b`](ve07-ci/20261110-ad7482b/summary.md) | VE-07 | GitHub Actions run [42870892583](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42870892583), runner image `ubuntu24` 20261101.360.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 37 of 37 runs, including 7 control runs. First run with TC-08e and TC-08f: the current release's policy, signed by the real K-CC-POL under another `policyRef` or under none, is refused at `VerifySignature`. TC-09's swtpm I/O logs have key bytes replaced by `--`, in the clear or decryptable from the traffic |
| [`ve07-ci/20261110-c19a7fa`](ve07-ci/20261110-c19a7fa/summary.md) | VE-07 | GitHub Actions run [42860314929](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42860314929), attempt 2 (attempt 1 stopped before the build: the Ubuntu snapshot server answered 503), runner image `ubuntu24` 20261101.360.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 35 of 35 runs, including 7 control runs. First run in which TC-09 checks that each unseal session is salted; in its second control, on an unsalted session, both keys decrypt from the traffic alone. TC-09's swtpm I/O logs have key bytes replaced by `--`, in the clear or decryptable that way |
| [`ve07-ci/20261110-3edd4f2`](ve07-ci/20261110-3edd4f2/summary.md) | VE-07 | GitHub Actions run [42775185879](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42775185879), runner image `ubuntu24` 20261101.360.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 34 of 34 runs, including 6 control runs. First run with TC-06f (kernel changed at its end) and the whole-image digest checks for PCRs 8 and 9. TC-09's swtpm I/O logs have key bytes replaced by `--` |
| [`ve07-ci/20261110-ec5ea72`](ve07-ci/20261110-ec5ea72/summary.md) | VE-07 | GitHub Actions run [42769477229](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42769477229), runner image `ubuntu24` 20261101.360.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6 | TC-01, TC-03 to TC-10 | Pass: 33 of 33 runs, including 6 control runs. First run with the PCR cap: TC-05b is refused a second unseal, and its control without the cap gets both keys again. TC-09's swtpm I/O logs have key bytes replaced by `--` |
| [`ve07-ci/20261110-acca55a`](ve07-ci/20261110-acca55a/summary.md) | VE-07 | GitHub Actions run [42756118017](https://github.com/samyoon727ca/uas-sec-p2-verified-boot/actions/runs/42756118017), runner image `ubuntu24` 20261101.360.1: QEMU `virt` 8.2.2 + U-Boot 2026.07 + swtpm 0.7.3 + tpm2-tools 5.6. The U-Boot tarball came from a mirror, with the pinned SHA-256 | TC-01, TC-03 to TC-10 | Pass: 31 of 31 runs, including 5 control runs. TC-09's swtpm I/O logs have key bytes replaced by `--` |
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
| `ve08-ci/20261110-5e7233a` | 42879974766 | 13793922380 | `sha256:97364b5beffc68b5b8bd1bcd5bad0a6bd0a712f67bc5c1066cdef351f0a28181` | 2027-02-08 |
| `ve07-ci/20261110-5e7233a` | 42879974771 | 13793878588 | `sha256:9c9376271474ac99cb7cdc33c11c7c00019d676988ef9f20ce87d17367d1e1b5` | 2027-02-08 |
| `ve07-ci/20261110-ae3149e` | 42876292325 | 13792387113 | `sha256:151776ee9379323d80db626897196df2dd8a3d383ed1d62eab643271c5574660` | 2027-02-08 |
| `ve07-ci/20261110-ad7482b` | 42870892583 | 13788474872 | `sha256:154de611342c200482af8ead1396eb9a1b09e67cbd2857f19791e1e1943d28f3` | 2027-02-08 |
| `ve07-ci/20261110-c19a7fa` | 42860314929 | 13788202199 | `sha256:772da4550c519031240f3f96f3aee0177ae37ba120dd92778f5a9c7b9a55556d` | 2027-02-08 |
| `ve07-ci/20261110-3edd4f2` | 42775185879 | 13743743470 | `sha256:e83c73b300929c3262ec760b7d243591b283781f8f87fbfc8607ca9f8a60ab96` | 2027-02-08 |
| `ve07-ci/20261110-ec5ea72` | 42769477229 | 13742015765 | `sha256:20b443377c178daa2ba13549957ff6e89deaa6db47e680a00ab83b8ddadba43e` | 2027-02-08 |
| `ve07-ci/20261110-acca55a` | 42756118017 | 13735767704 | `sha256:d42e398bf3f799e807f35956d54203622baed5e7b5bb32040bdeb6e6a07317aa` | 2027-02-08 |
| `ve08-ci/20261013-aac4299` | 38351585198 | 11790723761 | `sha256:9dcaa56deabbc280d28344d1f596d91cf95f0f7117487f8a00fae08f53b47ac0` | 2027-01-11 |
| `ve07-ci/20261013-d9149f6` | 38349138261 | 11791035439 | `sha256:953755016b7791871b6c0cf7b58d72fa36ac694c9f686b5bb292e798e71a77ab` | 2027-01-11 |
| `ve07-ci/20261013-cf38809` | 38347668352 | 11788788970 | `sha256:aca26b914abdddf0733d5bf1d7caede5e590962f3e0e2dea8116938a54e7a550` | 2027-01-11 |
| `ve07-ci/20261013-0d3ca38` | 38345035945 | 11788712833 | `sha256:20ec479368edfae5aeb08808de7c42c0bd7cd4c664f6c727424993916fd5f2ab` | 2027-01-11 |
| `ve07-ci/20261013-1c9867e` | 38340963718 | 11787081162 | `sha256:fde0587dd310ba5362a97f781dc0e287c5445a586d66acf4cbcab4e44b47f6c7` | 2027-01-11 |
| `ve07-ci/20261011-7bc523b` | 38120187352 | 11695296310 | `sha256:3301a9dda00161d2826dcd835e2adfaf63c462c841ef803daf2ac87d841fec2e` | 2027-01-09 |

Checked on 2026-11-09 for the six October runs, and for each later run when it was committed: the artifact was downloaded, its SHA-256 equalled the digest above, and it unpacked to exactly the files of its folder.

To repeat the check while an artifact exists:

```sh
gh api repos/samyoon727ca/uas-sec-p2-verified-boot/actions/artifacts/<artifact ID>/zip > a.zip
sha256sum a.zip                      # the digest in the table
unzip -q a.zip -d a && diff -r a evidence/<run folder>
```

[`SHA256SUMS`](SHA256SUMS) lists the SHA-256 of every file in every run folder. A run folder is never edited after it is committed, and [`tools/check_evidence.py`](../tools/check_evidence.py) fails the build if a listed file changes or goes missing, or if a run folder gains a file that is not listed. A new run is added once with `python tools/check_evidence.py --add <event>-<ci|hw>/<run>`.

What this does not give: once GitHub has deleted an artifact, nothing outside this repo vouches for the digest in the table. Lasting, independent provenance needs the artifact attested at build time or attached to a release; neither is set up yet.
