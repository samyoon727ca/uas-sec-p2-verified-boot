# Traceability data

These CSVs are the single source of truth for P2's child requirements, their trace to P1 threats, and the test cases that produce evidence for P1's verification events. `tools/validate_trace.py` enforces every rule below on each push. Multi-value cells are semicolon-separated (`SR-005; SR-005.1`).

## `p1/`: pinned P1 snapshot

Byte-for-byte copies of P1's `requirements.csv`, `threats.csv`, `trace.csv` and `verification.csv` at the commit in [`p1/pin.txt`](p1/pin.txt). `tools/check_p1_snapshot.py` compares them with P1 at that commit in CI. To move the pin, copy the four files from the new P1 commit and update `pin.txt` in the same change.

## `requirements.csv`: child requirements

| Column | Rule |
|---|---|
| `req_id` | Unique. `SR-###.#`, numbered under its parent (`SR-010.2` refines `SR-010`) |
| `parent_req` | A P1 requirement whose evidence repo is P2 |
| `statement` | Exactly one "shall" |
| `rationale` | Required |
| `allocated_to` | Same component as the parent |
| `verification` | Same method as the parent (`I`, `A`, `D`, `T`) |

## `trace.csv`

| Column | Rule |
|---|---|
| `req_id` | A child requirement |
| `threat_id` | A P1 threat that P1 traces to the child's parent. A threat outside that set is proposed to P1, not added here |

Every child needs at least one row. Duplicate pairs are rejected.

## `testcases.csv`

| Column | Rule |
|---|---|
| `tc_id` | Unique, `TC-##` |
| `ve_id` | A P1 verification event whose evidence repo is P2 |
| `title`, `procedure`, `pass_criteria` | Required |
| `verifies` | Child requirements or P1 requirements. A P1 requirement must be one the event verifies in P1; a child's parent must be |
| `ci_status`, `hw_status` | `planned`, `passed`, `failed` or `n/a` (does not run there). Not both `n/a` |
| `ci_evidence`, `hw_evidence` | Required when the status is `passed` or `failed`, empty otherwise. A path under `evidence/` that exists |

**Coverage rules:**
- every child requirement and every P1 requirement with evidence repo P2 is verified by at least one test case;
- every P2 verification event has at least one hardware test case.

## Running locally

```sh
python -m unittest discover -s tests   # tool self-tests
python tools/validate_trace.py         # validate data/
python tools/render_views.py           # regenerate views (--check in CI)
python tools/check_no_secrets.py       # no private keys in the tree
python tools/check_p1_snapshot.py      # data/p1 matches P1 (network)
```
