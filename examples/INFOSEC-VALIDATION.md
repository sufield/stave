# InfoSec Writeup Fixtures — Multi-Engine Validation Status

A follow-up to the H1 fixture × engine matrix validation
(commit `611d1f162`). Confirms the InfoSec writeup iterations
are already covered and identifies the residual gap.

## Summary

**All 20 InfoSec writeup iterations have on-disk fixtures, and
all 49 fixture pairs are already in the H1 matrix at
[`scripts/h1-matrix/matrix.json`](../scripts/h1-matrix/matrix.json).**
There is no separate "InfoSec" set to validate — the H1 matrix
runs the same 20 example directories.

The actual coverage gap is **paired SMT queries**: only 4 of 20
example directories have a sibling `examples/z3-*/query.smt2`
that the SMT solvers can consume. The remaining 16 example
directories are evaluated by every engine that consumes JSONL
(Soufflé, Clingo, Prolog, PySAT, Risk, TLA+, Game theory) but
the SMT pipeline (Z3 / cvc5 / Yices) is `n/a` because no
`query.smt2` is paired with them.

## InfoSec writeup iterations — on-disk state

Mapped from the InfoSec writeup work tracked in the project
task list (Iter 11 – Iter 16, Ext A, Ext B, Iter-15 ext) to the
present-day example directory.

| Iteration | Example dir | Article | Fixture pairs | In H1 matrix | Paired SMT query |
|---|---|---|---|---|---|
| Iter 11: cross-account replication overperm | `s3-cross-account-replication-overperm/` | `channels/devto/s3-cross-account-replication-overperm.md` | 2 | ✅ | ❌ |
| Iter 12: APIGW private API scoped deny | `apigw-private-api-scoped-deny/` | `channels/devto/apigw-private-api-scoped-deny.md` | 3 | ✅ | ❌ |
| Iter 13: autoscaling privesc bypass | `iam-autoscaling-privesc-bypass/` | `channels/devto/iam-autoscaling-privesc-bypass.md` | 2 | ✅ | ❌ |
| Iter 14: SNS secrets compound chain | `sns-secrets-compound-chain/` | `channels/devto/sns-secrets-compound-chain.md` | 2 | ✅ | ❌ |
| Iter 15: Rhino 21 / 5 patterns | `iam-21-privesc-5-patterns/` | (Rhino-21 article) | 4 | ✅ | ✅ (5 queries via `z3-rhino-pattern1..5/`) |
| Iter 15 ext: real-world-pattern3 | `iam-21-privesc-5-patterns/fixtures/real-world-pattern3` | (Rhino-21 article extension) | 1 | ✅ | ✅ (uses Rhino queries) |
| Iter 16: Cognito self-register-to-aws-creds | `cognito-self-register-to-aws-creds/` | `channels/devto/cognito-self-register-to-aws-creds.md` | 2 | ✅ | ✅ (3 queries via `z3-cognito-*/`) |
| Ext A: Bybit pattern | `iam-overpermission-wildcard/fixtures/bybit-pattern-*` | (article extension) | 2 | ✅ | ✅ (via `z3-bybit-tag-aware-compound/`) |
| Ext B: data-events fixtures | `cloudtrail-stop-logging/fixtures/data-events-*` | (article extension) | 2 | ✅ | ❌ |

Plus the H1-shared examples that also originated from InfoSec
work (Cognito MFA / Advanced Security, IAM overpermission,
multi-hop trust, EKS, S3 patterns, staging endpoint, IAM
self-attach) — all 20 directories are listed in
[`CATALOG.md`](CATALOG.md).

## The actual gap — paired SMT queries

Engines that consume JSONL run on every fixture
(Soufflé / Clingo / Prolog / PySAT / Risk / TLA+ / Game theory).
Their per-fixture verdicts live in each scenario's
`multi-engine-results.md`.

Engines that consume SMT-LIB (Z3, cvc5, Yices) need a paired
`query.smt2`. The matrix shows:

**Have paired SMT query** (4 of 20):
- `cognito-self-register-to-aws-creds` — three queries
  (`z3-cognito-unauth-chain/query.smt2`,
  `z3-cognito-auth-chain/query-auth-chain.smt2`,
  `z3-cognito-auth-chain/query-self-register-chain.smt2`)
- `iam-21-privesc-5-patterns` — five queries (Rhino patterns 1–5)
- `iam-multi-hop-trust` — one query (`z3-multi-hop-can-assume/`)
- `iam-overpermission-wildcard` — three queries
  (`z3-overpermission-fixture/`, `z3-bybit-tag-aware-compound/`,
  `z3-compound-overperm-assumable/`)

**Lack paired SMT query** (16 of 20):
- `apigw-private-api-scoped-deny`
- `cloudtrail-stop-logging`
- `cognito-no-mfa-advanced-security`
- `eks-aws-auth-template-injection`
- `eks-rbac-webhook-config-access`
- `iam-attach-user-policy-self`
- `iam-autoscaling-privesc-bypass`
- `s3-broad-write-scope`
- `s3-bucket-name-dangling`
- `s3-cross-account-replication-overperm`
- `s3-dotgit-readable`
- `s3-public-list-policy`
- `s3-public-read-policy`
- `s3-tenant-prefix-isolation`
- `sns-secrets-compound-chain`
- `staging-stale-endpoint`

For these 16, every per-fixture `multi-engine-results.md` shows
`SMT (Z3 / cvc5 / Yices) — —` (no paired query). Authoring a
`query.smt2` for each is the natural follow-up — each query is
a 20–30-line composition asking "does the unsafe state
described by this scenario's controls compose into a satisfying
model under the closed-world axioms?"

Several of these example directories have a sibling `z3prove/`
**Go program** (cgo + libz3) that runs the SMT proof through
the library API rather than the file boundary. That is the
older integration shape; the file-boundary path (a
`query.smt2`) is what would unblock cvc5 / Yices verdicts and
match the architecture described in
[files-as-the-boundary](https://www.systeminvariant.dev/docs/explanation/files-as-the-boundary).

## Spec-only InfoSec iterations (none found)

The user's spec anticipated some InfoSec iterations producing
specification documents *without* on-disk fixtures. Searching
the channels and project task list confirms **all
InfoSec writeup iterations have produced on-disk fixtures**.
There is no Phase D "missing-fixture" section to write.

## What this means for early adopters

The H1 matrix run is the InfoSec multi-engine result. Pick a
scenario from
[`CATALOG.md`](CATALOG.md), open its
`multi-engine-results.md`, and read the per-engine verdicts.
The **InfoSec lineage** of each scenario is recorded here in
the table above and in
[`channels/devto/<scenario>.md`](../../channels/devto/) for the
articles that originated each one.

The 16-fixture SMT-query gap is the highest-value follow-up —
adding a `query.smt2` to each example dir would let Z3 / cvc5 /
Yices speak about every scenario, multiplying the
multi-engine-result density without authoring any new fixtures.

## Verification

Per the spec:

```
$ git diff --stat HEAD~1 stave/internal stave/pkg stave/cmd
(empty — no Stave source changes)

$ git diff --stat HEAD~1 stave/examples/clingo-constraints \
                          stave/examples/souffle-reachability \
                          stave/examples/prolog-proof-trees \
                          stave/examples/sat-control-regression \
                          stave/examples/prism-risk-prioritization \
                          stave/examples/tlaplus-temporal-safety \
                          stave/examples/game-theory-cost
(empty — no engine-example changes)
```

This addendum is documentation only. The validation work
itself was completed in the H1 matrix run at commit
`611d1f162`.
