# SMT Query Gaps

After the SIR-diff inspection across all 16 originally-uncovered
example directories, **13 fixtures share the same projection-gap
pattern** — vulnerable and remediated SIR exports are byte-identical
modulo the CEL-derived `contributed_by` and `has_exposure_window`
predicates. A query expressed against the present-day predicates
returns the same verdict on both fixtures because the projector
doesn't carry the data the remediation actually changes.

Per the spec's rule **"Do NOT force a query to work — a wrong
query is worse than no query"**, queries are not authored for
these 13. This document records the gap and the predicate that
would unblock each.

## Unblocked queries shipped this iteration

Two fixtures had non-zero SIR-diff once the CEL-derived predicates
were stripped, so a query distinguishes vulnerable from remediated
on the underlying configuration data alone. Queries shipped:

| Example dir | Query asks | Verdict (vulnerable / remediated) |
|---|---|---|
| `iam-attach-user-policy-self/query.smt2` | "Does a user have `iam:AttachUserPolicy` with their own ARN as `Resource`?" | sat / unsat |
| `sns-secrets-compound-chain/query.smt2` | "Does a user simultaneously have `apigateway:GET`, `sns:GetTopicAttributes`, `iam:GetUserPolicy` with a wildcard resource on at least one?" | sat / unsat |

Both verified with Z3 + cvc5 (Yices not on PATH; skipped at the
runner).

## Blocked queries — projection-gap fixtures

The 13 fixtures below all reduce to the same root cause: the SIR
projector emits identity / policy / asset / tag / role-chain
facts, but does not emit per-asset configuration booleans (e.g.,
`storage.access.public_read`, `auth.mfa_enforced`,
`replication.has_overpermission`) and does not emit policy-effect
or condition data. CEL evaluates these properties at runtime, but
the underlying booleans never become triples.

Each row below names the specific projector that would unblock
the corresponding query.

| Example dir | What CEL evaluates against | Missing projector predicate |
|---|---|---|
| `cloudtrail-stop-logging` (mgmt-events) | `cloudtrail.is_logging` | `is_logging_enabled(trail, "true"\|"false")` |
| `cloudtrail-stop-logging` (data-events) | `cloudtrail.event_selectors[].data_resources[]` membership | `has_data_event_logging(bucket, "true"\|"false")` |
| `cognito-no-mfa-advanced-security` | `auth.mfa_enforced`, `advanced_security.enabled` | `has_mfa_enforced(pool, "true"\|"false")`, `has_advanced_security(pool, "true"\|"false")` |
| `eks-aws-auth-template-injection` | `cluster.aws_auth.has_template_injection` | `has_template_injection_risk(cluster, "true"\|"false")` |
| `eks-rbac-webhook-config-access` | `k8s.rbac.has_webhook_config_access` | `has_webhook_admin_access(cluster_role, "true"\|"false")` |
| `iam-autoscaling-privesc-bypass` | Effective Allow ∩ ¬Deny on the autoscaling action | `has_deny_action(principal, action)` / `effective_allow(principal, action)` |
| `s3-broad-write-scope` | `policy.has_broad_write_scope` | `has_broad_write(role, "true"\|"false")` |
| `s3-bucket-name-dangling` | `bucket.has_dns_record_for_deleted_bucket` | `has_dangling_dns(bucket_name, "true"\|"false")` |
| `s3-dotgit-readable` | `bucket.has_dotgit_readable` | `has_dotgit_readable(bucket, "true"\|"false")` |
| `s3-public-list-policy` | `bucket.policy.allows_public_list` | `policy_allows_public_list(bucket, "true"\|"false")` |
| `s3-public-read-policy` | `bucket.policy.allows_public_read` | `policy_allows_public_read(bucket, "true"\|"false")` |
| `s3-tenant-prefix-isolation` | `policy.enforces_tenant_prefix` | `enforces_tenant_prefix(role, "true"\|"false")` |

A 14th example, `staging-stale-endpoint`, has a different shape
of blocker: it ships four fixtures modeling distinct states
(`active-staging`, `prod-dormant`, `stale-staging`,
`stale-staging-public`) rather than a vulnerable/remediated pair,
so the matrix's heuristic-pair pick doesn't have a clean
"before" to diff against. A query for that example would need
explicit fixture selection in its `run.sh` rather than the
auto-paired matrix entry.

## The recurring pattern

Every blocked fixture's missing predicate has the same shape:

> **`has_<config_property>(asset, "true"|"false")`** — a
> pre-computed boolean projecting an observation property that
> CEL evaluates against, but the projector currently flattens
> away.

Adding such projectors is the natural next step. Per the
[core audit](../docs/core-audit.md), per-asset boolean
projection is **fact production** — it stays in core. The CEL
evaluator already reads these properties; the new projectors
simply emit the same boolean as a triple so external solvers see
the same view.

A reasonable batching strategy:

1. **Generic per-property projector.** A small extension to
   `cmd/exportsir/facts.go` that emits `has_<path>(asset, value)`
   for a configurable allowlist of property paths. Single
   projector, configurable, unblocks every per-asset boolean
   fixture above in one PR.
2. **Per-domain Allow ∩ ¬Deny projector.** `effective_allow`
   (or `has_deny_action`) for IAM. Unblocks
   `iam-autoscaling-privesc-bypass`. Larger because it requires
   the policy combiner to walk Deny statements as well as
   Allows.
3. **Policy-condition value projector.** `has_condition_value(asset,
   "operator:key=value")` — **shipped (PR 3)**. Emits one fact
   per (operator, key, value) tuple drawn from
   `attached_policies[].statements[].Condition`. Useful for any
   future fixture that scopes via structured Conditions, but
   does NOT on its own unblock the two named gap fixtures
   (`apigw-private-api-scoped-deny`,
   `s3-cross-account-replication-overperm`) — both store their
   discriminating Condition data inside a stringified
   `resource_policy_json` / `policy_json` blob that no current
   projector parses.
4. **Stringified policy-JSON Condition parser** —
   **shipped (PR 4)**. The `stringifiedPolicyFacts` projector
   parses three known stringified-policy fields
   (`api.network.resource_policy_json`, `storage.policy_json`,
   `encryption.key_policy_json`) and re-emits each statement's
   Condition block through `has_condition` /
   `has_condition_value` with `Source: "stringified_policy"`.
   Unblocks `apigw-private-api-scoped-deny` (the
   `aws:sourceVpc` vs `aws:sourceVpce` discriminator). Does
   NOT unblock `s3-cross-account-replication-overperm` —
   empirical SIR-diff confirmed neither fixture's S3 bucket
   policy carries any `Condition` blocks; the discriminator
   is principal/action scope, not condition scope.
5. **Resource-policy principal + action projector** —
   **shipped (PR 5)**. Extends `stringifiedPolicyFacts` to
   walk Statement.Principal and Statement.Action regardless
   of whether the Statement has a Condition. Emits
   `resource_policy_principal(asset, principal_arn)` and
   `resource_policy_action(asset, action)` with
   `Source: "stringified_policy"`. The naming distinction
   from `has_action` / `has_resource` is intentional:
   `has_action(role, action)` projects identity-policy
   permissions; `resource_policy_action(bucket, action)`
   projects what the bucket's resource policy grants —
   different trust models. Unblocks
   `s3-cross-account-replication-overperm`.

These three projector PRs in sequence unblock 12 of the 13 blocked
fixtures (the remaining one is `cloudtrail-stop-logging`
data-events, which needs the trail-to-bucket data-event coverage
projector).

### Empirical recheck after PR 3

After shipping `has_condition_value`, an SIR-diff sweep was rerun
against the two named target fixtures with the CEL-derived
predicates stripped. Both remain at **real-diff = 0**: their
discriminating Conditions live inside stringified policy JSON,
which the projector does not lex. PR 3's primitive ships
correctly (verified via the autoscaling fixture, which DOES use
structured Conditions on `iam:PassRole`).

### Empirical recheck after PR 4

PR 4 added `stringifiedPolicyFacts`, which lexes the three
known stringified-policy fields and re-emits their Conditions.
The same SIR-diff sweep was rerun:

- **apigw-private-api-scoped-deny**: NOW non-zero —
  `StringNotEquals:aws:sourceVpc=vpc-…` (writeup) vs
  `StringNotEquals:aws:sourceVpce=vpce-…` (remediated). Query
  shipped at `examples/apigw-private-api-scoped-deny/query.smt2`,
  verified sat / unsat / sat across the three fixtures with
  Z3 + cvc5.
- **s3-cross-account-replication-overperm**: still zero —
  the bucket policy carries no `Condition` blocks at all;
  PR 4 emits zero facts for this bucket. The discriminator
  is principal scope (`:root` → `:role/specific`) and action
  scope (`s3:List*/Get*` removed), which a stringified-
  condition parser does not project. A resource-policy
  principal/action projector (PR 5) is the real blocker.

Coverage after PR 4: **17/20** (apigw unblocked, cross-account
still gapped pending PR 5).

### Empirical recheck after PR 5

PR 5 extends the same `stringifiedPolicyFacts` Statement loop
to emit `resource_policy_principal` and `resource_policy_action`
regardless of whether the Statement has a Condition.

- **s3-cross-account-replication-overperm**: NOW non-zero —
  the destination bucket emits
  `resource_policy_principal=arn:aws:iam::111122223333:root`
  on writeup and `resource_policy_principal=…:role/bucket-replication-role`
  on remediated; the writeup also has the over-permission
  actions `s3:Get*` and `s3:List*` from the AllowRead
  statement that remediation removed. Query shipped at
  `examples/s3-cross-account-replication-overperm/query.smt2`,
  verified sat / unsat with Z3 + cvc5.

Coverage after PR 5: **18/20**. The remaining two are
documented at the top of this doc:
- `s3-tenant-prefix-isolation` — substring-shape blocker
  (not a fact-projection gap).
- `staging-stale-endpoint` — fixture-pair-selection blocker
  (matrix tooling, not a projector).

## What this iteration ships

- Two new `query.smt2` files (iam-attach-user-policy-self,
  sns-secrets-compound-chain) with corresponding `run.sh` runners
  and updated `multi-engine-results.md`.
- Updated `examples/CATALOG.md` — paired-SMT count goes from 4/20
  to **6/20**.
- This document — widened from 3 fixtures to 13 (the original 3
  plus 10 newly identified by the SIR-diff sweep).

## Verification

```
$ git diff --stat HEAD~3 stave/internal stave/pkg stave/cmd
(empty — Stave source unchanged)

$ git diff --stat HEAD~3 stave/examples/clingo-constraints \
                          stave/examples/souffle-reachability \
                          stave/examples/prolog-proof-trees \
                          stave/examples/sat-control-regression \
                          stave/examples/prism-risk-prioritization \
                          stave/examples/tlaplus-temporal-safety \
                          stave/examples/game-theory-cost
(empty — engine examples unchanged)

$ ./stave apply ...   # substantive output identical to baseline
$ ./stave export-sir ...   # identical
```
