# S3 Vendor Delegation Failure

Your bucket has an owner. The vendor has control. The vendor can
rewrite your bucket policy. You can't revoke it. The review is
344 days overdue.

Fixture-level demo of the new
`chains/delegated_control_failure.yaml` compound chain (5
members, threshold=3, severity=critical). The catalog already
carries the five `CTL.S3.DELEGATION.*` controls; this example
contributes the chain definition, writeup / remediated
observations, the runner, and the interpretation.

## What it shows

| Member | Property checked |
|---|---|
| `CTL.S3.DELEGATION.KNOWN.001` | `delegation.has_unknown_external_principal` |
| `CTL.S3.DELEGATION.SCOPE.001` | `delegation.has_scope_exceeded` |
| `CTL.S3.DELEGATION.LIFECYCLE.001` | `delegation.has_expired_review` |
| `CTL.S3.DELEGATION.REVOCABLE.001` | `delegation.customer_can_revoke == false` |
| `CTL.S3.DELEGATION.ESCALATION.001` | `delegation.vendor_can_make_public` |

All five predicates require `kind == bucket`, so the chain fires
via default `asset.ID` grouping — no `scope_field` needed.

Threshold 3 of 5 distinguishes systemic governance breakdown
from a single overdue review. A bucket with only
`LIFECYCLE.001` firing (1 of 5) is a reminder; a bucket with 3
or more firing is a compound finding.

## Run

```bash
cd <repo-root>/stave
make build
bash examples/s3-delegation-failure/run.sh
```

## The distinction

- **Orphan bucket** — no owner. Bucket forgotten.
- **Delegation failure** — owner exists; control transferred to
  a weaker party without safety continuity. Ownership exists,
  assurance does not.

Scanners report "cross-account access detected." Stave's
compound output reads: "this vendor can rewrite your bucket
policy, you cannot revoke it, the review is 344 days overdue,
and an unknown account has the same access."

## Relationship to vendor_attack_path

[`chains/vendor_attack_path.yaml`](../../chains/vendor_attack_path.yaml)
checks whether a vendor CAN reach the bucket via confused-deputy
(IAM trust policy + S3 access). This chain checks whether the
delegation governance itself is intact (vendor registry,
declared scope, review cadence, revocability, escalation
ceiling). Both may fire on the same bucket — they describe
different parts of the supply-chain failure mode.

## Inputs

- `fixtures/writeup-config/observations/` — bucket with
  5/5 delegation defects ⇒ all 5 controls fire, chain fires
  (CRITICAL).
- `fixtures/remediated-config/observations/` — same bucket
  with vendor scoped, unknown principal removed, review
  refreshed, customer-revocable, vendor cannot escalate ⇒
  0 findings, 0 chains.

The vendor registry the collector consults to compute these
booleans lives at
[`internal/controldata/taxonomy/vendor_registry.yaml`](../../internal/controldata/taxonomy/vendor_registry.yaml).
