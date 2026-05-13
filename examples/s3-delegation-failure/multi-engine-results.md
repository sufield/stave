# S3 Delegation Failure — Multi-Engine Analysis

Detection runs through three reasoning layers. CEL evaluates
the YAML controls' predicates and produces findings. The chain
engine composes them. Three external engines then consume the
same fact export (`stave export-sir`) and each contributes a
different reasoning dimension on top.

## Writeup fixture

`fixtures/writeup-config/observations/` — vendor delegation
governance has degraded across all five axes: unknown
principal, scope exceeded, expired review, irrevocable,
public-escalation capability.

| Engine | Verdict | Detail |
|---|---|---|
| **CEL** (built-in) | 5 findings | `CTL.S3.DELEGATION.{KNOWN,SCOPE,LIFECYCLE,REVOCABLE,ESCALATION}.001` |
| **Chain engine** | 1 CRITICAL | `delegated_control_failure` (threshold 3 of 5 met) |
| **Clingo** | 5 violation kinds | enumerates every (bucket, principal, kind) triple — see below |
| **Soufflé** | 4 `excessive_reach` rows, 2 distinct principals | blast-radius count + per-principal reason |
| **Encoding verifier** | 5/5 verifiable facts match | every projected fact traceable to its observation property |

### CEL (the YAML predicate evaluator)

```
CTL.S3.DELEGATION.KNOWN.001        HIGH
CTL.S3.DELEGATION.SCOPE.001        HIGH
CTL.S3.DELEGATION.LIFECYCLE.001    MEDIUM
CTL.S3.DELEGATION.REVOCABLE.001    HIGH
CTL.S3.DELEGATION.ESCALATION.001   CRITICAL
```

### Chain engine

```
delegated_control_failure
  threshold:           3 of 5
  controls_failing:    KNOWN, SCOPE, LIFECYCLE, REVOCABLE, ESCALATION
  compound_severity:   CRITICAL
```

### Clingo (`examples/clingo-constraints/ai-delegation-shadow.lp`)

```
violation: delegation_review_expired  (1)
    arn:aws:s3:::customer-data-lake
violation: delegation_scope_exceeded_for  (1)
    arn:aws:s3:::customer-data-lake  ->  arn:aws:iam::999988887777:role/AcmeDataPipeline
violation: irrevocable_delegation  (1)
    arn:aws:s3:::customer-data-lake
violation: unknown_delegated_principal  (1)
    arn:aws:s3:::customer-data-lake  ->  arn:aws:iam::333322221111:role/UnknownRole
violation: vendor_can_make_public  (1)
    arn:aws:s3:::customer-data-lake
```

Clingo's ASP stable-model semantics enumerates every grounded
violation atom — the right shape for "list every (bucket,
principal, violation kind) triple." For the two per-principal
predicates (`delegation_scope_exceeded_for`,
`unknown_delegated_principal`), the rule names the specific
principal carrying the violation. The three bucket-level
predicates (review_expired, irrevocable_delegation,
vendor_can_make_public) attach to the bucket itself.

### Soufflé (`examples/souffle-reachability/delegation-reach.dl`)

```
delegated_principal_count
    arn:aws:s3:::customer-data-lake    2

excessive_reach_count
    arn:aws:s3:::customer-data-lake    4

excessive_reach
    arn:aws:s3:::customer-data-lake    any_principal     vendor_can_make_public
    arn:aws:s3:::customer-data-lake    any_principal     customer_cannot_revoke
    arn:aws:s3:::customer-data-lake    arn:aws:iam::999988887777:role/AcmeDataPipeline   scope_exceeded
    arn:aws:s3:::customer-data-lake    arn:aws:iam::333322221111:role/UnknownRole        unknown_principal
```

Soufflé's bottom-up evaluation produces counts in one pass.
`delegated_principal_count = 2` says "this bucket has 2 external
principals total." `excessive_reach_count = 4` says "4 of the
4 possible delegation failure modes apply to this bucket." The
ratio (4 reasons / 2 principals) is the per-principal blast
radius — every external principal hits at least one delegation
failure mode.

## Remediated fixture

`fixtures/remediated-config/observations/` — bucket policy
scoped to a registered vendor with current review date,
revocable, no escalation capability.

| Engine | Verdict |
|---|---|
| CEL | 0 findings |
| Chain engine | 0 chains |
| Clingo | (clean) — every rule body returns false |
| Soufflé | 1 `delegated_principal_count` row (AcmeDataPipeline), 0 `excessive_reach` rows |
| Encoding verifier | 5/5 facts match (all values are the safe-side scalars) |

Remediation drives every predicate to its safe value; the
violation rule bodies require unsafe values, so nothing
grounds. Soufflé's `delegated_principal_count` still reports
1 — there IS still a delegated principal, but no excessive
reach attaches to it.

## What each engine adds

- **CEL** is the primary detection: it evaluates the YAML
  controls' predicates against observation properties and
  produces findings.
- **The chain engine** composes findings: it groups by
  `asset.ID` (or `scope_field`) and applies the chain
  threshold; the `delegated_control_failure` chain converts
  three of the five individual findings into a single CRITICAL
  compound output.
- **Clingo** enumerates every grounded violation triple. The
  list "this bucket, this principal, this violation kind"
  is the structure a triage queue consumes — every row is
  one actionable item.
- **Soufflé** counts. `excessive_reach_count` per bucket
  answers "how wide is the per-bucket delegation failure"
  in one number, plus a per-principal breakdown that lets a
  reviewer rank buckets by exposure surface.
- The fact export is the shared substrate; no engine calls
  another, no engine calls Stave back, the boundary is the
  on-disk JSONL.

## Reproduce

```bash
cd <repo-root>/stave
make build

# Fact export
./stave export-sir --format jsonl \
    --observations internal/controldata/testdata/s3/delegation/writeup-config/observations \
    --now 2027-01-01T00:00:00Z > /tmp/delegation.jsonl

# Clingo
.tools-venv/bin/python3 examples/clingo-constraints/run.py \
    "s3-delegation" /tmp/delegation.jsonl \
    examples/clingo-constraints/constraints.lp \
    examples/clingo-constraints/ai-delegation-shadow.lp

# Soufflé
SDIR=$(mktemp -d); ODIR=$(mktemp -d)
bash examples/souffle-reachability/transform.sh /tmp/delegation.jsonl "$SDIR"
souffle -F "$SDIR" -D "$ODIR" examples/souffle-reachability/delegation-reach.dl
cat "$ODIR"/*.csv
```
