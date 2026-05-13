# Shadow Admin Detection — Multi-Engine Analysis

Detection runs through three reasoning layers. CEL evaluates
the YAML controls' predicates and produces findings. The chain
engine composes them. Three external engines then consume the
same fact export (`stave export-sir`) and each contributes a
different reasoning dimension on top.

## Writeup fixture

`fixtures/writeup-config/observations/` — IAM role
`S3-ReadOnly` declared `role-type=readonly` but accumulated
8 unused services + the `data_read+secrets_access`
incompatible pair + `secrets_access` and `compute_control`
forbidden categories.

| Engine | Verdict | Detail |
|---|---|---|
| **CEL** (built-in) | 3 findings | `CTL.IAM.ROLE.{PERMISSIONDRIFT,CATEGORYMIX,INTENTMISMATCH}.001` |
| **Chain engine** | 2 CRITICAL | `shadow_admin_by_accumulation`, `privilege_creep_lateral_movement` |
| **Clingo** | 4 violation kinds + 8 latent risks | per-category and per-service enumeration — see below |
| **Soufflé** | 4 derived relations | blast radius + combined shadow risk + forbidden-category count + per-category enumeration |
| **Encoding verifier** | 3/3 verifiable facts match | every projected fact traceable to its observation property |

### CEL (the YAML predicate evaluator)

```
CTL.IAM.ROLE.PERMISSIONDRIFT.001   HIGH
CTL.IAM.ROLE.CATEGORYMIX.001       CRITICAL
CTL.IAM.ROLE.INTENTMISMATCH.001    HIGH
```

### Chain engine

```
shadow_admin_by_accumulation
  threshold:           2 of 3
  controls_failing:    PERMISSIONDRIFT, CATEGORYMIX, INTENTMISMATCH
  compound_severity:   CRITICAL

privilege_creep_lateral_movement
  threshold:           2 of 2
  controls_failing:    CATEGORYMIX, PERMISSIONDRIFT
  compound_severity:   CRITICAL
```

### Clingo (`examples/clingo-constraints/ai-delegation-shadow.lp`)

```
violation: forbidden_category  (2)
    arn:aws:iam::111122223333:role/S3-ReadOnly  ->  compute_control
    arn:aws:iam::111122223333:role/S3-ReadOnly  ->  secrets_access
violation: incompatible_pair  (1)
    arn:aws:iam::111122223333:role/S3-ReadOnly  ->  data_read+secrets_access
violation: intent_mismatch  (1)
    arn:aws:iam::111122223333:role/S3-ReadOnly
violation: shadow_admin_signal  (1)
    arn:aws:iam::111122223333:role/S3-ReadOnly
latent_risk  (8)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: cloudtrail)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: ec2)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: ecs)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: eks)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: iam)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: kms)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: lambda)
    arn:aws:iam::111122223333:role/S3-ReadOnly  (unused_service: secretsmanager)
```

Clingo's ASP grounding names every specific forbidden category
and every specific unused service. The triage queue is the
literal `latent_risk(role, "unused_service: <svc>")` list —
each row is one actionable item.

### Soufflé (`examples/souffle-reachability/shadow-admin-reach.dl`)

```
unused_blast_radius
    arn:aws:iam::111122223333:role/S3-ReadOnly    8

forbidden_category_count
    arn:aws:iam::111122223333:role/S3-ReadOnly    2

combined_shadow_risk
    arn:aws:iam::111122223333:role/S3-ReadOnly    readonly    8    data_read+secrets_access

shadow_admin_finding
    arn:aws:iam::111122223333:role/S3-ReadOnly    readonly    secrets_access
    arn:aws:iam::111122223333:role/S3-ReadOnly    readonly    compute_control
```

Soufflé's bottom-up evaluation produces the **blast radius
count** in one number (`unused_blast_radius = 8`) — the
question Clingo can't answer in a single query.
`combined_shadow_risk` is the join Stave's chain engine and
Clingo can't compute together: declared role-type + drift
count + the specific incompatible pair, in one row.

## Remediated fixture

`fixtures/remediated-config/observations/` — same role,
permissions scoped, drift cleared, intent aligned.

| Engine | Verdict |
|---|---|
| CEL | 0 findings |
| Chain engine | 0 chains |
| Clingo | (clean) — every rule body returns false |
| Soufflé | 0 rows in all output relations |
| Encoding verifier | 3/3 facts match |

## What each engine adds

- **CEL** is the primary detection: it evaluates each entropy
  control against the pre-computed boolean predicates.
- **The chain engine** composes findings into the
  `shadow_admin_by_accumulation` (3-of-3) and
  `privilege_creep_lateral_movement` (2-of-2) compounds.
- **Clingo** enumerates every forbidden category and every
  unused service as a separate triple. The triage report is
  the literal list of rows.
- **Soufflé** counts. `unused_blast_radius = 8` is the
  single-number answer to "how big is this role's drifted
  surface" — the Clingo enumeration produces the 8 names;
  the Soufflé count produces the magnitude.

## Reproduce

```bash
cd <repo-root>/stave
make build

./stave export-sir --format jsonl \
    --observations internal/controldata/testdata/iam/role/shadow-admin/observations \
    --now 2027-01-01T00:00:00Z > /tmp/shadow.jsonl

.tools-venv/bin/python3 examples/clingo-constraints/run.py \
    "shadow-admin" /tmp/shadow.jsonl \
    examples/clingo-constraints/constraints.lp \
    examples/clingo-constraints/ai-delegation-shadow.lp

SDIR=$(mktemp -d); ODIR=$(mktemp -d)
bash examples/souffle-reachability/transform.sh /tmp/shadow.jsonl "$SDIR"
souffle -F "$SDIR" -D "$ODIR" examples/souffle-reachability/shadow-admin-reach.dl
cat "$ODIR"/*.csv
```
