# Shadow EC2 Lateral Movement — Multi-Engine Analysis

Detection runs through three reasoning layers. CEL evaluates
the YAML controls' predicates and produces findings. The chain
engine composes them. External engines then consume the same
fact export (`stave export-sir`) for additional reasoning
dimensions.

## Writeup fixture

`fixtures/writeup-config/observations/` — EC2 instance
`i-0shadow123456789` stopped for 180 days
(`stopped_age_exceeds_threshold = true`), instance profile is
overprivileged, and ENIs span the staging + production
subnets (`spans_security_zones = true`).

| Engine | Verdict | Detail |
|---|---|---|
| **CEL** (built-in) | 3 findings | `CTL.EC2.INSTANCE.STOPPED.AGED.001`, `CTL.EC2.PROFILE.OVERBROAD.001`, `CTL.EC2.NETWORK.DUALHOMED.001` |
| **Chain engine** | 2 CRITICAL/HIGH | `shadow_ec2_lateral_movement` (3 of 3, CRITICAL), `ec2_network_pivot` (HIGH, shares `DUALHOMED`) |
| **Clingo** | 1 violation kind | `shadow_ec2_pivot` — three-axis structural compound |
| **Soufflé** | n/a | no `shadow-ec2-reach.dl` authored yet — three predicates all target the same EC2 asset, no per-element array facts to enumerate |
| **Encoding verifier** | 2/2 verifiable facts match | every projected fact traceable to its observation property |

### CEL (the YAML predicate evaluator)

```
CTL.EC2.INSTANCE.STOPPED.AGED.001   HIGH
CTL.EC2.PROFILE.OVERBROAD.001       HIGH
CTL.EC2.NETWORK.DUALHOMED.001       HIGH
```

All three predicates target `kind == instance`, so chain
grouping by default `asset.ID` joins them naturally — no
`scope_field` needed (cleaner than the VPC peering case).

### Chain engine

```
shadow_ec2_lateral_movement
  threshold:           3 of 3
  controls_failing:    STOPPED.AGED, PROFILE.OVERBROAD, NETWORK.DUALHOMED
  compound_severity:   CRITICAL

ec2_network_pivot
  threshold:           1
  controls_failing:    NETWORK.DUALHOMED
  compound_severity:   HIGH
```

`ec2_network_pivot` is a legitimate co-finding — it shares the
`DUALHOMED` member with the new chain. Both narratives are
true: the network position bridges two zones (existing chain),
AND the lifecycle/profile axes make the instance a pivot (new
chain). Different stories, both valid.

### Clingo (`examples/clingo-constraints/ai-delegation-shadow.lp`)

```
violation: shadow_ec2_pivot  (1)
    arn:aws:ec2:us-east-1:111122223333:instance/i-0shadow123456789
```

The rule body joins the three structural axes:

```
violation(I, "shadow_ec2_pivot") :-
    has_instance_stopped_aged(I, "true"),
    has_instance_profile_overprivileged(I, "true"),
    has_instance_dual_homed(I, "true").
```

One row per instance that satisfies all three conditions —
Clingo's atom-enumeration here is conservative because there's
only one offending instance in the fixture. On a real account
with thousands of EC2 instances, the same rule grounds one
atom per shadow pivot.

### Soufflé

No `shadow-ec2-reach.dl` exists. The shadow-EC2 domain ships
scalar booleans only — `stopped_age_exceeds_threshold`,
`is_overprivileged`, `spans_security_zones`. Without
per-element arrays (like the role's `unused_services[]` or the
bucket's `external_principals[]`), there's nothing for
Soufflé to count or join transitively. A reachability program
would need a per-(instance, subnet) or per-(role, permission)
projection that the current allowlist doesn't emit.

## Remediated fixture

`fixtures/remediated-config/observations/` — instance
restarted into a dedicated staging VPC
(`spans_security_zones=false`), role scoped
(`is_overprivileged=false`), no longer stopped aged
(`state=running`, `stopped_age_exceeds_threshold=false`).

| Engine | Verdict |
|---|---|
| CEL | 0 findings |
| Chain engine | 0 chains (both `shadow_ec2_lateral_movement` and `ec2_network_pivot` silent) |
| Clingo | (clean) — every rule body returns false |
| Encoding verifier | 2/2 facts match |

## What each engine adds

- **CEL** is the primary detection: per-axis predicate
  evaluation produces one finding per structural defect.
- **The chain engine** composes the three axes onto the same
  EC2 asset; with `threshold = 3 of 3`, every member must
  fire for the compound to ground.
- **Clingo** restates the same join in ASP form. The single
  Clingo row (`shadow_ec2_pivot`) confirms the chain's
  three-way conjunction independently — if a regression in
  the chain wiring caused it to misfire, the Clingo row
  would still surface the structural compound.

## Reproduce

```bash
cd <repo-root>/stave
make build

./stave export-sir --format jsonl \
    --observations examples/shadow-ec2-lateral-movement/fixtures/writeup-config/observations \
    --now 2027-01-01T00:00:00Z > /tmp/shadow-ec2.jsonl

.tools-venv/bin/python3 examples/clingo-constraints/run.py \
    "shadow-ec2" /tmp/shadow-ec2.jsonl \
    examples/clingo-constraints/constraints.lp \
    examples/clingo-constraints/ai-delegation-shadow.lp
```
