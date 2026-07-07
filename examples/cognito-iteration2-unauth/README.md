# Cognito Iteration 2 — Identity Pool Unauthenticated Access

End-to-end fixtures for the 7 unauth identity-pool controls plus
the two compound chains. Demonstrates the marketing-grade
finding (`cognito_unauth_s3public`: anonymous AWS credentials
with broad S3 access) firing automatically on a realistic
observation.

```
7 individual controls   (writeup → all fire ; remediated → none fire)
2 compound chains       (cognito_unauth_s3public, cognito_unauth_escalation)
```

## Controls covered

All 7 predicates evaluate on a single `cognito_identity_pool`
asset — the per-asset state is rich enough that no
`scope_field` is needed for the compound chains.

| Control | Predicate signal |
|---|---|
| `CTL.COGNITO.IDENTITY.GUEST.001`        | `access.allow_unauthenticated == true` |
| `CTL.COGNITO.IDPOOL.UNAUTH.BROAD.001`   | `cognito.unauth_role_broad == true` |
| `CTL.COGNITO.IDPOOL.UNAUTH.IAM.001`     | `cognito.unauth_role_has_iam == true` |
| `CTL.COGNITO.IDPOOL.UNAUTH.S3.001`      | `cognito.unauth_role_has_s3 == true` |
| `CTL.COGNITO.IDPOOL.UNAUTH.DDB.001`     | `cognito.unauth_role_has_ddb == true` |
| `CTL.COGNITO.IDPOOL.UNAUTH.LAMBDA.001`  | `cognito.unauth_role_has_lambda == true` |
| `CTL.COGNITO.IDPOOL.UNAUTH.UNUSED.001`  | `cognito.is_unauth_unused == true` |

## Compound chains

| Chain | Members | Threshold | Fires? |
|---|---|---|---|
| `cognito_unauth_s3public`  | IDENTITY.GUEST, UNAUTH.BROAD, UNAUTH.S3 | 2 | **YES** — all 3 fire on the writeup identity pool |
| `cognito_unauth_escalation` | IDENTITY.GUEST, UNAUTH.IAM, UNAUTH.LAMBDA | 2 | **YES** — same |

Both chain definitions reference controls that all match on the
same asset, so legacy `asset.ID` grouping suffices.
`scope_field` is unused here.

## Run

```bash
cd <repo-root>/stave
make build

./stave apply \
    --observations examples/cognito-iteration2-unauth/fixtures/writeup-config/observations \
    --eval-time 2026-05-09T12:00:00Z --format json \
  | jq '{controls: ([.findings[] | select(.control_id | test("CTL.COGNITO.(IDENTITY.GUEST|IDPOOL.UNAUTH)"))] | map(.control_id) | sort), chains: (.chain_findings // [] | map(.chain) | sort)}'

./stave apply \
    --observations examples/cognito-iteration2-unauth/fixtures/remediated-config/observations \
    --eval-time 2026-05-09T12:00:00Z --format json \
  | jq '{count: ([.findings[] | select(.control_id | test("CTL.COGNITO.(IDENTITY.GUEST|IDPOOL.UNAUTH)"))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup    → 7 controls, 2 chains
remediated → 0, 0
```

## Architecture gap: cross-resource joins

The Iteration 2 plan called for a compound:

> **UNAUTH.S3PUBLIC** — Unauthenticated enabled AND unauth role
> has `s3:GetObject` on bucket AND bucket has no resource policy
> deny → publicly accessible data via Cognito

The shipped catalog implements a coarser version: `UNAUTH.S3`
fires when the unauth role has *any* S3 action on *any*
resource. The compound chain links it to `IDENTITY.GUEST` and
`UNAUTH.BROAD` — all three findings on a single identity-pool
asset. That works because the collector pre-computes the
boolean: `unauth_role_has_s3 = (role policy contains any s3:*
action)`.

The plan's stronger framing — "role has `s3:GetObject` on a
bucket tagged `data_classification=phi`" — requires a
cross-resource join. The `fixtures/cross-resource-config/`
snapshot includes both halves of that join:

```
identity pool   →  cognito.unauth_role_grants_actions_on_buckets:
                     [ "arn:aws:s3:::acme-phi-records",
                       "arn:aws:s3:::acme-public-marketing" ]
s3 bucket       →  storage.tags.data-classification: "phi"
```

Run `stave apply` on it — **the PHI-specific compound now
fires** as `cognito_unauth_phi_s3`, since marker controls
shipped (see "Marker controls" below). UNAUTH.BROAD / UNAUTH.S3
/ IDENTITY.GUEST fire on the identity pool; `CTL.S3.MARKER.PHI.001`
fires on the bucket as a non-violation marker; the chain links
them by `target_bucket_arn` ↔ bucket ARN.

### Marker controls (now shipped)

Stave's CEL evaluator is per-asset: a predicate reads from
exactly one asset's `Properties` map. A predicate of the shape
"role X grants `s3:GetObject` on resource Y AND Y is tagged
phi" spans two assets and cannot be written in one control YAML
— that's two assets in one decision. The catalog has historically
relied on **collector denormalisation**: the collector pre-computes
the cross-resource boolean (e.g. `unauth_role_has_s3`) and
stamps it on the consuming asset. Each new compound shape
needed a collector change.

Marker controls (`type: marker`) lift that constraint inside
the engine. A marker emits a finding the same way an
`unsafe_state` control does, but the finding is classified as
informational rather than a violation:

| | Violation finding | Marker finding |
|---|---|---|
| Counts toward `Summary.Violations` | yes | no |
| Flips `SecurityState` to NON_COMPLIANT | yes | no |
| Triggers exit code 3 | yes | no |
| Surfaces in `findings` JSON field | yes | no |
| Surfaces in `marker_findings` JSON field | no | yes |
| Composable as a chain member | yes | yes |
| Routes through SLA / acknowledgment / exception pipelines | yes | no |

A chain that lists a marker control as a member treats it as a
contributing co-failure when the marker fires on a co-scoped
asset. The PHI compound lives in `chains/cognito_unauth_phi_s3.yaml`:

```yaml
controls:
  - CTL.COGNITO.IDPOOL.UNAUTH.S3.001        # violation, fires on identity_pool
  - CTL.S3.MARKER.PHI.001                   # marker, fires on s3 bucket
escalation_threshold: 2
scope_field: properties.identity.cognito.target_bucket_arn
```

The Cognito side stamps `cognito.target_bucket_arn` on the
identity-pool asset (the bucket the unauth role can reach). The
S3 side has no `target_bucket_arn` property — the resolver
falls back to the bucket's own asset.ID, which IS the bucket
ARN. Both sides bucket together; the chain fires.

Run the cross-resource fixture to see it end-to-end:

```bash
./stave apply \
    --observations examples/cognito-iteration2-unauth/fixtures/cross-resource-config/observations \
    --eval-time 2026-05-09T12:00:00Z --format json \
  | jq '{violations: [.findings[] | select(.control_id | startswith("CTL.COGNITO."))] | map(.control_id) | sort | unique, markers: (.marker_findings // [] | map(.control_id)), chains: (.chain_findings // [] | map(.chain) | sort)}'
```

Expected:

```
violations: 3 cognito findings
markers:    ["CTL.S3.MARKER.PHI.001"]
chains:     ["cognito_unauth_phi_s3", "cognito_unauth_s3public"]
```

### Why marker controls matter beyond Cognito

The same gap blocks declarative cross-resource compounds the
plan describes for other iterations:

- **CloudTrail mgmt-event monitoring vs. specific KMS-key
  events** — control reads "any mgmt events not logged" today;
  fine-grained "key X events not logged" needs cross-resource.
- **IAM role can `sts:AssumeRole` a target whose policy
  contains admin actions** — already partially solved via the
  IAM role-chain projector + has_action predicate, but joining
  to "target carries data-classification=tier-0" needs the same
  marker-control machinery.
- **VPC endpoint policy permits actions outside endpoint's
  declared service scope** — endpoint ↔ service-API join.

Marker controls + scope_field together unlock all of these.
Larger reach options exist (multi-asset CEL primitives,
datalog-style relational evaluation), but they would
re-architect the engine; marker controls preserve the per-asset
evaluation primitive and just expand the "kind of finding"
vocabulary. Same fix pays off across CloudTrail / IAM / VPC
compounds in later iterations.

### What this iteration shipped

- **7 individual unauth controls + 2 pre-existing compound
  chains** fire end-to-end on a single identity-pool asset.
  No engine change required for these.
- **TypeMarker control type + MarkerFindings wire format.**
  Markers emit non-violation findings that participate in
  chain detection. Status / Summary.Violations / exit codes
  ignore them; the new `marker_findings` JSON field surfaces
  them separately for renderers and downstream consumers.
- **`CTL.S3.MARKER.PHI.001` + `cognito_unauth_phi_s3` chain.**
  Demonstrates the cross-resource compound the plan asked for:
  Cognito unauth role with S3 access on a PHI-tagged bucket.
  No collector contract change, no CEL primitive change — just
  a new control type and a chain that composes existing
  per-asset findings via scope_field.
- **The same fix unlocks CloudTrail / IAM / VPC compounds** in
  later iterations rather than just Iteration 2. Each new
  cross-resource shape ships as a new marker control + chain;
  no engine change.
