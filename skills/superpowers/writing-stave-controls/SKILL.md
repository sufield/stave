---
name: writing-stave-controls
description: Author a new CEL control in the Stave catalog with test-first discipline and binary-checkpoint verification
triggers:
  - write a control
  - new control
  - author a security control
  - CEL predicate
  - Stave control
  - control catalog
  - detect misconfiguration
  - add a check
  - CSL spec
  - twin-state pack
requires:
  - stave (go install github.com/sufield/stave@latest)
  - superpowers:test-driven-development (recommended — same discipline)
---

# Writing Stave Controls

Announce: *"I'm using the writing-stave-controls skill to author a new
control."*

## When to use this skill

- Task asks for a new security check, detection rule, or compliance assertion
- Existing Stave controls don't cover the misconfiguration of interest
- You need to encode a known vulnerability pattern as a reusable check
- A finding requires a more specific predicate than the existing catalog has

If the task is *querying existing controls* → use
`stave:verifying-cloud-security` instead.

## Prerequisites

```bash
go install github.com/sufield/stave@latest
stave search "<similar concept>"   # confirm no existing control covers this
```

## Workflow

Test-first. The fixtures come BEFORE the predicate. This is the same
discipline as `superpowers:test-driven-development` — write the failing
case, then write the rule that makes it fail, then write the passing
case to confirm scope.

### Phase 1 — Define the misconfiguration

State the misconfiguration in **one sentence** without the words "bad",
"insecure", or "wrong". Examples of good statements:

- *"An IAM role's trust policy admits `Principal: "*"` with no Condition."*
- *"An S3 bucket has `data-classification=phi` tag AND `access.public_read=true`."*
- *"A Cognito identity pool with `allow_unauthenticated=true` AND the
  unauthenticated role carries any `s3:*` action."*

If you can't write the sentence, you don't yet know what the control
should detect. Stop and clarify before continuing.

### Phase 2 — Find a structural template

```bash
stave search "<similar misconfiguration>"
```

Pick the closest existing control and read its YAML — it's your template.

```bash
find internal/controldata/embedded -name "*.yaml" | head -3
# pick one that matches your asset type
```

### Phase 3 — Write the predicate fixtures FIRST

In a fresh directory, write **two** observations:

`fixtures/writeup/observations/2026-05-17T00:00:00Z.obs.json` —
the observation that **should** trigger your control.

`fixtures/remediated/observations/2026-05-17T00:00:00Z.obs.json` —
the same asset but in the safe state. Same `id`, same `type`, only
the property the control reads is different.

Validate both before writing the control:

```bash
stave validate --in fixtures/writeup/observations/*.obs.json --kind observation --strict
stave validate --in fixtures/remediated/observations/*.obs.json --kind observation --strict
```

**Checkpoint 1: both validations exit 0.**

### Phase 4 — Write the control YAML

Use the template at `control-template.yaml` next to this skill. Minimal
required fields:

```yaml
dsl_version: ctrl.v1
id: CTL.<SERVICE>.<CATEGORY>.<SHORTNAME>.001
name: Human-readable name
description: >
  Single-paragraph description. Explain what the misconfiguration is and
  why it's unsafe. No marketing language.
domain: <governance|exposure|identity|encryption|...>
severity: <low|medium|high|critical>
type: unsafe_state
applicable_asset_types:
  - aws_s3_bucket  # the asset type your predicate reads
classification: state_assertion
unsafe_predicate:
  all:
    - field: properties.storage.kind
      op: eq
      value: bucket
    - field: properties.storage.access.public_read
      op: eq
      value: true
```

Predicate operators: `eq`, `ne`, `in`, `not_in`, `missing`, `present`,
`any_match`, `all_match`, `prefix`, `suffix`, `regex`, `gt`, `gte`,
`lt`, `lte`. Nested `any` / `all` blocks are allowed and combine
logically.

Read the per-asset schema to discover available property paths:

```bash
stave contract show --asset-type aws_s3_bucket --format json | jq '.property_paths[]'
```

### Phase 5 — Embed tests in the control YAML

Stave controls carry their own test cases. Add a `tests:` block at the
bottom of your control YAML:

```yaml
tests:
  - name: writeup fires
    verdict: VIOLATION
    asset:
      asset_id: "arn:aws:s3:::test-bucket"
      asset_type: aws_s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          access: {public_read: true}
  - name: remediated passes
    verdict: PASS
    asset:
      asset_id: "arn:aws:s3:::test-bucket"
      asset_type: aws_s3_bucket
      vendor: aws
      properties:
        storage:
          kind: bucket
          access: {public_read: false}
```

Run the embedded tests:

```bash
stave test --control path/to/your/control.yaml
```

**Checkpoint 2: both tests pass.** Run output reads
`All N tests passed.`

### Phase 6 — End-to-end against the fixtures

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Fires on writeup
stave apply --controls $(dirname your-control.yaml) \
    --observations fixtures/writeup/observations \
    --format json --eval-time $NOW \
    | jq '[.findings[] | select(.control_id == "YOUR.CTL.ID")] | length'
# Expected: > 0

# Silent on remediated
stave apply --controls $(dirname your-control.yaml) \
    --observations fixtures/remediated/observations \
    --format json --eval-time $NOW \
    | jq '[.findings[] | select(.control_id == "YOUR.CTL.ID")] | length'
# Expected: 0
```

**Checkpoint 3:** fires on writeup AND silent on remediated. Both must
hold. If only one holds, your predicate is over- or under-specified.

### Phase 7 — Register the control + regenerate goldens

Move the control file into the catalog tree:

```bash
mv your-control.yaml controls/<service>/<category>/CTL.YOUR.ID.yaml
make sync-controls       # copy into the embedded mirror
make regenerate-goldens  # update e2e golden outputs that include your new finding
```

Review the golden diff carefully — confirm the new finding appears
where expected and nothing else moved.

**Checkpoint 4:** `make test` passes after regenerating goldens.

## Key principles

- **Tests first, predicate second.** Without fixtures you can't tell
  whether the predicate is doing what you intend.
- **One predicate per misconfiguration.** Don't or-together unrelated
  cases — they will produce one finding that doesn't tell the operator
  which condition fired.
- **Embed tests in the YAML.** The `tests:` block travels with the
  control. Anyone modifying the predicate runs the tests automatically.
- **Severity matches blast radius, not difficulty to detect.** A `critical`
  control should describe a state that, if exploited, costs the
  organisation money / data / trust. Detection complexity is irrelevant
  to severity.
- **No marketing language in `description`.** Operators read the
  description in `stave apply` output; it must be operationally precise.

## CSL-driven workflow (alternative entry point)

When the user provides a CSL spec (YAML file matching the schema at
`data/schemas/csl-spec.schema.json`), use this workflow instead of
Phases 1–4 above. The CSL spec replaces the narrative definition —
it already contains the control ID, asset type, unsafe/safe conditions,
severity, and references.

### CSL Phase A — Validate the spec

```bash
cd stave
go run ./internal/tools/csl validate --spec path/to/spec.yaml
```

If validation fails, fix the spec before proceeding.

### CSL Phase B — Generate the twin-state pack

From the validated spec, generate:

**1. Control YAML** → `controls/<service>/<category>/<ID>.yaml`

Map CSL fields to control YAML:

| CSL spec field | Control YAML field |
|---|---|
| `id` | `id` |
| `service` | first scope tag |
| `asset_type` | `applicable_asset_types[0]` |
| `severity` | `severity` |
| `attack_stage` | `params.attack_stage` |
| `unsafe_condition.field` | `unsafe_predicate.all[].field` (prefix with `properties.`) |
| `unsafe_condition.operator` | `unsafe_predicate.all[].op` |
| `unsafe_condition.value` | `unsafe_predicate.all[].value` |
| `references.mitre` | `corpus_reference` |
| `references.framework` | `compliance` |

Use `control-template.yaml` as the structural template. All other
fields (description, remediation, defect, infection, failure) are
derived from `spec.threat` and the condition descriptions.

**2. Embedded tests** → in the same control YAML `tests:` block

```yaml
tests:
  - name: writeup fires
    verdict: VIOLATION
    asset:
      asset_id: "<generated from asset_type>"
      asset_type: <spec.asset_type>
      vendor: aws
      properties:
        # nested from spec.unsafe_condition.field = spec.unsafe_condition.value
  - name: remediated passes
    verdict: PASS
    asset:
      asset_id: "<same as above>"
      asset_type: <spec.asset_type>
      vendor: aws
      properties:
        # nested from spec.safe_condition.field = spec.safe_condition.value
```

**3. Writeup fixture** → `fixtures/labs/<threat>/writeup/observations/`

obs.v0.1 JSON with the asset in the unsafe state (the property at
`spec.unsafe_condition.field` has `spec.unsafe_condition.value`).
Two snapshots at T1 and T2 for duration-based controls.

**4. Remediated fixture** → `fixtures/labs/<threat>/remediated/observations/`

Same observation but with `spec.safe_condition.field` =
`spec.safe_condition.value`.

**5. repro.tf** → `fixtures/labs/<threat>/repro.tf`

Terraform HCL that creates the vulnerable resource. Only generate
for controls that check raw AWS state (not computed properties like
escalation paths). The `.tf` file must pass `terraform validate`.

**6. differential/** → `fixtures/labs/<threat>/differential/.gitkeep`

Empty directory for future scanner comparison results.

### CSL Phase C — Verify the pack

Run the same checkpoints as Phase 5–7 of the standard workflow:

```bash
# Embedded tests
stave test --control controls/<service>/<category>/<ID>.yaml

# E2E: fires on writeup
stave apply --controls controls/<service>/<category>/ \
    --observations fixtures/labs/<threat>/writeup/observations \
    --format json --eval-time 2026-01-15T00:00:00Z \
    | jq '[.findings[] | select(.control_id == "<ID>")] | length'
# Expected: > 0

# E2E: silent on remediated
stave apply --controls controls/<service>/<category>/ \
    --observations fixtures/labs/<threat>/remediated/observations \
    --format json --eval-time 2026-01-15T00:00:00Z \
    | jq '[.findings[] | select(.control_id == "<ID>")] | length'
# Expected: 0

# Terraform (if repro.tf was generated)
cd fixtures/labs/<threat> && terraform validate
```

### CSL Phase D — Register and report

```bash
make sync-controls
make regenerate-goldens
make test
```

Report:

```
Twin-state pack generated for <ID>
  Writeup:    N finding(s) (expected)
  Remediated: 0 findings (expected)
  Terraform:  valid | skipped (computed property)
  Ready to commit
```

### CSL spec format reference

```yaml
spec:
  id: CTL.S3.ENCRYPT.001
  service: S3
  asset_type: aws_s3_bucket
  threat: unencrypted_storage_at_rest
  attack_stage: exfiltration
  severity: high
  unsafe_condition:
    field: storage.encryption.at_rest_enabled
    operator: eq
    value: false
  safe_condition:
    field: storage.encryption.at_rest_enabled
    operator: eq
    value: true
  invariant: "encryption_at_rest(bucket) = true"
  references:
    mitre: "T1530"
    framework: "CIS AWS 2.1.1"
```

Full schema: `data/schemas/csl-spec.schema.json`

Validate: `go run ./internal/tools/csl validate --spec spec.yaml`

## Supporting files

- `control-template.yaml` — fillable starter; remove the `# TODO` lines
  as you complete each section
- `data/schemas/csl-spec.schema.json` — CSL JSON Schema definition

## Related skills

- `superpowers:test-driven-development` — same discipline, framed for
  general code
- `stave:verifying-cloud-security` — once your control ships, use this
  skill to run it against real fixtures
- `stave:writing-steampipe-mappings` — if your control reads a property
  no existing collector populates
