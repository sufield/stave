---
name: verifying-cloud-security
description: Verify cloud infrastructure security using the Stave platform with machine-verifiable contracts at every step
triggers:
  - cloud security
  - AWS security
  - IAM role
  - S3 bucket security
  - infrastructure verification
  - compliance check
  - HIPAA
  - CIS benchmark
  - security posture
  - misconfiguration
  - compound risk
  - attack path
  - blast radius
  - configuration drift
requires:
  - stave (go install github.com/sufield/stave@latest)
---

# Verifying Cloud Security

Announce: *"I'm using the verifying-cloud-security skill to verify this
infrastructure."*

## When to use this skill

Load this skill when the task involves any of:

- AWS resources (IAM, S3, Lambda, Bedrock, VPC, KMS, Cognito, CloudTrail)
- Compliance frameworks (HIPAA, CIS, NIST 800-53, PCI-DSS, SOC 2)
- Questions of the form *"is this safe?"*, *"what's misconfigured?"*,
  *"what's the blast radius?"*, *"can an attacker reach X?"*
- Reviewing cloud configuration snapshots
- Detecting compound risk, attack paths, ghost references, or configuration drift

If the task is *writing a new control* → use `stave:writing-stave-controls`.
If the task is *adding a new collector mapping* → use `stave:writing-steampipe-mappings`.
If the task is *formal verification* → use `stave:writing-reasoning-specs`.

## Prerequisites

```bash
go install github.com/sufield/stave@latest
stave --version  # confirm install
```

For live AWS data collection:

```bash
brew install turbot/tap/steampipe
steampipe plugin install aws
```

Stave is offline — no AWS credentials required for evaluation. Credentials
only flow to Steampipe during collection.

## Workflow

Every phase has a **binary checkpoint** — exit code or count, not prose.
Stop and fix at the first failed checkpoint; do not proceed to the next
phase with a failure behind you.

### Phase 1 — Discover what to check

```bash
stave search "<the security concern>"
```

Searches the capability catalog (controls + chains + operational features).
If zero results, try synonyms: `public` ↔ `open`, `ghost` ↔ `orphan`,
`mfa` ↔ `two-factor`, `unauthenticated` ↔ `anonymous`.

For the contract of a specific asset type:

```bash
stave contract show --asset-type aws_s3_bucket --format json
```

Returns the per-asset JSON schema, the property paths the catalog reads,
the control/chain count per path, and the Steampipe mapping if one exists.

**Checkpoint 1:** `stave search` returns at least one capability.

### Phase 2 — Collect observations

If you already have Stave-shape observations, skip to Phase 3.

If you have raw Steampipe rows, transform them:

```bash
python3 examples/agents/stave_transform.py \
    --input raw.json \
    --asset-type aws_s3_bucket \
    --output observations/
```

The transform reads `contracts/steampipe/<asset_type>.yaml` to map
Steampipe columns onto Stave property paths. If no mapping exists for
your asset type, switch to the `stave:writing-steampipe-mappings` skill.

Validate the observation **before** trying to evaluate it:

```bash
stave validate --in observations/*.obs.json --kind observation --strict
```

**Checkpoint 2: exit code MUST be 0.** Validation errors name the
specific field and what's wrong. Read them, fix the observation, retry.
Do not proceed with `--strict` failures — they will surface as confusing
evaluation errors later.

Note: `stave validate` can return exit 0 with "0 asset observations
checked" when the file is structurally valid but empty or the loader
skipped it. Confirm the count is non-zero before treating exit 0 as a
green light.

### Phase 3 — Evaluate

```bash
stave apply --observations ./observations \
    --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --format json
```

**Always pass `--eval-time`.** Without it, time-dependent controls (credential
TTL, observation freshness, unsafe-duration thresholds) read the system
clock and the same snapshot produces different findings on different
days. Pin `--eval-time` to the observation's `captured_at` for reproducibility
across CI runs and agent iterations.

The loader accepts observations whose `generated_by.source_type` is
missing or non-standard by default — common on fixtures and
hand-authored test cases. No flag is required.

Exit codes:
- `0` — no findings
- `3` — findings present (this is expected on insecure fixtures, NOT an error)
- `2` — input error (validation failed, bad flag)
- `4` — internal error

Check what you're missing:

```bash
stave gaps --observations ./observations --format json | jq '.summary'
```

Each gap is typed in `.remediation.type`:
- `tag` → add a tag to the resource (agent fixable in seconds)
- `derived` → add a field map entry in the Steampipe transform (agent fixable)
- `api` → secondary cloud API call needed (operator escalation)
- `collector` → cross-inventory analysis needed (operator escalation)

Read `.summary.fixable_by_agent_gaps` to know whether the OODA loop has
work it can converge on without escalation.

Coverage overview:

```bash
stave readiness --observations ./observations --format json
```

Three buckets: `confirmed_active` (catalog evaluates this), `confirmed_blocked`
(asset type absent from snapshot), `indeterminate` (control has no
`applicable_asset_types` declaration). The `readiness_score` divides
`can_fire` by `(can_fire + blocked)` — indeterminate controls are
excluded from both sides; see `readiness_denominator` in the output.

**Checkpoint 3:** `stave apply` exits 0 or 3 (not 2 or 4). Findings are
the catalog's verdict on your observation; do not treat exit 3 as a
failure.

### Phase 4 — Formal proof (optional)

For chains the SIR projects, export facts and run an external solver:

```bash
stave export-sir --format smt2 \
    --observations ./observations \
    --eval-time $(date -u +%Y-%m-%dT%H:%M:%SZ) > facts.smt2
```

The export emits declarations + facts only — no query, no
`(check-sat)`. You append a query that names the unsafe state you want
checked. Minimal "is anonymous read of the PHI bucket reachable?"
query:

```smt2
; query.smt2 — paste at the end of facts.smt2 before invoking z3
(assert (exists ((p Principal))
  (and (allows_unauthenticated p "true")
       (has_permission_action p "s3:GetObject")
       (has_tag "arn:aws:s3:::<bucket-arn>" "data-classification:phi"))))
(check-sat)
(get-model)
```

Replace `<bucket-arn>` with the asset id from your fixture. Predicate
names come from the SIR's vocabulary — run
`stave export-sir --format smt2 ... | grep '^(declare-fun'` to list
what's available before authoring more complex queries. For full
solver-spec authoring discipline (engine selection, blind-trial,
scope caveats), use the `stave:writing-reasoning-specs` skill.

```bash
cat facts.smt2 query.smt2 | z3 -in
```

Z3 returns:
- `sat` — the dangerous state is reachable. SAT comes with a constructive
  witness — the principal, action, and resource that compose the attack
  path.
- `unsat` — provably unreachable **within the SIR's exported scope**.

The scope qualifier matters. The SIR covers 13 top-level configuration
domains today (IAM, Cognito, S3 storage policies, Bedrock AI, delegation,
credential lifecycle, trail logging, network, parts of compute/k8s).
Properties in uncovered domains (Azure, GCP, M365, databases, messaging,
secrets, monitoring, and others) are evaluated by CEL inside `stave apply`
but are not in the export, so the proof is silent about chains whose
members live in those domains. See `stave export-sir --help` and the
[Fact Export reference](https://github.com/sufield/stave-guide/blob/main/reference/fact-export.md#scope-of-the-exported-fact-set)
for the full domain table.

**Checkpoint 4:** solver returns `sat` or `unsat`. A timeout or `unknown`
verdict means the query exceeded resource bounds — narrow the query or
increase the solver's resource limits, do not interpret silence as safety.

## Key principles

- **Every step has a binary assertion.** Exit codes and counts, not
  prose. If you cannot state a check as "exit 0" or "X > Y", you have
  not defined the check.
- **Determinism requires `--eval-time`.** Same snapshot + same `--eval-time` = same
  findings, every time. CI workflows that omit it will see verdict counts
  drift as time passes.
- **Gaps are prioritized.** `stave gaps` ranks the missing properties by
  how many controls and chains each would unlock. Fix the highest-impact
  one first, not the alphabetically-first one.
- **Compound risk > individual findings.** A chain that composes three
  HIGHs into one CRITICAL is more important than any individual HIGH;
  the chain's `compound_score` carries the escalation weight.
- **Trust the collector, but verify boundary by boundary.** Stave reads
  observation values as truth. The collector is responsible for value
  correctness. If a finding looks wrong, check the observation before
  doubting the control.

## Supporting files

- `commands-reference.md` — every Stave command relevant to verification,
  with exit codes and an example each
- `observation-format.md` — what a valid `obs.v0.1` JSON looks like,
  with a minimal working example

## Related skills

- `superpowers:test-driven-development` — same binary-assertion discipline
  applied to test-first authoring
- `stave:writing-stave-controls` — author a new CEL control
- `stave:writing-steampipe-mappings` — connect a new data source
- `stave:writing-reasoning-specs` — formal verification questions for Z3,
  cvc5, Soufflé, Clingo, Prolog, PRISM
