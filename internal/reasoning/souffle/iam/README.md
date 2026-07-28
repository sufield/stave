# Phase 7 G0 — Access-graph Datalog schema (Option B)

This directory ships the G0 base-fact schema + extractor for Phase 7
of the AWS Compound Control Authoring plan. Downstream G1+ programs
(transitive closure, CIA queries) live alongside `schema.dl` here.

See:
- `bizacademy/aws-compound-control-authoring-plan.md` § Phase 7 — G0
- `bizacademy/aws-compound-control-authoring-plan-phase7-observation-audit.md`

## Quick start

```bash
# Mode A — extract from a Stave snapshot directory.
go run ./reasoning/souffle/iam/extract.go \
    -snapshot ./observations \
    -out      ./facts

# Mode B — split a pre-existing JSONL fact stream (trial fixture).
go run ./reasoning/souffle/iam/extract.go \
    -jsonl reasoning-specs/trials/souffle-anonymous-reachability/input.jsonl \
    -out   /tmp/g0-facts

# Run the schema (sanity outputs only — G0 has no derived queries yet).
mkdir -p /tmp/g0-out
souffle reasoning/souffle/iam/schema.dl -F /tmp/g0-facts -D /tmp/g0-out

# Regression: existing reachability.dl still works against the same facts.
mkdir -p /tmp/g0-reach-out
souffle examples/engines/souffle/reachability.dl -F /tmp/g0-facts -D /tmp/g0-reach-out
wc -l /tmp/g0-reach-out/anonymous_reachable.csv
# Expected: 12 (matches the trial golden)
```

## Coverage limitations

See the verbatim header block in `schema.dl`. Three known gaps recorded
at G0 entry (Option B locked):

1. `group_membership` not populated — no `aws_iam_group` asset type
2. `policy_statement` granularity not preserved — sirfacts pre-evaluated
3. `trust_policy(condition_key)` partial — condition-aware queries need extension

Each is a tracked gap, not a defect. G6 is the gate where they either
materialize as triage blockers or stay benign.
