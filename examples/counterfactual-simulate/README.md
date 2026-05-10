# Counterfactual Simulate — External Replacement for `internal/app/simulate/`

External Python implementation of Stave's "what if I fixed these
controls?" simulator. Reads a `stave apply --format json` assessment,
takes a list of control IDs to remediate, and reports posture-score
delta + which compound chains would deactivate — same arithmetic as
`internal/app/simulate/simulate.go`, ported to pure-stdlib Python.

This example closes item 6 in the core-audit migration tracking
table (`internal/app/simulate/` had no external equivalent at the
2026-05-08 audit; this is the equivalent).

## What it does

```
stave apply --format json   →  assessment.json
chains.yaml                  (chain definitions)
simulate.py --fix C1 --fix C2 …  →  • findings eliminated
                                    • chains deactivated
                                    • posture-score delta
```

Three computations:

1. **Findings removed** — exact: count of findings whose `control_id`
   matches one of `--fix`.
2. **Chains deactivated** — exact: a compound chain deactivates when
   the count of remaining failing members drops *below* its
   `escalation_threshold`. The chain's currently-firing members are
   read from the assessment; thresholds + member sets come from
   `--chains-file` (or are inferred from the assessment itself if
   omitted).
3. **Score delta** — proportional model. Mirrors
   `internal/app/simulate/simulate.go`:
   - `improvement_ratio = removed / total_findings`
   - `max_improvement = 100 - current_score`
   - `simulated = current + max_improvement × improvement_ratio × 0.6`
   - plus `+2.0` per chain that deactivates
   - clamped to [0, 100]

The proportional score model is intentionally a *quick estimate*. The
authoritative posture score after the fix lands comes from rerunning
`stave apply` on the post-fix observation snapshot; this script is
for ranking *which* fix to ship first, not predicting the post-fix
absolute score.

## Run

```bash
# Single fix
./simulate.py --assessment fixtures/assessment.json \
    --chains-file fixtures/chains.yaml \
    --fix CTL.COGNITO.MFA.001

# Multi-fix
./simulate.py --assessment fixtures/assessment.json \
    --chains-file fixtures/chains.yaml \
    --fix CTL.S3.PUBLIC.001 \
    --fix CTL.S3.ENCRYPT.001

# JSON output
./simulate.py --assessment fixtures/assessment.json \
    --chains-file fixtures/chains.yaml \
    --fix CTL.COGNITO.MFA.001 --format json

# Or via the bundled runner — 4 scenarios + interpretation
bash run.sh
```

The shipped fixture has 7 findings (1 critical, 3 high, 3 medium)
and 2 compound chains (`cognito_weakauth`, `s3_phi_exposure`). The
runner's four scenarios show the typical decision shapes:

| Scenario | Fixes | Effect |
|---|---|---|
| 1 | MFA.001 alone | -1 finding, no chain change (cognito_weakauth still has 2 of 3 members failing — meets threshold) |
| 2 | S3.PUBLIC + S3.ENCRYPT | -2 findings, **s3_phi_exposure deactivates** (threshold 2, only 1 member remains) |
| 3 | All 3 weakauth members | -3 findings, **cognito_weakauth deactivates** |
| 4 | S3.PUBLIC alone | JSON output for tooling integration |

Scenario 1 is the canonical "single fix inside a compound chain
moves the needle very little" lesson. Scenario 3 is the operator's
correct play — fix the whole compound to deactivate the chain.

## Why this lives outside core

Per the core-audit thin-core contract, Stave does two things:
**evaluate** (apply controls) and **export** (project facts).
Counterfactual analysis is reasoning over a *hypothetical* state
("what would the verdict be if these findings were not present?")
— that is verdict-shaped logic, not fact production. It belongs
in an external script that consumes Stave's published JSON, like
this one.

The chain deactivation rule is also pure boolean logic:

```
chain.deactivates(fixed) ⇔
    count(m ∈ chain.members : m ∈ fixed_set) < chain.threshold
```

This is one set difference + one comparison per chain. No SAT
solver, no graph traversal — just stdlib `set`. The same shape
that `examples/sat-control-regression/` runs through Z3 for the
"is the deactivated state actually reachable from a real
observation?" question; this script is the lighter sibling that
takes the user's word for it.

## Severity weights

For the posture score, the script uses the same per-severity
weights as `examples/forecast/` to keep them in lockstep.
Edit `SEVERITY_WEIGHT` in `simulate.py` to recalibrate:

| Severity | Weight (deducted per finding) |
|---|---|
| critical | 20 |
| high | 10 |
| medium | 5 |
| low | 2 |

## Layout

```
examples/counterfactual-simulate/
├── README.md           — this file
├── simulate.py         — the simulator (pure stdlib)
├── run.sh              — 4-scenario demo runner
└── fixtures/
    ├── assessment.json — synthetic stave-apply output (7 findings, 2 chains)
    └── chains.yaml     — chain definitions (members + thresholds)
```
