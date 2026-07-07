# Stave Workflow Guides

Each guide is **one workflow, one outcome, under five minutes**. Every
command is run against bundled examples and exercised in CI, so they
stay accurate as the code changes.

They cover the full chain — getting state *in*, the core evaluation,
and acting on what comes *out*:

| # | Guide | Stage | Outcome |
|---|---|---|---|
| 01 | [From Steampipe to Stave](./01-from-steampipe-to-stave.md) | BEFORE | Turn Steampipe state into an `obs.v0.1` snapshot and evaluate it |
| 02 | [Your First Evaluation](./02-first-evaluation.md) | **CORE** | Run a bundled example and read the verdicts (start here) |
| 03 | [Reading Chain Findings](./03-reading-chain-findings.md) | AFTER · triage | Understand and prioritize compound risk |
| 04 | [Fix and Verify](./04-fix-and-verify.md) | AFTER · remediate | Fix a finding and prove it with `stave check` |
| 05 | [Compliance Evidence](./05-compliance-evidence.md) | AFTER · prove | Produce deterministic auditor evidence |
| 06 | [CI Pipeline Gate](./06-ci-pipeline-gate.md) | AFTER · prevent | Block the unsafe state from ever merging |

**New to Stave?** Start with [02 — Your First Evaluation](./02-first-evaluation.md).
It needs no cloud credentials and no setup.

```
BEFORE          CORE               AFTER
  01    →    02 (verdicts)   →   03 triage → 04 remediate → 05 prove → 06 prevent
```

All evaluation is offline and deterministic: same snapshot + same
`--eval-time` → byte-identical output, every time.
