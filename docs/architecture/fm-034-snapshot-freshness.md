# FM-034: Snapshot Freshness — UNCERTAIN Verdict on Stale Data

Status: DESIGN (not yet implemented)

## Problem

Every finding Stave produces is an assertion about infrastructure state
at capture time T. A FAIL on a three-week-old snapshot might already be
remediated; a PASS might no longer hold. Both are presented with the same
confidence as findings on a five-minute-old snapshot. This is a silent
epistemic failure.

## What Already Exists

Before designing, audit what the codebase already has:

| Component | Location | Status |
|-----------|----------|--------|
| `captured_at` in obs.v0.1 | Snapshot envelope, `internal/core/asset` | Done |
| `--eval-time` flag | All eval commands, wired through `params.nowTime` | Done |
| `staleness.Check()` | `internal/app/staleness/staleness.go` | Done — binary check, threshold, `--eval-time` aware |
| `--assert-recent` flag | `validate`, `apply` | Done — stale = warn/fail, but doesn't affect verdicts |
| `ConfidenceLevel` enum | `internal/core/evaluation/audit.go` | Done — HIGH/MEDIUM/LOW/INCONCLUSIVE |
| `Verdict` enum | Same file | Done — VIOLATION/PASS/INCONCLUSIVE/NOT_APPLICABLE/SKIPPED |
| `ResourceCheck.Confidence` | Same file | Done — already on every check |

The infrastructure is 80% built. What's missing is wiring staleness
into the per-finding confidence level and surfacing it in output.

## Decisions

### 1. Timestamp Granularity: Option A (single per snapshot)

Use the existing `captured_at` on the snapshot envelope. obs.v0.1
already has this field and every snapshot produced by `stave transform`
populates it.

Per-service-group timestamps (Option B) would require schema changes
to obs.v0.1 for marginal precision gain. If a 20-minute collection
window matters, the user should collect more frequently, not track
per-API timestamps. YAGNI.

### 2. Binary Freshness (not graduated)

`age <= threshold` → original verdict with ConfidenceHigh.
`age > threshold` → original verdict preserved, confidence downgraded
to ConfidenceLow, reason set to staleness message.

Why not graduated: every additional tier is a configuration surface
the user must understand and downstream consumers must handle. The
user's action is the same regardless — re-collect. Binary gives one
threshold, one decision point, one action.

Default threshold: **24h**. Override: `--freshness-threshold=168h`
or `--skip-freshness`.

### 3. Post-Evaluation Qualifier (not pre-evaluation gate)

Evaluate the CEL predicate normally, producing PASS or VIOLATION.
Then check the snapshot's age. If stale, downgrade `Confidence` to
`ConfidenceLow` and set `Reason` to the staleness message. The
verdict itself (PASS/VIOLATION) is preserved.

Why: the underlying verdict is always useful. For breach
reconstruction (`--eval-time` set to breach time), the user wants the
finding regardless. For continuous governance, the user wants to know
"this was VIOLATION when captured, but data is old." Post-eval serves
both.

`--eval-time` set close to `captured_at` naturally produces `age ≈ 0`,
so freshness passes. `--skip-freshness` is the escape hatch for
users who don't want the qualifier at all (legacy behavior).

### 4. No New Verdict Value

Do NOT add a `VerdictUncertain`. The existing `VerdictInconclusive`
already means "check ran but result is qualified." UNCERTAIN is better
expressed as `Verdict=VIOLATION, Confidence=LOW, Reason="snapshot
captured 72h ago, threshold 24h"`. This avoids:

- Adding a sixth verdict that every consumer must handle
- Breaking the COMPLIANT/AT_RISK/NON_COMPLIANT SecurityState derivation
- Changing exit code semantics

Confidence downgrade is metadata, not a verdict change. Finding counts,
exit codes, and SecurityState are unaffected. The confidence field is
already on every `ResourceCheck`.

### 5. Compound Chain Propagation: Worst-Case (Option C)

Each compound finding reports the age of its oldest input snapshot.
The freshness threshold is applied once at the compound level. If any
input snapshot is stale, the compound finding's confidence is
downgraded.

Why not fact-level tagging: modifying Datalog relations adds a column
to every fact table. Worst-case propagation is one comparison after
the chain runs — zero changes to Datalog rules.

For cross-group compounds (e.g., Lambda → IAM → S3), the finding
metadata includes the oldest `captured_at` and which group is stale:

```json
{
  "confidence": "LOW",
  "staleness": {
    "oldest_input": "2026-06-20T10:00:00Z",
    "stale_group": "storage",
    "age_hours": 192,
    "threshold_hours": 24
  }
}
```

### 6. Export Engine Propagation: Assert Normally, Annotate Result

Z3/SMT-LIB and Soufflé get all facts regardless of freshness.
Omitting stale facts creates false negatives (UNSAT for a property
that would be SAT). The freshness qualifier is applied to the
engine's output, not its input — consistent with the post-eval
qualifier approach at the CEL level.

### 7. Missing `captured_at`: Treat as Fresh (legacy compat)

Existing snapshots without `captured_at` are treated as fresh
(ConfidenceHigh). Rationale: breaking existing users' workflows on
upgrade is worse than silently skipping the freshness check. The
migration path is natural — new snapshots from `stave transform`
always include `captured_at`, so the gap closes organically.

If the user explicitly passes `--assert-recent` with a legacy
snapshot that has no `captured_at`, that's an error (exit 2) with
a hint to add the field.

### 8. CLI Output and Exit Codes

**Display**: stale findings are shown normally (not hidden). A
summary line at the top of the report: "47 findings have LOW
confidence due to snapshot age > 24h. Re-collect for current
results."

**Exit codes**: unchanged. VIOLATION findings still exit 3 whether
confidence is HIGH or LOW. Confidence is advisory metadata, not a
gating mechanism. The existing `--assert-recent` flag already
provides the "fail on stale data" gate for CI pipelines.

**`--quiet` mode**: confidence downgrade does not affect exit code
behavior — `--quiet` still reports exit 0/3 based on violations
alone.

## Implementation Path

1. Add `--freshness-threshold` and `--skip-freshness` flags to
   `apply` and `validate` commands (alongside existing `--assert-recent`)
2. After evaluation, if `!skipFreshness`, run `staleness.Check()` on
   the loaded snapshots. If stale, iterate findings and downgrade
   `Confidence` to `ConfidenceLow` with reason
3. For compound chains, track the oldest input `captured_at` and
   apply the same downgrade
4. Add staleness metadata to the `out.v0.1` output schema (new
   `input_freshness` section in the report)
5. Update text/JSON renderers to show the confidence summary line
6. Tests: stale snapshot → findings have LOW confidence; fresh →
   HIGH; `--skip-freshness` → always HIGH; `--eval-time` close to
   `captured_at` → HIGH

Estimated scope: ~200 lines of production code (the infrastructure
is already built), ~150 lines of tests.

## Worked Examples

### A. Continuous governance — stale pipeline

```
$ stave apply --observations obs/ --eval-time 2026-06-28T02:00:00Z

⚠ 83 findings have LOW confidence: snapshot captured 2026-06-26T10:00:00Z
  (40 hours ago, threshold 24h). Re-collect for current results.

security_state: NON_COMPLIANT
violations: 12
findings: 83 (confidence: 83 LOW)
```

Exit code 3 (violations found). The staleness warning tells the team
their pipeline is broken — the finding count is unreliable.

### B. Breach reconstruction — intentional old data

```
$ stave apply --observations obs/ --eval-time 2025-01-15T14:00:00Z --skip-freshness

security_state: NON_COMPLIANT
violations: 47
findings: 203 (confidence: 203 HIGH)
```

`--skip-freshness` disables the check. All findings report HIGH
confidence relative to the `--eval-time` time. The IR team gets the full
finding set without qualification.

### C. Mixed-freshness compound

```
Finding: Lambda data-processor blast radius = 38 resources
  Verdict:    VIOLATION
  Confidence: LOW
  Reason:     storage group captured 2026-06-20T10:00:00Z (8 days ago,
              threshold 24h); identity group fresh (1 hour ago)
```

The compound finding fires (VIOLATION) because the IAM data shows
the blast radius. Confidence is LOW because the S3 target inventory
is stale — the actual reachable count may differ.
