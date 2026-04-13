# Security Chronology

Security posture is a function over time. `stave bisect` lets you
query that function retroactively with any invariant — including ones
written today against data captured last year.

## The problem

When a breach is discovered, the most expensive forensic question is
"when did this start?" Log analysis is incomplete, timestamps are
unreliable, and CloudTrail can be tampered with. Configuration state
is concrete — it was either public or private at snapshot time.

## How it works

```bash
# Find when a bucket became public (binary search, O(log N))
stave bisect \
  --controls controls/s3 \
  --observations snapshots/ \
  --control-id CTL.S3.PUBLIC.001

# Find ALL violation windows over 12 months (linear scan, O(N))
stave bisect \
  --controls controls/s3 \
  --observations snapshots/ \
  --control-id CTL.S3.PUBLIC.001 \
  --mode scan
```

Bisect loads all snapshots from a directory, sorts them by
`captured_at`, then binary-searches (or linear-scans) by evaluating
the specified control against each snapshot.

## Two modes

### Bisect (default)

Binary search. O(log N) assessments. Finds the transition into the
**current** violation window. Correct when the invariant has been
continuously violated since introduction.

### Scan

Linear scan. O(N) assessments. Finds **all** violation windows,
including the earliest (Patient Zero). Correct for non-monotonic
histories where a misconfiguration was fixed and later re-introduced.

If bisect mode detects non-monotonicity, it emits a warning:

```
WARNING: Multiple violation windows detected in this snapshot range.
         --mode bisect found the start of the current window only.
         Run with --mode scan to find the earliest occurrence.
```

## Output precision

Stave operates on snapshots. Output uses "between A and B" language.
It never claims sub-window precision:

```
The change occurred between 2025-11-12T14:00:00Z and 2025-11-12T14:30:00Z.
Stave cannot attribute the change to a specific event within this window.
```

The property delta shows exactly which fields changed between the last
PASS and first VIOLATION snapshots, using the same diff engine as
`stave drift`.

## Relationship to other features

| Command | Question it answers |
|---|---|
| `stave apply` | Is the current state safe? |
| `stave drift` | What changed between two points? |
| `stave bisect` | When was a violation first introduced? |
| `stave bisect --mode scan` | Has this invariant ever been violated? |

Drift finds *what* changed. Bisect finds *when*. Apply finds *if* it
matters. Use them together for complete forensic coverage.

## Business value

1. **Patient Zero forensics** — bounded time window for incident response,
   collapsing multi-day forensic efforts into minutes
2. **Retroactive policy validation** — run new invariants against 12 months
   of historical snapshots to assess past compliance
3. **Dwell time proof** — GDPR/HIPAA/SEC breach notification evidence
   derived from configuration state, not log analysis
4. **New invariant impact assessment** — "if we had enforced this rule last
   year, how many violations would we have caught?"
5. **Vendor SLA verification** — objective remediation duration measurement
   from snapshot timestamps
6. **Cyber insurance evidence** — 12-month clean history artifact for
   premium calculation and claims adjudication

## Key files

| File | Purpose |
|---|---|
| `cmd/bisect/cmd.go` | CLI command with --control-id, --mode, --format |
| `internal/app/bisect/engine.go` | Bisect + scan algorithms |
| `internal/app/bisect/loader.go` | Snapshot directory loading |
| `internal/app/bisect/result.go` | ViolationWindow, Result types |
