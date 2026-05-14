# Plan: Export CoverageValidator state as SIR coverage facts

## Why

`sat-readiness.md` audit gap #2 ("Hidden facts") shipped most of its
scope (`IdentityFact.RoleChains`, `AssetFact.Lifecycle`) but left
`CoverageValidator` state internal. Without it, downstream SIR
consumers cannot distinguish *observed-safe* from *unobserved*: an
asset with no exposure window in `TemporalFacts.Windows` could mean
"definitely safe across the audit window" or "not enough observations
to tell." Today's SIR collapses these into the same shape.

The `CoverageGap` struct already exists at
`internal/core/sir/types.go:389` — but it's an orphan: no field on
`Document` or `TemporalFacts` references it, and no builder code
populates it.

This is the last open item from the original Z3-readiness audit. The
2026-05-06 architectural pivot (commit `82118471e`) closed every
other line item but does not affect this one — coverage gaps are
useful to any SIR consumer, not just an SMT solver.

## Current state

### What `CoverageValidator` knows

`internal/core/evaluation/engine/coverage.go`:

```go
type CoverageValidator struct {
    minRequiredSpan time.Duration
    maxAllowedGap   time.Duration
}

func (v CoverageValidator) IsSufficient(t *asset.ExposureLifecycle) (string, bool)
```

`IsSufficient` returns `(reason, ok)` where `ok=false` means the
lifecycle has either a too-short audit window or a gap that
exceeds `maxAllowedGap`. Reasons are human strings; the underlying
stats come from `asset.ExposureLifecycle.Stats()` —
`CoverageSpan()`, `MaxGap()`, `HasCoverageData()`.

Construction: `engine/strategy.go:61` calls `NewCoverageValidator`
with `(minSpan, deps.ContinuityLimit())`. `IsSufficient` is invoked
inside `unsafeDurationStrategy` / `unsafeRecurrenceStrategy` to
decide whether to emit INCONCLUSIVE rather than PASS/VIOLATION.

### What SIR already has

- `internal/core/sir/types.go:333` — `TemporalFacts { Observations,
  Windows }`. No coverage field.
- `internal/core/sir/types.go:389` — `CoverageGap { AssetID, Start,
  End, Reason }`. Declared, unused.
- `internal/core/sir/builder.go:47` — `LifecycleSource` interface
  pattern. Same shape works for coverage.
- `internal/core/sir/builder.go:509` — `buildTemporalFacts`. Natural
  place to extend.

The kernel package boundary forbids `internal/core/sir/` from
importing `internal/core/evaluation/engine/`, so the validator
itself can't live in the builder. The existing `LifecycleSource` /
`RoleChainSource` adapter pattern is the template.

## Design

### Data shape

Add to `TemporalFacts`:

```go
type TemporalFacts struct {
    Observations []time.Time      `json:"observations"`
    Windows      []ExposureWindow `json:"windows"`
    Coverage     CoveragePolicy   `json:"coverage"`
    Gaps         []CoverageGap    `json:"coverage_gaps,omitempty"`
}

type CoveragePolicy struct {
    MinRequiredSpan time.Duration `json:"min_required_span_ns"`
    MaxAllowedGap   time.Duration `json:"max_allowed_gap_ns"`
}
```

Why `CoveragePolicy` alongside the gap list: a consumer reading a
gap of 5 minutes can't tell whether that's policy-violating without
the thresholds. Exporting the policy makes the SIR self-describing.

Why nanoseconds in JSON: matches Go's `time.Duration` marshal
default and avoids precision drift through round-trip. The field
suffix `_ns` documents the unit so consumers don't guess.

Granularity: one `CoverageGap` per (asset, gap-window) — *not* per
(control, asset, gap-window). Coverage is an observation property
of the asset, not the control. Two controls sharing a snapshot grid
share the same gaps.

### Builder seam

New interface alongside `LifecycleSource`:

```go
// CoverageSource produces coverage facts for the SIR. Implementations
// live outside the SIR package (the validator depends on engine
// state) and are injected via WithCoverageSource.
type CoverageSource interface {
    Coverage(snapshots []asset.Snapshot,
             lifecycles map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle,
    ) (CoverageReport, error)
}

type CoverageReport struct {
    Policy CoveragePolicy
    Gaps   []CoverageGap
}
```

The builder calls `CoverageSource` after `collectLifecycles`, then
folds the result into `buildTemporalFacts`. If no source is
registered, `Coverage` defaults to zero-value `CoveragePolicy` and
empty `Gaps` — the field stays `omitempty` for gaps but the policy
serializes either way (so consumers can tell "policy was 0/0" from
"policy was set but no gaps tripped").

Builder Option (matches existing pattern):

```go
func WithCoverageSource(s CoverageSource) Option { ... }
```

### Adapter

New file `internal/adapters/sirbridge/coverage.go`:

```go
type EngineCoverageSource struct {
    minSpan time.Duration
    maxGap  time.Duration
}

func NewEngineCoverageSource(minSpan, maxGap time.Duration) (*EngineCoverageSource, error) {
    if _, err := engine.NewCoverageValidator(minSpan, maxGap); err != nil {
        return nil, err
    }
    return &EngineCoverageSource{minSpan, maxGap}, nil
}

func (s *EngineCoverageSource) Coverage(
    snapshots []asset.Snapshot,
    lifecycles map[kernel.ControlID]map[asset.ID]*asset.ExposureLifecycle,
) (sir.CoverageReport, error) {
    // For each asset that appears in any lifecycle, walk
    // ObservationStats and emit a CoverageGap whenever a gap
    // exceeds maxGap. De-duplicate across controls (same asset,
    // same gap, multiple control lifecycles → one row).
    ...
}
```

The adapter validates input via `engine.NewCoverageValidator`'s
constructor so adapter and engine stay in lock-step on what a valid
threshold pair looks like.

Wiring: `cmd/exportsir/...` and any other call site that already
configures `WithLifecycleSource` adds a parallel
`WithCoverageSource`. Pull the thresholds from the same place the
strategies pull them (`deps.ContinuityLimit()` and the per-control
SLA default).

### Tests

1. **Type-level builder test**
   (`internal/core/sir/builder_coverage_test.go`): a fake
   `CoverageSource` returns a known report; assert the SIR
   `Document.Temporal.Gaps` and `.Coverage` match byte-for-byte
   after round-trip.

2. **Adapter test** (`internal/adapters/sirbridge/coverage_test.go`):
   feed a synthetic snapshot set with a deliberate gap, run
   `EngineCoverageSource.Coverage`, assert one `CoverageGap` row
   with the expected `Start`/`End`/`Reason`. Edge cases: no
   lifecycles, lifecycles without gaps, gap exactly at threshold.

3. **Determinism gate**: extend the existing `stave export-sir`
   determinism test in `cmd/exportsir/` to a fixture that produces
   ≥1 gap row. Two runs must be byte-identical (sort gaps by
   `AssetID`, then `Start`).

4. **E2E fixture goldens**: pick one existing fixture with a known
   coverage gap (e.g. an `e2e-22-ignore` or similar sparse snapshot
   set), regenerate the export-sir golden, confirm the diff is
   additive (`coverage_gaps`, `coverage` fields appear; existing
   shape unchanged).

## Files touched

| File | Change |
|------|--------|
| `internal/core/sir/types.go` | Extend `TemporalFacts`; add `CoveragePolicy` |
| `internal/core/sir/builder.go` | `CoverageSource` interface, Option, plumb into `buildTemporalFacts` |
| `internal/core/sir/builder_coverage_test.go` | New |
| `internal/adapters/sirbridge/coverage.go` | New |
| `internal/adapters/sirbridge/coverage_test.go` | New |
| `cmd/exportsir/...` | Register `WithCoverageSource` at composition root |
| `testdata/<chosen-fixture>/expected.export-sir.json` | Golden regen |

## Out of scope

- Surfacing coverage gaps in the human-facing `apply` output. The
  strategies already emit INCONCLUSIVE findings with the validator
  reason string; coverage in SIR is a separate machine-readable
  channel.
- Per-control coverage rows. Coverage is an asset/observation
  property; controls just consume it. If a future consumer needs a
  per-control rollup, derive it from `Gaps` × `Windows`.
- Coverage *recommendations* (suggesting longer audit windows or
  denser collection). That's UX work for `stave diagnose`, not SIR.

## Acceptance

- `internal/core/sir/types.go` compiles with the new fields; existing
  callers untouched (additive).
- `stave export-sir` against the chosen fixture emits a
  `coverage_gaps` array with the expected rows; `coverage` policy
  block shows the configured `min_required_span_ns` /
  `max_allowed_gap_ns`.
- Determinism test passes with the new fields populated.
- `make test` green; no changes to existing E2E `expected.out.json`
  goldens (apply's text/JSON output unchanged — this is SIR-only).
- `sat-readiness.md` conclusion item #2 flips from ⏳ to ✅.
