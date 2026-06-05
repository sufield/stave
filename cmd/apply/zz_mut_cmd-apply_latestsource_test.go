package apply

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// Test_Mut_LatestSnapshotSource pins the behavior of latestSnapshotSource
// (profile.go), the fix-site helper that emitEmptyScopeResult uses to stamp
// out.v0.1's evaluated_state when the scope filter removed every asset.
//
// The function must return the Source of the most recent snapshot that
// carries a non-empty Source, defaulting to "deployed" only when none does.
// The guard `s != ""` exists so a blank Source never overwrites a real one
// and never blanks the default. Negating it to `s == ""` (the surviving
// CONDITIONALS_NEGATION at profile.go:305:34) flips the helper to ignore
// every populated Source and always fall back to "deployed", which would
// stamp the wrong evaluated_state on an empty-scope report whose snapshots
// were "planned" or "local".
func Test_Mut_LatestSnapshotSource(t *testing.T) {
	base := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	t.Run("returns latest non-empty source, not the default", func(t *testing.T) {
		// Latest snapshot carries a non-default ("planned") Source.
		// Original: returns "planned" (the populated Source of the
		// most recent snapshot). Mutant (s == ""): skips every
		// populated Source and returns the "deployed" default.
		snaps := []asset.Snapshot{
			{Source: asset.SourceLocal, CapturedAt: base},
			{Source: asset.SourcePlanned, CapturedAt: base.Add(time.Hour)},
		}
		if got := latestSnapshotSource(snaps); got != asset.SourcePlanned {
			t.Fatalf("latestSnapshotSource = %q, want %q (latest populated source must win, not the deployed default)", got, asset.SourcePlanned)
		}
	})

	t.Run("single planned snapshot resolves to planned", func(t *testing.T) {
		// A lone snapshot whose Source is non-default. Original keeps
		// "planned"; the mutant ignores it and returns "deployed".
		snaps := []asset.Snapshot{
			{Source: asset.SourcePlanned, CapturedAt: base},
		}
		if got := latestSnapshotSource(snaps); got != asset.SourcePlanned {
			t.Fatalf("latestSnapshotSource = %q, want %q", got, asset.SourcePlanned)
		}
	})

	t.Run("defaults to deployed when no source populated", func(t *testing.T) {
		// All sources blank: both original and mutant return the
		// "deployed" default. Pins the documented fallback so the
		// non-empty case above is not over-fitted.
		snaps := []asset.Snapshot{
			{CapturedAt: base},
			{CapturedAt: base.Add(time.Hour)},
		}
		if got := latestSnapshotSource(snaps); got != asset.SourceDeployed {
			t.Fatalf("latestSnapshotSource = %q, want %q (default when no snapshot carries a source)", got, asset.SourceDeployed)
		}
	})
}
