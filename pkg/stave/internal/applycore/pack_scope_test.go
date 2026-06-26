package applycore

import (
	"context"
	"slices"
	"testing"
	"time"
)

// fixtureGhostref has three controls (CTL.IAM.POLICY.GHOSTREF.001/002/003) and
// a two-snapshot observation set — enough to exercise the dir-loading path.
const fixtureGhostref = "../../../../testdata/e2e/e2e-forge-iam-policy-ghostref-pass"

// TestRun_ControlIDAllowlist_DirPath is the regression guard for the --pack
// bypass: with a non-empty ControlsDir, resolveControls defers loading to the
// repo and leaves the controls slice nil. An allowlist filter applied to that
// nil slice silently evaluated ZERO controls (a false COMPLIANT). The unit test
// for filterControlsByID passed throughout because it never exercised the
// deferred dir-loading path. This drives a real Run against a controls dir and
// asserts the evaluated set is exactly the allowlisted subset.
func TestRun_ControlIDAllowlist_DirPath(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ids := func(r *Result) []string {
		out := make([]string, len(r.Controls))
		for i := range r.Controls {
			out[i] = string(r.Controls[i].ID)
		}
		slices.Sort(out)
		return out
	}

	// Baseline: no allowlist evaluates all three controls in the dir.
	full, err := Run(context.Background(), Inputs{
		ControlsDir:  fixtureGhostref + "/controls",
		SnapshotsDir: fixtureGhostref + "/observations",
		Now:          now,
	})
	if err != nil {
		t.Fatalf("baseline Run: %v", err)
	}
	if got := len(full.Controls); got != 3 {
		t.Fatalf("baseline evaluated %d controls, want 3: %v", got, ids(full))
	}

	// Scoped: allowlisting one control must evaluate exactly that one — not
	// zero (the bug) and not all three (filter ignored).
	want := "CTL.IAM.POLICY.GHOSTREF.002"
	scoped, err := Run(context.Background(), Inputs{
		ControlsDir:        fixtureGhostref + "/controls",
		SnapshotsDir:       fixtureGhostref + "/observations",
		Now:                now,
		ControlIDAllowlist: []string{want},
	})
	if err != nil {
		t.Fatalf("scoped Run: %v", err)
	}
	got := ids(scoped)
	if len(got) != 1 || got[0] != want {
		t.Errorf("scoped evaluation = %v, want exactly [%s] (0 = silent-bypass bug, 3 = filter ignored)", got, want)
	}
}
