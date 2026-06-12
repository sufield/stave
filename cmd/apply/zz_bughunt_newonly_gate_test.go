package apply

import (
	"errors"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// TestBugHunt_NewOnlyGate_BlocksNonCompliant proves the gating decision used
// by the --new-only branch of runStandardApply mirrors ReportApply: a BLOCK
// gate must surface ui.ErrViolationsFound so the CLI exits non-zero,
// otherwise CI runs with --new-only would pass on every active finding.
func TestBugHunt_NewOnlyGate_BlocksNonCompliant(t *testing.T) {
	tests := []struct {
		name      string
		gate      string
		wantBlock bool
	}{
		{"block gate blocks (exit 3)", "BLOCK", true},
		{"allow gate does not block", "ALLOW", false},
		{"advisory gate does not block under default policy", "ADVISORY", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := gateViolations(stave.StandardResult{Gate: tc.gate})
			if tc.wantBlock {
				if !errors.Is(err, ui.ErrViolationsFound) {
					t.Fatalf("gate %s: expected ErrViolationsFound, got: %v", tc.gate, err)
				}
			} else if err != nil {
				t.Fatalf("gate %s: expected nil gating error, got: %v", tc.gate, err)
			}
		})
	}
}

// TestBugHunt_NewOnlyGate_MatchesReportApply locks the new-only gating
// decision to the standard path's ReportApply decision so the two modes can
// never drift: for any gate, gateViolations must return a violation iff
// ReportApply does.
func TestBugHunt_NewOnlyGate_MatchesReportApply(t *testing.T) {
	for _, gate := range []string{"ALLOW", "ADVISORY", "BLOCK"} {
		res := stave.StandardResult{Gate: gate}

		rep := &Reporter{Quiet: true}
		standardViolation := errors.Is(rep.ReportApply(res, "ctl", "obs"), ui.ErrViolationsFound)
		newOnlyViolation := errors.Is(gateViolations(res), ui.ErrViolationsFound)

		if standardViolation != newOnlyViolation {
			t.Fatalf("gate %s: standard-path violation=%v but new-only gate violation=%v; modes must agree",
				gate, standardViolation, newOnlyViolation)
		}
	}
}
