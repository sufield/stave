package apply

import (
	"errors"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation"
)

// TestBugHunt_NewOnlyGate_BlocksNonCompliant proves that the gating
// decision used by the --new-only / --new-since branch of
// runStandardApply must mirror ReportApply: a NON_COMPLIANT
// (block) security state has to surface ui.ErrViolationsFound so the
// CLI exits non-zero. The in-code comment at run_standard.go:109-113
// states this gating MUST still apply in new-only mode ("otherwise CI
// runs with --new-only would pass on every active finding"), but the
// branch only called CheckSLAPolicy, dropping the violation gate.
//
// gateViolations is the smallest seam the fix introduces/uses to make
// the gating decision. Before the fix this file fails to compile
// (missing symbol), which is the RED signal.
func TestBugHunt_NewOnlyGate_BlocksNonCompliant(t *testing.T) {
	tests := []struct {
		name      string
		state     evaluation.SecurityState
		wantBlock bool
	}{
		{
			name:      "non-compliant blocks (exit 3)",
			state:     evaluation.StateNonCompliant,
			wantBlock: true,
		},
		{
			name:      "compliant does not block",
			state:     evaluation.StateCompliant,
			wantBlock: false,
		},
		{
			name:      "at-risk is advisory, does not block under default policy",
			state:     evaluation.StateAtRisk,
			wantBlock: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := EvaluateResult{SecurityState: tc.state}
			err := gateViolations(res)
			if tc.wantBlock {
				if !errors.Is(err, ui.ErrViolationsFound) {
					t.Fatalf("state %s: expected ErrViolationsFound, got: %v", tc.state, err)
				}
			} else if err != nil {
				t.Fatalf("state %s: expected nil gating error, got: %v", tc.state, err)
			}
		})
	}
}

// TestBugHunt_NewOnlyGate_MatchesReportApply locks the new-only gating
// decision to the standard path's ReportApply decision so the two
// modes can never drift: for any security state, gateViolations must
// return a violation iff ReportApply(default policy) does.
func TestBugHunt_NewOnlyGate_MatchesReportApply(t *testing.T) {
	states := []evaluation.SecurityState{
		evaluation.StateCompliant,
		evaluation.StateAtRisk,
		evaluation.StateNonCompliant,
	}

	for _, state := range states {
		res := EvaluateResult{SecurityState: state}

		// Standard-path decision via ReportApply with a discarding,
		// quiet reporter (output is irrelevant; only the error matters).
		rep := &Reporter{Quiet: true}
		standardViolation := errors.Is(
			rep.ReportApply(res, evaluation.EnforcementPolicy{}),
			ui.ErrViolationsFound,
		)

		newOnlyViolation := errors.Is(gateViolations(res), ui.ErrViolationsFound)

		if standardViolation != newOnlyViolation {
			t.Fatalf("state %s: standard-path violation=%v but new-only gate violation=%v; modes must agree",
				state, standardViolation, newOnlyViolation)
		}
	}
}
