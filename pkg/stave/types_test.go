package stave_test

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/pkg/stave"
)

// The identity assertions below compile only when the library's
// typed IDs are aliases of the internal types rather than distinct
// copies. Aliases share identity; copies would require explicit
// conversion at every boundary — the whole primitive-obsession
// reduction turns on this.

func takesInternalControlID(kernel.ControlID)             {}
func takesInternalAssetID(asset.ID)                       {}
func takesInternalClassification(policy.Classification)   {}
func takesInternalIssue(evaluation.Issue)                 {}
func takesInternalMatchedClause(evaluation.MatchedClause) {}

func TestTypeAliasesShareIdentity(t *testing.T) {
	takesInternalControlID(stave.ControlID("CTL.TEST.001"))
	takesInternalAssetID(stave.AssetID("bucket-1"))
	takesInternalClassification(stave.StateAssertion)
	takesInternalIssue(stave.Issue{IssueID: "x", AssetID: "a"})
	takesInternalMatchedClause(stave.MatchedClause{ObservationKey: "k", Operator: "eq"})
}

// TestClassificationConstants confirms the library's string values
// match the internal engine's enum.
func TestClassificationConstants(t *testing.T) {
	cases := map[stave.Classification]string{
		stave.StateAssertion:     "state_assertion",
		stave.ParameterizedCheck: "parameterized_check",
		stave.AbsenceCheck:       "absence_check",
		stave.AggregateCheck:     "aggregate_check",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("Classification mismatch: %q != %q", got, want)
		}
	}
}

// TestSeverityConstants confirms the library's severity strings
// match the engine's canonical names.
func TestSeverityConstants(t *testing.T) {
	cases := map[stave.Severity]string{
		stave.SeverityInfo:     "info",
		stave.SeverityLow:      "low",
		stave.SeverityMedium:   "medium",
		stave.SeverityHigh:     "high",
		stave.SeverityCritical: "critical",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("Severity mismatch: %q != %q", got, want)
		}
	}
}

// TestStatusConstants confirms Status values match the engine's
// SecurityState enum.
func TestStatusConstants(t *testing.T) {
	cases := map[stave.Status]evaluation.SecurityState{
		stave.StatusCompliant:    evaluation.StateCompliant,
		stave.StatusAtRisk:       evaluation.StateAtRisk,
		stave.StatusNonCompliant: evaluation.StateNonCompliant,
	}
	for got, want := range cases {
		if string(got) != string(want) {
			t.Errorf("Status mismatch: %q != %q", got, want)
		}
	}
}
