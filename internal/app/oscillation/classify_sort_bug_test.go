package oscillation

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

func TestClassify_UnsortedInputSortsChronologically(t *testing.T) {
	ast := "ast-1"

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)

	// Chronological sequence: Fail (t0) -> Pass (t1) -> Fail (t2) -> Pass (t3)
	// That is 3 transitions (fail->pass, pass->fail, fail->pass), i.e. 3 cycles.
	a0 := report.Assessment{Run: evaluation.RunInfo{EvalTime: t0}, Findings: []remediation.Finding{{ControlID: "CTL.S3.001", AssetID: asset.ID("ast-1")}}}
	a1 := report.Assessment{Run: evaluation.RunInfo{EvalTime: t1}, Findings: nil}
	a2 := report.Assessment{Run: evaluation.RunInfo{EvalTime: t2}, Findings: []remediation.Finding{{ControlID: "CTL.S3.001", AssetID: asset.ID("ast-1")}}}
	a3 := report.Assessment{Run: evaluation.RunInfo{EvalTime: t3}, Findings: nil}

	// Pass in reversed / unsorted order: a3, a0, a2, a1
	unsorted := []report.Assessment{a3, a0, a2, a1}

	c := Classify(Input{
		Assessments:     unsorted,
		ControlID:       "CTL.S3.001",
		AssetID:         asset.ID(ast),
		MinOscillations: 3,
	})

	// Must sort input chronologically, counting 3 cycles
	if c.Cycles != 3 {
		t.Fatalf("expected 3 cycles when sorted chronologically, got %d", c.Cycles)
	}
}
