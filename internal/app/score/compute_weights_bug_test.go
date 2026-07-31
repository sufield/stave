package score

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestCompute_UninitializedWeightsFallsBackToDefault(t *testing.T) {
	// A completely clean posture (0 findings, 100% coverage, 0 SLA breaches)
	input := Input{
		Findings:      []remediation.Finding{},
		CoveragePct:   100.0,
		HasCoverage:   true,
		Weights:       Weights{}, // zero-value uninitialized weights
		GeneratedAt:   time.Now(),
	}

	res := Compute(input)

	// Clean posture with uninitialized weights should score 100.0 (using DefaultWeights), NOT 0.0 ("critical")
	if res.Score != 100.0 {
		t.Errorf("expected posture score 100.0 for clean input with uninitialized weights, got %.1f (band %s)", res.Score, res.RubricBand)
	}
}
