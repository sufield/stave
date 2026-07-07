package exemptionsuggest

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func finding(ctl string, ast string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			AssetID:         asset.ID(ast),
			ControlSeverity: sev,
		},
	}
}

func assessment(t time.Time, findings ...remediation.Finding) *report.Assessment {
	return &report.Assessment{
		Run:      evaluation.RunInfo{EvalTime: t},
		Findings: findings,
	}
}

var (
	day  = 24 * time.Hour
	t0   = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	t1   = t0.Add(7 * day)
	t2   = t0.Add(14 * day)
	t3   = t0.Add(21 * day)
	t4   = t0.Add(28 * day)
	t5   = t0.Add(35 * day)
	tNow = t0.Add(40 * day)
)

func TestSuggest_OscillatingDetected(t *testing.T) {
	// Finding appears, disappears, reappears, disappears, reappears.
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "sg-abc", policy.SeverityCritical)), // present
		assessment(t1), // absent
		assessment(t2, finding("CTL.A.001", "sg-abc", policy.SeverityCritical)), // present
		assessment(t3), // absent
		assessment(t4, finding("CTL.A.001", "sg-abc", policy.SeverityCritical)), // present (latest)
	}

	result := Suggest(Input{
		History:  history,
		Window:   90 * day,
		MinDwell: 14 * day,
		EvalTime: t5,
	})

	if len(result.Oscillating) != 1 {
		t.Fatalf("oscillating = %d, want 1", len(result.Oscillating))
	}
	osc := result.Oscillating[0]
	if osc.ControlID != "CTL.A.001" {
		t.Errorf("control = %s, want CTL.A.001", osc.ControlID)
	}
	if osc.Cycles < 2 {
		t.Errorf("cycles = %d, want >= 2", osc.Cycles)
	}
	if osc.Pattern != PatternOscillating {
		t.Errorf("pattern = %s, want oscillating", osc.Pattern)
	}
}

func TestSuggest_ChronicThresholdRespected(t *testing.T) {
	// Finding open for 28 days. MinDwell = 14 days → should be chronic.
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "asset1", policy.SeverityHigh)),
		assessment(t1, finding("CTL.A.001", "asset1", policy.SeverityHigh)),
		assessment(t2, finding("CTL.A.001", "asset1", policy.SeverityHigh)),
		assessment(t3, finding("CTL.A.001", "asset1", policy.SeverityHigh)),
		assessment(t4, finding("CTL.A.001", "asset1", policy.SeverityHigh)),
	}

	result := Suggest(Input{
		History:  history,
		Window:   90 * day,
		MinDwell: 14 * day,
		EvalTime: tNow,
	})

	if len(result.Chronic) != 1 {
		t.Fatalf("chronic = %d, want 1", len(result.Chronic))
	}

	// With MinDwell = 45 days → should NOT be chronic (only 40 days old).
	result2 := Suggest(Input{
		History:  history,
		Window:   90 * day,
		MinDwell: 45 * day,
		EvalTime: tNow,
	})

	if len(result2.Chronic) != 0 {
		t.Errorf("chronic with 45d threshold = %d, want 0", len(result2.Chronic))
	}
}

func TestSuggest_ExemptedFindingsExcluded(t *testing.T) {
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "asset1", policy.SeverityCritical)),
		assessment(t4, finding("CTL.A.001", "asset1", policy.SeverityCritical)),
	}

	result := Suggest(Input{
		History:      history,
		Window:       90 * day,
		MinDwell:     14 * day,
		EvalTime:     tNow,
		ExemptedKeys: map[string]struct{}{"CTL.A.001@asset1": {}},
	})

	if len(result.Chronic) != 0 {
		t.Errorf("chronic = %d, want 0 (exempted)", len(result.Chronic))
	}
	if len(result.Oscillating) != 0 {
		t.Errorf("oscillating = %d, want 0 (exempted)", len(result.Oscillating))
	}
}

func TestSuggest_NoHistory_EmptyResult(t *testing.T) {
	result := Suggest(Input{
		Window:   30 * day,
		MinDwell: 14 * day,
		EvalTime: tNow,
	})

	if len(result.Oscillating) != 0 || len(result.Chronic) != 0 {
		t.Error("expected empty result with no history")
	}
}

func TestSuggest_ResolvedFindingsNotSuggested(t *testing.T) {
	// Finding present in t0 and t1, but absent in latest (t4).
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "asset1", policy.SeverityHigh)),
		assessment(t1, finding("CTL.A.001", "asset1", policy.SeverityHigh)),
		assessment(t4), // resolved
	}

	result := Suggest(Input{
		History:  history,
		Window:   90 * day,
		MinDwell: 7 * day,
		EvalTime: tNow,
	})

	if len(result.Chronic) != 0 {
		t.Errorf("chronic = %d, want 0 (resolved)", len(result.Chronic))
	}
}

func TestCountCycles(t *testing.T) {
	tests := []struct {
		name        string
		appearances []bool
		want        int
	}{
		{"no gap", []bool{true, true, true}, 0},
		{"one gap", []bool{true, false, true}, 1},
		{"two gaps", []bool{true, false, true, false, true}, 2},
		{"starts absent", []bool{false, true, false, true}, 1},
		{"all absent", []bool{false, false, false}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countCycles(tt.appearances)
			if got != tt.want {
				t.Errorf("countCycles(%v) = %d, want %d", tt.appearances, got, tt.want)
			}
		})
	}
}
