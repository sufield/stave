package oscillation

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func assessmentWith(findings ...remediation.Finding) report.Assessment {
	return report.Assessment{
		Findings: findings,
	}
}

func mkFinding(ctlID string, astID string) remediation.Finding {
	return remediation.Finding{
		ControlID:       kernel.ControlID(ctlID),
		AssetID:         asset.ID(astID),
		ControlSeverity: policy.SeverityHigh,
	}
}

func TestClassify_ChronicAtHighFailureRate(t *testing.T) {
	// 9 out of 10 assessments have the finding -> >80% failure rate -> chronic
	var assessments []report.Assessment
	for i := range 10 {
		if i == 5 {
			// One assessment without the finding.
			assessments = append(assessments, assessmentWith())
		} else {
			assessments = append(assessments, assessmentWith(
				mkFinding("ctl-1", "asset-a"),
			))
		}
	}

	result := Classify(Input{
		Assessments:     assessments,
		ControlID:       "ctl-1",
		AssetID:         asset.ID("asset-a"),
		MinOscillations: 3,
	})

	if result.Pattern != PatternChronic {
		t.Errorf("expected pattern %q, got %q", PatternChronic, result.Pattern)
	}
	if result.FailureRate != 0.9 {
		t.Errorf("expected failure rate 0.9, got %v", result.FailureRate)
	}
	if result.Confidence < 0.8 {
		t.Errorf("expected high confidence, got %v", result.Confidence)
	}
}

func TestClassify_DeployTimeDetected(t *testing.T) {
	// Alternating pass/fail pattern with enough cycles.
	assessments := []report.Assessment{
		assessmentWith(mkFinding("ctl-1", "asset-a")),
		assessmentWith(), // pass
		assessmentWith(mkFinding("ctl-1", "asset-a")),
		assessmentWith(), // pass
		assessmentWith(mkFinding("ctl-1", "asset-a")),
		assessmentWith(), // pass
		assessmentWith(mkFinding("ctl-1", "asset-a")),
		assessmentWith(), // pass
	}

	result := Classify(Input{
		Assessments:     assessments,
		ControlID:       "ctl-1",
		AssetID:         asset.ID("asset-a"),
		MinOscillations: 3,
	})

	if result.Pattern != PatternDeployTime {
		t.Errorf("expected pattern %q, got %q", PatternDeployTime, result.Pattern)
	}
	// 7 transitions in 8 assessments -> cycles=7
	if result.Cycles < 3 {
		t.Errorf("expected at least 3 cycles, got %d", result.Cycles)
	}
}

func TestClassifications_CollectionMethods(t *testing.T) {
	cs := Classifications{
		{Pattern: PatternChronic, Confidence: 0.9},
		{Pattern: PatternDeployTime, Confidence: 0.4},
		{Pattern: PatternChronic, Confidence: 0.85},
	}

	if cs.Len() != 3 {
		t.Errorf("cs.Len() = %d, want 3", cs.Len())
	}

	if cs.FilterByPattern(PatternChronic).Len() != 2 {
		t.Errorf("FilterByPattern len = %d, want 2", cs.FilterByPattern(PatternChronic).Len())
	}

	if cs.HighConfidence(0.8).Len() != 2 {
		t.Errorf("HighConfidence len = %d, want 2", cs.HighConfidence(0.8).Len())
	}
}
