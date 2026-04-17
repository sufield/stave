package oscillation

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
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
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctlID),
			AssetID:         asset.ID(astID),
			ControlSeverity: policy.SeverityHigh,
		},
	}
}

func TestClassify_ChronicAtHighFailureRate(t *testing.T) {
	// 9 out of 10 assessments have the finding -> >80% failure rate -> chronic
	var assessments []report.Assessment
	for i := 0; i < 10; i++ {
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
		AssetID:         "asset-a",
		MinOscillations: 3,
	})

	if result.Pattern != "chronic" {
		t.Errorf("expected pattern 'chronic', got %q", result.Pattern)
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
		AssetID:         "asset-a",
		MinOscillations: 3,
	})

	if result.Pattern != "deploy-time" {
		t.Errorf("expected pattern 'deploy-time', got %q", result.Pattern)
	}
	// 7 transitions in 8 assessments -> cycles=7
	if result.Cycles < 3 {
		t.Errorf("expected at least 3 cycles, got %d", result.Cycles)
	}
}
