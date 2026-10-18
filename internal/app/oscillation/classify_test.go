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

func TestFailureRate_DomainMethods(t *testing.T) {
	fr := FailureRate(0.85)

	if fr.Value() != 0.85 {
		t.Errorf("Value() = %f, want 0.85", fr.Value())
	}
	if fr.Percentage() != 85.0 {
		t.Errorf("Percentage() = %f, want 85.0", fr.Percentage())
	}
	if !fr.IsChronic() {
		t.Error("IsChronic() = false, want true for 0.85")
	}
	if FailureRate(0.5).IsChronic() {
		t.Error("IsChronic() = true, want false for 0.5")
	}
	if !FailureRate(0.0).IsClean() {
		t.Error("IsClean() = false, want true for 0.0")
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
		{ControlID: "ctl-1", AssetID: "ast-1", Pattern: PatternChronic, Confidence: 0.9, Cycles: 0},
		{ControlID: "ctl-2", AssetID: "ast-1", Pattern: PatternDeployTime, Confidence: 0.4, Cycles: 4},
		{ControlID: "ctl-1", AssetID: "ast-2", Pattern: PatternChronic, Confidence: 0.85, Cycles: 0},
	}

	if cs.Len() != 3 {
		t.Errorf("cs.Len() = %d, want 3", cs.Len())
	}

	if cs.FilterByPattern(PatternChronic).Len() != 2 {
		t.Errorf("FilterByPattern len = %d, want 2", cs.FilterByPattern(PatternChronic).Len())
	}

	if cs.Chronic().Len() != 2 {
		t.Errorf("Chronic len = %d, want 2", cs.Chronic().Len())
	}

	if cs.DeployTime().Len() != 1 {
		t.Errorf("DeployTime len = %d, want 1", cs.DeployTime().Len())
	}

	if cs.ByControlID("ctl-1").Len() != 2 {
		t.Errorf("ByControlID(ctl-1) len = %d, want 2", cs.ByControlID("ctl-1").Len())
	}

	if cs.ByAssetID("ast-1").Len() != 2 {
		t.Errorf("ByAssetID(ast-1) len = %d, want 2", cs.ByAssetID("ast-1").Len())
	}

	if cs.HighConfidence(0.8).Len() != 2 {
		t.Errorf("HighConfidence len = %d, want 2", cs.HighConfidence(0.8).Len())
	}

	var empty Classifications
	if empty.Len() != 0 || empty.Chronic() != nil || empty.DeployTime() != nil || empty.ByControlID("ctl-1") != nil || empty.ByAssetID("ast-1") != nil {
		t.Error("empty Classifications methods failed")
	}
}

func TestPattern_DomainMethods(t *testing.T) {
	if !PatternDeployTime.IsDeployTime() || PatternDeployTime.IsChronic() || PatternDeployTime.IsRandom() || PatternDeployTime.IsSeasonal() {
		t.Error("PatternDeployTime checks failed")
	}
	if !PatternRandom.IsRandom() || PatternRandom.IsDeployTime() {
		t.Error("PatternRandom checks failed")
	}
	if !PatternChronic.IsChronic() || PatternChronic.IsSeasonal() {
		t.Error("PatternChronic checks failed")
	}
	if !PatternSeasonal.IsSeasonal() || PatternSeasonal.IsChronic() {
		t.Error("PatternSeasonal checks failed")
	}
	if PatternDeployTime.String() != "deploy-time" {
		t.Errorf("String() = %q, want deploy-time", PatternDeployTime.String())
	}
}

func TestClassification_DomainMethods(t *testing.T) {
	c1 := Classification{
		Pattern:    PatternChronic,
		Confidence: 0.85,
		Cycles:     0,
	}
	if !c1.IsChronic() || c1.IsDeployTime() || c1.HasOscillations() {
		t.Error("c1 domain checks failed")
	}
	if !c1.IsHighConfidence(0.8) || c1.IsHighConfidence(0.9) {
		t.Error("c1 IsHighConfidence failed")
	}

	c2 := Classification{
		Pattern:    PatternDeployTime,
		Confidence: 0.6,
		Cycles:     4,
	}
	if c2.IsChronic() || !c2.IsDeployTime() || !c2.HasOscillations() {
		t.Error("c2 domain checks failed")
	}
}
