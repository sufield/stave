package catalogquality

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestAnalyze_MissingFieldDetected(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       "ctl-complete",
			Severity: policy.SeverityCritical,
			Remediation: policy.NewRemediationSpec(
				"Fix it", "run terraform apply", "",
			),
			Compliance: policy.ComplianceMapping{"hipaa": "164.312(a)"},
			Params:     policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
		},
		{
			ID:       "ctl-incomplete",
			Severity: policy.SeverityNone, // missing severity
			// no remediation, no compliance, no attack_stage
		},
	}

	report := Analyze(Input{
		Controls:   controls,
		AssetTypes: map[kernel.AssetType]int{},
	})

	if report.TotalControls != 2 {
		t.Fatalf("expected 2 controls, got %d", report.TotalControls)
	}

	// severity: 1 present (Critical), 1 missing (None)
	sev := report.Completeness[FieldSeverity]
	if sev.Present != 1 || sev.Missing != 1 {
		t.Errorf("severity: present=%d missing=%d, want 1/1", sev.Present, sev.Missing)
	}

	// remediation.action: 1 present, 1 missing
	rem := report.Completeness[FieldRemediationAction]
	if rem.Present != 1 || rem.Missing != 1 {
		t.Errorf("remediation.action: present=%d missing=%d, want 1/1", rem.Present, rem.Missing)
	}

	if report.OverallPct >= 100 {
		t.Errorf("expected overall pct below 100, got %v", report.OverallPct)
	}
}

func TestAnalyze_BlindSpotIdentified(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       "s3-ctl",
			Domain:   "s3_bucket",
			Severity: policy.SeverityHigh,
		},
	}

	report := Analyze(Input{
		Controls: controls,
		AssetTypes: map[kernel.AssetType]int{
			"s3_bucket":       5,
			"lambda_function": 3, // no controls cover this
		},
	})

	if len(report.BlindSpots) != 1 {
		t.Fatalf("expected 1 blind spot, got %d", len(report.BlindSpots))
	}
	if report.BlindSpots[0].AssetType != "lambda_function" {
		t.Errorf("expected blind spot for lambda_function, got %q", report.BlindSpots[0].AssetType)
	}
	if report.BlindSpots[0].AssetCount != 3 {
		t.Errorf("expected 3 assets, got %d", report.BlindSpots[0].AssetCount)
	}
}

func TestBlindSpots_CollectionMethods(t *testing.T) {
	bs := BlindSpots{
		{AssetType: "aws_lambda_function", AssetCount: 3},
		{AssetType: "aws_sqs_queue", AssetCount: 7},
	}

	if bs.Len() != 2 {
		t.Errorf("bs.Len() = %d, want 2", bs.Len())
	}

	found := bs.ByAssetType("aws_sqs_queue")
	if found == nil || found.AssetCount != 7 {
		t.Errorf("ByAssetType = %v, want asset count 7", found)
	}

	if bs.TotalUncoveredAssets() != 10 {
		t.Errorf("TotalUncoveredAssets = %d, want 10", bs.TotalUncoveredAssets())
	}
}

func TestAttackStages_DomainMethods(t *testing.T) {
	stages := AttackStages{"initial_access", "exfiltration"}

	if stages.Len() != 2 {
		t.Errorf("stages.Len() = %d, want 2", stages.Len())
	}

	if !stages.Contains("initial_access") {
		t.Errorf("Contains(initial_access) = false, want true")
	}

	if stages.Contains("persistence") {
		t.Errorf("Contains(persistence) = true, want false")
	}

	var empty AttackStages
	if empty.Len() != 0 || empty.Contains("initial_access") {
		t.Errorf("empty AttackStages methods failed")
	}
}

func TestQualityPercentage_DomainMethods(t *testing.T) {
	qp := QualityPercentage(85.5)

	if qp.Value() != 85.5 {
		t.Errorf("Value() = %f, want 85.5", qp.Value())
	}
	if !qp.IsHighQuality() {
		t.Error("IsHighQuality() = false, want true for 85.5%")
	}
	if QualityPercentage(65.0).IsHighQuality() {
		t.Error("IsHighQuality() = true, want false for 65.0%")
	}
	if gap := qp.Gap(); gap != 14.5 {
		t.Errorf("Gap() = %f, want 14.5", gap)
	}
	if gap := QualityPercentage(100.0).Gap(); gap != 0.0 {
		t.Errorf("Gap() for 100%% = %f, want 0.0", gap)
	}
}

func TestFieldStat_DomainMethods(t *testing.T) {
	// Zero/empty
	var empty FieldStat
	if empty.Total() != 0 {
		t.Errorf("empty.Total() = %d, want 0", empty.Total())
	}
	if empty.Percentage() != 0.0 {
		t.Errorf("empty.Percentage() = %f, want 0.0", empty.Percentage())
	}
	if empty.IsComplete() {
		t.Errorf("empty.IsComplete() = true, want false")
	}
	if empty.HasMissing() {
		t.Errorf("empty.HasMissing() = true, want false")
	}

	// Complete
	complete := FieldStat{Present: 10, Missing: 0}
	if complete.Total() != 10 {
		t.Errorf("complete.Total() = %d, want 10", complete.Total())
	}
	if complete.Percentage() != 100.0 {
		t.Errorf("complete.Percentage() = %f, want 100.0", complete.Percentage())
	}
	if !complete.IsComplete() {
		t.Errorf("complete.IsComplete() = false, want true")
	}
	if complete.HasMissing() {
		t.Errorf("complete.HasMissing() = true, want false")
	}

	// Partial
	partial := FieldStat{Present: 3, Missing: 1}
	if partial.Total() != 4 {
		t.Errorf("partial.Total() = %d, want 4", partial.Total())
	}
	if partial.Percentage() != 75.0 {
		t.Errorf("partial.Percentage() = %f, want 75.0", partial.Percentage())
	}
	if partial.IsComplete() {
		t.Errorf("partial.IsComplete() = true, want false")
	}
	if !partial.HasMissing() {
		t.Errorf("partial.HasMissing() = false, want true")
	}
}

func TestFieldCompleteness_DomainMethods(t *testing.T) {
	fc := FieldCompleteness{
		FieldSeverity:          FieldStat{Present: 4, Missing: 0},
		FieldCompliance:        FieldStat{Present: 2, Missing: 2},
		FieldAttackStage:       FieldStat{Present: 0, Missing: 4},
		FieldRemediationAction: FieldStat{Present: 4, Missing: 0},
	}

	// ForField
	sev := fc.ForField(FieldSeverity)
	if sev.Present != 4 || sev.Missing != 0 {
		t.Errorf("ForField(FieldSeverity) = %+v, want 4/0", sev)
	}
	unknown := fc.ForField("unknown_field")
	if unknown.Total() != 0 {
		t.Errorf("ForField(unknown) = %+v, want empty", unknown)
	}
	var nilFC FieldCompleteness
	if nilFC.ForField(FieldSeverity).Total() != 0 {
		t.Errorf("nilFC.ForField() should return empty stat")
	}

	// SortedFields
	sorted := fc.SortedFields()
	expectedOrder := []MetadataField{
		FieldAttackStage,
		FieldCompliance,
		FieldRemediationAction,
		FieldSeverity,
	}
	if len(sorted) != len(expectedOrder) {
		t.Fatalf("SortedFields len = %d, want %d", len(sorted), len(expectedOrder))
	}
	for i, f := range expectedOrder {
		if sorted[i] != f {
			t.Errorf("SortedFields[%d] = %q, want %q", i, sorted[i], f)
		}
	}
	if nilFC.SortedFields() != nil {
		t.Error("nilFC.SortedFields() should return nil")
	}

	// AllComplete
	if fc.AllComplete() {
		t.Error("fc.AllComplete() = true, want false")
	}
	allGood := FieldCompleteness{
		FieldSeverity:   FieldStat{Present: 5, Missing: 0},
		FieldCompliance: FieldStat{Present: 5, Missing: 0},
	}
	if !allGood.AllComplete() {
		t.Error("allGood.AllComplete() = false, want true")
	}
	if nilFC.AllComplete() {
		t.Error("nilFC.AllComplete() = true, want false")
	}

	// CompletenessPercentage: 10 present out of 16 total = 62.5%
	pct := fc.CompletenessPercentage()
	if pct.Value() != 62.5 {
		t.Errorf("CompletenessPercentage() = %f, want 62.5", pct.Value())
	}
	if nilFC.CompletenessPercentage().Value() != 0.0 {
		t.Errorf("nilFC.CompletenessPercentage() = %f, want 0.0", nilFC.CompletenessPercentage().Value())
	}
}
