package fieldcov

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestClassify_Evaluable(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.001",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq},
			},
		},
	}
	fields := map[string]struct{}{"properties.storage.kind": {}}
	result := classifyControl(&ctl, fields, nil)
	if result.Classification != Evaluable {
		t.Errorf("classification = %q, want EVALUABLE", result.Classification)
	}
}

func TestClassify_SilentRisk_UnguardedField(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.002",
		Severity: policy.SeverityCritical,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.encryption.enabled"), Op: predicate.OpEq},
			},
		},
	}
	// Field is NOT present in snapshot.
	fields := map[string]struct{}{"properties.storage.kind": {}}
	result := classifyControl(&ctl, fields, nil)
	if result.Classification != SilentRisk {
		t.Errorf("classification = %q, want SILENT_RISK", result.Classification)
	}
	if len(result.MissingFields) != 1 {
		t.Fatalf("expected 1 missing field, got %d", len(result.MissingFields))
	}
	if result.MissingFields[0] != "properties.encryption.enabled" {
		t.Errorf("missing field = %q, want properties.encryption.enabled", result.MissingFields[0])
	}
}

func TestClassify_Incomplete_MissingOperator(t *testing.T) {
	// A predicate using "missing" operator is NOT silent-risk —
	// it explicitly checks for absence.
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.003",
		Severity: policy.SeverityMedium,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.tags.env"), Op: predicate.OpMissing},
			},
		},
	}
	fields := map[string]struct{}{"properties.storage.kind": {}}
	result := classifyControl(&ctl, fields, nil)
	if result.Classification != Incomplete {
		t.Errorf("classification = %q, want INCOMPLETE (missing op is not silent-risk)", result.Classification)
	}
}

func TestClassify_NoPredicate(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.004",
		Severity: policy.SeverityLow,
	}
	fields := map[string]struct{}{}
	result := classifyControl(&ctl, fields, nil)
	if result.Classification != Evaluable {
		t.Errorf("classification = %q, want EVALUABLE (no predicate)", result.Classification)
	}
}

func TestCollectPresentFields(t *testing.T) {
	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Properties: map[string]any{
						"storage": map[string]any{
							"kind": "bucket",
							"encryption": map[string]any{
								"enabled": true,
							},
						},
					},
				},
			},
		},
	}
	fields := collectPresentFields(snapshots)
	expected := []string{
		"properties.storage",
		"properties.storage.kind",
		"properties.storage.encryption",
		"properties.storage.encryption.enabled",
	}
	for _, e := range expected {
		if _, ok := fields[e]; !ok {
			t.Errorf("expected field %q to be present", e)
		}
	}
}

func TestAnalyze_FrameworkCoverage(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       "CTL.A.001",
			Severity: policy.SeverityHigh,
			Compliance: policy.ComplianceMapping{
				"hipaa": "164.312",
			},
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.x.y"), Op: predicate.OpEq},
				},
			},
		},
		{
			ID:       "CTL.B.001",
			Severity: policy.SeverityMedium,
			Compliance: policy.ComplianceMapping{
				"hipaa": "164.308",
			},
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.x.y"), Op: predicate.OpEq},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{Properties: map[string]any{"x": map[string]any{"y": true}}},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  controls,
		Snapshots: snapshots,
	})

	if report.Summary.Evaluable != 2 {
		t.Errorf("evaluable = %d, want 2", report.Summary.Evaluable)
	}

	fc, ok := report.FrameworkCoverage["hipaa"]
	if !ok {
		t.Fatal("expected hipaa in framework coverage")
	}
	if fc.Evaluable != 2 || fc.Total != 2 {
		t.Errorf("hipaa coverage = %d/%d, want 2/2", fc.Evaluable, fc.Total)
	}
	if fc.CoveragePct != 100.0 {
		t.Errorf("hipaa coverage_pct = %.1f, want 100.0", fc.CoveragePct)
	}
}
