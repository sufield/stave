package eval

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/findings"
)

// stubEnricher returns its configured findings unchanged so the test
// controls finding shape directly. The package-level stubSanitizer
// from sanitize_actual_value_test.go is reused.
type stubEnricher struct{ findings []remediation.Finding }

func (e *stubEnricher) EnrichFindings(*evaluation.ComplianceReport) []remediation.Finding {
	return e.findings
}

func (e *stubEnricher) EnrichMarkerFindings(*evaluation.ComplianceReport) []remediation.Finding {
	return nil
}

func (e *stubEnricher) EnrichIndeterminateFindings(*evaluation.ComplianceReport) []remediation.Finding {
	return nil
}

// TestEnrich_SanitizesReasoningTraceAndDelta verifies that
// ReasoningTrace observed values and DeltaPath current values flow
// through the per-field Sanitizer when --sanitize is on. Without
// this, the DTO mapper would copy the raw values into output
// because ReasoningTrace and Delta are built before sanitization
// runs in the engine pipeline.
func TestEnrich_SanitizesReasoningTraceAndDelta(t *testing.T) {
	enricher := &stubEnricher{
		findings: []remediation.Finding{
			{
				AssetID: asset.ID("arn:aws:s3:::bucket"),
				ReasoningTrace: []evaluation.MatchedClause{
					{ObservedValue: "arn:aws:iam::123:role/admin"},
				},
				Delta: []policy.DeltaPath{
					{CurrentValue: "arn:aws:s3:::secret-bucket"},
				}},
		},
	}
	res := &evaluation.ComplianceReport{}
	enriched, err := Enrich(enricher, stubSanitizer{}, res)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(enriched.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(enriched.Findings))
	}
	f := enriched.Findings[0]
	if got := f.ReasoningTrace[0].ObservedValue.(string); got != "VAL:arn:aws:iam::123:role/admin" {
		t.Errorf("ReasoningTrace ObservedValue = %q, want VAL:-prefixed", got)
	}
	if got := f.Delta[0].CurrentValue; got != "VAL:arn:aws:s3:::secret-bucket" {
		t.Errorf("Delta CurrentValue = %q, want VAL:-prefixed", got)
	}
}

// TestEnrich_SanitizesSidecars verifies that --sanitize masks asset
// identifiers across the sidecar collections (RiskSignals,
// TopExposures) plus the resolved-paths metadata.
func TestEnrich_SanitizesSidecars(t *testing.T) {
	enricher := &stubEnricher{findings: nil}
	res := &evaluation.ComplianceReport{
		RiskSignals: findings.ThresholdItems{
			{AssetID: asset.ID("arn:aws:s3:::risky"), DueAt: time.Now()},
		},
		TopExposures: []findings.ExposureRank{
			{AssetID: asset.ID("arn:aws:s3:::top"), ExposureScore: 1},
		},
		Metadata: evaluation.Metadata{
			ResolvedPaths: evaluation.ResolvedPaths{
				Controls:     "/abs/path/controls",
				Observations: "/abs/path/observations",
			},
		},
	}
	enriched, err := Enrich(enricher, stubSanitizer{}, res)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if got := string(enriched.Result.RiskSignals[0].AssetID); got != "ID:arn:aws:s3:::risky" {
		t.Errorf("RiskSignals AssetID = %q, want ID:-prefixed", got)
	}
	if got := string(enriched.Result.TopExposures[0].AssetID); got != "ID:arn:aws:s3:::top" {
		t.Errorf("TopExposures AssetID = %q, want ID:-prefixed", got)
	}
	if got := enriched.Result.Metadata.ResolvedPaths.Controls; got != "PATH:/abs/path/controls" {
		t.Errorf("ResolvedPaths.Controls = %q, want PATH:-prefixed", got)
	}
	if got := enriched.Result.Metadata.ResolvedPaths.Observations; got != "PATH:/abs/path/observations" {
		t.Errorf("ResolvedPaths.Observations = %q, want PATH:-prefixed", got)
	}

	// The original input must not be mutated.
	if got := string(res.RiskSignals[0].AssetID); got != "arn:aws:s3:::risky" {
		t.Errorf("input mutated: original RiskSignals AssetID = %q, want untouched", got)
	}
	if got := res.Metadata.ResolvedPaths.Controls; got != "/abs/path/controls" {
		t.Errorf("input mutated: original ResolvedPaths.Controls = %q, want untouched", got)
	}
}
