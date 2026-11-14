package eval

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	appcontracts "github.com/sufield/stave/internal/core/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

func TestPrepareFindings_NilEnricher(t *testing.T) {
	_, err := PrepareFindings(nil, nil, &evaluation.ComplianceReport{})
	if err == nil || !strings.Contains(err.Error(), "must not be nil") {
		t.Fatalf("expected must not be nil error, got: %v", err)
	}
}

func TestSanitizeFindings_WithSanitizer(t *testing.T) {
	findings := []remediation.Finding{
		{AssetID: "res-1"},
		{AssetID: "res-2"},
	}
	s := sanitize.New(sanitize.WithIDSanitization(true))
	result := SanitizeFindings(s, findings)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	// IDs should be sanitized (not equal to originals)
	if result[0].AssetID == "res-1" {
		t.Error("expected sanitized asset ID")
	}
}

func TestSanitizeInputHashKeys_Nil(t *testing.T) {
	result := SanitizeInputHashKeys(nil, nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestSanitizeExemptedAssets_Empty(t *testing.T) {
	result := SanitizeExemptedAssets(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

func TestEnrich_NilSanitizer(t *testing.T) {
	enricher := remediation.NewPlanner()
	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			EvalTime:          time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			EvaluatedState:    "deployed",
		},
		ExemptedAssets: []asset.ExemptedAsset{
			{ID: "res-1", Reason: "test"},
		},
	}
	enriched, err := Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}
	if len(enriched.ExemptedAssets) != 1 {
		t.Errorf("ExemptedAssets = %v", enriched.ExemptedAssets)
	}
}

func TestOutputPipeline_Run_Success(t *testing.T) {
	var buf bytes.Buffer
	pipeline := &OutputPipeline{
		Marshaler: &marshalerStub{},
		Enricher: func(result *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{Result: *result}, nil
		},
	}
	result := evaluation.ComplianceReport{Summary: evaluation.ComplianceSummary{Violations: 0}}
	err := pipeline.Run(context.Background(), &buf, &result)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestOutputPipeline_Run_EnrichError(t *testing.T) {
	var buf bytes.Buffer
	pipeline := &OutputPipeline{
		Marshaler: &marshalerStub{},
		Enricher: func(_ *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{}, errors.New("enrich failed")
		},
	}
	err := pipeline.Run(context.Background(), &buf, &evaluation.ComplianceReport{})
	if err == nil || !strings.Contains(err.Error(), "enrich") {
		t.Fatalf("expected enrich error, got: %v", err)
	}
}

func TestOutputPipeline_Run_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	var buf bytes.Buffer
	pipeline := &OutputPipeline{
		Marshaler: &marshalerStub{},
		Enricher: func(result *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{Result: *result}, nil
		},
	}
	err := pipeline.Run(ctx, &buf, &evaluation.ComplianceReport{})
	if err == nil {
		t.Fatal("expected context cancelled error")
	}
}

func TestRunDirectoryEvaluation_NilLoader(t *testing.T) {
	_, _, err := RunDirectoryEvaluation(context.Background(), DirectoryEvaluationRequest{})
	if err == nil || !strings.Contains(err.Error(), "observation loader is required") {
		t.Fatalf("expected nil loader error, got: %v", err)
	}
}
