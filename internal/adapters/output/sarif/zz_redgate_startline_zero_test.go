package sarif

import (
	"encoding/json"
	"testing"
	"time"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Test_RedGate_StartLineZero asserts the CORRECT behavior: a finding
// whose Source carries a file but a zero Line (e.g. observation asset
// JSON contains "source": {"file": "main.tf"} with line omitted) must
// NOT emit a SARIF physicalLocation region with "startLine": 0.
//
// SARIF v2.1.0 §3.30.6 requires region.startLine to be a positive
// integer (minimum 1); 0 is invalid and SARIF validators / GitHub
// Code Scanning reject the run. buildLocations
// (finding_writer.go:291) gates only on f.HasSource() (a nil-check,
// finding.go:842) and the sarifRegion.StartLine json tag lacks
// omitempty (finding_types.go:69), so Line==0 serializes as
// "startLine": 0.
func Test_RedGate_StartLineZero(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()

	w := NewFindingWriter()
	enricher := remediation.NewPlanner()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.2.0",
			Now:               now,
			MaxUnsafeDuration: kernel.Duration(12 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "S3 Bucket Public Access",
				ControlDescription: "S3 bucket has public access enabled",
				ControlSeverity:    policy.SeverityHigh,
				AssetID:            "arn:aws:s3:::mybucket",
				AssetType:          "aws_s3_bucket",
				AssetVendor:        "aws",
				// Source object has a file but NO line — Line defaults
				// to 0. Mirrors observation JSON "source":{"file":...}.
				Source: &asset.SourceRef{File: "main.tf"},
			},
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0].(map[string]any)
	locations := r["locations"].([]any)
	loc := locations[0].(map[string]any)

	physLoc, ok := loc["physicalLocation"].(map[string]any)
	if !ok {
		// No physicalLocation at all (e.g. logicalLocation fallback)
		// would also satisfy SARIF validity for a line-less source.
		return
	}
	region, ok := physLoc["region"].(map[string]any)
	if !ok {
		// A physicalLocation with no region is valid for SARIF.
		return
	}

	startLineRaw, present := region["startLine"]
	if !present {
		// startLine absent (omitempty) is valid — nothing to assert.
		return
	}
	startLine, ok := startLineRaw.(float64)
	if !ok {
		t.Fatalf("region.startLine has unexpected type %T: %v", startLineRaw, startLineRaw)
	}

	// SARIF v2.1.0 §3.30.6: region.startLine MUST be a positive
	// integer (minimum 1). A value of 0 is invalid.
	if startLine < 1 {
		t.Fatalf("region.startLine = %v, want >= 1 (SARIF v2.1.0 §3.30.6 requires a positive integer; 0 is rejected by validators)", startLine)
	}
}
