package sarif

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestNewFindingWriter_NilEnricher(t *testing.T) {
	_, err := NewFindingWriter(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil enricher")
	}
}

func TestWriteFindings_EmptyFindings(t *testing.T) {
	w, err := NewFindingWriter(remediation.NewMapper(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "0.1.0",
			Now:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafe:   kernel.Duration(12 * time.Hour),
			Snapshots:   2,
		},
	}

	if err := w.WriteFindings(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if sarif["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %v", sarif["version"])
	}

	runs := sarif["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(runs))
	}

	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestWriteFindings_SARIFStructure(t *testing.T) {
	w, err := NewFindingWriter(remediation.NewMapper(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	firstUnsafe := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)

	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "0.2.0",
			Now:         now,
			MaxUnsafe:   kernel.Duration(12 * time.Hour),
			Snapshots:   2,
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
				Source:             &asset.SourceRef{File: "main.tf", Line: 42},
				Evidence: evaluation.Evidence{
					FirstUnsafeAt:       firstUnsafe,
					UnsafeDurationHours: 24,
					ThresholdHours:      12,
					WhyNow:              "Unsafe for 24h (threshold: 12h)",
				},
				ControlRemediation: &policy.RemediationSpec{
					Description: "Disable public access",
					Action:      "Set block_public_access to true",
				},
			},
		},
	}

	if err := w.WriteFindings(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)

	// Check tool info
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	if driver["name"] != "stave" {
		t.Errorf("expected tool name 'stave', got %v", driver["name"])
	}
	if driver["version"] != "0.2.0" {
		t.Errorf("expected tool version '0.2.0', got %v", driver["version"])
	}

	// Check rules
	rules := driver["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	rule := rules[0].(map[string]any)
	if rule["id"] != "CTL.S3.PUBLIC.001" {
		t.Errorf("expected rule id CTL.S3.PUBLIC.001, got %v", rule["id"])
	}

	// Check results
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0].(map[string]any)
	if r["ruleId"] != "CTL.S3.PUBLIC.001" {
		t.Errorf("expected ruleId CTL.S3.PUBLIC.001, got %v", r["ruleId"])
	}
	if r["level"] != "error" {
		t.Errorf("expected level error, got %v", r["level"])
	}

	// Check physical location
	locations := r["locations"].([]any)
	loc := locations[0].(map[string]any)
	physLoc := loc["physicalLocation"].(map[string]any)
	artLoc := physLoc["artifactLocation"].(map[string]any)
	if artLoc["uri"] != "main.tf" {
		t.Errorf("expected uri main.tf, got %v", artLoc["uri"])
	}

	// Check fixes
	fixes := r["fixes"].([]any)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
}

func TestWriteFindings_RuleDeduplication(t *testing.T) {
	w, err := NewFindingWriter(remediation.NewMapper(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer

	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "0.1.0",
			Now:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafe:   kernel.Duration(12 * time.Hour),
			Snapshots:   2,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "S3 Bucket Public Access",
				ControlDescription: "S3 bucket has public access enabled",
				AssetID:            "arn:aws:s3:::bucket1",
				AssetType:          "aws_s3_bucket",
				AssetVendor:        "aws",
			},
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "S3 Bucket Public Access",
				ControlDescription: "S3 bucket has public access enabled",
				AssetID:            "arn:aws:s3:::bucket2",
				AssetType:          "aws_s3_bucket",
				AssetVendor:        "aws",
			},
			{
				ControlID:          "CTL.S3.ENCRYPT.001",
				ControlName:        "S3 Bucket Encryption",
				ControlDescription: "S3 bucket lacks encryption",
				AssetID:            "arn:aws:s3:::bucket1",
				AssetType:          "aws_s3_bucket",
				AssetVendor:        "aws",
			},
		},
	}

	if err := w.WriteFindings(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)

	// Should have 2 rules (deduplicated)
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("expected 2 rules (deduplicated), got %d", len(rules))
	}

	// Should have 3 results
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// Second result should reference rule index 0 (same control as first)
	r1 := results[1].(map[string]any)
	if r1["ruleIndex"] != float64(0) {
		t.Errorf("expected ruleIndex 0 for second result, got %v", r1["ruleIndex"])
	}

	// Third result should reference rule index 1 (different control)
	r2 := results[2].(map[string]any)
	if r2["ruleIndex"] != float64(1) {
		t.Errorf("expected ruleIndex 1 for third result, got %v", r2["ruleIndex"])
	}
}

func TestWriteFindings_LogicalLocation(t *testing.T) {
	w, err := NewFindingWriter(remediation.NewMapper(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer

	result := evaluation.Result{
		Run: evaluation.RunInfo{
			ToolVersion: "0.1.0",
			Now:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafe:   kernel.Duration(12 * time.Hour),
			Snapshots:   2,
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "S3 Bucket Public Access",
				ControlDescription: "Bucket is public",
				AssetID:            "arn:aws:s3:::mybucket",
				AssetType:          "aws_s3_bucket",
				AssetVendor:        "aws",
				// No Source — should produce logicalLocations
			},
		},
	}

	if err := w.WriteFindings(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	r := results[0].(map[string]any)
	locations := r["locations"].([]any)
	loc := locations[0].(map[string]any)

	// Should have logicalLocations, not physicalLocation
	if _, hasPhysical := loc["physicalLocation"]; hasPhysical {
		t.Error("expected logicalLocations, not physicalLocation")
	}
	logicals := loc["logicalLocations"].([]any)
	if len(logicals) != 1 {
		t.Fatalf("expected 1 logical location, got %d", len(logicals))
	}
	ll := logicals[0].(map[string]any)
	if ll["name"] != "arn:aws:s3:::mybucket" {
		t.Errorf("expected name arn:aws:s3:::mybucket, got %v", ll["name"])
	}
}
