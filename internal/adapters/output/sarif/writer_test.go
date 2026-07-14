package sarif

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestWriteFindings_EmptyFindings(t *testing.T) {
	w := NewFindingWriter()
	enricher := remediation.NewPlanner()
	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.1.0",
			EvalTime:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(12 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
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
	w := NewFindingWriter()
	enricher := remediation.NewPlanner()

	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	firstUnsafe := time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.2.0",
			EvalTime:          now,
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
				Source:             &asset.SourceRef{File: "main.tf", Line: 42},
				Evidence: evaluation.Evidence{
					FirstUnsafeAt:       firstUnsafe,
					UnsafeDurationHours: 24,
					ThresholdHours:      12,
					TemporalRisk:        "Unsafe for 24h (threshold: 12h)",
				},
				ControlRemediation: &policy.RemediationSpec{
					Description: "Disable public access",
					Action:      "Set block_public_access to true",
				},
			},
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
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

	// Check fixes — SARIF 2.1.0 §3.55 requires every fix object
	// carry a non-empty changes array with at least one
	// artifactLocation+replacements entry. Validators reject
	// otherwise.
	fixes := r["fixes"].([]any)
	if len(fixes) != 1 {
		t.Fatalf("expected 1 fix, got %d", len(fixes))
	}
	fix := fixes[0].(map[string]any)
	changes, ok := fix["changes"].([]any)
	if !ok || len(changes) == 0 {
		t.Fatalf("fix.changes empty: %v", fix)
	}
	change := changes[0].(map[string]any)
	if _, hasLoc := change["artifactLocation"].(map[string]any); !hasLoc {
		t.Errorf("change.artifactLocation missing or wrong shape: %v", change)
	}
	replacements, ok := change["replacements"].([]any)
	if !ok || len(replacements) == 0 {
		t.Errorf("change.replacements empty: %v", change)
	}
}

func TestWriteFindings_RuleDeduplication(t *testing.T) {
	w := NewFindingWriter()
	enricher := remediation.NewPlanner()

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.1.0",
			EvalTime:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(12 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
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

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
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

func TestWriteFindings_ChainMemberProperties(t *testing.T) {
	w := NewFindingWriter()
	enricher := remediation.NewPlanner()

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.1.0",
			EvalTime:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(12 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
		},
		Findings: []evaluation.Finding{
			{
				FindingID:          "sha256:abc123",
				ControlID:          "CTL.S3.PUBLIC.001",
				ControlName:        "S3 Bucket Public Access",
				ControlDescription: "S3 bucket has public access enabled",
				AssetID:            "arn:aws:s3:::phi-bucket",
				AssetType:          "aws_s3_bucket",
				AssetVendor:        "aws",
				ControlSeverity:    policy.SeverityHigh,
				ChainMembership: []evaluation.ChainMembershipEntry{
					{
						ChainID:       "data_exfiltration_path",
						ChainSeverity: policy.SeverityCritical,
						StageSpan:     []kernel.AttackStage{"initial_access", "exfiltration"},
						Narrative:     "Public S3 bucket enables data exfiltration",
					},
				},
			},
			{
				ControlID:          "CTL.IAM.PASSWORD.001",
				ControlName:        "IAM Password Policy",
				ControlDescription: "Password policy too weak",
				AssetID:            "arn:aws:iam::123:account",
				AssetType:          "aws_iam_account",
				AssetVendor:        "aws",
			},
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarifDoc map[string]any
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := sarifDoc["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)

	// First result (chain member) should have properties.
	r0 := results[0].(map[string]any)
	props, ok := r0["properties"].(map[string]any)
	if !ok {
		t.Fatal("chain member result should have properties")
	}
	if props["chain_id"] != "data_exfiltration_path" {
		t.Errorf("chain_id = %v, want data_exfiltration_path", props["chain_id"])
	}
	if props["chain_severity"] != "critical" {
		t.Errorf("chain_severity = %v, want critical", props["chain_severity"])
	}
	if props["finding_id"] != "sha256:abc123" {
		t.Errorf("finding_id = %v, want sha256:abc123", props["finding_id"])
	}

	// Message should have ATTACK PATH prefix.
	msg := r0["message"].(map[string]any)["text"].(string)
	if !strings.Contains(msg, "[ATTACK PATH: data_exfiltration_path]") {
		t.Errorf("message should contain ATTACK PATH prefix, got: %s", msg)
	}

	// Second result (isolated) should NOT have properties.
	r1 := results[1].(map[string]any)
	if _, hasProps := r1["properties"]; hasProps {
		t.Error("isolated finding should not have chain properties")
	}
}

func TestWriteFindings_ChainFindingsInSARIF(t *testing.T) {
	w := NewFindingWriter()
	enricher := remediation.NewPlanner()

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.1.0",
			EvalTime:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(12 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
		},
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:           kernel.ChainID("CHAIN.BUCKET.HIJACK.001"),
				AssetID:           "arn:aws:s3:::target-bucket",
				Severity:          policy.SeverityCritical,
				Narrative:         "Identity X can delete bucket Y",
				Description:       "Bucket hijack via delete",
				ControlsFailing:   []kernel.ControlID{"CTL.S3.001", "CTL.IAM.002"},
				MissingSafeguards: []kernel.ControlID{"CTL.SCP.001"},
				AttackStages:      []kernel.AttackStage{"initial_access", "impact"},
				CompoundScore:     95.0,
			},
			{
				ChainID:       kernel.ChainID("CHAIN.TRUST.CYCLE.001"),
				AssetID:       "arn:aws:iam::123:role/admin",
				Severity:      policy.SeverityHigh,
				Narrative:     "Trust cycle: A ↔ B (2 hops)",
				Description:   "Trust cycle detected",
				AttackStages:  []kernel.AttackStage{"lateral_movement"},
				CompoundScore: 70.0,
			},
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarifDoc map[string]any
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, string(data))
	}

	runs := sarifDoc["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)

	if len(results) != 2 {
		t.Fatalf("results = %d, want 2 (chain findings)", len(results))
	}

	r0 := results[0].(map[string]any)
	if r0["ruleId"] != "CHAIN.BUCKET.HIJACK.001" {
		t.Errorf("ruleId = %v, want CHAIN.BUCKET.HIJACK.001", r0["ruleId"])
	}
	if r0["level"] != "error" {
		t.Errorf("level = %v, want error (critical)", r0["level"])
	}
	msg := r0["message"].(map[string]any)["text"].(string)
	if !strings.Contains(msg, "Identity X can delete bucket Y") {
		t.Errorf("message should contain narrative, got: %s", msg)
	}
	props := r0["properties"].(map[string]any)
	if props["stave/severity"] != "critical" {
		t.Errorf("severity property = %v, want critical", props["stave/severity"])
	}

	// Verify rules include chain rules.
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
}

func TestWriteFindings_ExploitabilityInProperties(t *testing.T) {
	w := NewFindingWriter()
	enricher := remediation.NewPlanner()

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.1.0",
			EvalTime:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(12 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
		},
		Findings: []evaluation.Finding{
			{
				ControlID:          "CTL.S3.001",
				ControlName:        "S3 Public",
				ControlDescription: "Bucket is public",
				AssetID:            "arn:aws:s3:::bucket",
				AssetType:          "aws_s3_bucket",
				AssetVendor:        "aws",
				Exploitability:     evaluation.ExploitabilityExploitable,
				DecidingLayer:      evaluation.LayerResourcePolicy,
			},
		},
	}

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarifDoc map[string]any
	if err := json.Unmarshal(data, &sarifDoc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := sarifDoc["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	r0 := results[0].(map[string]any)
	props, ok := r0["properties"].(map[string]any)
	if !ok {
		t.Fatal("finding with exploitability should have properties")
	}
	if props["stave/exploitability"] != "exploitable" {
		t.Errorf("exploitability = %v, want exploitable", props["stave/exploitability"])
	}
	if props["stave/deciding_layer"] != "resource_control_policy" {
		t.Errorf("deciding_layer = %v, want resource_control_policy", props["stave/deciding_layer"])
	}
}

func TestWriteFindings_LogicalLocation(t *testing.T) {
	w := NewFindingWriter()
	enricher := remediation.NewPlanner()

	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      "0.1.0",
			EvalTime:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(12 * time.Hour),
			Snapshots:         2,
			EvaluatedState:    "deployed",
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

	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var sarif map[string]any
	if err := json.Unmarshal(data, &sarif); err != nil {
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
