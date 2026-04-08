package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/internal/core/trace"
)

func TestLocalFileTracer_EndToEnd(t *testing.T) {
	tracer := NewLocalFileTracer()

	// Simulate a PASS assessment
	span1 := tracer.BeginAssessment("bucket-private", "CTL.S3.PUBLIC.001")
	span1.RecordStep("exemption_check", nil, map[string]any{"exempted": false})
	span1.RecordStep("predicate_evaluation", map[string]any{
		"currently_unsafe": false,
	}, map[string]any{
		"matched": false,
	})
	span1.RecordStep("verdict_decision", nil, map[string]any{
		"verdict": "PASS",
		"reason":  "predicate not matched — resource is compliant",
	})
	span1.SetVerdict("PASS", "HIGH")
	span1.End()

	// Simulate a VIOLATION assessment
	span2 := tracer.BeginAssessment("bucket-public", "CTL.S3.PUBLIC.001")
	span2.RecordStep("exemption_check", nil, map[string]any{"exempted": false})
	span2.RecordStep("predicate_evaluation", map[string]any{
		"currently_unsafe": true,
	}, map[string]any{
		"matched": true,
	})
	span2.RecordStep("threshold_check", map[string]any{
		"threshold_hours": 168.0,
	}, map[string]any{
		"exceeds_threshold": true,
	})
	span2.SetVerdict("VIOLATION", "HIGH")
	span2.SetFindingID("CTL.S3.PUBLIC.001@bucket-public")
	span2.End()

	// Finalize
	lt := tracer.Finalize("test-run-001", "0.9.0", map[string]string{
		"overall": "abc123",
	})

	if lt.SchemaVersion != trace.SchemaVersion {
		t.Fatalf("schema version = %q", lt.SchemaVersion)
	}
	if lt.RunID != "test-run-001" {
		t.Fatalf("run ID = %q", lt.RunID)
	}
	if len(lt.Assessments) != 2 {
		t.Fatalf("assessments = %d, want 2", len(lt.Assessments))
	}

	// Verify PASS assessment has steps
	pass := lt.Assessments[0]
	if pass.Verdict != "PASS" {
		t.Errorf("pass verdict = %q", pass.Verdict)
	}
	if len(pass.Steps) != 3 {
		t.Errorf("pass steps = %d, want 3", len(pass.Steps))
	}
	if pass.FindingID != "" {
		t.Errorf("pass should have no finding ID, got %q", pass.FindingID)
	}

	// Verify VIOLATION assessment has finding linkage
	violation := lt.Assessments[1]
	if violation.Verdict != "VIOLATION" {
		t.Errorf("violation verdict = %q", violation.Verdict)
	}
	if violation.FindingID != "CTL.S3.PUBLIC.001@bucket-public" {
		t.Errorf("finding ID = %q", violation.FindingID)
	}

	// Verify summary
	if lt.Summary.Passes != 1 {
		t.Errorf("summary passes = %d", lt.Summary.Passes)
	}
	if lt.Summary.Violations != 1 {
		t.Errorf("summary violations = %d", lt.Summary.Violations)
	}

	// Write to file and verify JSON is valid
	outPath := filepath.Join(t.TempDir(), "audit_trace.json")
	if err := WriteTraceFile(lt, outPath); err != nil {
		t.Fatalf("WriteTraceFile: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read trace file: %v", err)
	}
	var parsed trace.LogicTrace
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse trace JSON: %v", err)
	}
	if parsed.Summary.TotalAssessments != 2 {
		t.Errorf("parsed total = %d", parsed.Summary.TotalAssessments)
	}
}

func TestLocalFileTracer_NoAssessments(t *testing.T) {
	tracer := NewLocalFileTracer()
	lt := tracer.Finalize("empty-run", "0.9.0", nil)
	if len(lt.Assessments) != 0 {
		t.Fatalf("expected 0 assessments, got %d", len(lt.Assessments))
	}
	if lt.Summary.TotalAssessments != 0 {
		t.Fatalf("summary total = %d", lt.Summary.TotalAssessments)
	}
}
