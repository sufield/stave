package applycmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/outcome"
	schemaval "github.com/sufield/stave/internal/core/schemaval"
)

func sampleReadiness() schemaval.ReadinessAssessment {
	return schemaval.ReadinessAssessment{
		IsSafe:            true,
		ControlSource:     "controls/s3",
		ObservationSource: "observations",
		Summary: schemaval.AssessmentSummary{
			ControlsVerified:  5,
			StatesVerified:    3,
			ResourcesAnalyzed: 10,
		},
	}
}

func TestRenderReadiness_TextAndJSON(t *testing.T) {
	report := sampleReadiness()

	textOut, err := renderReadiness("text", report)
	if err != nil {
		t.Fatalf("renderReadiness text: %v", err)
	}
	if !strings.Contains(string(textOut), "Plan Summary") {
		t.Errorf("text render missing Plan Summary: %s", textOut)
	}

	jsonOut, err := renderReadiness("json", report)
	if err != nil {
		t.Fatalf("renderReadiness json: %v", err)
	}
	if !strings.Contains(string(jsonOut), `"next_command"`) {
		t.Errorf("json render missing next_command: %s", jsonOut)
	}
}

func TestWriteReadinessPlan(t *testing.T) {
	var buf bytes.Buffer
	if err := writeReadinessPlan(&buf, sampleReadiness()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Plan Summary") {
		t.Fatalf("expected Plan Summary, got: %s", out)
	}
	if !strings.Contains(out, "Ready:        true") {
		t.Fatalf("expected Ready: true, got: %s", out)
	}
	if !strings.Contains(out, "stave apply") {
		t.Fatalf("expected apply next command, got: %s", out)
	}
}

func TestPrintReadinessIssue(t *testing.T) {
	var buf bytes.Buffer
	issue := schemaval.ValidationFinding{
		Name:        "controls",
		Status:      outcome.Pass,
		Message:     "found 5 controls",
		Remediation: "run validate",
		FixCommand:  "stave validate",
	}
	if err := printReadinessIssue(&buf, issue); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "controls") {
		t.Fatalf("expected name in output, got: %s", out)
	}
	if !strings.Contains(out, "Fix: run validate") {
		t.Fatalf("expected fix in output, got: %s", out)
	}
	if !strings.Contains(out, "Command: stave validate") {
		t.Fatalf("expected command in output, got: %s", out)
	}
}

func TestPrintReadinessIssue_NoFixOrCommand(t *testing.T) {
	var buf bytes.Buffer
	issue := schemaval.ValidationFinding{
		Name:    "obs",
		Status:  outcome.Pass,
		Message: "found 3 snapshots",
	}
	if err := printReadinessIssue(&buf, issue); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Fix:") {
		t.Fatalf("should not contain Fix: when empty, got: %s", out)
	}
	if strings.Contains(out, "Command:") {
		t.Fatalf("should not contain Command: when empty, got: %s", out)
	}
}
