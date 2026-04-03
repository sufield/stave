package securityaudit

import (
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"

	domain "github.com/sufield/stave/internal/core/securityaudit"
)

func TestMarshalMarkdownReport_NoFindings(t *testing.T) {
	report := domain.Report{
		SchemaVersion: "security-audit.v1",
		StaveVersion:  "v0.0.0-test",
		Summary:       domain.Summary{FailOn: policy.SeverityHigh},
	}
	data, err := MarshalMarkdownReport(report)
	if err != nil {
		t.Fatalf("MarshalMarkdownReport: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "No findings") {
		t.Fatalf("expected 'No findings' for empty findings: %s", out)
	}
}

func TestMarshalMarkdownReport_WithEvidenceAndControls(t *testing.T) {
	report := sampleReport()
	report.EvidenceIndex = []domain.EvidenceRef{
		{ID: "build_info.json", Path: "build_info.json", SHA256: "abc123"},
	}
	report.Controls = []domain.ControlRef{
		{Framework: "soc2", ControlID: "CC6.1", Rationale: "Access control"},
	}
	report.Findings[0].ControlRefs = []domain.ControlRef{
		{Framework: "soc2", ControlID: "CC6.1", Rationale: "Access control"},
	}
	report.Findings[0].EvidenceRefs = []string{"build_info.json"}

	data, err := MarshalMarkdownReport(report)
	if err != nil {
		t.Fatalf("MarshalMarkdownReport: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "Evidence Index") {
		t.Fatalf("missing Evidence Index: %s", out)
	}
	if !strings.Contains(out, "Control Coverage") {
		t.Fatalf("missing Control Coverage: %s", out)
	}
	if !strings.Contains(out, "soc2") {
		t.Fatalf("missing framework ref: %s", out)
	}
}

func TestEscapeMarkdownPipe(t *testing.T) {
	got := escapeMarkdownPipe("hello | world")
	if got != `hello \| world` {
		t.Fatalf("got %q", got)
	}
}

func TestSarifLevelFromSeverity(t *testing.T) {
	tests := []struct {
		sev  policy.Severity
		want string
	}{
		{policy.SeverityCritical, "error"},
		{policy.SeverityHigh, "error"},
		{policy.SeverityMedium, "warning"},
		{policy.SeverityLow, "note"},
		{policy.SeverityNone, "note"},
	}
	for _, tt := range tests {
		got := sarifLevelFromSeverity(tt.sev)
		if got != tt.want {
			t.Errorf("sarifLevelFromSeverity(%v) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}
