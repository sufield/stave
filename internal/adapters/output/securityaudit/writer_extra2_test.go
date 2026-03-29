package securityaudit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	domain "github.com/sufield/stave/internal/core/securityaudit"
)

func sampleReportWithFindings() domain.Report {
	return domain.Report{
		SchemaVersion: "security-audit.v1",
		StaveVersion:  "v0.1.0-test",
		GeneratedAt:   time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Summary: domain.Summary{
			Total:             3,
			Pass:              1,
			Warn:              1,
			Fail:              1,
			GatedFindingCount: 1,
			Gated:             true,
			FailOn:            domain.SeverityHigh,
			EvidenceFreshness: "24h",
			VulnSourceUsed:    "embedded",
		},
		Findings: []domain.Finding{
			{
				ID:             "SC-001",
				Pillar:         domain.PillarSupplyChain,
				Status:         domain.StatusFail,
				Severity:       domain.SeverityCritical,
				Title:          "Unsigned dependency",
				Details:        "Package foo is unsigned",
				AuditorHint:    "Verify chain of custody",
				Recommendation: "Pin all dependencies",
				ControlRefs: []domain.ControlRef{
					{Framework: "soc2", ControlID: "CC6.1", Rationale: "Supply chain"},
				},
				EvidenceRefs: []string{"build_info.json"},
			},
			{
				ID:             "RT-001",
				Pillar:         domain.PillarRuntime,
				Status:         domain.StatusWarn,
				Severity:       domain.SeverityMedium,
				Title:          "Elevated permissions | detected",
				Details:        "Role has admin",
				AuditorHint:    "Review RBAC",
				Recommendation: "Reduce scope",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// MarshalJSONReport
// ---------------------------------------------------------------------------

func TestMarshalJSONReport_Full(t *testing.T) {
	report := sampleReportWithFindings()
	data, err := MarshalJSONReport(report)
	if err != nil {
		t.Fatalf("MarshalJSONReport: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "SC-001") {
		t.Error("missing finding ID")
	}
	if !strings.Contains(out, "security-audit.v1") {
		t.Error("missing schema version")
	}
	// Verify it's valid JSON
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestMarshalJSONReport_Empty(t *testing.T) {
	report := domain.Report{
		SchemaVersion: "security-audit.v1",
		StaveVersion:  "v0.0.0",
		Summary:       domain.Summary{FailOn: domain.SeverityHigh},
	}
	data, err := MarshalJSONReport(report)
	if err != nil {
		t.Fatalf("MarshalJSONReport: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

// ---------------------------------------------------------------------------
// MarshalSARIFReport
// ---------------------------------------------------------------------------

func TestMarshalSARIFReport_Full(t *testing.T) {
	report := sampleReportWithFindings()
	data, err := MarshalSARIFReport(report)
	if err != nil {
		t.Fatalf("MarshalSARIFReport: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "2.1.0") {
		t.Error("missing SARIF version")
	}
	if !strings.Contains(out, "SC-001") {
		t.Error("missing finding ID")
	}
	if !strings.Contains(out, "stave-security-audit") {
		t.Error("missing tool name")
	}
	// Verify valid JSON structure
	var doc sarifDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(doc.Runs[0].Results))
	}
	// First result should be "error" level (critical)
	if doc.Runs[0].Results[0].Level != "error" {
		t.Fatalf("expected error level for critical, got %q", doc.Runs[0].Results[0].Level)
	}
	// Second result should be "warning" level (medium)
	if doc.Runs[0].Results[1].Level != "warning" {
		t.Fatalf("expected warning level for medium, got %q", doc.Runs[0].Results[1].Level)
	}
}

func TestMarshalSARIFReport_EmptyFindings(t *testing.T) {
	report := domain.Report{
		SchemaVersion: "security-audit.v1",
		StaveVersion:  "v0.0.0",
		Summary:       domain.Summary{FailOn: domain.SeverityHigh},
	}
	data, err := MarshalSARIFReport(report)
	if err != nil {
		t.Fatalf("MarshalSARIFReport: %v", err)
	}
	var doc sarifDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(doc.Runs[0].Results))
	}
}

// ---------------------------------------------------------------------------
// MarshalMarkdownReport — full with pipe escaping
// ---------------------------------------------------------------------------

func TestMarshalMarkdownReport_Full(t *testing.T) {
	report := sampleReportWithFindings()
	data, err := MarshalMarkdownReport(report)
	if err != nil {
		t.Fatalf("MarshalMarkdownReport: %v", err)
	}
	out := string(data)

	expects := []string{
		"# Stave Security Audit Report",
		"## Summary",
		"## Findings",
		"SC-001",
		"RT-001",
		"supply_chain",
		"Unsigned dependency",
		`Elevated permissions \| detected`, // pipe should be escaped
	}
	for _, exp := range expects {
		if !strings.Contains(out, exp) {
			t.Errorf("output missing %q", exp)
		}
	}
}

// ---------------------------------------------------------------------------
// MarshalSARIFReport — duplicate finding IDs
// ---------------------------------------------------------------------------

func TestMarshalSARIFReport_DuplicateFindingIDs(t *testing.T) {
	report := domain.Report{
		SchemaVersion: "security-audit.v1",
		StaveVersion:  "v0.0.0",
		Findings: []domain.Finding{
			{ID: "SC-001", Title: "First", Severity: domain.SeverityHigh, Status: domain.StatusFail},
			{ID: "SC-001", Title: "First", Severity: domain.SeverityHigh, Status: domain.StatusFail},
		},
	}
	data, err := MarshalSARIFReport(report)
	if err != nil {
		t.Fatalf("MarshalSARIFReport: %v", err)
	}
	var doc sarifDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// Duplicate ID should produce 1 rule but 2 results
	if len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule for duplicate IDs, got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(doc.Runs[0].Results))
	}
}
