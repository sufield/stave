package securityaudit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	domain "github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

func sampleReport() domain.Report {
	return domain.Report{
		SchemaVersion: "security-audit.v1",
		GeneratedAt:   time.Date(2026, 2, 28, 0, 0, 0, 0, time.UTC),
		StaveVersion:  "v0.0.0-test",
		Summary: domain.Summary{
			Total:      1,
			Pass:       0,
			Warn:       1,
			Fail:       0,
			BySeverity: map[domain.Severity]int{domain.SeverityHigh: 1},
			FailOn:     domain.SeverityHigh,
		},
		Findings: []domain.Finding{
			{
				ID:             domain.CheckVulnResults,
				Pillar:         domain.PillarSupplyChain,
				Status:         domain.StatusWarn,
				Severity:       domain.SeverityHigh,
				Title:          "No vulnerability evidence found",
				Details:        "missing evidence",
				AuditorHint:    "needs artifact",
				Recommendation: "run with --live-vuln-check",
			},
		},
	}
}

func TestMarshalJSONReport(t *testing.T) {
	data, err := MarshalJSONReport(sampleReport())
	if err != nil {
		t.Fatalf("MarshalJSONReport: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if decoded["schema_version"] != "security-audit.v1" {
		t.Fatalf("schema_version=%v, want security-audit.v1", decoded["schema_version"])
	}
}

func TestMarshalMarkdownReport(t *testing.T) {
	data, err := MarshalMarkdownReport(sampleReport())
	if err != nil {
		t.Fatalf("MarshalMarkdownReport: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "# Stave Security Audit Report") {
		t.Fatalf("missing markdown heading: %s", out)
	}
	if !strings.Contains(out, "`SC.VULN.RESULTS`") {
		t.Fatalf("missing finding check id: %s", out)
	}
}

func TestMarshalSARIFReport(t *testing.T) {
	data, err := MarshalSARIFReport(sampleReport())
	if err != nil {
		t.Fatalf("MarshalSARIFReport: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if decoded["version"] != "2.1.0" {
		t.Fatalf("sarif version=%v, want 2.1.0", decoded["version"])
	}
	runs, ok := decoded["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("unexpected runs payload: %#v", decoded["runs"])
	}
}
