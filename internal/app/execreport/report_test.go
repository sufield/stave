package execreport

import (
	"bytes"
	"strings"
	"testing"
)

func TestBand_Boundaries(t *testing.T) {
	tests := []struct {
		score float64
		band  string
	}{
		{0, "CRITICAL"},
		{39.9, "CRITICAL"},
		{40, "POOR"},
		{59.9, "POOR"},
		{60, "FAIR"},
		{69.9, "FAIR"},
		{70, "GOOD"},
		{84.9, "GOOD"},
		{85, "STRONG"},
		{94.9, "STRONG"},
		{95, "EXCELLENT"},
		{100, "EXCELLENT"},
	}
	for _, tt := range tests {
		name, _ := Band(tt.score)
		if name != tt.band {
			t.Errorf("Band(%.1f) = %q, want %q", tt.score, name, tt.band)
		}
	}
}

func TestGenerateSummary_Improving(t *testing.T) {
	r := &Report{
		Period: "2026-Q1",
		Posture: PostureSection{
			Score:    81.2,
			Delta30d: 4.1,
		},
		FindingsSummary: FindingsSummary{Total: 84},
	}
	s := GenerateSummary(r)
	if !strings.Contains(s.OneLiner, "improved") {
		t.Errorf("one-liner should mention improvement: %q", s.OneLiner)
	}
	if !strings.Contains(s.Paragraph, "81.2") {
		t.Errorf("paragraph should contain score: %q", s.Paragraph)
	}
}

func TestGenerateSummary_Declining(t *testing.T) {
	r := &Report{
		Period: "2026-Q1",
		Posture: PostureSection{
			Score:    55.0,
			Delta30d: -8.3,
		},
		FindingsSummary: FindingsSummary{Total: 120},
	}
	s := GenerateSummary(r)
	if !strings.Contains(s.OneLiner, "declined") {
		t.Errorf("one-liner should mention decline: %q", s.OneLiner)
	}
}

func TestGenerateSummary_NoTeams(t *testing.T) {
	r := &Report{
		Posture:         PostureSection{Score: 80},
		FindingsSummary: FindingsSummary{Total: 10},
	}
	s := GenerateSummary(r)
	if len(s.Attention) != 0 {
		t.Error("should have no attention items without teams")
	}
}

func TestGenerateSummary_WithRegressingTeam(t *testing.T) {
	r := &Report{
		Period:          "2026-Q1",
		Posture:         PostureSection{Score: 70, Delta30d: -3},
		FindingsSummary: FindingsSummary{Total: 50},
		Teams: []TeamSection{
			{Name: "Identity", Score: 55, Trajectory: "REGRESSING", CriticalOpen: 3, Contact: "id@test.com"},
		},
	}
	s := GenerateSummary(r)
	if len(s.Attention) != 1 {
		t.Fatalf("attention items = %d, want 1", len(s.Attention))
	}
	if s.Attention[0].Subject != "Identity" {
		t.Errorf("attention subject = %q, want Identity", s.Attention[0].Subject)
	}
}

func TestWriteMarkdown_ContainsAllSections(t *testing.T) {
	r := &Report{
		Title:       "Test Report",
		Period:      "2026-Q1",
		GeneratedAt: "2026-04-01T00:00:00Z",
		Posture: PostureSection{
			Score: 81.2, Band: "GOOD", Delta30d: 4.1,
		},
		FindingsSummary: FindingsSummary{Total: 10, Critical: 2},
		TopFindings: []TopFinding{
			{Rank: 1, ControlID: "CTL.A.001", Severity: "critical", DwellHours: 48},
		},
		AttackCoverage: AttackCoverageSection{
			TacticsCovered: 11, TacticsTotal: 11, CoveragePct: 100,
		},
		ExecutiveSummary: ExecutiveSummary{
			Paragraph: "Test paragraph.",
		},
	}
	var buf bytes.Buffer
	WriteMarkdown(&buf, r)
	out := buf.String()
	for _, section := range []string{"Posture Score", "Findings Summary", "Top Findings", "ATT&CK Coverage", "Executive Summary"} {
		if !strings.Contains(out, section) {
			t.Errorf("markdown missing section: %q", section)
		}
	}
}
