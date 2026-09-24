package execreport

import (
	"bytes"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestBand_Boundaries(t *testing.T) {
	tests := []struct {
		score float64
		band  PostureBand
	}{
		{0, BandCritical},
		{39.9, BandCritical},
		{40, BandPoor},
		{59.9, BandPoor},
		{60, BandFair},
		{69.9, BandFair},
		{70, BandGood},
		{84.9, BandGood},
		{85, BandStrong},
		{94.9, BandStrong},
		{95, BandExcellent},
		{100, BandExcellent},
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
			{Rank: 1, ControlID: kernel.ControlID("CTL.A.001"), Severity: policy.SeverityCritical, DwellHours: 48},
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

func TestTopFindings_DomainMethods(t *testing.T) {
	tf := TopFindings{
		{Rank: 1, ControlID: kernel.ControlID("CTL.A.001"), Severity: policy.SeverityCritical, SLABreached: true},
		{Rank: 2, ControlID: kernel.ControlID("CTL.B.002"), Severity: policy.SeverityHigh, SLABreached: false},
		{Rank: 3, ControlID: kernel.ControlID("CTL.C.003"), Severity: policy.SeverityCritical, SLABreached: false},
	}

	if tf.Len() != 3 {
		t.Errorf("Len() = %d, want 3", tf.Len())
	}

	crit := tf.BySeverity(policy.SeverityCritical)
	if crit.Len() != 2 {
		t.Errorf("BySeverity(Critical).Len() = %d, want 2", crit.Len())
	}

	breached := tf.Breached()
	if breached.Len() != 1 {
		t.Errorf("Breached().Len() = %d, want 1", breached.Len())
	}

	var empty TopFindings
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.BySeverity(policy.SeverityCritical) != nil {
		t.Error("empty.BySeverity() should return nil")
	}
	if empty.Breached() != nil {
		t.Error("empty.Breached() should return nil")
	}
}

func TestFrameworkReadinesses_DomainMethods(t *testing.T) {
	frs := FrameworkReadinesses{
		{Framework: policy.ComplianceFramework("soc2"), Total: 10, Passing: 9, Failing: 1, ReadinessPct: 90.0},
		{Framework: policy.ComplianceFramework("iso27001"), Total: 20, Passing: 20, Failing: 0, ReadinessPct: 100.0},
	}

	if frs.Len() != 2 {
		t.Errorf("Len() = %d, want 2", frs.Len())
	}

	soc2 := frs.ByFramework(policy.ComplianceFramework("soc2"))
	if soc2 == nil || soc2.Failing != 1 {
		t.Errorf("ByFramework(soc2) = %v, want Failing=1", soc2)
	}

	missing := frs.ByFramework(policy.ComplianceFramework("hipaa"))
	if missing != nil {
		t.Errorf("ByFramework(hipaa) = %v, want nil", missing)
	}

	var empty FrameworkReadinesses
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.ByFramework(policy.ComplianceFramework("soc2")) != nil {
		t.Error("empty.ByFramework() should return nil")
	}
}
