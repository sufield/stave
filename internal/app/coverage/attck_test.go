package coverage

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func makeCtl(id, stage string) policy.ControlDefinition {
	params := map[string]any{}
	if stage != "" {
		params["attack_stage"] = stage
	}
	return policy.ControlDefinition{
		ID:     kernel.ControlID(id),
		Params: policy.NewParams(params),
	}
}

func TestBuild_StaticCoverage(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeCtl("CTL.A", "initial_access"),
		makeCtl("CTL.B", "initial_access"),
		makeCtl("CTL.C", "exfiltration"),
		makeCtl("CTL.D", ""),
	}

	report := Build(BuildInput{Controls: controls, MinControls: 2})

	if report.ControlsAnalyzed != 4 {
		t.Errorf("analyzed = %d, want 4", report.ControlsAnalyzed)
	}
	if report.ControlsAnnotated != 3 {
		t.Errorf("annotated = %d, want 3", report.ControlsAnnotated)
	}
	if report.ControlsUnannotated != 1 {
		t.Errorf("unannotated = %d, want 1", report.ControlsUnannotated)
	}

	// Initial Access should have 2 controls.
	ia := findTactic(report.Tactics, "TA0001")
	if ia == nil {
		t.Fatal("TA0001 not found")
	}
	if ia.ControlCount != 2 {
		t.Errorf("TA0001 controls = %d, want 2", ia.ControlCount)
	}
	if ia.Status != "covered" {
		t.Errorf("TA0001 status = %q, want covered", ia.Status)
	}

	// Exfiltration should be thin (1 < 2).
	ex := findTactic(report.Tactics, "TA0010")
	if ex == nil {
		t.Fatal("TA0010 not found")
	}
	if ex.Status != "thin" {
		t.Errorf("TA0010 status = %q, want thin", ex.Status)
	}

	// Lateral Movement should be no_coverage.
	lm := findTactic(report.Tactics, "TA0008")
	if lm == nil {
		t.Fatal("TA0008 not found")
	}
	if lm.Status != "no_coverage" {
		t.Errorf("TA0008 status = %q, want no_coverage", lm.Status)
	}

	// No assessment overlay — passing/failing should be nil.
	if ia.PassingCount != nil {
		t.Error("passing should be nil without overlay")
	}
}

func TestBuild_PostureOverlay(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeCtl("CTL.A", "initial_access"),
		makeCtl("CTL.B", "initial_access"),
	}
	findings := []remediation.Finding{
		{ControlID: "CTL.B"},
	}

	report := Build(BuildInput{Controls: controls, Findings: findings})

	if !report.AssessmentOverlay {
		t.Error("expected overlay = true")
	}

	ia := findTactic(report.Tactics, "TA0001")
	if ia == nil {
		t.Fatal("TA0001 not found")
	}
	if ia.PassingCount == nil || *ia.PassingCount != 1 {
		t.Errorf("passing = %v, want 1", ia.PassingCount)
	}
	if ia.FailingCount == nil || *ia.FailingCount != 1 {
		t.Errorf("failing = %v, want 1", ia.FailingCount)
	}
	if ia.CoveragePercent == nil || *ia.CoveragePercent != 50 {
		t.Errorf("coverage = %v, want 50", ia.CoveragePercent)
	}
}

func TestBuild_Resilience(t *testing.T) {
	controls := []policy.ControlDefinition{
		makeCtl("CTL.R", "resilience"),
	}
	report := Build(BuildInput{Controls: controls})

	if len(report.StaveOnly) != 1 {
		t.Fatalf("stave_only = %d, want 1", len(report.StaveOnly))
	}
	if report.StaveOnly[0].TacticName != "Resilience" {
		t.Errorf("name = %q, want Resilience", report.StaveOnly[0].TacticName)
	}
}

func TestNavigatorLayer(t *testing.T) {
	report := &CoverageReport{
		Tactics: []TacticCoverage{
			{TacticID: "TA0001", TacticName: "Initial Access", ControlCount: 5},
			{TacticID: "TA0008", TacticName: "Lateral Movement", ControlCount: 0},
		},
	}

	layer := NavigatorLayer(report)
	techniques, ok := layer["techniques"].([]map[string]any)
	if !ok {
		t.Fatal("techniques missing")
	}
	if len(techniques) != 2 {
		t.Fatalf("techniques = %d, want 2", len(techniques))
	}
	if techniques[1]["score"] != 0 {
		t.Errorf("no-coverage score = %v, want 0", techniques[1]["score"])
	}
}

func findTactic(tactics []TacticCoverage, id string) *TacticCoverage {
	for i := range tactics {
		if tactics[i].TacticID == id {
			return &tactics[i]
		}
	}
	return nil
}
