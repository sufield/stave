package trend

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func makeAssessment(t time.Time, findings []evaluation.Finding, totalAssets, exposed int) *report.Assessment {
	rFindings := make([]remediation.Finding, len(findings))
	for i, f := range findings {
		rFindings[i] = remediation.Finding{Finding: f}
	}
	return &report.Assessment{
		SchemaVersion: "out.v0.1",
		Kind:          report.KindAssessment,
		Run:           evaluation.RunInfo{Now: t, EvaluatedState: "deployed"},
		Summary:       evaluation.ComplianceSummary{TotalAssets: totalAssets, ExposedResources: exposed, Violations: len(findings)},
		Findings:      rFindings,
	}
}

func finding(ctlID, assetID string, sev policy.Severity) evaluation.Finding {
	return evaluation.Finding{
		ControlID:       kernel.ControlID(ctlID),
		AssetID:         asset.ID(assetID),
		ControlSeverity: sev,
	}
}

func TestComputeRunMetrics_Basic(t *testing.T) {
	a := makeAssessment(
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		[]evaluation.Finding{
			finding("CTL.A", "res1", policy.SeverityCritical),
			finding("CTL.B", "res2", policy.SeverityHigh),
		},
		10, 2,
	)

	m := computeRunMetrics(a, nil)

	if m.ViolationCount != 2 {
		t.Errorf("ViolationCount = %d, want 2", m.ViolationCount)
	}
	if m.PassCount != 8 {
		t.Errorf("PassCount = %d, want 8", m.PassCount)
	}
	if m.BySeverity["critical"] != 1 {
		t.Errorf("critical = %d, want 1", m.BySeverity["critical"])
	}
	if m.BySeverity["high"] != 1 {
		t.Errorf("high = %d, want 1", m.BySeverity["high"])
	}
}

func TestComputeVelocity_Improving(t *testing.T) {
	runs := []RunMetrics{
		{ViolationCount: 50},
		{ViolationCount: 45},
		{ViolationCount: 38},
		{ViolationCount: 30},
		{ViolationCount: 22},
	}

	v := computeVelocity(runs, 5)
	if v.Direction != "improving" {
		t.Errorf("Direction = %q, want improving", v.Direction)
	}
	if v.AvgNetChange >= 0 {
		t.Errorf("AvgNetChange = %f, want negative", v.AvgNetChange)
	}
}

func TestComputeVelocity_Regressing(t *testing.T) {
	runs := []RunMetrics{
		{ViolationCount: 10},
		{ViolationCount: 15},
		{ViolationCount: 22},
	}

	v := computeVelocity(runs, 5)
	if v.Direction != "regressing" {
		t.Errorf("Direction = %q, want regressing", v.Direction)
	}
}

func TestComputeMTTR_ClosedWindows(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC) // 3 days later
	t3 := time.Date(2026, 1, 7, 0, 0, 0, 0, time.UTC) // 6 days after t1

	assessments := []*report.Assessment{
		makeAssessment(t1, []evaluation.Finding{
			finding("CTL.A", "res1", policy.SeverityCritical),
			finding("CTL.B", "res2", policy.SeverityHigh),
		}, 10, 2),
		makeAssessment(t2, []evaluation.Finding{
			finding("CTL.B", "res2", policy.SeverityHigh), // CTL.A resolved
		}, 10, 1),
		makeAssessment(t3, []evaluation.Finding{}, 10, 0), // CTL.B resolved
	}

	mttr := computeMTTR(assessments)

	// CTL.A: opened t1, closed t2 = 3 days
	if entry, ok := mttr["critical"]; !ok || entry.WindowCount != 1 {
		t.Errorf("critical MTTR: %+v, want 1 window", mttr["critical"])
	} else if entry.AvgDays < 2.9 || entry.AvgDays > 3.1 {
		t.Errorf("critical avg = %.1f, want ~3.0", entry.AvgDays)
	}

	// CTL.B: opened t1, closed t3 = 6 days
	if entry, ok := mttr["high"]; !ok || entry.WindowCount != 1 {
		t.Errorf("high MTTR: %+v, want 1 window", mttr["high"])
	} else if entry.AvgDays < 5.9 || entry.AvgDays > 6.1 {
		t.Errorf("high avg = %.1f, want ~6.0", entry.AvgDays)
	}
}

func TestComputeMTTR_NoClosedWindows(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)

	assessments := []*report.Assessment{
		makeAssessment(t1, []evaluation.Finding{
			finding("CTL.A", "res1", policy.SeverityCritical),
		}, 10, 1),
		makeAssessment(t2, []evaluation.Finding{
			finding("CTL.A", "res1", policy.SeverityCritical), // still open
		}, 10, 1),
	}

	mttr := computeMTTR(assessments)

	if len(mttr) != 0 {
		t.Errorf("expected empty MTTR for no closed windows, got %+v", mttr)
	}
}

func TestComputeProjection_Improving(t *testing.T) {
	runs := []RunMetrics{
		{ViolationCount: 20, PassCount: 80, ViolationRate: 0.2},
		{ViolationCount: 15, PassCount: 85, ViolationRate: 0.15},
		{ViolationCount: 10, PassCount: 90, ViolationRate: 0.1},
	}
	velocity := VelocityMetrics{Direction: "improving", AvgNetChange: -5}

	p := computeProjection(runs, velocity)
	if p == nil {
		t.Fatal("expected projection")
	}
	if p.EstimatedRuns <= 0 {
		t.Errorf("EstimatedRuns = %d, want > 0", p.EstimatedRuns)
	}
}

func TestComputeProjection_Regressing(t *testing.T) {
	runs := []RunMetrics{
		{ViolationCount: 10, PassCount: 90, ViolationRate: 0.1},
	}
	velocity := VelocityMetrics{Direction: "regressing", AvgNetChange: 5}

	p := computeProjection(runs, velocity)
	if p != nil {
		t.Error("expected nil projection for regression")
	}
}
