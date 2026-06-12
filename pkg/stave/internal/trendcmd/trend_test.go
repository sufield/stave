package trendcmd

import (
	"bytes"
	"strings"
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
	runs := []runMetrics{
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
	runs := []runMetrics{
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
	runs := []runMetrics{
		{ViolationCount: 20, PassCount: 80, ViolationRate: 0.2},
		{ViolationCount: 15, PassCount: 85, ViolationRate: 0.15},
		{ViolationCount: 10, PassCount: 90, ViolationRate: 0.1},
	}
	velocity := velocityMetrics{Direction: "improving", AvgNetChange: -5}

	p := computeProjection(runs, velocity)
	if p == nil {
		t.Fatal("expected projection")
	}
	if p.EstimatedRuns <= 0 {
		t.Errorf("EstimatedRuns = %d, want > 0", p.EstimatedRuns)
	}
}

func TestComputeProjection_Regressing(t *testing.T) {
	runs := []runMetrics{
		{ViolationCount: 10, PassCount: 90, ViolationRate: 0.1},
	}
	velocity := velocityMetrics{Direction: "regressing", AvgNetChange: 5}

	p := computeProjection(runs, velocity)
	if p != nil {
		t.Error("expected nil projection for regression")
	}
}

func TestRenderOpenMetrics_ContainsAllMetrics(t *testing.T) {
	r := &trendReport{
		Runs: []runMetrics{{
			CapturedAt:     time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			ViolationCount: 10,
			PassCount:      90,
			ViolationRate:  0.1,
			BySeverity:     map[string]int{"critical": 3, "high": 7},
		}},
		MTTR: map[string]mttrEntry{
			"critical": {AvgDays: 3.2, WindowCount: 5},
		},
		FrameworkTrends: []frameworkTrend{
			{Framework: "hipaa", Scores: []float64{0.8}, Direction: "stable"},
		},
		Velocity: velocityMetrics{AvgNetChange: -2.0, Direction: "improving"},
	}

	var buf bytes.Buffer
	if err := renderTrendOpenMetrics(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	checks := []string{
		"stave_violations_total",
		"stave_violation_rate",
		"stave_mttr_days",
		"stave_framework_coverage",
		"stave_velocity_per_run",
		"# EOF",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("openmetrics output missing %q", c)
		}
	}
}

func TestRenderOpenMetrics_MTTROmittedWhenNoWindows(t *testing.T) {
	r := &trendReport{
		Runs: []runMetrics{{
			CapturedAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			ViolationRate: 0.1,
			BySeverity:    map[string]int{"high": 5},
		}},
		MTTR:     nil, // no closed windows
		Velocity: velocityMetrics{AvgNetChange: 0},
	}

	var buf bytes.Buffer
	_ = renderTrendOpenMetrics(&buf, r)
	out := buf.String()

	if strings.Contains(out, "stave_mttr_days") {
		t.Error("stave_mttr_days should be omitted when no closed windows")
	}
	if !strings.Contains(out, "# EOF") {
		t.Error("missing # EOF")
	}
}

func TestComputeFrameworkTrends_Direction(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	// Run 1: 2 HIPAA violations, Run 2: 1, Run 3: 0
	assessments := []*report.Assessment{
		makeAssessment(t1, []evaluation.Finding{
			{ControlID: "CTL.A", AssetID: "r1", ControlSeverity: policy.SeverityHigh,
				ControlCompliance: policy.ComplianceMapping{"hipaa": "164.312(a)(1)"}},
			{ControlID: "CTL.B", AssetID: "r2", ControlSeverity: policy.SeverityHigh,
				ControlCompliance: policy.ComplianceMapping{"hipaa": "164.312(b)"}},
		}, 10, 2),
		makeAssessment(t2, []evaluation.Finding{
			{ControlID: "CTL.A", AssetID: "r1", ControlSeverity: policy.SeverityHigh,
				ControlCompliance: policy.ComplianceMapping{"hipaa": "164.312(a)(1)"}},
		}, 10, 1),
		makeAssessment(t3, []evaluation.Finding{}, 10, 0),
	}

	trends := computeFrameworkTrends(assessments, "hipaa")

	if len(trends) == 0 {
		t.Fatal("expected at least one framework trend")
	}
	if trends[0].Framework != "hipaa" {
		t.Errorf("Framework = %q", trends[0].Framework)
	}
	if len(trends[0].Scores) != 3 {
		t.Fatalf("expected 3 scores, got %d", len(trends[0].Scores))
	}
	if trends[0].Direction != "improving" {
		t.Errorf("Direction = %q, want improving", trends[0].Direction)
	}
	// Last run has 0 violations = 100% coverage
	if trends[0].Scores[2] < 0.99 {
		t.Errorf("last score = %f, want ~1.0", trends[0].Scores[2])
	}
}
