package metrics

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

func finding(ctl string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		ControlID:       kernel.ControlID(ctl),
		AssetID:         asset.ID("test-asset"),
		ControlSeverity: sev,
	}
}

func TestWrite_ContainsPostureScore(t *testing.T) {
	var buf bytes.Buffer
	Write(&buf, Input{
		Assessment: &report.Assessment{
			Run:      evaluation.RunInfo{EvalTime: time.Now()},
			Findings: []remediation.Finding{},
		},
		PostureScore: 81.2,
	})

	output := buf.String()
	if !strings.Contains(output, "stave_posture_score 81.2") {
		t.Error("missing posture score metric")
	}
}

func TestWrite_FindingsBySeverity(t *testing.T) {
	var buf bytes.Buffer
	Write(&buf, Input{
		Assessment: &report.Assessment{
			Findings: []remediation.Finding{
				finding("CTL.A.001", policy.SeverityCritical),
				finding("CTL.B.001", policy.SeverityCritical),
				finding("CTL.C.001", policy.SeverityHigh),
			},
		},
	})

	output := buf.String()
	if !strings.Contains(output, `stave_findings_total{severity="critical"} 2`) {
		t.Error("missing critical count")
	}
	if !strings.Contains(output, `stave_findings_total{severity="high"} 1`) {
		t.Error("missing high count")
	}
}

func TestWrite_TeamMetrics(t *testing.T) {
	var buf bytes.Buffer
	Write(&buf, Input{
		Assessment: &report.Assessment{},
		TeamFindings: map[string][]remediation.Finding{
			"payments": {finding("CTL.A.001", policy.SeverityHigh)},
		},
	})

	output := buf.String()
	if !strings.Contains(output, `stave_team_findings_total{team="payments"} 1`) {
		t.Error("missing team metric")
	}
}

func TestPostureScore_DomainMethods(t *testing.T) {
	ps := PostureScore(85.5)
	if ps.Float64() != 85.5 {
		t.Errorf("Float64: got %f, want 85.5", ps.Float64())
	}
	if !ps.IsPassing(80.0) {
		t.Error("IsPassing(80.0): got false, want true")
	}
	if ps.IsPassing(90.0) {
		t.Error("IsPassing(90.0): got true, want false")
	}

	computed := PostureScoreFromViolations(2, 10)
	if computed.Float64() != 80.0 {
		t.Errorf("PostureScoreFromViolations(2, 10): got %f, want 80.0", computed.Float64())
	}

	zeroAssets := PostureScoreFromViolations(0, 0)
	if zeroAssets.Float64() != 100.0 {
		t.Errorf("PostureScoreFromViolations(0, 0): got %f, want 100.0", zeroAssets.Float64())
	}

	excessive := PostureScoreFromViolations(15, 10)
	if excessive.Float64() != 0.0 {
		t.Errorf("PostureScoreFromViolations(15, 10): got %f, want 0.0 (clamped)", excessive.Float64())
	}
}

func TestSeverityCounts_DomainMethods(t *testing.T) {
	counts := SeverityCounts{
		policy.SeverityCritical: 3,
		policy.SeverityHigh:     2,
		policy.SeverityMedium:   1,
	}

	if counts.Total() != 6 {
		t.Errorf("Total: got %d, want 6", counts.Total())
	}
	if counts.Critical() != 3 {
		t.Errorf("Critical: got %d, want 3", counts.Critical())
	}
	if counts.High() != 2 {
		t.Errorf("High: got %d, want 2", counts.High())
	}
	if counts.ForSeverity(policy.SeverityLow) != 0 {
		t.Errorf("ForSeverity Low: got %d, want 0", counts.ForSeverity(policy.SeverityLow))
	}
}

func TestSLABurnRate_DomainMethods(t *testing.T) {
	br := SLABurnRate(0.25)
	if br.Float64() != 0.25 {
		t.Errorf("Float64: got %f, want 0.25", br.Float64())
	}
	if br.Percentage() != 25.0 {
		t.Errorf("Percentage: got %f, want 25.0", br.Percentage())
	}
	if !br.IsBreached() {
		t.Error("IsBreached: got false, want true")
	}
	if !br.IsWarning(0.20) {
		t.Error("IsWarning(0.20): got false, want true")
	}
	if br.IsWarning(0.50) {
		t.Error("IsWarning(0.50): got true, want false")
	}

	zero := SLABurnRate(0.0)
	if zero.IsBreached() {
		t.Error("zero IsBreached: got true, want false")
	}
}

func TestSLAMetrics_DomainMethods(t *testing.T) {
	m := SLAMetrics{
		policy.SeverityCritical: SLABurnRate(0.5),
		policy.SeverityHigh:     SLABurnRate(0.0),
	}

	if !m.HasBreaches() {
		t.Error("HasBreaches: got false, want true")
	}
	if m.RateFor(policy.SeverityCritical) != 0.5 {
		t.Errorf("RateFor Critical: got %v, want 0.5", m.RateFor(policy.SeverityCritical))
	}
	if m.RateFor(policy.SeverityLow) != 0.0 {
		t.Errorf("RateFor Low: got %v, want 0.0", m.RateFor(policy.SeverityLow))
	}

	clean := SLAMetrics{
		policy.SeverityHigh: SLABurnRate(0.0),
	}
	if clean.HasBreaches() {
		t.Error("clean HasBreaches: got true, want false")
	}
}
