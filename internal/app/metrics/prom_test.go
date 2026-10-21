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
