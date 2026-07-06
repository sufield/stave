package metrics

import (
	"bytes"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Write_PrometheusExpositionHeadersOnly(t *testing.T) {
	// Create an Info-severity finding with an SLA.
	f := finding("CTL.INFO.001", policy.SeverityInfo)
	deadline := 24.0
	overdue := 12.0
	f.RehydrateSLA(&deadline, true, &overdue, policy.SeverityNone, kernel.SLAPolicySource("default"))

	var buf bytes.Buffer
	Write(&buf, Input{
		Assessment: &report.Assessment{
			Findings: []remediation.Finding{f},
		},
	})

	output := buf.String()

	// Since info is the only SLA-bearing finding, and info is NOT in the loop:
	// The HELP/TYPE headers for stave_sla_burn_rate will be written, but NO metrics lines will follow.
	// This violates the Prometheus exposition format where headers must not stand alone.

	hasHeader := strings.Contains(output, "# HELP stave_sla_burn_rate")
	hasMetric := strings.Contains(output, "stave_sla_burn_rate{")

	if hasHeader && !hasMetric {
		t.Errorf("Prometheus violation: output has HELP/TYPE comments for stave_sla_burn_rate, but no corresponding metric lines:\n%s", output)
	}
}
