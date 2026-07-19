package eval

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestEnrichReport_AnnotatesMarkerFindingsDecidingLayer(t *testing.T) {
	report := &evaluation.ComplianceReport{
		MarkerFindings: []evaluation.Finding{
			{
				ControlID: kernel.ControlID("CTL.A"),
				ReasoningTrace: []evaluation.MatchedClause{
					{
						ObservationKey: kernel.ObservationKey("identity.scp.denies_leave_org"),
					},
				},
			},
		},
	}

	EnrichReport(report, nil, nil, nil)

	if len(report.MarkerFindings) == 0 {
		t.Fatal("MarkerFindings was emptied")
	}

	got := report.MarkerFindings[0].DecidingLayer
	if got == "" {
		t.Errorf("DecidingLayer was not annotated on MarkerFindings")
	} else if got != evaluation.LayerSCPCeiling {
		t.Errorf("Expected DecidingLayer %q, got %q", evaluation.LayerSCPCeiling, got)
	}
}
