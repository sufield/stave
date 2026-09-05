package ocsf

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestExport_OCSFStatusIDMatchesNewStatus(t *testing.T) {
	finding := remediation.Finding{
		ControlID:       kernel.ControlID("CTL.S3.001"),
		AssetID:         asset.ID("my-bucket"),
		ControlSeverity: policy.SeverityHigh,
	}

	events := Export([]remediation.Finding{finding})
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Under OCSF 1.1 Compliance Finding specification:
	// Status "New" corresponds to StatusID 1 (not 2). StatusID 2 corresponds to "In Progress".
	if events[0].Status == "New" && events[0].StatusID != 1 {
		t.Errorf("expected StatusID = 1 for Status = %q, got StatusID = %d", events[0].Status, events[0].StatusID)
	}
}
