package ticketexport

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func mkFinding(ctlID, astID string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:          kernel.ControlID(ctlID),
			AssetID:            asset.ID(astID),
			ControlSeverity:    sev,
			ControlName:        "S3 Public Read",
			ControlDescription: "Detects public read access on S3 buckets",
			AssetType:          "s3_bucket",
			Evidence: evaluation.Evidence{
				UnsafeDurationHours: 48,
			},
		},
		RemediationSpec: policy.RemediationSpec{
			Action: "Set block_public_access to true",
		},
	}
}

func TestStableTicketID_Deterministic(t *testing.T) {
	id1 := StableTicketID("s3_public_read", "arn:aws:s3:::my-bucket")
	id2 := StableTicketID("s3_public_read", "arn:aws:s3:::my-bucket")

	if id1 != id2 {
		t.Errorf("ticket IDs not stable: %q != %q", id1, id2)
	}
	if id1[:4] != "TKT-" {
		t.Errorf("expected TKT- prefix, got %q", id1[:4])
	}

	// Different inputs should produce different IDs.
	id3 := StableTicketID("s3_public_read", "arn:aws:s3:::other-bucket")
	if id1 == id3 {
		t.Error("different inputs produced the same ticket ID")
	}
}

func TestGenerate_PriorityMapping(t *testing.T) {
	findings := []remediation.Finding{
		mkFinding("ctl-1", "asset-a", policy.SeverityCritical),
		mkFinding("ctl-2", "asset-b", policy.SeverityHigh),
		mkFinding("ctl-3", "asset-c", policy.SeverityMedium),
		mkFinding("ctl-4", "asset-d", policy.SeverityLow),
	}

	tickets := Generate(findings)
	if len(tickets) != 4 {
		t.Fatalf("expected 4 tickets, got %d", len(tickets))
	}

	expected := map[string]string{
		"critical": "P1",
		"high":     "P2",
		"medium":   "P3",
		"low":      "P4",
	}

	for _, ticket := range tickets {
		wantPriority := expected[ticket.Severity]
		if ticket.Priority != wantPriority {
			t.Errorf("severity %q: got priority %q, want %q",
				ticket.Severity, ticket.Priority, wantPriority)
		}
		if ticket.Status != "open" {
			t.Errorf("expected status 'open', got %q", ticket.Status)
		}
		if ticket.DwellDays != 2 { // 48h / 24
			t.Errorf("expected dwell days 2, got %v", ticket.DwellDays)
		}
	}
}
