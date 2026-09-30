package ticketexport

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestGenerate_DistinctAssetTypeUniqueTicketIDs(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.001",
				AssetID:   asset.ID("arn:aws:s3:::my-resource"),
				AssetType: "aws_s3_bucket",
			},
		},
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.S3.001",
				AssetID:   asset.ID("arn:aws:s3:::my-resource"),
				AssetType: "aws_s3_access_point",
			},
		},
	}

	tickets := Generate(findings)
	if len(tickets) != 2 {
		t.Fatalf("expected 2 tickets, got %d", len(tickets))
	}

	if tickets[0].TicketID == tickets[1].TicketID {
		t.Fatalf("ticket ID collision for different AssetTypes on same AssetID: %s", tickets[0].TicketID)
	}
}
