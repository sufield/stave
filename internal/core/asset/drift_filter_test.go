package asset

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestObservationDeltaApplyFilter(t *testing.T) {
	delta := InfrastructureDrift{
		Changes: []AssetChange{
			{AssetID: "bucket-a", Action: DriftProvisioned, CurrentType: "res:aws:s3:bucket"},
			{AssetID: "bucket-b", Action: DriftReconfigured, PreviousType: "res:aws:s3:bucket", CurrentType: "res:aws:s3:bucket"},
			{AssetID: "queue-a", Action: DriftDecommissioned, PreviousType: "res:aws:sqs:queue"},
		},
	}

	filtered := delta.ApplyFilter(FilterOptions{
		ChangeTypes: []DriftType{DriftReconfigured, DriftDecommissioned},
		AssetTypes:  []kernel.AssetType{"res:aws:s3:bucket"},
		AssetID:     "bucket",
	})

	if len(filtered.Changes) != 1 {
		t.Fatalf("expected 1 filtered change, got %d", len(filtered.Changes))
	}
	if filtered.Changes[0].AssetID != "bucket-b" {
		t.Fatalf("unexpected filtered resource: %+v", filtered.Changes[0])
	}

	if filtered.Summary.Reconfigured() != 1 || filtered.Summary.Total() != 1 {
		t.Fatalf("unexpected filtered summary: %+v", filtered.Summary)
	}
}
