package asset

import "testing"

func TestObservationDeltaApplyFilter(t *testing.T) {
	delta := ObservationDelta{
		Changes: []AssetDiff{
			{AssetID: "bucket-a", ChangeType: ChangeAdded, ToType: "res:aws:s3:bucket"},
			{AssetID: "bucket-b", ChangeType: ChangeModified, FromType: "res:aws:s3:bucket", ToType: "res:aws:s3:bucket"},
			{AssetID: "queue-a", ChangeType: ChangeRemoved, FromType: "res:aws:sqs:queue"},
		},
	}

	filtered := delta.ApplyFilter(FilterOptions{
		ChangeTypes: []ChangeType{ChangeModified, ChangeRemoved},
		AssetTypes:  []string{"res:aws:s3:bucket"},
		AssetID:     "bucket",
	})

	if len(filtered.Changes) != 1 {
		t.Fatalf("expected 1 filtered change, got %d", len(filtered.Changes))
	}
	if filtered.Changes[0].AssetID != "bucket-b" {
		t.Fatalf("unexpected filtered resource: %+v", filtered.Changes[0])
	}

	if filtered.Summary.Modified() != 1 || filtered.Summary.Total() != 1 {
		t.Fatalf("unexpected filtered summary: %+v", filtered.Summary)
	}
}
