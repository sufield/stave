package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestCompareVerificationFindings(t *testing.T) {
	before := []Finding{
		{ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"), AssetID: asset.ID("bucket-a"), AssetType: kernel.AssetType("aws_s3_bucket")},
		{ControlID: kernel.ControlID("CTL.S3.PUBLIC.002"), AssetID: asset.ID("bucket-b"), AssetType: kernel.AssetType("aws_s3_bucket")},
	}
	after := []Finding{
		{ControlID: kernel.ControlID("CTL.S3.PUBLIC.002"), AssetID: asset.ID("bucket-b"), AssetType: kernel.AssetType("aws_s3_bucket")},
		{ControlID: kernel.ControlID("CTL.S3.PUBLIC.003"), AssetID: asset.ID("bucket-c"), AssetType: kernel.AssetType("aws_s3_bucket")},
	}

	got := CompareVerificationFindings(before, after)

	if len(got.Resolved) != 1 || got.Resolved[0].ControlID != kernel.ControlID("CTL.S3.PUBLIC.001") {
		t.Fatalf("resolved mismatch: %#v", got.Resolved)
	}
	if len(got.Remaining) != 1 || got.Remaining[0].ControlID != kernel.ControlID("CTL.S3.PUBLIC.002") {
		t.Fatalf("remaining mismatch: %#v", got.Remaining)
	}
	if len(got.Introduced) != 1 || got.Introduced[0].ControlID != kernel.ControlID("CTL.S3.PUBLIC.003") {
		t.Fatalf("introduced mismatch: %#v", got.Introduced)
	}
}

func TestCompareVerificationFindings_SortsDeterministically(t *testing.T) {
	before := []Finding{
		{ControlID: kernel.ControlID("CTL.S3.PUBLIC.002"), AssetID: asset.ID("bucket-z")},
		{ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"), AssetID: asset.ID("bucket-a")},
		{ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"), AssetID: asset.ID("bucket-b")},
	}

	got := CompareVerificationFindings(before, nil)
	if len(got.Resolved) != 3 {
		t.Fatalf("expected 3 resolved, got %d", len(got.Resolved))
	}

	wantOrder := []string{
		"CTL.S3.PUBLIC.001\x00bucket-a",
		"CTL.S3.PUBLIC.001\x00bucket-b",
		"CTL.S3.PUBLIC.002\x00bucket-z",
	}
	for i, f := range got.Resolved {
		key := f.ControlID.String() + "\x00" + f.AssetID.String()
		if key != wantOrder[i] {
			t.Fatalf("resolved[%d] order mismatch: got %q want %q", i, key, wantOrder[i])
		}
	}
}
