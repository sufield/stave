package sirbridge

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func bucketWithPAB(id string, bpa map[string]bool, accountFullyBlocked bool) asset.Asset {
	storage := map[string]any{
		"ownership_controls": "ObjectWriter",
	}
	controls := map[string]any{
		"account_public_access_fully_blocked": accountFullyBlocked,
	}
	if bpa != nil {
		block := map[string]any{}
		for k, v := range bpa {
			block[k] = v
		}
		controls["public_access_block"] = block
	}
	storage["controls"] = controls
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   kernel.AssetType("aws_s3_bucket"),
		Vendor: kernel.Vendor("aws"),
		Properties: map[string]any{
			"storage": storage,
		},
	}
}

func TestExtractPublicAccessBlock_AllFourTrue(t *testing.T) {
	a := bucketWithPAB("arn:aws:s3:::b1", map[string]bool{
		"block_public_acls":       true,
		"ignore_public_acls":      true,
		"block_public_policy":     true,
		"restrict_public_buckets": true,
	}, false)
	got := extractPublicAccessBlock(a)
	if len(got) != 1 {
		t.Fatalf("expected 1 fact, got %d", len(got))
	}
	fact := got[0]
	if !fact.BlockPublicAcls || !fact.IgnorePublicAcls || !fact.BlockPublicPolicy || !fact.RestrictPublicBuckets {
		t.Errorf("all four flags should be true: %+v", fact)
	}
	wantPath := []string{"PublicAccessBlockConfiguration"}
	if !reflect.DeepEqual(fact.Source.Path, wantPath) {
		t.Errorf("Source.Path: want %v, got %v", wantPath, fact.Source.Path)
	}
}

func TestExtractPublicAccessBlock_AbsentReturnsEmpty(t *testing.T) {
	a := asset.Asset{
		ID:         asset.ID("arn:aws:s3:::b2"),
		Type:       kernel.AssetType("aws_s3_bucket"),
		Vendor:     kernel.Vendor("aws"),
		Properties: map[string]any{},
	}
	got := extractPublicAccessBlock(a)
	if len(got) != 0 {
		t.Errorf("absent PAB must return empty slice, got %+v", got)
	}
}

func TestExtractPublicAccessBlock_AccountAndBucketBothPresent(t *testing.T) {
	a := bucketWithPAB("arn:aws:s3:::b3", map[string]bool{
		"block_public_acls":       true,
		"ignore_public_acls":      false,
		"block_public_policy":     false,
		"restrict_public_buckets": false,
	}, true)
	got := extractPublicAccessBlock(a)
	if len(got) != 2 {
		t.Fatalf("expected 2 facts (bucket + account), got %d", len(got))
	}
	// Bucket-level first.
	if got[0].Source.Kind != "s3_public_access_block" {
		t.Errorf("got[0].Source.Kind: want s3_public_access_block, got %q", got[0].Source.Kind)
	}
	if got[1].Source.Kind != "s3_account_public_access_block" {
		t.Errorf("got[1].Source.Kind: want s3_account_public_access_block, got %q", got[1].Source.Kind)
	}
	// Bucket-level reflects the partial flag set.
	if !got[0].BlockPublicAcls || got[0].IgnorePublicAcls {
		t.Errorf("bucket-level flags wrong: %+v", got[0])
	}
	// Account-level always emits all four true (asset model
	// exposes a single rolled-up boolean).
	if !got[1].BlockPublicAcls || !got[1].IgnorePublicAcls || !got[1].BlockPublicPolicy || !got[1].RestrictPublicBuckets {
		t.Errorf("account-level all-four-true: %+v", got[1])
	}
}

func TestExtractPublicAccessBlock_OnlyAccountLevel(t *testing.T) {
	a := bucketWithPAB("arn:aws:s3:::b4", nil, true)
	got := extractPublicAccessBlock(a)
	if len(got) != 1 {
		t.Fatalf("expected 1 fact (account-only), got %d", len(got))
	}
	if got[0].Source.Kind != "s3_account_public_access_block" {
		t.Errorf("got[0].Source.Kind: want s3_account_public_access_block, got %q", got[0].Source.Kind)
	}
}
