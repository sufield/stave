package resource

import (
	"testing"

	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestBuildBucketRefAsset(t *testing.T) {
	model := s3storage.BuildBucketRefModel(
		"cdn.example.com",
		kernel.NewBucketRef("dangling-bucket"),
		false, false,
	)
	a := BuildBucketRefAsset("ref-1", model)

	if a.ID != "ref-1" {
		t.Errorf("ID = %q, want %q", a.ID, "ref-1")
	}
	if a.Type != s3storage.TypeS3BucketRef {
		t.Errorf("Type = %q, want %q", a.Type, s3storage.TypeS3BucketRef)
	}
	if a.Vendor != s3storage.VendorAWS {
		t.Errorf("Vendor = %q, want %q", a.Vendor, s3storage.VendorAWS)
	}

	s3Ref, ok := a.Properties["s3_ref"].(map[string]any)
	if !ok {
		t.Fatal("Properties[\"s3_ref\"] missing or wrong type")
	}
	if s3Ref["endpoint"] != "cdn.example.com" {
		t.Errorf("s3_ref.endpoint = %v, want %q", s3Ref["endpoint"], "cdn.example.com")
	}
	if s3Ref["bucket"] != "dangling-bucket" {
		t.Errorf("s3_ref.bucket = %v, want %q", s3Ref["bucket"], "dangling-bucket")
	}
	if s3Ref["bucket_exists"] != false {
		t.Errorf("s3_ref.bucket_exists = %v, want false", s3Ref["bucket_exists"])
	}
	if s3Ref["bucket_owned"] != false {
		t.Errorf("s3_ref.bucket_owned = %v, want false", s3Ref["bucket_owned"])
	}
}

func TestBuildBucketRefAssetSafeState(t *testing.T) {
	model := s3storage.BuildBucketRefModel(
		"app.example.com",
		kernel.NewBucketRef("owned-bucket"),
		true, true,
	)
	a := BuildBucketRefAsset("ref-safe", model)

	s3Ref, ok := a.Properties["s3_ref"].(map[string]any)
	if !ok {
		t.Fatal("Properties[\"s3_ref\"] missing or wrong type")
	}
	if s3Ref["bucket_exists"] != true {
		t.Errorf("s3_ref.bucket_exists = %v, want true", s3Ref["bucket_exists"])
	}
	if s3Ref["bucket_owned"] != true {
		t.Errorf("s3_ref.bucket_owned = %v, want true", s3Ref["bucket_owned"])
	}
}
