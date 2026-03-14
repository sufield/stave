package storage

import (
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"
)

func TestBuildBucketRefModel(t *testing.T) {
	ref := kernel.NewBucketRef("arn:aws:s3:::my-bucket")
	model := BuildBucketRefModel("cdn.example.com", ref, false, false)

	if model.Endpoint != "cdn.example.com" {
		t.Errorf("Endpoint = %q, want %q", model.Endpoint, "cdn.example.com")
	}
	if model.Bucket != "my-bucket" {
		t.Errorf("Bucket = %q, want %q", model.Bucket, "my-bucket")
	}
	if model.BucketExists {
		t.Error("BucketExists = true, want false")
	}
	if model.BucketOwned {
		t.Error("BucketOwned = true, want false")
	}
}

func TestBuildBucketRefModelNormalizesBucket(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-bucket", "my-bucket"},
		{"arn:aws:s3:::my-bucket", "my-bucket"},
		{"aws:s3:::my-bucket", "my-bucket"},
		{"s3://my-bucket/path", "my-bucket"},
		{"MY-BUCKET", "my-bucket"},
	}
	for _, tc := range tests {
		model := BuildBucketRefModel("ep", kernel.NewBucketRef(tc.input), true, true)
		if model.Bucket != tc.want {
			t.Errorf("BuildBucketRefModel(%q).Bucket = %q, want %q", tc.input, model.Bucket, tc.want)
		}
	}
}

func TestBuildBucketRefModelSafeState(t *testing.T) {
	model := BuildBucketRefModel("app.example.com", kernel.NewBucketRef("safe-bucket"), true, true)
	if !model.BucketExists {
		t.Error("BucketExists = false, want true")
	}
	if !model.BucketOwned {
		t.Error("BucketOwned = false, want true")
	}
}
