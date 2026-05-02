package s3

import (
	"errors"
	"testing"
)

func TestParseS3Reference(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"arn:aws:s3:::my-bucket", "my-bucket"},
		{"aws:s3:::my-bucket", "my-bucket"},
		{"s3://my-bucket/key", "my-bucket"},
		{"s3://my-bucket/deep/path", "my-bucket"},
		{"ARN:AWS:S3:::MY-BUCKET", "my-bucket"},
		{"my-bucket", "my-bucket"},
		{"  my-bucket  ", "my-bucket"},
		{"MY-BUCKET", "my-bucket"},
	}
	for _, tc := range tests {
		ref, err := ParseS3Reference(tc.input)
		if err != nil {
			t.Errorf("ParseS3Reference(%q) error = %v", tc.input, err)
			continue
		}
		if got := ref.Name(); got != tc.want {
			t.Errorf("ParseS3Reference(%q).Name() = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseS3Reference_EmptyInputReturnsError(t *testing.T) {
	if _, err := ParseS3Reference(""); !errors.Is(err, ErrEmptyS3Reference) {
		t.Errorf("ParseS3Reference(\"\") expected ErrEmptyS3Reference, got %v", err)
	}
	if _, err := ParseS3Reference("arn:aws:s3:::"); !errors.Is(err, ErrEmptyS3Reference) {
		t.Errorf("ParseS3Reference(\"arn:aws:s3:::\") expected ErrEmptyS3Reference, got %v", err)
	}
}

func TestParseS3ReferenceRoundTrip(t *testing.T) {
	ref, err := ParseS3Reference("my-bucket")
	if err != nil {
		t.Fatalf("ParseS3Reference: %v", err)
	}
	round, err := ParseS3Reference(ARN(ref))
	if err != nil || round.Name() != "my-bucket" {
		t.Error("round-trip through ARN failed")
	}
	round2, err := ParseS3Reference("aws:s3:::my-bucket")
	if err != nil || round2.Name() != "my-bucket" {
		t.Error("round-trip through model ID prefix failed")
	}
}
