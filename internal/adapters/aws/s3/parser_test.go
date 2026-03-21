package s3

import "testing"

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
		{"", ""},
	}
	for _, tc := range tests {
		got := ParseS3Reference(tc.input).Name()
		if got != tc.want {
			t.Errorf("ParseS3Reference(%q).Name() = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseS3ReferenceRoundTrip(t *testing.T) {
	ref := ParseS3Reference("my-bucket")
	if ParseS3Reference(ARN(ref)).Name() != "my-bucket" {
		t.Error("round-trip through ARN failed")
	}
	if ParseS3Reference(ModelID(ref)).Name() != "my-bucket" {
		t.Error("round-trip through ModelID failed")
	}
}
