package kernel

import "testing"

func TestBucketRefName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-bucket", "my-bucket"},
		{"arn:aws:s3:::my-bucket", "my-bucket"},
		{"aws:s3:::my-bucket", "my-bucket"},
		{"s3://my-bucket/key", "my-bucket"},
		{"s3://my-bucket/deep/path", "my-bucket"},
		{"MY-BUCKET", "my-bucket"},
		{"  my-bucket  ", "my-bucket"},
		{"ARN:AWS:S3:::MY-BUCKET", "my-bucket"},
		{"", ""},
	}
	for _, tc := range tests {
		got := NewBucketRef(tc.input).Name()
		if got != tc.want {
			t.Errorf("NewBucketRef(%q).Name() = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestBucketRefARN(t *testing.T) {
	got := NewBucketRef("my-bucket").ARN()
	if got != "arn:aws:s3:::my-bucket" {
		t.Errorf("ARN() = %q, want %q", got, "arn:aws:s3:::my-bucket")
	}
}

func TestBucketRefModelID(t *testing.T) {
	got := NewBucketRef("my-bucket").ModelID()
	if got != "aws:s3:::my-bucket" {
		t.Errorf("ModelID() = %q, want %q", got, "aws:s3:::my-bucket")
	}
}

func TestBucketRefIsEmpty(t *testing.T) {
	if !NewBucketRef("").IsEmpty() {
		t.Error("expected empty BucketRef to be empty")
	}
	if NewBucketRef("x").IsEmpty() {
		t.Error("expected non-empty BucketRef to not be empty")
	}
}

func TestBucketRefEquals(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"my-bucket", "my-bucket", true},
		{"arn:aws:s3:::my-bucket", "my-bucket", true},
		{"aws:s3:::my-bucket", "my-bucket", true},
		{"s3://my-bucket/key", "my-bucket", true},
		{"MY-BUCKET", "my-bucket", true},
		{"arn:aws:s3:::a", "arn:aws:s3:::b", false},
		{"a", "b", false},
	}
	for _, tc := range tests {
		got := NewBucketRef(tc.a).Equals(NewBucketRef(tc.b))
		if got != tc.want {
			t.Errorf("NewBucketRef(%q).Equals(NewBucketRef(%q)) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBucketRefString(t *testing.T) {
	got := NewBucketRef("arn:aws:s3:::test").String()
	if got != "test" {
		t.Errorf("String() = %q, want %q", got, "test")
	}
}

func TestBucketRefRoundTrip(t *testing.T) {
	ref := NewBucketRef("my-bucket")
	if NewBucketRef(ref.ARN()).Name() != "my-bucket" {
		t.Error("round-trip through ARN failed")
	}
	if NewBucketRef(ref.ModelID()).Name() != "my-bucket" {
		t.Error("round-trip through ModelID failed")
	}
}
