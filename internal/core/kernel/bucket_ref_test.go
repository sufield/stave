package kernel

import (
	"errors"
	"testing"
)

func TestBucketRefName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-bucket", "my-bucket"},
		{"MY-BUCKET", "my-bucket"},
		{"  my-bucket  ", "my-bucket"},
		{"", ""},
	}
	for _, tc := range tests {
		got := NewBucketRef(tc.input).Name()
		if got != tc.want {
			t.Errorf("NewBucketRef(%q).Name() = %q, want %q", tc.input, got, tc.want)
		}
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
		{"MY-BUCKET", "my-bucket", true},
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
	got := NewBucketRef("test").String()
	if got != "test" {
		t.Errorf("String() = %q, want %q", got, "test")
	}
}

func TestBucketRefValidate(t *testing.T) {
	valid := []string{
		"my-bucket",
		"bucket123",
		"my.bucket.name",
		"a-b",
		"abc",
	}
	for _, name := range valid {
		if err := NewBucketRef(name).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", name, err)
		}
	}

	// Uppercase input is normalized before validation.
	if err := NewBucketRef("MyBucket").Validate(); err != nil {
		t.Errorf("Validate(MyBucket) should pass after normalization, got %v", err)
	}
}

func TestBucketRefValidateInvalid(t *testing.T) {
	invalid := []string{
		"",
		"bucket\\escape",
		"bucket..name",
		"ab",
		".bucket",
		"my_bucket",
	}
	for _, name := range invalid {
		err := NewBucketRef(name).Validate()
		if err == nil {
			t.Errorf("Validate(%q) = nil, want error", name)
		}
		if !errors.Is(err, ErrInvalidBucket) {
			t.Errorf("Validate(%q) error = %v, want ErrInvalidBucket", name, err)
		}
	}
}
