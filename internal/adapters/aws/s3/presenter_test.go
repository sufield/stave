package s3

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestARN(t *testing.T) {
	got := ARN(kernel.NewBucketRef("my-bucket"))
	if got != "arn:aws:s3:::my-bucket" {
		t.Errorf("ARN() = %q, want %q", got, "arn:aws:s3:::my-bucket")
	}
}

func TestARNEmpty(t *testing.T) {
	got := ARN(kernel.NewBucketRef(""))
	if got != "arn:aws:s3:::" {
		t.Errorf("ARN(empty) = %q, want %q", got, "arn:aws:s3:::")
	}
}
