package s3

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestARN(t *testing.T) {
	got := ARN(kernel.NewBucketRef("my-bucket"))
	if got != "arn:aws:s3:::my-bucket" {
		t.Errorf("ARN() = %q, want %q", got, "arn:aws:s3:::my-bucket")
	}
}

func TestModelID(t *testing.T) {
	got := ModelID(kernel.NewBucketRef("my-bucket"))
	if got != "aws:s3:::my-bucket" {
		t.Errorf("ModelID() = %q, want %q", got, "aws:s3:::my-bucket")
	}
}

func TestARNEmpty(t *testing.T) {
	got := ARN(kernel.NewBucketRef(""))
	if got != "arn:aws:s3:::" {
		t.Errorf("ARN(empty) = %q, want %q", got, "arn:aws:s3:::")
	}
}

func TestModelIDEmpty(t *testing.T) {
	got := ModelID(kernel.NewBucketRef(""))
	if got != "aws:s3:::" {
		t.Errorf("ModelID(empty) = %q, want %q", got, "aws:s3:::")
	}
}
