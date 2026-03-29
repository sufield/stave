package capabilities_test

import (
	"testing"

	s3 "github.com/sufield/stave/internal/adapters/aws/s3"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestIsSourceTypeSupported_Known(t *testing.T) {
	if !capabilities.IsSourceTypeSupported(s3.SourceTypeAWSS3Snapshot) {
		t.Fatal("expected aws_s3_snapshot to be supported")
	}
}

func TestIsSourceTypeSupported_Unknown(t *testing.T) {
	if capabilities.IsSourceTypeSupported(kernel.ObservationSourceType("totally_unknown")) {
		t.Fatal("unexpected source type should not be supported")
	}
}
