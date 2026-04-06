package capabilities_test

import (
	"testing"

	s3 "github.com/sufield/stave/internal/adapters/aws/s3"
	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestIsConnectorSupported_Known(t *testing.T) {
	if !capabilities.IsConnectorSupported(s3.SourceTypeAWSS3Snapshot) {
		t.Fatal("expected aws_s3_snapshot to be supported")
	}
}

func TestIsConnectorSupported_Unknown(t *testing.T) {
	if capabilities.IsConnectorSupported(kernel.ObservationSourceType("totally_unknown")) {
		t.Fatal("unexpected source type should not be supported")
	}
}
