package capabilities_test

import (
	"testing"

	"github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/core/kernel"
	aws "github.com/sufield/stave/internal/platform/providers/aws"
)

func TestIsConnectorSupported_Known(t *testing.T) {
	if !capabilities.IsConnectorSupported(aws.SourceTypeAWSS3Snapshot) {
		t.Fatal("expected aws_s3_snapshot to be supported")
	}
}

func TestIsConnectorSupported_Unknown(t *testing.T) {
	if capabilities.IsConnectorSupported(kernel.ObservationSourceType("totally_unknown")) {
		t.Fatal("unexpected source type should not be supported")
	}
}
