package domain

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestValidateControlIDFormat_Valid(t *testing.T) {
	t.Parallel()

	valid := []string{
		"CTL.S3.PUBLIC.901",
		"CTL.S3.PUBLIC.LIST.001",
		"CTL.UPLOAD.WRITE.SCOPE.001",
		"CTL.CLOUD.EXPOSURE.001",
	}

	for _, id := range valid {
		if err := kernel.ValidateControlIDFormat(id); err != nil {
			t.Fatalf("expected valid ID %q, got error: %v", id, err)
		}
	}
}

func TestValidateControlIDFormat_Invalid(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		"CTL.S3.001",
		"CTL.S3.PUBLIC.01",
		"ctl.S3.PUBLIC.001",
		"CTL.S3.public.001",
		"CTL.S3.PUBLIC_.001",
	}

	for _, id := range invalid {
		if err := kernel.ValidateControlIDFormat(id); err == nil {
			t.Fatalf("expected invalid ID %q to fail validation", id)
		}
	}
}
