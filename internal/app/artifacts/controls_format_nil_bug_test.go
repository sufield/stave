package artifacts

import (
	"testing"

	"github.com/sufield/stave/internal/app/catalog"
)

func TestFormatControlOutput_NilWriterHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("FormatControlOutput panicked on nil writer: %v", rec)
		}
	}()

	cfg := catalog.DiscoveryRequest{
		OutputFormat: "json",
	}

	rows := []catalog.PolicyEntry{
		{ID: "CTL.S3.001"},
	}

	err := FormatControlOutput(nil, cfg, rows)
	if err == nil {
		t.Errorf("expected error when passing nil writer to FormatControlOutput")
	}
}
