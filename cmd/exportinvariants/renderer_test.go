package exportinvariants

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

func TestValidateFormat_KnownFormats(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "", "JSON", "  json  "} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			if err := validateFormat(format); err != nil {
				t.Fatalf("validateFormat(%q): unexpected error: %v", format, err)
			}
		})
	}
}

func TestValidateFormat_UnknownFormatErrors(t *testing.T) {
	t.Parallel()
	err := validateFormat("yaml")
	if err == nil {
		t.Fatal("validateFormat(\"yaml\"): want error, got nil")
	}
	if !errors.Is(err, stave.ErrInvalidInput) {
		t.Errorf("error should wrap stave.ErrInvalidInput, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--format must be json") {
		t.Errorf("error should explain format: got %q", err.Error())
	}
}

func TestRenderJSON_NonEmptyOutput(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := renderJSON(&buf, &stave.InvariantExport{}); err != nil {
		t.Fatalf("renderJSON: unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Errorf("renderJSON produced empty output")
	}
}
