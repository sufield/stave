package stave

import (
	"errors"
	"testing"
	"time"
)

// TestCompareFrameworks_Formats exercises the renderers that moved here
// from cmd/compare. An assessment with zero findings is valid; every
// format must still produce output.
func TestCompareFrameworks_Formats(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	data := []byte(`{"findings":[]}`)
	for _, format := range []string{"json", "markdown", "table", ""} {
		out, err := CompareFrameworks(at, "hipaa", "soc2", data, format)
		if err != nil {
			t.Fatalf("CompareFrameworks(%q): unexpected error: %v", format, err)
		}
		if len(out) == 0 {
			t.Errorf("CompareFrameworks(%q): produced empty output", format)
		}
	}
}

func TestCompareFrameworks_UnsupportedFormat(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := CompareFrameworks(at, "hipaa", "soc2", []byte(`{"findings":[]}`), "xml")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unsupported format should wrap ErrInvalidInput, got: %v", err)
	}
}

func TestCompareFrameworks_ParseError(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := CompareFrameworks(at, "hipaa", "soc2", []byte(`not json`), "table")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("parse error should wrap ErrInvalidInput, got: %v", err)
	}
}
