package diff

import "testing"

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.ObservationsDir != "observations" {
		t.Fatalf("ObservationsDir = %q, want 'observations'", opts.ObservationsDir)
	}
	if opts.Format != "text" {
		t.Fatalf("Format = %q, want 'text'", opts.Format)
	}
}
