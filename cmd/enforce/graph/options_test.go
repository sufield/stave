package graph

import "testing"

func TestDefaultCoverageOptions(t *testing.T) {
	opts := defaultCoverageOptions()
	if opts.Format != "dot" {
		t.Fatalf("Format = %q, want dot", opts.Format)
	}
	if opts.ObservationsDir != "observations" {
		t.Fatalf("ObservationsDir = %q", opts.ObservationsDir)
	}
}
