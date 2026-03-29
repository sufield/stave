package gate

import (
	"testing"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.InPath != "output/evaluation.json" {
		t.Fatalf("InPath = %q", opts.InPath)
	}
	if opts.BaselinePath != "output/baseline.json" {
		t.Fatalf("BaselinePath = %q", opts.BaselinePath)
	}
	if opts.ObservationsDir != "observations" {
		t.Fatalf("ObservationsDir = %q", opts.ObservationsDir)
	}
	if opts.Format != "text" {
		t.Fatalf("Format = %q", opts.Format)
	}
	// Policy and MaxUnsafeDuration should be zero (filled from config later)
	if opts.Policy != "" {
		t.Fatalf("Policy should be empty, got %q", opts.Policy)
	}
	if opts.MaxUnsafeDuration != "" {
		t.Fatalf("MaxUnsafeDuration should be empty, got %q", opts.MaxUnsafeDuration)
	}
}
