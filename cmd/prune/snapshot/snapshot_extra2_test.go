package snapshot

import (
	"testing"
)

func TestQualityOptions_Prepare_ZeroMinSnapshots(t *testing.T) {
	opts := &qualityOptions{
		MinSnapshots: 0,
		MaxStaleness: "48h",
		MaxGap:       "7d",
	}
	err := opts.Prepare(nil)
	if err == nil {
		t.Fatal("expected error for MinSnapshots < 1")
	}
}

func TestQualityOptions_Prepare_ValidDefaults(t *testing.T) {
	opts := &qualityOptions{
		MinSnapshots: 2,
		MaxStaleness: "48h",
		MaxGap:       "7d",
	}
	if err := opts.Prepare(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQualityOptions_Prepare_ZeroDurations(t *testing.T) {
	opts := &qualityOptions{
		MinSnapshots: 1,
		MaxStaleness: "0",
		MaxGap:       "0",
	}
	if err := opts.Prepare(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
