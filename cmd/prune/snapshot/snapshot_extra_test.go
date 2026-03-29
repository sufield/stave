package snapshot

import (
	"testing"
)

func TestQualityOptions_Prepare_Valid(t *testing.T) {
	opts := &qualityOptions{
		MinSnapshots: 2,
		MaxStaleness: "48h",
		MaxGap:       "7d",
	}
	err := opts.Prepare(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestQualityOptions_Prepare_InvalidMinSnapshots(t *testing.T) {
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

func TestQualityOptions_Prepare_NegativeMinSnapshots(t *testing.T) {
	opts := &qualityOptions{
		MinSnapshots: -1,
		MaxStaleness: "48h",
		MaxGap:       "7d",
	}
	err := opts.Prepare(nil)
	if err == nil {
		t.Fatal("expected error for MinSnapshots < 1")
	}
}

func TestQualityOptions_Prepare_InvalidMaxStaleness(t *testing.T) {
	opts := &qualityOptions{
		MinSnapshots: 2,
		MaxStaleness: "bad",
		MaxGap:       "7d",
	}
	err := opts.Prepare(nil)
	if err == nil {
		t.Fatal("expected error for invalid MaxStaleness")
	}
}

func TestQualityOptions_Prepare_InvalidMaxGap(t *testing.T) {
	opts := &qualityOptions{
		MinSnapshots: 2,
		MaxStaleness: "48h",
		MaxGap:       "bad",
	}
	err := opts.Prepare(nil)
	if err == nil {
		t.Fatal("expected error for invalid MaxGap")
	}
}
