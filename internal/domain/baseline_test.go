package domain

import (
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/evaluation"
)

func TestBaselineEntryKey(t *testing.T) {
	e := evaluation.BaselineEntry{ControlID: "CTL.A", AssetID: "res-1"}
	want := evaluation.BaselineEntryKey{ControlID: "CTL.A", AssetID: "res-1"}
	if got := e.Key(); got != want {
		t.Errorf("Key() = %+v, want %+v", got, want)
	}
}

func TestCompareBaseline(t *testing.T) {
	base := []evaluation.BaselineEntry{
		{ControlID: "CTL.A", AssetID: "res-1"},
		{ControlID: "CTL.B", AssetID: "res-2"},
	}
	current := []evaluation.BaselineEntry{
		{ControlID: "CTL.B", AssetID: "res-2"},
		{ControlID: "CTL.C", AssetID: "res-3"},
	}

	result := evaluation.CompareBaseline(base, current)
	if len(result.New) != 1 || result.New[0].ControlID != "CTL.C" {
		t.Errorf("new = %+v, want [CTL.C/res-3]", result.New)
	}
	if len(result.Resolved) != 1 || result.Resolved[0].ControlID != "CTL.A" {
		t.Errorf("resolved = %+v, want [CTL.A/res-1]", result.Resolved)
	}
}

func TestSortBaselineEntries(t *testing.T) {
	entries := []evaluation.BaselineEntry{
		{ControlID: "CTL.B", AssetID: "res-2"},
		{ControlID: "CTL.A", AssetID: "res-2"},
		{ControlID: "CTL.A", AssetID: "res-1"},
	}
	evaluation.SortBaselineEntries(entries)
	if entries[0].ControlID != "CTL.A" || entries[0].AssetID != "res-1" {
		t.Errorf("entries[0] = %+v, want CTL.A/res-1", entries[0])
	}
	if entries[1].ControlID != "CTL.A" || entries[1].AssetID != "res-2" {
		t.Errorf("entries[1] = %+v, want CTL.A/res-2", entries[1])
	}
	if entries[2].ControlID != "CTL.B" || entries[2].AssetID != "res-2" {
		t.Errorf("entries[2] = %+v, want CTL.B/res-2", entries[2])
	}
}

func TestBaselineEntryFromFinding(t *testing.T) {
	f := evaluation.Finding{
		ControlID:   "CTL.A",
		ControlName: "Test",
		AssetID:     "res-1",
		AssetType:   kernel.AssetType("bucket"),
	}
	entry := evaluation.BaselineEntryFromFinding(f)
	if entry.ControlID != "CTL.A" || entry.AssetID != "res-1" || entry.AssetType != "bucket" {
		t.Errorf("unexpected entry: %+v", entry)
	}
}
