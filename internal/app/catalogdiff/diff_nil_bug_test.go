package catalogdiff

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestFormatTable_NilDeltaHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("FormatTable panicked on nil delta: %v", rec)
		}
	}()

	res := FormatTable(nil)
	if res != "" {
		t.Errorf("expected empty string for nil delta, got %q", res)
	}
}

func TestSeverityChanges_CollectionMethods(t *testing.T) {
	scs := SeverityChanges{
		{ControlID: "CTL-1", Before: policy.SeverityMedium, After: policy.SeverityHigh},
		{ControlID: "CTL-2", Before: policy.SeverityHigh, After: policy.SeverityLow},
	}

	if scs.Len() != 2 {
		t.Errorf("scs.Len() = %d, want 2", scs.Len())
	}

	if scs.Escalated().Len() != 1 {
		t.Errorf("Escalated len = %d, want 1", scs.Escalated().Len())
	}

	if scs.Deescalated().Len() != 1 {
		t.Errorf("Deescalated len = %d, want 1", scs.Deescalated().Len())
	}
}

func TestControlIDs_DomainMethods(t *testing.T) {
	ids := ControlIDs{"CTL-1", "CTL-2"}

	if ids.Len() != 2 {
		t.Errorf("ids.Len() = %d, want 2", ids.Len())
	}

	if !ids.Contains("CTL-1") {
		t.Errorf("Contains(CTL-1) = false, want true")
	}

	if ids.Contains("CTL-3") {
		t.Errorf("Contains(CTL-3) = true, want false")
	}

	var empty ControlIDs
	if empty.Len() != 0 || empty.Contains("CTL-1") {
		t.Errorf("empty ControlIDs methods failed")
	}
}

func TestCatalogCount_DomainMethods(t *testing.T) {
	c := CatalogCount(150)

	if c.Int() != 150 {
		t.Errorf("Int() = %d, want 150", c.Int())
	}
	if c.IsEmpty() {
		t.Error("IsEmpty() = true, want false for 150")
	}
	if !CatalogCount(0).IsEmpty() {
		t.Error("IsEmpty() = false, want true for 0")
	}
	if d := CatalogCount(150).Delta(CatalogCount(120)); d != 30 {
		t.Errorf("Delta() = %d, want 30", d)
	}
}

func TestSeverityChange_DomainMethods(t *testing.T) {
	escalated := SeverityChange{ControlID: "CTL-1", Before: policy.SeverityLow, After: policy.SeverityHigh}
	if !escalated.IsEscalated() || escalated.IsDeescalated() {
		t.Error("escalated IsEscalated / IsDeescalated failed")
	}
	if escalated.String() != "CTL-1: low → high" {
		t.Errorf("String() = %q, want CTL-1: low → high", escalated.String())
	}

	deescalated := SeverityChange{ControlID: "CTL-2", Before: policy.SeverityCritical, After: policy.SeverityMedium}
	if !deescalated.IsDeescalated() || deescalated.IsEscalated() {
		t.Error("deescalated IsEscalated / IsDeescalated failed")
	}

	same := SeverityChange{ControlID: "CTL-3", Before: policy.SeverityMedium, After: policy.SeverityMedium}
	if same.IsEscalated() || same.IsDeescalated() {
		t.Error("same severity should not be escalated or deescalated")
	}
}

func TestSeverityChanges_ExtendedMethods(t *testing.T) {
	var empty SeverityChanges
	if !empty.IsEmpty() {
		t.Error("empty.IsEmpty() = false, want true")
	}
	if empty.ByControlID("X") != nil || empty.ControlIDs() != nil {
		t.Error("empty ByControlID / ControlIDs failed")
	}

	sc1 := SeverityChange{ControlID: "CTL-1", Before: policy.SeverityLow, After: policy.SeverityHigh}
	sc2 := SeverityChange{ControlID: "CTL-2", Before: policy.SeverityHigh, After: policy.SeverityLow}
	scs := SeverityChanges{sc1, sc2}

	if scs.IsEmpty() {
		t.Error("non-empty scs reported IsEmpty() = true")
	}

	found := scs.ByControlID("CTL-1")
	if found == nil || found.ControlID != "CTL-1" {
		t.Error("ByControlID(CTL-1) failed")
	}
	if scs.ByControlID("CTL-NONE") != nil {
		t.Error("ByControlID(CTL-NONE) should return nil")
	}

	ids := scs.ControlIDs()
	if ids.Len() != 2 || ids[0] != "CTL-1" || ids[1] != "CTL-2" {
		t.Errorf("ControlIDs() failed: %v", ids)
	}
}

func TestControlIDs_ExtendedMethods(t *testing.T) {
	var empty ControlIDs
	if !empty.IsEmpty() {
		t.Error("empty ControlIDs.IsEmpty() = false, want true")
	}
	if empty.Strings() != nil {
		t.Error("empty ControlIDs.Strings() should be nil")
	}

	ids := ControlIDs{"CTL-1", "CTL-2"}
	if ids.IsEmpty() {
		t.Error("non-empty ControlIDs reported IsEmpty() = true")
	}
	strs := ids.Strings()
	if len(strs) != 2 || strs[0] != "CTL-1" || strs[1] != "CTL-2" {
		t.Errorf("Strings() failed: %v", strs)
	}
}

func TestDelta_DomainMethods(t *testing.T) {
	var nilDelta *Delta
	if nilDelta.HasChanges() || nilDelta.HasNew() || nilDelta.HasRemoved() || nilDelta.HasSeverityChanges() ||
		nilDelta.TotalChanges() != 0 || nilDelta.NetCountDelta() != 0 || nilDelta.IsClean() {
		t.Error("nil Delta should return zero/false safely")
	}

	cleanDelta := &Delta{
		CatalogBefore: CatalogCount(10),
		CatalogAfter:  CatalogCount(10),
	}
	if cleanDelta.HasChanges() || cleanDelta.HasNew() || cleanDelta.HasRemoved() || cleanDelta.HasSeverityChanges() {
		t.Error("cleanDelta should report no changes")
	}
	if !cleanDelta.IsClean() {
		t.Error("cleanDelta.IsClean() = false, want true")
	}
	if cleanDelta.TotalChanges() != 0 {
		t.Errorf("TotalChanges() = %d, want 0", cleanDelta.TotalChanges())
	}
	if cleanDelta.NetCountDelta() != 0 {
		t.Errorf("NetCountDelta() = %d, want 0", cleanDelta.NetCountDelta())
	}

	changeDelta := &Delta{
		CatalogBefore:   CatalogCount(10),
		CatalogAfter:    CatalogCount(12),
		NewControls:     ControlIDs{"CTL-NEW-1", "CTL-NEW-2"},
		RemovedControls: ControlIDs{"CTL-OLD-1"},
		SeverityChanges: SeverityChanges{
			{ControlID: "CTL-MOD-1", Before: policy.SeverityLow, After: policy.SeverityHigh},
		},
	}
	if !changeDelta.HasChanges() {
		t.Error("HasChanges() = false, want true")
	}
	if !changeDelta.HasNew() {
		t.Error("HasNew() = false, want true")
	}
	if !changeDelta.HasRemoved() {
		t.Error("HasRemoved() = false, want true")
	}
	if !changeDelta.HasSeverityChanges() {
		t.Error("HasSeverityChanges() = false, want true")
	}
	if changeDelta.IsClean() {
		t.Error("IsClean() = true, want false")
	}
	if changeDelta.TotalChanges() != 4 {
		t.Errorf("TotalChanges() = %d, want 4", changeDelta.TotalChanges())
	}
	if changeDelta.NetCountDelta() != 2 {
		t.Errorf("NetCountDelta() = %d, want 2", changeDelta.NetCountDelta())
	}

	formatted := FormatTable(changeDelta)
	if formatted == "" {
		t.Error("FormatTable should produce non-empty output")
	}
}
