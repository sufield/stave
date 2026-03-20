package evaluation

import "testing"

func TestBaselineEntriesFromFindings_DedupesAndSorts(t *testing.T) {
	// This test validates BaselineEntryFromFinding + dedup logic.
	// BaselineEntriesFromFindings moved to remediation package;
	// we test the core building block here.
	findings := []Finding{
		{
			ControlID:   "CTL.TEST.B.001",
			ControlName: "B",
			AssetID:     "res-2",
			AssetType:   "bucket",
		},
		{
			ControlID:   "CTL.TEST.A.001",
			ControlName: "A",
			AssetID:     "res-1",
			AssetType:   "bucket",
		},
	}

	byKey := make(map[BaselineEntryKey]BaselineEntry, len(findings))
	for _, f := range findings {
		entry := BaselineEntryFromFinding(f)
		byKey[entry.Key()] = entry
	}
	entries := make([]BaselineEntry, 0, len(byKey))
	for _, e := range byKey {
		entries = append(entries, e)
	}
	SortBaselineEntries(entries)

	if len(entries) != 2 {
		t.Fatalf("expected 2 deduped entries, got %d", len(entries))
	}
	if entries[0].ControlID != "CTL.TEST.A.001" || entries[0].AssetID != "res-1" {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].ControlID != "CTL.TEST.B.001" || entries[1].AssetID != "res-2" {
		t.Fatalf("unexpected second entry: %+v", entries[1])
	}
}
