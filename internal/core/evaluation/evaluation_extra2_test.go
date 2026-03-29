package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// InputHashes.Sanitized — non-nil receiver
// ---------------------------------------------------------------------------

type stubPathSanitizer struct{}

func (s *stubPathSanitizer) Path(p string) string {
	return "sanitized:" + p
}

func TestInputHashesSanitized_NonNil(t *testing.T) {
	h := &InputHashes{
		Files: map[FilePath]kernel.Digest{
			"/tmp/a.json": "sha256:aaa",
			"/tmp/b.json": "sha256:bbb",
		},
		Overall: "sha256:combined",
	}
	sanitized := h.Sanitized(&stubPathSanitizer{})
	if sanitized == nil {
		t.Fatal("expected non-nil")
	}
	if sanitized.Overall != "sha256:combined" {
		t.Fatalf("Overall = %v", sanitized.Overall)
	}
	if len(sanitized.Files) != 2 {
		t.Fatalf("Files count = %d", len(sanitized.Files))
	}
	for path := range sanitized.Files {
		if path != "sanitized:/tmp/a.json" && path != "sanitized:/tmp/b.json" {
			t.Fatalf("unexpected path key %q", path)
		}
	}
}

// ---------------------------------------------------------------------------
// Metadata.ToMap — pack source with git info
// ---------------------------------------------------------------------------

func TestMetadataToMap_PacksSource(t *testing.T) {
	m := Metadata{
		ContextName: "test-project",
		ControlSource: ControlSourceInfo{
			Source:             ControlSourcePacks,
			EnabledPacks:       []string{"s3"},
			ResolvedControlIDs: []kernel.ControlID{"CTL.A.001"},
			RegistryVersion:    "v1.0.0",
			RegistryHash:       "sha256:abc",
		},
		Git: &GitInfo{
			RepoRoot:  "/repo",
			Head:      "abc123",
			Dirty:     true,
			DirtyList: []string{"file.go"},
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/repo/controls",
			Observations: "/repo/observations",
		},
	}

	result := m.ToMap()
	if result == nil {
		t.Fatal("expected non-nil map")
	}
	if result["context_name"] != "test-project" {
		t.Fatalf("context_name = %v", result["context_name"])
	}
	if result["selected_controls_source"] != "packs" {
		t.Fatalf("selected_controls_source = %v", result["selected_controls_source"])
	}
	// Git metadata should be present
	gitRaw, ok := result["git"]
	if !ok {
		t.Fatal("expected git key")
	}
	gitMap, ok := gitRaw.(map[string]any)
	if !ok {
		t.Fatalf("git is %T, not map", gitRaw)
	}
	if gitMap["dirty"] != true {
		t.Fatalf("git.dirty = %v", gitMap["dirty"])
	}
}

func TestMetadataToMap_EmptySource(t *testing.T) {
	m := Metadata{}
	result := m.ToMap()
	if len(result) != 0 {
		t.Fatalf("empty metadata should return empty map, got %d keys", len(result))
	}
}

func TestMetadataToMap_DirSource(t *testing.T) {
	m := Metadata{
		ControlSource: ControlSourceInfo{
			Source: ControlSourceDir,
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/repo/controls",
			Observations: "/repo/observations",
		},
	}
	result := m.ToMap()
	if result["selected_controls_source"] != "dir" {
		t.Fatalf("selected_controls_source = %v", result["selected_controls_source"])
	}
	// Dir source should NOT have enabled_packs
	if _, ok := result["enabled_control_packs"]; ok {
		t.Fatal("dir source should not have enabled_control_packs")
	}
}

// ---------------------------------------------------------------------------
// ToExtensions — with packs
// ---------------------------------------------------------------------------

func TestToExtensions_NilForEmpty(t *testing.T) {
	m := Metadata{}
	if m.ToExtensions() != nil {
		t.Fatal("empty metadata should return nil extensions")
	}
}

func TestToExtensions_PacksSource(t *testing.T) {
	m := Metadata{
		ControlSource: ControlSourceInfo{
			Source:             ControlSourcePacks,
			EnabledPacks:       []string{"hipaa", "s3"},
			ResolvedControlIDs: []kernel.ControlID{"CTL.A.001", "CTL.B.001"},
			RegistryVersion:    "v2.0",
			RegistryHash:       "sha256:xyz",
		},
		ResolvedPaths: ResolvedPaths{
			Controls:     "/c",
			Observations: "/o",
		},
	}
	ext := m.ToExtensions()
	if ext == nil {
		t.Fatal("expected non-nil extensions")
	}
	if len(ext.EnabledPacks) != 2 {
		t.Fatalf("EnabledPacks = %v", ext.EnabledPacks)
	}
	if len(ext.ResolvedControlIDs) != 2 {
		t.Fatalf("ResolvedControlIDs = %v", ext.ResolvedControlIDs)
	}
	if ext.PackRegistryVersion != "v2.0" {
		t.Fatalf("PackRegistryVersion = %v", ext.PackRegistryVersion)
	}
}

// ---------------------------------------------------------------------------
// BaselineEntryFromFinding
// ---------------------------------------------------------------------------

func TestBaselineEntryFromFinding(t *testing.T) {
	f := Finding{
		ControlID:   "CTL.A.001",
		ControlName: "Test Control",
		AssetID:     "bucket-1",
		AssetType:   "s3_bucket",
	}
	entry := BaselineEntryFromFinding(f)
	if entry.ControlID != f.ControlID {
		t.Fatalf("ControlID = %v", entry.ControlID)
	}
	if entry.ControlName != f.ControlName {
		t.Fatalf("ControlName = %v", entry.ControlName)
	}
	if entry.AssetID != f.AssetID {
		t.Fatalf("AssetID = %v", entry.AssetID)
	}
	if entry.AssetType != f.AssetType {
		t.Fatalf("AssetType = %v", entry.AssetType)
	}
}

// ---------------------------------------------------------------------------
// SortBaselineEntries
// ---------------------------------------------------------------------------

func TestSortBaselineEntries(t *testing.T) {
	entries := []BaselineEntry{
		{ControlID: "CTL.C.001", AssetID: "z"},
		{ControlID: "CTL.A.001", AssetID: "a"},
		{ControlID: "CTL.A.001", AssetID: "c"},
		{ControlID: "CTL.B.001", AssetID: "b"},
	}
	SortBaselineEntries(entries)
	if entries[0].ControlID != "CTL.A.001" || entries[0].AssetID != "a" {
		t.Fatalf("[0] = %v/%v", entries[0].ControlID, entries[0].AssetID)
	}
	if entries[1].ControlID != "CTL.A.001" || entries[1].AssetID != "c" {
		t.Fatalf("[1] = %v/%v", entries[1].ControlID, entries[1].AssetID)
	}
}

// ---------------------------------------------------------------------------
// ActionSeverity constants
// ---------------------------------------------------------------------------

func TestActionSeverityConstants(t *testing.T) {
	if ActionPass != "pass" {
		t.Fatal("ActionPass")
	}
	if ActionWarn != "warn" {
		t.Fatal("ActionWarn")
	}
	if ActionFail != "fail" {
		t.Fatal("ActionFail")
	}
}

// ---------------------------------------------------------------------------
// CompareVerificationFindings
// ---------------------------------------------------------------------------

func TestCompareVerificationFindings_Empty(t *testing.T) {
	diff := CompareVerificationFindings(nil, nil)
	if len(diff.Resolved) != 0 || len(diff.Remaining) != 0 || len(diff.Introduced) != 0 {
		t.Fatalf("expected empty diff: %+v", diff)
	}
}

func TestCompareVerificationFindings_AllResolved(t *testing.T) {
	before := []Finding{
		{ControlID: "CTL.A.001", AssetID: "b1"},
	}
	diff := CompareVerificationFindings(before, nil)
	if len(diff.Resolved) != 1 {
		t.Fatalf("Resolved = %d", len(diff.Resolved))
	}
	if len(diff.Remaining) != 0 || len(diff.Introduced) != 0 {
		t.Fatalf("unexpected remaining/introduced: %+v", diff)
	}
}

func TestCompareVerificationFindings_AllIntroduced(t *testing.T) {
	after := []Finding{
		{ControlID: "CTL.B.001", AssetID: "b2"},
	}
	diff := CompareVerificationFindings(nil, after)
	if len(diff.Introduced) != 1 {
		t.Fatalf("Introduced = %d", len(diff.Introduced))
	}
}

func TestCompareVerificationFindings_MixedDiff(t *testing.T) {
	before := []Finding{
		{ControlID: "CTL.A.001", AssetID: "b1"},
		{ControlID: "CTL.B.001", AssetID: "b2"},
	}
	after := []Finding{
		{ControlID: "CTL.B.001", AssetID: "b2"},
		{ControlID: "CTL.C.001", AssetID: "b3"},
	}
	diff := CompareVerificationFindings(before, after)
	if len(diff.Resolved) != 1 || diff.Resolved[0].ControlID != "CTL.A.001" {
		t.Fatalf("Resolved = %v", diff.Resolved)
	}
	if len(diff.Remaining) != 1 || diff.Remaining[0].ControlID != "CTL.B.001" {
		t.Fatalf("Remaining = %v", diff.Remaining)
	}
	if len(diff.Introduced) != 1 || diff.Introduced[0].ControlID != "CTL.C.001" {
		t.Fatalf("Introduced = %v", diff.Introduced)
	}
}

// ---------------------------------------------------------------------------
// ConfidenceLevel and Decision constants
// ---------------------------------------------------------------------------

func TestConfidenceLevelConstants(t *testing.T) {
	if ConfidenceHigh != "high" {
		t.Fatal("ConfidenceHigh")
	}
	if ConfidenceMedium != "medium" {
		t.Fatal("ConfidenceMedium")
	}
	if ConfidenceLow != "low" {
		t.Fatal("ConfidenceLow")
	}
	if ConfidenceInconclusive != "inconclusive" {
		t.Fatal("ConfidenceInconclusive")
	}
}

func TestDecisionConstants(t *testing.T) {
	if DecisionViolation != "VIOLATION" {
		t.Fatal("DecisionViolation")
	}
	if DecisionPass != "PASS" {
		t.Fatal("DecisionPass")
	}
	if DecisionInconclusive != "INCONCLUSIVE" {
		t.Fatal("DecisionInconclusive")
	}
	if DecisionNotApplicable != "NOT_APPLICABLE" {
		t.Fatal("DecisionNotApplicable")
	}
	if DecisionSkipped != "SKIPPED" {
		t.Fatal("DecisionSkipped")
	}
}

// ---------------------------------------------------------------------------
// ControlSourceMode constants
// ---------------------------------------------------------------------------

func TestControlSourceModeConstants(t *testing.T) {
	if ControlSourceDir != "dir" {
		t.Fatal("ControlSourceDir")
	}
	if ControlSourcePacks != "packs" {
		t.Fatal("ControlSourcePacks")
	}
}

// ---------------------------------------------------------------------------
// ClassifySafetyStatus
// ---------------------------------------------------------------------------

func TestClassifySafetyStatus_Constants(t *testing.T) {
	if StatusSafe != "SAFE" {
		t.Fatal("StatusSafe")
	}
	if StatusBorderline != "BORDERLINE" {
		t.Fatal("StatusBorderline")
	}
	if StatusUnsafe != "UNSAFE" {
		t.Fatal("StatusUnsafe")
	}
}

// ---------------------------------------------------------------------------
// ExceptedFinding
// ---------------------------------------------------------------------------

func TestExceptedFindingFields(t *testing.T) {
	ef := ExceptedFinding{
		ControlID: "CTL.A.001",
		AssetID:   "bucket-1",
		Reason:    "accepted risk",
		Expires:   "2026-12-31",
	}
	if ef.ControlID != "CTL.A.001" {
		t.Fatal("ControlID")
	}
	if ef.Reason != "accepted risk" {
		t.Fatal("Reason")
	}
}
