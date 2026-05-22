package evaluation

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// Metadata.ToMap — pack source with git info
// ---------------------------------------------------------------------------

func TestMetadataToMap_PacksSource(t *testing.T) {
	m := Metadata{
		ContextName: "test-project",
		ControlSource: ControlSourceInfo{
			Source:             ControlSourcePacks,
			EnabledPacks:       []kernel.PackName{"s3"},
			ResolvedControlIDs: []kernel.ControlID{"CTL.A.001"},
			RegistryVersion:    "v1.0.0",
			RegistryHash:       "sha256:abc",
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
			EnabledPacks:       []kernel.PackName{"hipaa", "s3"},
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
	entry := BaselineEntryFromFinding(&f)
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
// EnforcementLevel constants
// ---------------------------------------------------------------------------

func TestEnforcementLevelConstants(t *testing.T) {
	if LevelAllow != "ALLOW" {
		t.Fatal("LevelAllow")
	}
	if LevelAdvisory != "ADVISORY" {
		t.Fatal("LevelAdvisory")
	}
	if LevelBlock != "BLOCK" {
		t.Fatal("LevelBlock")
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
// ConfidenceLevel and Verdict constants
// ---------------------------------------------------------------------------

func TestConfidenceLevelConstants(t *testing.T) {
	if ConfidenceHigh != "HIGH" {
		t.Fatal("ConfidenceHigh")
	}
	if ConfidenceMedium != "MEDIUM" {
		t.Fatal("ConfidenceMedium")
	}
	if ConfidenceLow != "LOW" {
		t.Fatal("ConfidenceLow")
	}
	if ConfidenceInconclusive != "INCONCLUSIVE" {
		t.Fatal("ConfidenceInconclusive")
	}
}

func TestDecisionConstants(t *testing.T) {
	if VerdictViolation != "VIOLATION" {
		t.Fatal("VerdictViolation")
	}
	if VerdictPass != "PASS" {
		t.Fatal("VerdictPass")
	}
	if VerdictInconclusive != "INCONCLUSIVE" {
		t.Fatal("VerdictInconclusive")
	}
	if VerdictNotApplicable != "NOT_APPLICABLE" {
		t.Fatal("VerdictNotApplicable")
	}
	if VerdictSkipped != "SKIPPED" {
		t.Fatal("VerdictSkipped")
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
// DeriveSecurityState
// ---------------------------------------------------------------------------

func TestClassifySafetyStatus_Constants(t *testing.T) {
	if StateCompliant != "COMPLIANT" {
		t.Fatal("StateCompliant")
	}
	if StateAtRisk != "AT_RISK" {
		t.Fatal("StateAtRisk")
	}
	if StateNonCompliant != "NON_COMPLIANT" {
		t.Fatal("StateNonCompliant")
	}
}

// ---------------------------------------------------------------------------
// ExceptedFinding
// ---------------------------------------------------------------------------

func TestExceptedFindingFields(t *testing.T) {
	expires, _ := policy.ParseExpiryDate("2026-12-31")
	ef := ExceptedFinding{
		ControlID: "CTL.A.001",
		AssetID:   "bucket-1",
		Reason:    "accepted risk",
		Expires:   expires,
	}
	if ef.ControlID != "CTL.A.001" {
		t.Fatal("ControlID")
	}
	if ef.Reason != "accepted risk" {
		t.Fatal("Reason")
	}
}
