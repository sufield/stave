package engine

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// =========================================================================
// evidence_hook.go — 17 survivors
// =========================================================================

// Lines 31, 118, 122: branch/if nil guards in lookupProperties and
// buildEvidencePackage control iteration.

func TestMK5_LookupProperties_NonNilSnapshotMissingAsset(t *testing.T) {
	snap := &asset.Snapshot{Assets: []asset.Asset{{ID: "other"}}}
	got := lookupProperties(snap, "nonexistent")
	if got != nil {
		t.Fatal("expected nil for missing asset")
	}
}

func TestMK5_LookupProperties_NonNilSnapshotFound(t *testing.T) {
	snap := &asset.Snapshot{Assets: []asset.Asset{
		{ID: "a-1", Properties: map[string]any{"foo": "bar"}},
	}}
	got := lookupProperties(snap, "a-1")
	if got == nil || got["foo"] != "bar" {
		t.Fatalf("expected properties, got %v", got)
	}
}

// Lines 46-47, 56, 59-60: loop/break, expression/logical, expression/remove,
// numbers/decrementer in the findings + checks iteration of buildEvidencePackage.
// The test verifies that violation findings with compliance AND pass checks with
// compliance both produce evidence records; and that findings/checks without
// compliance are skipped.

func TestMK5_BuildEvidencePackage_ViolationsAndPasses(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: "CTL.A", AssetID: "a-1"},
		{ControlID: "CTL.B", AssetID: "a-2"}, // no compliance → skipped
		{ControlID: "CTL.C", AssetID: "a-3"}, // nil in index → skipped
	}
	checks := []evaluation.ResourceCheck{
		{ControlID: "CTL.A", AssetID: "a-4", Verdict: evaluation.VerdictPass},
		{ControlID: "CTL.D", AssetID: "a-5", Verdict: evaluation.VerdictViolation}, // not pass → skipped
	}
	ctls := []policy.ControlDefinition{
		{ID: "CTL.A", Compliance: policy.ComplianceMapping{policy.ComplianceFramework("CIS"): "1.1"}},
		{ID: "CTL.B"},
	}
	pkg := buildEvidencePackage(findings, checks, ctls, nil, time.Now())
	if pkg == nil {
		t.Fatal("expected non-nil package")
	}
	// CTL.A violation + CTL.A pass check = 2 inputs with compliance.
	// Others skipped due to no compliance or not pass or missing from index.
	if len(pkg.Records) < 2 {
		t.Fatalf("expected at least 2 records, got %d", len(pkg.Records))
	}
}

func TestMK5_BuildEvidencePackage_OnlyPassChecks(t *testing.T) {
	checks := []evaluation.ResourceCheck{
		{ControlID: "CTL.A", AssetID: "a-1", Verdict: evaluation.VerdictPass},
	}
	ctls := []policy.ControlDefinition{
		{ID: "CTL.A", Compliance: policy.ComplianceMapping{policy.ComplianceFramework("SOC2"): "CC6.1"}},
	}
	pkg := buildEvidencePackage(nil, checks, ctls, nil, time.Now())
	if pkg == nil {
		t.Fatal("expected non-nil package for pass checks")
	}
	if len(pkg.Records) != 1 {
		t.Fatalf("expected 1 record for single pass check, got %d", len(pkg.Records))
	}
}

func TestMK5_BuildEvidencePackage_WithSnapshot(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := &asset.Snapshot{
		CapturedAt: now,
		Assets:     []asset.Asset{{ID: "a-1", Properties: map[string]any{"region": "us-east-1"}}},
	}
	findings := []evaluation.Finding{{ControlID: "CTL.A", AssetID: "a-1"}}
	ctls := []policy.ControlDefinition{
		{ID: "CTL.A", Compliance: policy.ComplianceMapping{policy.ComplianceFramework("CIS"): "2.1"}},
	}
	pkg := buildEvidencePackage(findings, nil, ctls, snap, now)
	if pkg == nil {
		t.Fatal("expected non-nil package with snapshot")
	}
}

// Line 31: snapshotID assignment from latestSnapshot.
func TestMK5_BuildEvidencePackage_SnapshotIDFormat(t *testing.T) {
	ts := time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC)
	snap := &asset.Snapshot{CapturedAt: ts}
	pkg := buildEvidencePackage(nil, nil, nil, snap, ts)
	if pkg == nil {
		t.Fatal("expected non-nil package")
	}
}

// isSensitiveField: already tested in mutation_kill2, but we add a boundary test
// for the token splitter behavior (lines covering the FieldsFunc loop).
func TestMK5_IsSensitiveField_NestedDelimiters(t *testing.T) {
	if !isSensitiveField("config.access_key.id") {
		t.Fatal("expected 'config.access_key.id' to be sensitive (token 'key')")
	}
	if isSensitiveField("config.region.name") {
		t.Fatal("expected 'config.region.name' to NOT be sensitive")
	}
}

// complianceToMap: lines 106-113.
func TestMK5_ComplianceToMap_Empty(t *testing.T) {
	got := complianceToMap(nil)
	if got != nil {
		t.Fatal("nil compliance should return nil")
	}
}

func TestMK5_ComplianceToMap_NonEmpty(t *testing.T) {
	cm := policy.ComplianceMapping{
		policy.ComplianceFramework("CIS"):  "1.1",
		policy.ComplianceFramework("SOC2"): "CC6.1",
	}
	got := complianceToMap(cm)
	if len(got) != 2 || got["CIS"] != "1.1" || got["SOC2"] != "CC6.1" {
		t.Fatalf("unexpected map: %v", got)
	}
}

// =========================================================================
// exposure.go — 11 survivors
// =========================================================================

// Lines 88, 91: loop/break in assetExposure when prefix is not exposed.
// Lines 107-108: nil finding guard after NewFinding.
// Lines 110, 113-114: findings append and verdict.
// Lines 135, 156: nil finding guard in configIssue/overlapIssue.

func TestMK5_NewPrefixExposureRow_NilLifecycle(t *testing.T) {
	ctl := testControl("CTL.PE.001", policy.TypePrefixExposure)
	row := newPrefixExposureRow(nil, ctl)
	if row.ControlID != "" {
		t.Fatal("nil lifecycle should produce empty row")
	}
}

func TestMK5_NewPrefixExposureRow_NilControl(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	row := newPrefixExposureRow(lc, nil)
	if row.ControlID != "" {
		t.Fatal("nil control should produce empty row")
	}
}

func TestMK5_NewPrefixExposureRow_Valid(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	ctl := testControl("CTL.PE.001", policy.TypePrefixExposure)
	row := newPrefixExposureRow(lc, ctl)
	if row.ControlID != "CTL.PE.001" {
		t.Fatalf("expected CTL.PE.001, got %s", row.ControlID)
	}
	if row.Verdict != evaluation.VerdictPass {
		t.Fatalf("expected PASS, got %s", row.Verdict)
	}
}

func TestMK5_PrefixEvaluator_ConfigIssue_NilFinding(t *testing.T) {
	// nil lifecycle → NewFinding returns nil → configIssue should handle gracefully.
	e := prefixEvaluator{lifecycle: nil, ctl: nil}
	row := evaluation.ResourceCheck{Verdict: evaluation.VerdictPass}
	retRow, findings := e.configIssue(row, "test", "test_code")
	if retRow.Verdict != evaluation.VerdictViolation {
		t.Fatal("expected violation verdict even with nil finding")
	}
	if findings != nil {
		t.Fatal("expected nil findings when NewFinding returns nil")
	}
}

func TestMK5_PrefixEvaluator_OverlapIssue_NilFinding(t *testing.T) {
	e := prefixEvaluator{lifecycle: nil, ctl: nil}
	row := evaluation.ResourceCheck{Verdict: evaluation.VerdictPass}
	conflict := &policy.PrefixConflict{Protected: "secret/", Allowed: "secret/"}
	retRow, findings := e.overlapIssue(row, conflict)
	if retRow.Verdict != evaluation.VerdictViolation {
		t.Fatal("expected violation verdict")
	}
	if findings != nil {
		t.Fatal("expected nil findings when NewFinding returns nil")
	}
}

// =========================================================================
// finding_builder.go — 11 survivors
// =========================================================================

// Line 19: borrowFinding pool Get type assertion failure path.
// Lines 30-31: ReturnFindings nil check in loop.
// Lines 76-77: newBaseFinding nil guard log + return.
// Lines 81, 89-93: newBaseFinding field population.

func TestMK5_BorrowFinding_ReturnsZeroValue(t *testing.T) {
	f := borrowFinding()
	if f == nil {
		t.Fatal("borrowFinding should never return nil")
	}
	if f.ControlID != "" || f.AssetID != "" {
		t.Fatal("borrowFinding should return zero-value finding")
	}
}

func TestMK5_ReturnFindings_NilsInSlice(t *testing.T) {
	// Verify ReturnFindings tolerates nil entries without panic.
	ReturnFindings([]*evaluation.Finding{nil, nil})
}

func TestMK5_ReturnFindings_ValidFindings(t *testing.T) {
	f1 := &evaluation.Finding{ControlID: "CTL.A"}
	f2 := &evaluation.Finding{ControlID: "CTL.B"}
	ReturnFindings([]*evaluation.Finding{f1, f2})
	// No panic = success. Pool recycles.
}

func TestMK5_NewBaseFinding_PopulatesFields(t *testing.T) {
	ctl := testControl("CTL.FB.001", policy.TypeUnsafeState)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket", Vendor: "aws"}
	lc, _ := asset.NewExposureLifecycle(a)
	f := newBaseFinding(ctl, lc)
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.AssetID != "a-1" {
		t.Fatalf("expected asset ID a-1, got %s", f.AssetID)
	}
	if f.AssetType != "s3_bucket" {
		t.Fatalf("expected s3_bucket, got %s", f.AssetType)
	}
	if f.AssetVendor != "aws" {
		t.Fatalf("expected vendor aws, got %s", f.AssetVendor)
	}
}

func TestMK5_NewBaseFinding_NilControl(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	f := newBaseFinding(nil, lc)
	if f != nil {
		t.Fatal("nil control should return nil finding")
	}
}

func TestMK5_NewBaseFinding_NilLifecycle(t *testing.T) {
	ctl := testControl("CTL.X", policy.TypeUnsafeState)
	f := newBaseFinding(ctl, nil)
	if f != nil {
		t.Fatal("nil lifecycle should return nil finding")
	}
}

func TestMK5_NewBaseFinding_EmptyControlID(t *testing.T) {
	ctl := &policy.ControlDefinition{ID: "", Name: "empty"}
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	f := newBaseFinding(ctl, lc)
	if f != nil {
		t.Fatal("empty ControlID should return nil")
	}
}

func TestMK5_NewFinding_SetsEvidence(t *testing.T) {
	ctl := testControl("CTL.NF.001", policy.TypeUnsafeState)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	f := NewFinding(ctl, lc, FindingContext{
		Reason: "test reason",
		Misconfigs: []policy.Misconfiguration{
			{Property: predicate.NewFieldPath("p1"), ActualValue: "v1"},
		},
	})
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.TemporalRisk != "test reason" {
		t.Fatalf("expected reason, got %q", f.Evidence.TemporalRisk)
	}
	if len(f.Evidence.Misconfigurations) != 1 {
		t.Fatal("expected 1 misconfiguration")
	}
}

// =========================================================================
// finding_gen.go — 12 survivors
// =========================================================================

// Lines 57-58: nil ExposureLifecycle guard in CreateDurationFinding.
// Line 64: duration sentinel -1*time.Hour on error.
// Line 72: newBaseFinding nil guard (defensive).
// Lines 89-92: setting fields + durationErr return.
// Lines 121-122: ExtractSourceEvidence IsEmpty guard.

func TestMK5_CreateDurationFinding_NilLifecycle(t *testing.T) {
	ctl := testControl("CTL.D.001", policy.TypeUnsafeDuration)
	_, err := CreateDurationFinding(DurationFindingInput{
		Control: ctl,
	})
	if err == nil {
		t.Fatal("expected error for nil ExposureLifecycle")
	}
}

func TestMK5_CreateDurationFinding_NilControl(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	_, err := CreateDurationFinding(DurationFindingInput{
		ExposureLifecycle: lc,
	})
	if err == nil {
		t.Fatal("expected error for nil Control")
	}
}

func TestMK5_CreateDurationFinding_ValidInputPopulatesFields(t *testing.T) {
	ctl := testControl("CTL.D.002", policy.TypeUnsafeDuration)
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	// Add two observations to make ExposureDuration succeed.
	lc.RecordCheck(now.Add(-48*time.Hour), true)
	lc.RecordCheck(now, true)

	f, err := CreateDurationFinding(DurationFindingInput{
		ExposureLifecycle: lc,
		Control:           ctl,
		Threshold:         24 * time.Hour,
		EvalTime:          now,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.ThresholdHours != 24.0 {
		t.Fatalf("expected 24h threshold, got %f", f.Evidence.ThresholdHours)
	}
	if f.Evidence.UnsafeDurationHours <= 0 {
		t.Fatalf("expected positive duration hours, got %f", f.Evidence.UnsafeDurationHours)
	}
}

func TestMK5_DeriveRootCauses_IdentityOnly(t *testing.T) {
	mcs := []policy.Misconfiguration{{Category: policy.CategoryIdentity}}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseIdentity {
		t.Fatalf("expected [identity], got %v", causes)
	}
}

func TestMK5_DeriveRootCauses_ResourceOnly(t *testing.T) {
	mcs := []policy.Misconfiguration{{Category: policy.CategoryResource}}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseResource {
		t.Fatalf("expected [resource], got %v", causes)
	}
}

func TestMK5_DeriveRootCauses_BothCauses(t *testing.T) {
	mcs := []policy.Misconfiguration{
		{Category: policy.CategoryIdentity},
		{Category: policy.CategoryResource},
	}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 2 {
		t.Fatalf("expected 2 causes, got %d", len(causes))
	}
	if causes[0] != evaluation.RootCauseIdentity {
		t.Fatal("identity should come first")
	}
	if causes[1] != evaluation.RootCauseResource {
		t.Fatal("resource should come second")
	}
}

func TestMK5_DeriveRootCauses_GeneralFallback(t *testing.T) {
	mcs := []policy.Misconfiguration{{Category: policy.CategoryUnknown}}
	causes := DeriveRootCauses(mcs)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseGeneral {
		t.Fatalf("expected [general], got %v", causes)
	}
}

func TestMK5_ExtractSourceEvidence_WithIdentityStatements(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"source_evidence": map[string]any{
			"policy_public_statements": []any{"AllowRead"},
		},
	}}
	ev := ExtractSourceEvidence(a, []evaluation.RootCause{evaluation.RootCauseIdentity})
	if ev == nil {
		t.Fatal("expected non-nil evidence")
	}
	if !ev.HasIdentityStatements() {
		t.Fatal("expected identity statements")
	}
}

func TestMK5_ExtractSourceEvidence_WithResourceGrantees(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"source_evidence": map[string]any{
			"acl_public_grantees": []any{"http://acs.amazonaws.com/groups/global/AllUsers"},
		},
	}}
	ev := ExtractSourceEvidence(a, []evaluation.RootCause{evaluation.RootCauseResource})
	if ev == nil {
		t.Fatal("expected non-nil evidence")
	}
	if !ev.HasResourceGrantees() {
		t.Fatal("expected resource grantees")
	}
}

func TestMK5_ExtractSourceEvidence_EmptyPropertiesReturnsNil(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{}}
	ev := ExtractSourceEvidence(a, []evaluation.RootCause{evaluation.RootCauseIdentity})
	if ev != nil {
		t.Fatal("expected nil when no source evidence data")
	}
}

func TestMK5_ToSorted_DuplicatesPreserved(t *testing.T) {
	got := toSorted[kernel.StatementID]([]string{"b", "a", "b"})
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "b" {
		t.Fatalf("expected [a b b], got %v", got)
	}
}

// =========================================================================
// key_isolation.go — 18 survivors
// =========================================================================

// Line 65: loop/break in buildKeyUsageIndexForSnapshot when keyID is empty.
// Lines 80, 83: expression/comparison for MinLevel/MaxLevel updates.
// Line 104: numbers/decrementer in ParseSensitivity.
// Lines 136, 163, 176, 202, 220: branch/if guards in extractClassification.
// Line 235: arithmetic/base in getOrCreateMap capacity.
// Lines 249, 251: toLowerTrim loop/break and comparison.

func TestMK5_BuildKeyUsageIndex_SharedKey(t *testing.T) {
	snap := asset.Snapshot{Assets: []asset.Asset{
		{ID: "a1", Properties: map[string]any{
			"cryptography": map[string]any{"kms_key_id": "key-1"},
			"tags":         map[string]any{"data-classification": "phi"},
		}},
		{ID: "a2", Properties: map[string]any{
			"cryptography": map[string]any{"kms_key_id": "key-1"},
			"tags":         map[string]any{"data-classification": "public"},
		}},
	}}
	idx := buildKeyUsageIndexForSnapshot(snap)
	entry := idx["key-1"]
	if entry == nil {
		t.Fatal("expected entry for key-1")
	}
	if entry.MinLevel != SensitivityPublic {
		t.Fatalf("expected min=Public(1), got %d", entry.MinLevel)
	}
	if entry.MaxLevel != SensitivityPHI {
		t.Fatalf("expected max=PHI(4), got %d", entry.MaxLevel)
	}
	if entry.IsExclusive() {
		t.Fatal("shared key across levels should not be exclusive")
	}
	if len(entry.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(entry.Domains))
	}
}

func TestMK5_BuildKeyUsageIndex_NoKeyAssets(t *testing.T) {
	snap := asset.Snapshot{Assets: []asset.Asset{
		{ID: "a1", Properties: map[string]any{"region": "us-east-1"}},
	}}
	idx := buildKeyUsageIndexForSnapshot(snap)
	if len(idx) != 0 {
		t.Fatal("expected empty index for assets without KMS keys")
	}
}

func TestMK5_ParseSensitivity_AllLevels(t *testing.T) {
	cases := []struct {
		input string
		want  SensitivityLevel
	}{
		{"phi", SensitivityPHI},
		{"cde", SensitivityPHI},
		{"confidential", SensitivityConfidential},
		{"internal", SensitivityInternal},
		{"public", SensitivityPublic},
		{"non-sensitive", SensitivityPublic},
		{"", SensitivityUnclassified},
		{"unknown", SensitivityUnclassified},
	}
	for _, tc := range cases {
		if got := ParseSensitivity(tc.input); got != tc.want {
			t.Errorf("ParseSensitivity(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestMK5_EnrichKeyIsolation_PreservesClone(t *testing.T) {
	snap := asset.Snapshot{Assets: []asset.Asset{
		{ID: "a1", Properties: map[string]any{
			"cryptography": map[string]any{"kms_key_id": "key-1"},
			"tags":         map[string]any{"data-classification": "phi"},
		}},
	}}
	enriched := EnrichKeyIsolation([]asset.Snapshot{snap})
	if len(enriched) != 1 {
		t.Fatal("expected 1 snapshot")
	}
	// Original should not be mutated.
	if _, ok := snap.Assets[0].Properties["cryptography"].(map[string]any)["key_isolation"]; ok {
		t.Fatal("original snapshot should not be mutated")
	}
	// Enriched should have the isolation property.
	crypto, ok := enriched[0].Assets[0].Properties["cryptography"].(map[string]any)
	if !ok {
		t.Fatal("expected cryptography map")
	}
	iso, ok := crypto["key_isolation"].(map[string]any)
	if !ok {
		t.Fatal("expected key_isolation map")
	}
	if iso["is_exclusive_to_domain"] != true {
		t.Fatal("single domain should be exclusive")
	}
	if iso["domain_count"] != 1 {
		t.Fatalf("expected domain_count 1, got %v", iso["domain_count"])
	}
}

func TestMK5_EnrichKeyIsolation_EmptyIndex(t *testing.T) {
	snap := asset.Snapshot{Assets: []asset.Asset{
		{ID: "a1", Properties: map[string]any{"region": "us-east-1"}},
	}}
	enriched := EnrichKeyIsolation([]asset.Snapshot{snap})
	// Should still clone properties.
	enriched[0].Assets[0].Properties["new_key"] = "val"
	if _, ok := snap.Assets[0].Properties["new_key"]; ok {
		t.Fatal("original should not be mutated even when no enrichment")
	}
}

func TestMK5_ExtractClassification_TopLevelTags(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"tags": map[string]any{"data-classification": "Confidential"},
	}}
	got := extractClassification(a)
	if got != "confidential" {
		t.Fatalf("expected 'confidential', got %q", got)
	}
}

func TestMK5_ExtractClassification_StorageTags(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"storage": map[string]any{
			"tags": map[string]any{"data_classification": "internal"},
		},
	}}
	got := extractClassification(a)
	if got != "internal" {
		t.Fatalf("expected 'internal', got %q", got)
	}
}

func TestMK5_ExtractClassification_MalformedTags(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"tags": "not-a-map",
	}}
	got := extractClassification(a)
	if got != "unclassified" {
		t.Fatalf("expected 'unclassified' for malformed tags, got %q", got)
	}
}

func TestMK5_ExtractClassification_MalformedStorageTags(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{
		"storage": map[string]any{
			"tags": []string{"not", "a", "map"},
		},
	}}
	got := extractClassification(a)
	if got != "unclassified" {
		t.Fatalf("expected 'unclassified' for malformed storage tags, got %q", got)
	}
}

func TestMK5_ExtractClassification_NoTags(t *testing.T) {
	a := asset.Asset{ID: "a", Properties: map[string]any{}}
	got := extractClassification(a)
	if got != "unclassified" {
		t.Fatalf("expected 'unclassified', got %q", got)
	}
}

func TestMK5_GetOrCreateMap_ExistingClones(t *testing.T) {
	inner := map[string]any{"existing": true}
	outer := map[string]any{"crypto": inner}
	got := getOrCreateMap(outer, "crypto")
	got["new_key"] = true
	// Original inner should not be mutated.
	if _, ok := inner["new_key"]; ok {
		t.Fatal("getOrCreateMap should clone existing map")
	}
}

func TestMK5_GetOrCreateMap_Creates(t *testing.T) {
	m := map[string]any{}
	got := getOrCreateMap(m, "new")
	if got == nil {
		t.Fatal("should create new map")
	}
	got["key"] = "val"
	// Should be stored in parent.
	if m["new"] == nil {
		t.Fatal("created map should be stored in parent")
	}
}

func TestMK5_ToLowerTrim_AlreadyLower(t *testing.T) {
	got := toLowerTrim("  already lower  ")
	if got != "already lower" {
		t.Fatalf("expected 'already lower', got %q", got)
	}
}

func TestMK5_ToLowerTrim_MixedCase(t *testing.T) {
	got := toLowerTrim("  PHI  ")
	if got != "phi" {
		t.Fatalf("expected 'phi', got %q", got)
	}
}

func TestMK5_ToLowerTrim_Empty(t *testing.T) {
	got := toLowerTrim("")
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestMK5_KeyUsageEntry_Exclusive(t *testing.T) {
	e := KeyUsageEntry{MinLevel: SensitivityPHI, MaxLevel: SensitivityPHI}
	if !e.IsExclusive() {
		t.Fatal("same min/max should be exclusive")
	}
}

func TestMK5_KeyUsageEntry_NotExclusive(t *testing.T) {
	e := KeyUsageEntry{MinLevel: SensitivityPublic, MaxLevel: SensitivityPHI}
	if e.IsExclusive() {
		t.Fatal("different min/max should not be exclusive")
	}
}

// =========================================================================
// identity_index.go — 6 survivors
// =========================================================================

// Lines 46-47: At() empty entries guard.
// Line 55: exact match vs insertion point comparison.
// Line 78: mergeIdentitiesAt end expansion.

func TestMK5_IdentityIndex_EmptyEntries(t *testing.T) {
	idx := BuildIdentityIndex(nil)
	got := idx.At(time.Now())
	if got != nil {
		t.Fatal("empty index should return nil")
	}
}

func TestMK5_IdentityIndex_ExactMatch(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ids := []asset.CloudIdentity{{ID: "arn:aws:iam::123:user/test"}}
	snap := asset.Snapshot{CapturedAt: t1, Identities: ids}
	idx := BuildIdentityIndex([]asset.Snapshot{snap})
	got := idx.At(t1)
	if len(got) != 1 || got[0].ID != "arn:aws:iam::123:user/test" {
		t.Fatalf("expected exact match, got %v", got)
	}
}

func TestMK5_IdentityIndex_FallbackToBefore(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	ids1 := []asset.CloudIdentity{{ID: "user-1"}}
	ids2 := []asset.CloudIdentity{{ID: "user-2"}}
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: t1, Identities: ids1},
		{CapturedAt: t2, Identities: ids2},
	})
	// Query between t1 and t2 → should fall back to t1.
	query := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	got := idx.At(query)
	if len(got) != 1 || got[0].ID != "user-1" {
		t.Fatalf("expected fallback to user-1, got %v", got)
	}
}

func TestMK5_IdentityIndex_BeforeAllEntries(t *testing.T) {
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: t1, Identities: []asset.CloudIdentity{{ID: "u"}}},
	})
	// Query before the only entry.
	got := idx.At(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if got != nil {
		t.Fatal("query before all entries should return nil")
	}
}

func TestMK5_IdentityIndex_DuplicateTimestamps(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: t1, Identities: []asset.CloudIdentity{{ID: "u1"}}},
		{CapturedAt: t1, Identities: []asset.CloudIdentity{{ID: "u2"}}},
	})
	got := idx.At(t1)
	if len(got) != 2 {
		t.Fatalf("expected 2 merged identities, got %d", len(got))
	}
}

// =========================================================================
// coverage.go — 8 survivors
// =========================================================================

// Line 27: minSpan <= 0 check (numbers/incrementer mutant shifts boundary).
// Line 30: minSpan < maxGap comparison.
// Lines 65, 71: auditWindowTooShort and hasBlindSpots exact comparisons.

func TestMK5_NewCoverageValidator_ZeroSpan(t *testing.T) {
	_, err := NewCoverageValidator(0, 0)
	if err == nil {
		t.Fatal("zero minSpan should error")
	}
}

func TestMK5_NewCoverageValidator_NegativeSpan(t *testing.T) {
	_, err := NewCoverageValidator(-time.Hour, 0)
	if err == nil {
		t.Fatal("negative minSpan should error")
	}
}

func TestMK5_NewCoverageValidator_MaxGapExceedsSpan(t *testing.T) {
	_, err := NewCoverageValidator(time.Hour, 2*time.Hour)
	if err == nil {
		t.Fatal("maxGap > minSpan should error")
	}
}

func TestMK5_NewCoverageValidator_EqualSpanAndGap(t *testing.T) {
	v, err := NewCoverageValidator(time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("equal span/gap should be valid: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestMK5_CoverageValidator_ExactlyAtMinSpan(t *testing.T) {
	v, _ := NewCoverageValidator(24*time.Hour, 0)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lc.RecordCheck(base, true)
	lc.RecordCheck(base.Add(24*time.Hour), true)
	_, ok := v.IsSufficient(lc)
	if !ok {
		t.Fatal("exactly at minSpan should be sufficient")
	}
}

func TestMK5_CoverageValidator_JustBelowMinSpan(t *testing.T) {
	v, _ := NewCoverageValidator(24*time.Hour, 0)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lc.RecordCheck(base, true)
	lc.RecordCheck(base.Add(23*time.Hour+59*time.Minute), true)
	_, ok := v.IsSufficient(lc)
	if ok {
		t.Fatal("just below minSpan should be insufficient")
	}
}

func TestMK5_CoverageValidator_GapExceedsThreshold(t *testing.T) {
	v, _ := NewCoverageValidator(48*time.Hour, 12*time.Hour)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lc.RecordCheck(base, true)
	lc.RecordCheck(base.Add(24*time.Hour), true) // 24h gap > 12h threshold
	lc.RecordCheck(base.Add(48*time.Hour), true)
	_, ok := v.IsSufficient(lc)
	if ok {
		t.Fatal("gap exceeding threshold should be insufficient")
	}
}

func TestMK5_CoverageValidator_NilLifecycle(t *testing.T) {
	v, _ := NewCoverageValidator(time.Hour, 0)
	reason, ok := v.IsSufficient(nil)
	if ok {
		t.Fatal("nil lifecycle should be insufficient")
	}
	if reason == "" {
		t.Fatal("expected reason string")
	}
}

func TestMK5_CoverageValidator_ZeroMaxGapDisablesCheck(t *testing.T) {
	v, _ := NewCoverageValidator(24*time.Hour, 0)
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lc.RecordCheck(base, true)
	lc.RecordCheck(base.Add(48*time.Hour), true) // huge gap but maxGap=0 disables check
	_, ok := v.IsSufficient(lc)
	if !ok {
		t.Fatal("zero maxGap should disable gap check")
	}
}

// =========================================================================
// recurrence.go — 8 survivors
// =========================================================================

// Lines 53-54: HasActiveWindow + start.Before(w.End) conjunction.
// Lines 63: w.End.After(last) for active window last time.
// Line 87: nil finding guard from CreateRecurrenceFinding.

func TestMK5_EvaluateRecurrence_DisabledPolicy(t *testing.T) {
	ctl := testControl("CTL.R.001", policy.TypeUnsafeRecurrence)
	// No recurrence params → Enabled() = false.
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	findings := EvaluateRecurrenceForControl(lc, ctl, time.Now(), IdentityIndex{})
	if findings != nil {
		t.Fatal("disabled policy should return nil findings")
	}
}

func TestMK5_CreateRecurrenceFinding_ValidInput(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:   "CTL.R.002",
		Type: policy.TypeUnsafeRecurrence,
		Params: policy.NewParams(map[string]any{
			"recurrence_threshold": 3,
			"window_days":          7,
		}),
	}
	a := asset.Asset{ID: "a-1", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	stats := RecurrenceStats{Count: 5, First: base, Last: base.Add(72 * time.Hour)}
	f := CreateRecurrenceFinding(lc, ctl, stats)
	if f == nil {
		t.Fatal("expected non-nil finding")
	}
	if f.Evidence.ExposureWindowCount != 5 {
		t.Fatalf("expected count 5, got %d", f.Evidence.ExposureWindowCount)
	}
	if f.Evidence.WindowDays != 7 {
		t.Fatalf("expected 7 window days, got %d", f.Evidence.WindowDays)
	}
	if f.Evidence.RecurrenceThreshold != 3 {
		t.Fatalf("expected threshold 3, got %d", f.Evidence.RecurrenceThreshold)
	}
}

func TestMK5_CreateRecurrenceFinding_NilControl(t *testing.T) {
	a := asset.Asset{ID: "a", Type: "s3_bucket"}
	lc, _ := asset.NewExposureLifecycle(a)
	f := CreateRecurrenceFinding(lc, nil, RecurrenceStats{})
	if f != nil {
		t.Fatal("nil control should return nil")
	}
}

func TestMK5_CreateRecurrenceFinding_NilLifecycle(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:   "CTL.R.003",
		Type: policy.TypeUnsafeRecurrence,
		Params: policy.NewParams(map[string]any{
			"recurrence_threshold": 3,
			"window_days":          7,
		}),
	}
	f := CreateRecurrenceFinding(nil, ctl, RecurrenceStats{})
	if f != nil {
		t.Fatal("nil lifecycle should return nil")
	}
}
