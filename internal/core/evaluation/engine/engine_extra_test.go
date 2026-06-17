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

// ---------------------------------------------------------------------------
// assetRegistry
// ---------------------------------------------------------------------------

func TestAssetIDSet(t *testing.T) {
	s := make(assetRegistry)
	if !s.register("a") {
		t.Fatal("first add should return true")
	}
	if s.register("a") {
		t.Fatal("duplicate add should return false")
	}
	if !s.register("b") {
		t.Fatal("different add should return true")
	}
}

// ---------------------------------------------------------------------------
// AssessmentCollector
// ---------------------------------------------------------------------------

func TestAssessmentCollectorTrackExemption(t *testing.T) {
	acc := NewCollector(10)
	if !acc.RecordExemption("asset-1") {
		t.Fatal("first exemption should return true")
	}
	if acc.RecordExemption("asset-1") {
		t.Fatal("duplicate exemption should return false")
	}
}

func TestAssessmentCollectorAddSkippedControl(t *testing.T) {
	acc := NewCollector(0)
	acc.RecordSkippedControl("CTL.TEST.001", "test-ctrl", "unsupported type")
	if len(acc.skippedControls) != 1 {
		t.Fatalf("len = %d", len(acc.skippedControls))
	}
	if acc.skippedControls[0].Reason != "unsupported type" {
		t.Fatalf("Reason = %q", acc.skippedControls[0].Reason)
	}
}

func TestAssessmentCollectorAddExemptedAsset(t *testing.T) {
	acc := NewCollector(0)
	acc.RecordExemptedAsset("bucket-1", "bucket-*", "temp data")
	// Read via the public Snapshot API rather than poking unexported
	// fields directly — the per-asset state lives on stripes keyed
	// by asset.ID hash, so there is no single backing slice to
	// inspect. Snapshot merges across stripes and returns the
	// consolidated view callers (compileReport, tests) need.
	snap := acc.Snapshot()
	if len(snap.ExemptedAssets) != 1 {
		t.Fatalf("len = %d", len(snap.ExemptedAssets))
	}
	if snap.ExemptedAssets[0].ID != "bucket-1" {
		t.Fatalf("ID = %v", snap.ExemptedAssets[0].ID)
	}
}

func TestAssessmentCollectorAddRow(t *testing.T) {
	acc := NewCollector(0)
	acc.RecordCheck(evaluation.ResourceCheck{ControlID: "CTL.A.001", AssetID: "res-1"})
	snap := acc.Snapshot()
	if len(snap.Checks) != 1 {
		t.Fatalf("len = %d", len(snap.Checks))
	}
}

func TestAssessmentCollectorAddFindings(t *testing.T) {
	acc := NewCollector(0)
	f := &evaluation.Finding{ControlID: "CTL.A.001", AssetID: "res-1"}
	acc.RecordFindings([]*evaluation.Finding{f, nil})
	snap := acc.Snapshot()
	if len(snap.Findings) != 1 {
		t.Fatalf("len = %d (nil should be filtered)", len(snap.Findings))
	}
}

// ---------------------------------------------------------------------------
// newControlRow and finalizeRow
// ---------------------------------------------------------------------------

func TestNewControlRowAndFinalize(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID: kernel.ControlID("CTL.TEST.001"),
	}
	a := asset.Asset{ID: "bucket-1", Type: "aws_s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)

	row := newControlRow(ctl, tl)
	if row.ControlID != "CTL.TEST.001" {
		t.Fatalf("ControlID = %v", row.ControlID)
	}
	if row.AssetID != "bucket-1" {
		t.Fatalf("AssetID = %v", row.AssetID)
	}

	row = finalizeRow(row, evaluation.VerdictPass, evaluation.ConfidenceHigh)
	if row.Verdict != evaluation.VerdictPass {
		t.Fatalf("Verdict = %v", row.Verdict)
	}
	if row.Confidence != evaluation.ConfidenceHigh {
		t.Fatalf("Confidence = %v", row.Confidence)
	}
}

// ---------------------------------------------------------------------------
// wrapInPointers
// ---------------------------------------------------------------------------

func TestWrapInPointers(t *testing.T) {
	if wrapInPointers(nil) != nil {
		t.Fatal("nil should return nil")
	}
	if wrapInPointers([]evaluation.Finding{}) != nil {
		t.Fatal("empty should return nil")
	}

	fs := []evaluation.Finding{{ControlID: "CTL.A.001"}}
	ptrs := wrapInPointers(fs)
	if len(ptrs) != 1 || ptrs[0].ControlID != "CTL.A.001" {
		t.Fatalf("unexpected: %v", ptrs)
	}
}

// ---------------------------------------------------------------------------
// DeriveRootCauses
// ---------------------------------------------------------------------------

func TestDeriveRootCauses(t *testing.T) {
	// No misconfigs
	if causes := DeriveRootCauses(nil); len(causes) != 0 {
		t.Fatalf("nil should return empty: %v", causes)
	}

	// Only identity
	identity := []policy.Misconfiguration{
		{Category: policy.CategoryIdentity},
	}
	causes := DeriveRootCauses(identity)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseIdentity {
		t.Fatalf("identity: %v", causes)
	}

	// Only resource
	resource := []policy.Misconfiguration{
		{Category: policy.CategoryResource},
	}
	causes = DeriveRootCauses(resource)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseResource {
		t.Fatalf("resource: %v", causes)
	}

	// Both
	both := []policy.Misconfiguration{
		{Category: policy.CategoryIdentity},
		{Category: policy.CategoryResource},
	}
	causes = DeriveRootCauses(both)
	if len(causes) != 2 || causes[0] != evaluation.RootCauseIdentity || causes[1] != evaluation.RootCauseResource {
		t.Fatalf("both: %v", causes)
	}

	// Unknown category -> general
	unknown := []policy.Misconfiguration{
		{Category: policy.CategoryUnknown},
	}
	causes = DeriveRootCauses(unknown)
	if len(causes) != 1 || causes[0] != evaluation.RootCauseGeneral {
		t.Fatalf("unknown: %v", causes)
	}
}

// ---------------------------------------------------------------------------
// ExtractSourceEvidence
// ---------------------------------------------------------------------------

func TestExtractSourceEvidence(t *testing.T) {
	// No causes
	if got := ExtractSourceEvidence(asset.Asset{}, nil); got != nil {
		t.Fatal("nil causes should return nil")
	}

	// Identity cause with policy statements
	a := asset.Asset{
		Properties: map[string]any{
			"source_evidence": map[string]any{
				"policy_public_statements": []any{"stmt-1", "stmt-2"},
			},
		},
	}
	se := ExtractSourceEvidence(a, []evaluation.RootCause{evaluation.RootCauseIdentity})
	if se == nil {
		t.Fatal("should return evidence")
	}
	if len(se.IdentityStatements) != 2 {
		t.Fatalf("IdentityStatements = %v", se.IdentityStatements)
	}

	// Resource cause with ACL grantees
	a2 := asset.Asset{
		Properties: map[string]any{
			"source_evidence": map[string]any{
				"acl_public_grantees": []any{"grantee-1"},
			},
		},
	}
	se2 := ExtractSourceEvidence(a2, []evaluation.RootCause{evaluation.RootCauseResource})
	if se2 == nil {
		t.Fatal("should return evidence")
	}
	if len(se2.ResourceGrantees) != 1 {
		t.Fatalf("ResourceGrantees = %v", se2.ResourceGrantees)
	}

	// General cause with no source evidence
	se3 := ExtractSourceEvidence(asset.Asset{}, []evaluation.RootCause{evaluation.RootCauseGeneral})
	if se3 != nil {
		t.Fatal("general cause with empty asset should return nil")
	}
}

// ---------------------------------------------------------------------------
// unsupportedStrategy
// ---------------------------------------------------------------------------

func TestUnsupportedStrategy(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:   "CTL.TEST.001",
		Type: policy.TypeUnknown,
	}
	a := asset.Asset{ID: "bucket-1"}
	tl, _ := asset.NewExposureLifecycle(a)

	s := &unsupportedStrategy{ctl: ctl}
	row, findings := s.Evaluate(tl, time.Now(), IdentityIndex{})
	if row.Verdict != evaluation.VerdictSkipped {
		t.Fatalf("Verdict = %v", row.Verdict)
	}
	if len(findings) != 0 {
		t.Fatal("unsupported should have no findings")
	}
}

// ---------------------------------------------------------------------------
// Assessor helpers
// ---------------------------------------------------------------------------

func TestAssessorContinuityLimit(t *testing.T) {
	a := NewAssessor()
	if got := a.ContinuityLimit(); got != DefaultContinuityLimit {
		t.Fatalf("default = %v", got)
	}

	a.continuityLimit = 6 * time.Hour
	if got := a.ContinuityLimit(); got != 6*time.Hour {
		t.Fatalf("custom = %v", got)
	}
}

func TestAssessorSLAThresholdFor(t *testing.T) {
	a := &Assessor{slaThreshold: 168 * time.Hour}

	// No per-control override
	ctl := &policy.ControlDefinition{}
	if got := a.slaThresholdFor(ctl); got != 168*time.Hour {
		t.Fatalf("got %v, want assessor default", got)
	}

	// Per-control override
	ctl = &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{"max_unsafe_duration": "24h"}),
	}
	if got := a.slaThresholdFor(ctl); got != 24*time.Hour {
		t.Fatalf("got %v, want per-control 24h", got)
	}
}

func TestAssessorSortSnapshots(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &Assessor{}
	snaps := []asset.Snapshot{
		{CapturedAt: base.Add(2 * time.Hour)},
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
	}

	sorted := a.sortSnapshots(snaps)
	if sorted[0].CapturedAt != base {
		t.Fatalf("[0] = %v", sorted[0].CapturedAt)
	}
	if sorted[2].CapturedAt != base.Add(2*time.Hour) {
		t.Fatalf("[2] = %v", sorted[2].CapturedAt)
	}
	// Original should not be modified
	if snaps[0].CapturedAt != base.Add(2*time.Hour) {
		t.Fatal("original was modified")
	}
}

func TestIdentityIndexAt(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	idx := BuildIdentityIndex([]asset.Snapshot{
		{CapturedAt: base, Identities: []asset.CloudIdentity{{ID: "id-1"}}},
		{CapturedAt: base.Add(2 * time.Hour), Identities: []asset.CloudIdentity{{ID: "id-2"}}},
	})

	// Exact match
	ids := idx.At(base)
	if len(ids) != 1 || ids[0].ID != "id-1" {
		t.Fatalf("exact: %v", ids)
	}

	// Fallback to closest before
	ids = idx.At(base.Add(time.Hour))
	if len(ids) != 1 || ids[0].ID != "id-1" {
		t.Fatalf("fallback: %v", ids)
	}

	// No match at all
	ids = idx.At(base.Add(-time.Hour))
	if len(ids) != 0 {
		t.Fatalf("no match: %v", ids)
	}
}

func TestBuildIdentityIndex(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: base, Identities: []asset.CloudIdentity{{ID: "id-1"}}},
		{CapturedAt: base.Add(time.Hour), Identities: []asset.CloudIdentity{{ID: "id-2"}}},
	}
	idx := BuildIdentityIndex(snapshots)
	if len(idx.entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx.entries))
	}
	ids := idx.At(base)
	if len(ids) != 1 || ids[0].ID != "id-1" {
		t.Fatalf("first snapshot: %v", ids)
	}
	ids = idx.At(base.Add(time.Hour))
	if len(ids) != 1 || ids[0].ID != "id-2" {
		t.Fatalf("second snapshot: %v", ids)
	}
}

// ---------------------------------------------------------------------------
// RecurrenceStats / CreateRecurrenceFinding
// ---------------------------------------------------------------------------

func TestCreateRecurrenceFinding(t *testing.T) {
	a := asset.Asset{ID: "bucket-1", Type: "aws_s3_bucket"}
	tl, _ := asset.NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tl.RecordCheck(base, true); err != nil {
		t.Fatal(err)
	}

	ctl := &policy.ControlDefinition{
		ID:   "CTL.REC.001",
		Name: "recurrence test",
		Type: policy.TypeUnsafeRecurrence,
		Params: policy.NewParams(map[string]any{
			"recurrence_threshold": 3,
			"window_days":          7,
		}),
	}

	stats := RecurrenceStats{
		Count: 5,
		First: base,
		Last:  base.Add(5 * 24 * time.Hour),
	}

	f := CreateRecurrenceFinding(tl, ctl, stats)
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.Evidence.ExposureWindowCount != 5 {
		t.Fatalf("ExposureWindowCount = %d", f.Evidence.ExposureWindowCount)
	}
	if f.Evidence.WindowDays != 7 {
		t.Fatalf("WindowDays = %d", f.Evidence.WindowDays)
	}
	if f.Evidence.RecurrenceThreshold != 3 {
		t.Fatalf("RecurrenceThreshold = %d", f.Evidence.RecurrenceThreshold)
	}
}

// ---------------------------------------------------------------------------
// FindingBuilder
// ---------------------------------------------------------------------------

func TestNewFinding(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:       "CTL.TEST.001",
		Name:     "test",
		Severity: policy.SeverityHigh,
	}
	a := asset.Asset{ID: "bucket-1", Type: "aws_s3_bucket", Vendor: "aws"}
	tl, _ := asset.NewExposureLifecycle(a)

	ctx := FindingContext{
		Reason: "test reason",
		Misconfigs: []policy.Misconfiguration{
			{Property: predicate.NewFieldPath("prop.x")},
		},
	}

	f := NewFinding(ctl, tl, ctx)
	if f.ControlID != "CTL.TEST.001" {
		t.Fatalf("ControlID = %v", f.ControlID)
	}
	if f.AssetID != "bucket-1" {
		t.Fatalf("AssetID = %v", f.AssetID)
	}
	if f.Evidence.TemporalRisk != "test reason" {
		t.Fatalf("TemporalRisk = %q", f.Evidence.TemporalRisk)
	}
	if len(f.Evidence.Misconfigurations) != 1 {
		t.Fatalf("Misconfigurations len = %d", len(f.Evidence.Misconfigurations))
	}
}

// ---------------------------------------------------------------------------
// toSorted helper
// ---------------------------------------------------------------------------

func TestToSorted(t *testing.T) {
	if got := toSorted[kernel.StatementID](nil); got != nil {
		t.Fatal("nil should return nil")
	}
	if got := toSorted[kernel.StatementID]([]string{}); got != nil {
		t.Fatal("empty should return nil")
	}

	got := toSorted[kernel.StatementID]([]string{"c", "a", "b"})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got %v", got)
	}
}
