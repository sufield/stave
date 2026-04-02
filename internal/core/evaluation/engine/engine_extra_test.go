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
// assetIDSet
// ---------------------------------------------------------------------------

func TestAssetIDSet(t *testing.T) {
	s := make(assetIDSet)
	if !s.Add("a") {
		t.Fatal("first add should return true")
	}
	if s.Add("a") {
		t.Fatal("duplicate add should return false")
	}
	if !s.Add("b") {
		t.Fatal("different add should return true")
	}
}

// ---------------------------------------------------------------------------
// Accumulator
// ---------------------------------------------------------------------------

func TestAccumulatorTrackExemption(t *testing.T) {
	acc := NewAccumulator(10)
	if !acc.TrackExemption("asset-1") {
		t.Fatal("first exemption should return true")
	}
	if acc.TrackExemption("asset-1") {
		t.Fatal("duplicate exemption should return false")
	}
}

func TestAccumulatorAddSkippedControl(t *testing.T) {
	acc := NewAccumulator(0)
	acc.AddSkippedControl("CTL.TEST.001", "test-ctrl", "unsupported type")
	if len(acc.skippedByCtl) != 1 {
		t.Fatalf("len = %d", len(acc.skippedByCtl))
	}
	if acc.skippedByCtl[0].Reason != "unsupported type" {
		t.Fatalf("Reason = %q", acc.skippedByCtl[0].Reason)
	}
}

func TestAccumulatorAddExemptedAsset(t *testing.T) {
	acc := NewAccumulator(0)
	acc.AddExemptedAsset("bucket-1", "bucket-*", "temp data")
	if len(acc.exemptedByAst) != 1 {
		t.Fatalf("len = %d", len(acc.exemptedByAst))
	}
	if acc.exemptedByAst[0].ID != "bucket-1" {
		t.Fatalf("ID = %v", acc.exemptedByAst[0].ID)
	}
}

func TestAccumulatorAddRow(t *testing.T) {
	acc := NewAccumulator(0)
	acc.AddRow(evaluation.Row{ControlID: "CTL.A.001", AssetID: "res-1"})
	if len(acc.rows) != 1 {
		t.Fatalf("len = %d", len(acc.rows))
	}
}

func TestAccumulatorAddFindings(t *testing.T) {
	acc := NewAccumulator(0)
	f := &evaluation.Finding{ControlID: "CTL.A.001"}
	acc.AddFindings([]*evaluation.Finding{f, nil})
	if len(acc.findings) != 1 {
		t.Fatalf("len = %d (nil should be filtered)", len(acc.findings))
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
	tl, _ := asset.NewTimeline(a)

	row := newControlRow(ctl, tl)
	if row.ControlID != "CTL.TEST.001" {
		t.Fatalf("ControlID = %v", row.ControlID)
	}
	if row.AssetID != "bucket-1" {
		t.Fatalf("AssetID = %v", row.AssetID)
	}

	row = finalizeRow(row, evaluation.DecisionPass, evaluation.ConfidenceHigh)
	if row.Decision != evaluation.DecisionPass {
		t.Fatalf("Decision = %v", row.Decision)
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
		Type: policy.TypeAuthorizationBoundary,
	}
	a := asset.Asset{ID: "bucket-1"}
	tl, _ := asset.NewTimeline(a)

	s := &unsupportedStrategy{ctl: ctl}
	row, findings := s.Evaluate(tl, time.Now(), nil)
	if row.Decision != evaluation.DecisionSkipped {
		t.Fatalf("Decision = %v", row.Decision)
	}
	if len(findings) != 0 {
		t.Fatal("unsupported should have no findings")
	}
}

// ---------------------------------------------------------------------------
// Runner helpers
// ---------------------------------------------------------------------------

func TestRunnerMaxGapThreshold(t *testing.T) {
	r := &Runner{}
	if got := r.maxGapThreshold(); got != DefaultMaxGapThreshold {
		t.Fatalf("default = %v", got)
	}

	r.MaxGapThreshold = 6 * time.Hour
	if got := r.maxGapThreshold(); got != 6*time.Hour {
		t.Fatalf("custom = %v", got)
	}
}

func TestRunnerMaxUnsafeDurationFor(t *testing.T) {
	r := &Runner{MaxUnsafeDuration: 168 * time.Hour}

	// No per-control override
	ctl := &policy.ControlDefinition{}
	if got := r.maxUnsafeDurationFor(ctl); got != 168*time.Hour {
		t.Fatalf("got %v, want runner default", got)
	}

	// Per-control override
	ctl = &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{"max_unsafe_duration": "24h"}),
	}
	if got := r.maxUnsafeDurationFor(ctl); got != 24*time.Hour {
		t.Fatalf("got %v, want per-control 24h", got)
	}
}

func TestRunnerNormalizeSnapshots(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &Runner{}
	snaps := []asset.Snapshot{
		{CapturedAt: base.Add(2 * time.Hour)},
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
	}

	sorted := r.normalizeSnapshots(snaps)
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
	idx := IdentityIndex{
		base:                    {{ID: "id-1"}},
		base.Add(2 * time.Hour): {{ID: "id-2"}},
	}

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
	if len(idx) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(idx))
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
	tl, _ := asset.NewTimeline(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tl.RecordObservation(base, true); err != nil {
		t.Fatal(err)
	}

	ctl := &policy.ControlDefinition{
		ID:   "CTL.REC.001",
		Name: "recurrence test",
		Type: policy.TypeUnsafeRecurrence,
		Params: policy.NewParams(map[string]any{
			"recurrence_limit": 3,
			"window_days":      7,
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
	if f.Evidence.EpisodeCount != 5 {
		t.Fatalf("EpisodeCount = %d", f.Evidence.EpisodeCount)
	}
	if f.Evidence.WindowDays != 7 {
		t.Fatalf("WindowDays = %d", f.Evidence.WindowDays)
	}
	if f.Evidence.RecurrenceLimit != 3 {
		t.Fatalf("RecurrenceLimit = %d", f.Evidence.RecurrenceLimit)
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
	tl, _ := asset.NewTimeline(a)

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
	if f.Evidence.WhyNow != "test reason" {
		t.Fatalf("WhyNow = %q", f.Evidence.WhyNow)
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
