package evaluation

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

func TestNewFindingFromMetadata(t *testing.T) {
	m := policy.ControlMetadata{
		ID:          kernel.ControlID("CTL.TEST.001"),
		Name:        "Test Control",
		Description: "Test desc",
		Severity:    policy.SeverityHigh,
		Compliance:  policy.ComplianceMapping{"hipaa": "164.312"},
	}
	f := NewFindingFromMetadata(m)
	if f.ControlID != m.ID {
		t.Fatalf("ControlID = %v", f.ControlID)
	}
	if f.ControlName != m.Name {
		t.Fatalf("ControlName = %v", f.ControlName)
	}
	if f.ControlSeverity != m.Severity {
		t.Fatalf("ControlSeverity = %v", f.ControlSeverity)
	}
	if !f.ControlCompliance.Has("hipaa") {
		t.Fatal("should have hipaa")
	}
}

func TestSortFindings(t *testing.T) {
	fs := []Finding{
		{ControlID: "CTL.B.001", AssetID: "z"},
		{ControlID: "CTL.A.001", AssetID: "a"},
		{ControlID: "CTL.A.001", AssetID: "b"},
	}
	SortFindings(fs)
	if fs[0].ControlID != "CTL.A.001" || fs[0].AssetID != "a" {
		t.Fatalf("[0] = %v/%v", fs[0].ControlID, fs[0].AssetID)
	}
	if fs[1].ControlID != "CTL.A.001" || fs[1].AssetID != "b" {
		t.Fatalf("[1] = %v/%v", fs[1].ControlID, fs[1].AssetID)
	}
	if fs[2].ControlID != "CTL.B.001" {
		t.Fatalf("[2] = %v", fs[2].ControlID)
	}
}

// ---------------------------------------------------------------------------
// Audit.FindFinding
// ---------------------------------------------------------------------------

func TestResultFindFinding(t *testing.T) {
	r := &Audit{
		Findings: []Finding{
			{ControlID: "CTL.A.001", AssetID: "bucket-1"},
			{ControlID: "CTL.B.002", AssetID: "bucket-2"},
		},
	}

	f := r.FindFinding("CTL.A.001", "bucket-1")
	if f == nil {
		t.Fatal("should find")
	}
	if f.ControlID != "CTL.A.001" {
		t.Fatalf("ControlID = %v", f.ControlID)
	}

	f = r.FindFinding("CTL.C.003", "bucket-3")
	if f != nil {
		t.Fatal("should not find")
	}
}

// ---------------------------------------------------------------------------
// ConfidenceLevel
// ---------------------------------------------------------------------------

func TestDeriveConfidenceLevel(t *testing.T) {
	tests := []struct {
		maxGap, required time.Duration
		want             ConfidenceLevel
	}{
		{0, 0, ConfidenceInconclusive},                     // Zero required
		{time.Hour, 0, ConfidenceInconclusive},             // Zero required
		{2 * time.Hour, 24 * time.Hour, ConfidenceHigh},    // 2h gap / 24h window = 8.3%
		{10 * time.Hour, 24 * time.Hour, ConfidenceMedium}, // 10h gap / 24h = 41.6%
		{20 * time.Hour, 24 * time.Hour, ConfidenceLow},    // 20h gap / 24h = 83%
		{6 * time.Hour, 24 * time.Hour, ConfidenceHigh},    // 25% exactly
		{12 * time.Hour, 24 * time.Hour, ConfidenceMedium}, // 50% exactly
		{13 * time.Hour, 24 * time.Hour, ConfidenceLow},    // >50%
	}
	calc := DefaultConfidenceCalculator()
	for _, tt := range tests {
		got := calc.Derive(tt.maxGap, tt.required)
		if got != tt.want {
			t.Errorf("Derive(%v, %v) = %q, want %q", tt.maxGap, tt.required, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Row.MarkInconclusive
// ---------------------------------------------------------------------------

func TestRowMarkInconclusive(t *testing.T) {
	r := &Row{Decision: DecisionPass, Confidence: ConfidenceHigh}
	r.MarkInconclusive("test reason")
	if r.Decision != DecisionInconclusive {
		t.Fatalf("Decision = %v", r.Decision)
	}
	if r.Confidence != ConfidenceInconclusive {
		t.Fatalf("Confidence = %v", r.Confidence)
	}
	if r.Reason != "test reason" {
		t.Fatalf("Reason = %q", r.Reason)
	}

	// Nil receiver is safe
	var nilRow *Row
	nilRow.MarkInconclusive("safe") // should not panic
}

// ---------------------------------------------------------------------------
// GroupViolationsByDomain
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

func TestEvidenceRootCauseStrings(t *testing.T) {
	e := Evidence{}
	if e.RootCauseStrings() != nil {
		t.Fatal("empty should return nil")
	}

	e.RootCauses = []RootCause{RootCauseIdentity, RootCauseResource}
	got := e.RootCauseStrings()
	if len(got) != 2 || got[0] != "identity" || got[1] != "resource" {
		t.Fatalf("got %v", got)
	}
}

func TestRootCauseString(t *testing.T) {
	if RootCauseIdentity.String() != "identity" {
		t.Fatal("identity")
	}
	if RootCauseResource.String() != "resource" {
		t.Fatal("resource")
	}
	if RootCauseGeneral.String() != "general" {
		t.Fatal("general")
	}
}

// ---------------------------------------------------------------------------
// TrendMetric
// ---------------------------------------------------------------------------

func TestTrendMetric(t *testing.T) {
	tests := []struct {
		name    string
		current int
		prev    int
		change  int
		dir     TrendDirection
		symbol  string
	}{
		{"improving", 3, 5, -2, TrendImproving, "↓ "},
		{"declining", 7, 3, 4, TrendDeclining, "↑ "},
		{"stable", 3, 3, 0, TrendStable, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := TrendMetric{Current: tt.current, Previous: tt.prev}
			if got := m.Change(); got != tt.change {
				t.Errorf("Change() = %d, want %d", got, tt.change)
			}
			if got := m.Direction(); got != tt.dir {
				t.Errorf("Direction() = %d, want %d", got, tt.dir)
			}
			if got := m.Symbol(); got != tt.symbol {
				t.Errorf("Symbol() = %q, want %q", got, tt.symbol)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ResponsePolicy
// ---------------------------------------------------------------------------

func TestResponsePolicyDecide(t *testing.T) {
	tests := []struct {
		strict bool
		status SafetyStatus
		want   ActionSeverity
	}{
		{false, StatusSafe, ActionPass},
		{false, StatusBorderline, ActionWarn},
		{false, StatusUnsafe, ActionFail},
		{true, StatusSafe, ActionPass},
		{true, StatusBorderline, ActionFail},
		{true, StatusUnsafe, ActionFail},
	}
	for _, tt := range tests {
		p := ResponsePolicy{StrictBorderline: tt.strict}
		got := p.Decide(tt.status)
		if got.Severity != tt.want {
			t.Errorf("Decide(strict=%v, %v) = %v, want %v", tt.strict, tt.status, got.Severity, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// CompareBaseline
// ---------------------------------------------------------------------------

func TestCompareBaseline(t *testing.T) {
	base := []BaselineEntry{
		{ControlID: "CTL.A.001", AssetID: "res-1"},
		{ControlID: "CTL.B.001", AssetID: "res-2"},
	}
	cur := []BaselineEntry{
		{ControlID: "CTL.B.001", AssetID: "res-2"},
		{ControlID: "CTL.C.001", AssetID: "res-3"},
	}

	result := CompareBaseline(base, cur)
	if len(result.New) != 1 || result.New[0].ControlID != "CTL.C.001" {
		t.Fatalf("New = %v", result.New)
	}
	if len(result.Resolved) != 1 || result.Resolved[0].ControlID != "CTL.A.001" {
		t.Fatalf("Resolved = %v", result.Resolved)
	}
}

func TestCompareBaselineEmpty(t *testing.T) {
	result := CompareBaseline(nil, nil)
	if len(result.New) != 0 || len(result.Resolved) != 0 {
		t.Fatalf("empty compare should have no entries: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// BaselineEntry.Key
// ---------------------------------------------------------------------------

func TestBaselineEntryKey(t *testing.T) {
	e := BaselineEntry{ControlID: "CTL.A.001", AssetID: "res-1"}
	k := e.Key()
	if k.ControlID != "CTL.A.001" || k.AssetID != "res-1" {
		t.Fatalf("Key = %+v", k)
	}
}

// ---------------------------------------------------------------------------
// ComputePostureDrift
// ---------------------------------------------------------------------------

func TestComputePostureDrift_SafeTimeline(t *testing.T) {
	a := asset.Asset{ID: "bucket-1"}
	tl, err := asset.NewTimeline(a)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tl.RecordObservation(base, false); err != nil {
		t.Fatal(err)
	}
	if d := ComputePostureDrift(tl); d != nil {
		t.Fatalf("safe timeline should return nil, got %+v", d)
	}
}

func TestComputePostureDrift_Persistent(t *testing.T) {
	a := asset.Asset{ID: "bucket-1"}
	tl, err := asset.NewTimeline(a)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tl.RecordObservation(base, true); err != nil {
		t.Fatal(err)
	}
	if err := tl.RecordObservation(base.Add(time.Hour), true); err != nil {
		t.Fatal(err)
	}

	d := ComputePostureDrift(tl)
	if d == nil {
		t.Fatal("expected drift")
	}
	if d.Pattern != DriftPersistent {
		t.Fatalf("Pattern = %v, want persistent", d.Pattern)
	}
	if d.EpisodeCount != 1 {
		t.Fatalf("EpisodeCount = %d, want 1", d.EpisodeCount)
	}
}

func TestComputePostureDrift_Degraded(t *testing.T) {
	a := asset.Asset{ID: "bucket-1"}
	tl, err := asset.NewTimeline(a)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// First safe, then unsafe
	if err := tl.RecordObservation(base, false); err != nil {
		t.Fatal(err)
	}
	if err := tl.RecordObservation(base.Add(time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if err := tl.RecordObservation(base.Add(2*time.Hour), true); err != nil {
		t.Fatal(err)
	}

	d := ComputePostureDrift(tl)
	if d == nil {
		t.Fatal("expected drift")
	}
	if d.Pattern != DriftDegraded {
		t.Fatalf("Pattern = %v, want degraded", d.Pattern)
	}
}

func TestComputePostureDrift_Intermittent(t *testing.T) {
	a := asset.Asset{ID: "bucket-1"}
	tl, err := asset.NewTimeline(a)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// unsafe -> safe -> unsafe
	if err := tl.RecordObservation(base, true); err != nil {
		t.Fatal(err)
	}
	if err := tl.RecordObservation(base.Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if err := tl.RecordObservation(base.Add(2*time.Hour), true); err != nil {
		t.Fatal(err)
	}

	d := ComputePostureDrift(tl)
	if d == nil {
		t.Fatal("expected drift")
	}
	if d.Pattern != DriftIntermittent {
		t.Fatalf("Pattern = %v, want intermittent", d.Pattern)
	}
	if d.EpisodeCount != 2 {
		t.Fatalf("EpisodeCount = %d, want 2", d.EpisodeCount)
	}
}

// ---------------------------------------------------------------------------
// RunInfo / InputHashes
// ---------------------------------------------------------------------------

func TestFilePathString(t *testing.T) {
	p := FilePath("/tmp/test.json")
	if p.String() != "/tmp/test.json" {
		t.Fatalf("got %q", p.String())
	}
}

// ---------------------------------------------------------------------------
// DriftPattern constants
// ---------------------------------------------------------------------------

func TestDriftPatternConstants(t *testing.T) {
	if DriftPersistent != "persistent" {
		t.Fatal("DriftPersistent")
	}
	if DriftDegraded != "degraded" {
		t.Fatal("DriftDegraded")
	}
	if DriftIntermittent != "intermittent" {
		t.Fatal("DriftIntermittent")
	}
}
