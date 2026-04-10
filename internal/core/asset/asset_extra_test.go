package asset

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// ExposureWindow
// ---------------------------------------------------------------------------

func TestNewOpenExposureWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ep := NewActiveWindow(now)
	if !ep.IsActive() {
		t.Fatal("should be open")
	}
	if ep.OpenedAt() != now {
		t.Fatalf("StartAt = %v", ep.OpenedAt())
	}
	if !ep.ResolvedAt().IsZero() {
		t.Fatalf("EndAt should be zero for open exposure window")
	}
}

func TestNewOpenExposureWindowZeroTime(t *testing.T) {
	ep := NewActiveWindow(time.Time{})
	if !ep.OpenedAt().IsZero() {
		t.Fatal("expected zero OpenedAt for zero-time input")
	}
}

func TestNewClosedExposureWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	ep := NewResolvedWindow(start, end)
	if ep.IsActive() {
		t.Fatal("should be closed")
	}
	if ep.OpenedAt() != start {
		t.Fatalf("StartAt = %v", ep.OpenedAt())
	}
	if ep.ResolvedAt() != end {
		t.Fatalf("EndAt = %v", ep.ResolvedAt())
	}
}

func TestNewClosedExposureWindowEndBeforeStart(t *testing.T) {
	start := time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
	end := start.Add(-time.Hour) // before start
	ep := NewResolvedWindow(start, end)
	// Close clamps end to start when end < start
	if ep.ResolvedAt().Before(ep.OpenedAt()) {
		t.Fatal("EndAt should be clamped to StartAt")
	}
}

func TestExposureWindowClose(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ep := NewActiveWindow(start)
	endAt := start.Add(3 * time.Hour)

	closed := ep.Resolve(endAt)
	if closed.IsActive() {
		t.Fatal("should be closed")
	}
	if closed.ResolvedAt() != endAt {
		t.Fatalf("EndAt = %v", closed.ResolvedAt())
	}

	// Idempotent
	closed2 := closed.Resolve(endAt.Add(time.Hour))
	if closed2.ResolvedAt() != endAt {
		t.Fatal("already closed, should not change")
	}
}

func TestExposureWindowEffectiveEndAt(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Open exposure window returns now
	ep := NewActiveWindow(start)
	if ep.EffectiveEndAt(now) != now {
		t.Fatalf("open EffectiveEndAt = %v", ep.EffectiveEndAt(now))
	}

	// Closed exposure window returns actual endAt
	end := start.Add(time.Hour)
	closed := NewResolvedWindow(start, end)
	if closed.EffectiveEndAt(now) != end {
		t.Fatalf("closed EffectiveEndAt = %v", closed.EffectiveEndAt(now))
	}
}

func TestExposureWindowOverlapsWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	ep := NewResolvedWindow(start, end)

	// Window fully overlapping
	w := kernel.NewTimeWindow(start, end)
	if !ep.OverlapsWindow(w) {
		t.Fatal("should overlap")
	}

	// Window completely before exposure window
	before := kernel.NewTimeWindow(start.Add(-48*time.Hour), start.Add(-24*time.Hour))
	if ep.OverlapsWindow(before) {
		t.Fatal("should not overlap - before")
	}

	// Window completely after exposure window
	after := kernel.NewTimeWindow(end.Add(time.Hour), end.Add(48*time.Hour))
	if ep.OverlapsWindow(after) {
		t.Fatal("should not overlap - after")
	}
}

func TestExposureWindowMarshalJSON(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ep := NewActiveWindow(start)

	b, err := json.Marshal(ep)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ExposureWindow
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.IsActive() {
		t.Fatal("should be open after roundtrip")
	}
	if !decoded.OpenedAt().Equal(start) {
		t.Fatalf("StartAt = %v after roundtrip", decoded.OpenedAt())
	}
}

func TestExposureWindowUnmarshalJSON_Closed(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	ep := NewResolvedWindow(start, end)

	b, err := json.Marshal(ep)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ExposureWindow
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.IsActive() {
		t.Fatal("should be closed")
	}
}

func TestExposureWindowUnmarshalJSON_MissingStart(t *testing.T) {
	// Missing start_at should error
	raw := `{"start_at":"0001-01-01T00:00:00Z","end_at":"0001-01-01T00:00:00Z","open":false}`
	var ep ExposureWindow
	if err := json.Unmarshal([]byte(raw), &ep); err == nil {
		t.Fatal("expected error for zero start_at")
	}
}

// ---------------------------------------------------------------------------
// ExposureHistory
// ---------------------------------------------------------------------------

func TestExposureHistoryRecord(t *testing.T) {
	h := &ExposureHistory{}

	start1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	start2 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	ep1 := NewResolvedWindow(start1, start1.Add(time.Hour))
	ep2 := NewResolvedWindow(start2, start2.Add(time.Hour))

	// Insert in reverse order — should still be sorted
	h.Record(ep2)
	h.Record(ep1)
	if h.Count() != 2 {
		t.Fatalf("Count = %d", h.Count())
	}

	// Open exposure windows are ignored
	open := NewActiveWindow(time.Now())
	h.Record(open)
	if h.Count() != 2 {
		t.Fatal("open exposure window should be ignored")
	}
}

func TestExposureHistoryRecurringViolationCount(t *testing.T) {
	h := &ExposureHistory{}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		start := base.Add(time.Duration(i*24) * time.Hour)
		ep := NewResolvedWindow(start, start.Add(time.Hour))
		h.Record(ep)
	}

	// Window covering days 2-4 (exclusive start)
	w := kernel.NewTimeWindow(
		base.Add(24*time.Hour),     // day 1
		base.Add(4*24*time.Hour+1), // day 4+
	)
	count := h.RecurringViolationCount(w)
	// ExposureWindows at day2, day3, day4 should match (start > w.Start && start < w.End)
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}
}

func TestExposureHistoryWindowSummary(t *testing.T) {
	h := &ExposureHistory{}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 3 {
		start := base.Add(time.Duration(i+1) * 24 * time.Hour)
		ep := NewResolvedWindow(start, start.Add(2*time.Hour))
		h.Record(ep)
	}

	w := kernel.NewTimeWindow(base, base.Add(5*24*time.Hour))
	count, first, last := h.WindowSummary(w)
	if count != 3 {
		t.Fatalf("count = %d", count)
	}
	if first.IsZero() || last.IsZero() {
		t.Fatal("first/last should not be zero")
	}
}

// ---------------------------------------------------------------------------
// ExposureLifecycle
// ---------------------------------------------------------------------------

func TestExposureLifecycleBasic(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)
	if tl.ID != "bucket-1" {
		t.Fatalf("ID = %v", tl.ID)
	}
	if !tl.IsSecure() {
		t.Fatal("new lifecycle should be safe")
	}
	if tl.IsExposed() {
		t.Fatal("new lifecycle should not be unsafe")
	}
}

func TestExposureLifecycleEmptyID(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty ID")
		}
	}()
	NewExposureLifecycle(Asset{})
}

func TestExposureLifecycleRecordObservation(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Zero time should error
	if err := tl.RecordCheck(time.Time{}, false); err == nil {
		t.Fatal("expected error for zero time")
	}

	// Safe observations
	if err := tl.RecordCheck(base, false); err != nil {
		t.Fatal(err)
	}
	if !tl.IsSecure() {
		t.Fatal("should be safe")
	}

	// Unsafe observation
	if err := tl.RecordCheck(base.Add(time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if !tl.IsExposed() {
		t.Fatal("should be unsafe")
	}
	if tl.FirstExposedAt().IsZero() {
		t.Fatal("FirstUnsafeAt should be set")
	}
	if tl.LastObservedAt().IsZero() {
		t.Fatal("LastSeenUnsafeAt should be set")
	}
	if !tl.HasExposureTimestamps() {
		t.Fatal("HasUnsafeTimestamps should be true")
	}
	if tl.MissingExposureTimestamps() {
		t.Fatal("MissingUnsafeTimestamps should be false")
	}
}

func TestExposureLifecycleUnsafeDuration(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := tl.RecordCheck(base, true); err != nil {
		t.Fatal(err)
	}

	now := base.Add(24 * time.Hour)
	d, err := tl.ExposureDuration(now)
	if err != nil {
		t.Fatal(err)
	}
	if d != 24*time.Hour {
		t.Fatalf("UnsafeDuration = %v", d)
	}

	// Safe lifecycle
	tl2 := NewExposureLifecycle(Asset{ID: "bucket-2"})
	if recErr := tl2.RecordCheck(base, false); recErr != nil {
		t.Fatal(recErr)
	}
	d, err = tl2.ExposureDuration(now)
	if err != nil || d != 0 {
		t.Fatalf("safe UnsafeDuration = %v, err=%v", d, err)
	}
}

func TestExposureLifecycleUnsafeDurationNowBeforeStart(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)
	base := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	if err := tl.RecordCheck(base, true); err != nil {
		t.Fatal(err)
	}

	earlier := base.Add(-time.Hour)
	_, err := tl.ExposureDuration(earlier)
	if err == nil {
		t.Fatal("expected error when now < start")
	}
}

func TestExposureLifecycleExceedsUnsafeThreshold(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := tl.RecordCheck(base, true); err != nil {
		t.Fatal(err)
	}

	now := base.Add(48 * time.Hour)
	exceeds, err := tl.ExceedsSLA(now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !exceeds {
		t.Fatal("48h > 24h threshold")
	}

	exceeds, _ = tl.ExceedsSLA(now, 72*time.Hour)
	if exceeds {
		t.Fatal("48h should not exceed 72h threshold")
	}
}

func TestExposureLifecycleFormatUnsafeSummary(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if err := tl.RecordCheck(base, true); err != nil {
		t.Fatal(err)
	}

	now := base.Add(48 * time.Hour)
	summary := tl.FormatExposureSummary(24*time.Hour, now)
	if summary == "" {
		t.Fatal("should produce summary")
	}
}

func TestExposureLifecycleExposureWindowClosure(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Unsafe -> safe transition closes exposure window
	if err := tl.RecordCheck(base, true); err != nil {
		t.Fatal(err)
	}
	if err := tl.RecordCheck(base.Add(time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if err := tl.RecordCheck(base.Add(2*time.Hour), false); err != nil {
		t.Fatal(err)
	}

	if tl.History().Count() != 1 {
		t.Fatalf("History count = %d, want 1", tl.History().Count())
	}
	if !tl.IsSecure() {
		t.Fatal("should be safe after transition")
	}
}

func TestExposureLifecycleSetAsset(t *testing.T) {
	a := Asset{ID: ID("bucket-1"), Type: "old_type"}
	tl := NewExposureLifecycle(a)

	newAsset := Asset{ID: ID("bucket-1"), Type: "new_type"}
	tl.SetAsset(newAsset)
	if tl.Asset().Type != "new_type" {
		t.Fatalf("Type = %v", tl.Asset().Type)
	}
}

func TestExposureLifecycleHasActiveWindow(t *testing.T) {
	a := Asset{ID: ID("bucket-1")}
	tl := NewExposureLifecycle(a)

	if tl.HasActiveWindow() {
		t.Fatal("no observation yet")
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := tl.RecordCheck(base, true); err != nil {
		t.Fatal(err)
	}
	if !tl.HasActiveWindow() {
		t.Fatal("should have open exposure window")
	}
}

// ---------------------------------------------------------------------------
// ObservationStats
// ---------------------------------------------------------------------------

func TestObservationStats(t *testing.T) {
	s := &ObservationStats{}
	if s.HasFirstObservation() {
		t.Fatal("empty should not have first observation")
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.RecordObservation(base); err != nil {
		t.Fatal(err)
	}
	if !s.HasFirstObservation() {
		t.Fatal("should have first observation")
	}
	if s.ObservationCount() != 1 {
		t.Fatalf("count = %d", s.ObservationCount())
	}

	if err := s.RecordObservation(base.Add(6 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordObservation(base.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	if s.ObservationCount() != 3 {
		t.Fatalf("count = %d", s.ObservationCount())
	}
	if s.CoverageSpan() != 24*time.Hour {
		t.Fatalf("CoverageSpan = %v", s.CoverageSpan())
	}
	if s.MaxGap() != 18*time.Hour {
		t.Fatalf("MaxGap = %v (expected 18h)", s.MaxGap())
	}
	if s.FirstSeenAt() != base {
		t.Fatalf("FirstSeenAt = %v", s.FirstSeenAt())
	}
	if s.LastSeenAt() != base.Add(24*time.Hour) {
		t.Fatalf("LastSeenAt = %v", s.LastSeenAt())
	}
}

func TestObservationStatsZeroTime(t *testing.T) {
	s := &ObservationStats{}
	if err := s.RecordObservation(time.Time{}); err == nil {
		t.Fatal("expected error for zero time")
	}
}

func TestObservationStatsOutOfOrder(t *testing.T) {
	s := &ObservationStats{}
	base := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	if err := s.RecordObservation(base); err != nil {
		t.Fatal(err)
	}
	// Out of order should be silently ignored
	if err := s.RecordObservation(base.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s.ObservationCount() != 1 {
		t.Fatalf("count = %d, out-of-order should be ignored", s.ObservationCount())
	}
}

// ---------------------------------------------------------------------------
// Delta
// ---------------------------------------------------------------------------

func TestChangeTypeIsValid(t *testing.T) {
	if !DriftProvisioned.IsValid() {
		t.Fatal("PROVISIONED")
	}
	if !DriftDecommissioned.IsValid() {
		t.Fatal("DECOMMISSIONED")
	}
	if !DriftReconfigured.IsValid() {
		t.Fatal("RECONFIGURED")
	}
	if DriftType("bogus").IsValid() {
		t.Fatal("bogus should not be valid")
	}
}

func TestObservationDeltaSummaryIncrement(t *testing.T) {
	s := &DriftSummary{}
	s.Record(DriftProvisioned)
	s.Record(DriftProvisioned)
	s.Record(DriftDecommissioned)
	s.Record(DriftReconfigured)

	if s.Provisioned() != 2 {
		t.Fatalf("Added = %d", s.Provisioned())
	}
	if s.Decommissioned() != 1 {
		t.Fatalf("Removed = %d", s.Decommissioned())
	}
	if s.Reconfigured() != 1 {
		t.Fatalf("Modified = %d", s.Reconfigured())
	}
	if s.Total() != 4 {
		t.Fatalf("Total = %d", s.Total())
	}

	// Invalid type should not increment
	s.Record(DriftType("invalid"))
	if s.Total() != 4 {
		t.Fatal("invalid type should not change total")
	}
}

func TestObservationDeltaSummaryJSON(t *testing.T) {
	s := DriftSummary{}
	s.Record(DriftProvisioned)
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]int
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["provisioned"] != 1 || decoded["total"] != 1 {
		t.Fatalf("decoded = %v", decoded)
	}
}

func TestSummarizeDeltaChanges(t *testing.T) {
	changes := []AssetChange{
		{Action: DriftProvisioned},
		{Action: DriftReconfigured},
		{Action: DriftDecommissioned},
		{Action: DriftReconfigured},
	}
	s := SummarizeDrift(changes)
	if s.Provisioned() != 1 || s.Decommissioned() != 1 || s.Reconfigured() != 2 || s.Total() != 4 {
		t.Fatalf("summary = added:%d removed:%d modified:%d total:%d", s.Provisioned(), s.Decommissioned(), s.Reconfigured(), s.Total())
	}
}

func TestLatestTwoSnapshots(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := []Snapshot{
		{CapturedAt: base.Add(2 * time.Hour)},
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
	}

	prev, curr, err := GetStateTransition(snaps)
	if err != nil {
		t.Fatal(err)
	}
	if prev.CapturedAt != base.Add(time.Hour) {
		t.Fatalf("prev CapturedAt = %v", prev.CapturedAt)
	}
	if curr.CapturedAt != base.Add(2*time.Hour) {
		t.Fatalf("curr CapturedAt = %v", curr.CapturedAt)
	}
}

func TestLatestTwoSnapshotsInsufficient(t *testing.T) {
	_, _, err := GetStateTransition([]Snapshot{{CapturedAt: time.Now()}})
	if err == nil {
		t.Fatal("expected error for insufficient snapshots")
	}
}

// ---------------------------------------------------------------------------
// DiffAssets
// ---------------------------------------------------------------------------

func TestDiffAssetsNoChange(t *testing.T) {
	a := Asset{
		ID:         "bucket-1",
		Type:       "aws_s3_bucket",
		Properties: map[string]any{"key": "val"},
	}
	changes := DiffAssets(a, a)
	if len(changes) != 0 {
		t.Fatalf("same asset should have no changes: %+v", changes)
	}
}

func TestDiffAssetsTypeChange(t *testing.T) {
	a := Asset{ID: "bucket-1", Type: "type_a"}
	b := Asset{ID: "bucket-1", Type: "type_b"}
	changes := DiffAssets(a, b)
	found := false
	for _, c := range changes {
		if c.Attribute == "_meta.type" {
			found = true
		}
	}
	if !found {
		t.Fatal("type change not detected")
	}
}

func TestDiffAssetsPropertyChange(t *testing.T) {
	a := Asset{ID: "bucket-1", Properties: map[string]any{"key": "old"}}
	b := Asset{ID: "bucket-1", Properties: map[string]any{"key": "new"}}
	changes := DiffAssets(a, b)
	if len(changes) != 1 || changes[0].Attribute != "properties.key" {
		t.Fatalf("changes = %+v", changes)
	}
}

func TestAppendPropertyPath(t *testing.T) {
	tests := []struct {
		base, segment, want string
	}{
		{"", "root", "root"},
		{"a", "b", "a.b"},
		{"a", "b.c", "a.[b.c]"},
	}
	for _, tt := range tests {
		got := appendPropertyPath(tt.base, tt.segment)
		if got != tt.want {
			t.Errorf("appendPropertyPath(%q, %q) = %q, want %q", tt.base, tt.segment, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ComputeDrift
// ---------------------------------------------------------------------------

func TestComputeObservationDelta(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := Snapshot{
		CapturedAt: base,
		Assets: []Asset{
			{ID: "bucket-1", Type: "aws_s3_bucket", Properties: map[string]any{"key": "old"}},
			{ID: "bucket-2", Type: "aws_s3_bucket"},
		},
	}
	curr := Snapshot{
		CapturedAt: base.Add(time.Hour),
		Assets: []Asset{
			{ID: "bucket-1", Type: "aws_s3_bucket", Properties: map[string]any{"key": "new"}},
			{ID: "bucket-3", Type: "aws_s3_bucket"},
		},
	}

	delta := ComputeDrift(prev, curr)
	if delta.Summary.Total() != 3 {
		t.Fatalf("Total = %d (expected 3: 1 modified, 1 removed, 1 added)", delta.Summary.Total())
	}
	if delta.Summary.Provisioned() != 1 {
		t.Fatalf("Added = %d", delta.Summary.Provisioned())
	}
	if delta.Summary.Decommissioned() != 1 {
		t.Fatalf("Removed = %d", delta.Summary.Decommissioned())
	}
	if delta.Summary.Reconfigured() != 1 {
		t.Fatalf("Modified = %d", delta.Summary.Reconfigured())
	}
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

func TestSnapshotsHelpers(t *testing.T) {
	var s Snapshots
	if !s.IsEmpty() {
		t.Fatal("nil should be empty")
	}
	s = Snapshots{{}}
	if !s.IsSingle() {
		t.Fatal("one element should be single")
	}
	if s.IsMultiSnapshot() {
		t.Fatal("one element should not be multi")
	}
	s = Snapshots{{}, {}}
	if !s.IsMultiSnapshot() {
		t.Fatal("two elements should be multi")
	}
}

func TestSnapshotsTemporalBounds(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := Snapshots{
		{CapturedAt: base.Add(2 * time.Hour)},
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
	}
	earliest, latest := s.TemporalBounds()
	if earliest != base {
		t.Fatalf("min = %v", earliest)
	}
	if latest != base.Add(2*time.Hour) {
		t.Fatalf("max = %v", latest)
	}

	var empty Snapshots
	earliest, latest = empty.TemporalBounds()
	if !earliest.IsZero() || !latest.IsZero() {
		t.Fatal("empty bounds should be zero")
	}
}

func TestSnapshotsUniqueAssetCount(t *testing.T) {
	s := Snapshots{
		{Assets: []Asset{{ID: "a"}, {ID: "b"}}},
		{Assets: []Asset{{ID: "b"}, {ID: "c"}}},
	}
	if got := s.UniqueAssetCount(); got != 3 {
		t.Fatalf("UniqueAssetCount = %d, want 3", got)
	}

	if Snapshots(nil).UniqueAssetCount() != 0 {
		t.Fatal("nil should be 0")
	}
}

func TestSnapshotsFindFirstUnsortedPair(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := Snapshots{
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
		{CapturedAt: base.Add(-time.Hour)}, // unsorted
	}
	pair, found := s.FindFirstUnsortedPair()
	if !found {
		t.Fatal("should find unsorted pair")
	}
	if pair.snapshotAt != base.Add(-time.Hour) {
		t.Fatalf("snapshotAt = %v", pair.snapshotAt)
	}

	sorted := Snapshots{
		{CapturedAt: base},
		{CapturedAt: base.Add(time.Hour)},
	}
	_, found = sorted.FindFirstUnsortedPair()
	if found {
		t.Fatal("sorted should not have unsorted pair")
	}
}

func TestCountUnprovablySafe(t *testing.T) {
	snaps := []Snapshot{
		{Assets: []Asset{
			{ID: "safe", Properties: map[string]any{"safety_provable": true}},
			{ID: "unsafe", Properties: map[string]any{}},
		}},
	}
	if got := CountUnprovablySafe(snaps); got != 1 {
		t.Fatalf("got %d, want 1", got)
	}
}

func TestSnapshotFindAsset(t *testing.T) {
	s := Snapshot{
		Assets: []Asset{
			{ID: "bucket-1"},
			{ID: "bucket-2"},
		},
	}
	if _, ok := s.FindAsset("bucket-1"); !ok {
		t.Fatal("should find bucket-1")
	}
	if _, ok := s.FindAsset("bucket-3"); ok {
		t.Fatal("should not find bucket-3")
	}
}

func TestSnapshotHasTimestamp(t *testing.T) {
	s := Snapshot{}
	if s.HasTimestamp() {
		t.Fatal("zero time should not have timestamp")
	}
	s.CapturedAt = time.Now()
	if !s.HasTimestamp() {
		t.Fatal("should have timestamp")
	}
}

// ---------------------------------------------------------------------------
// AuditScope
// ---------------------------------------------------------------------------

func TestUniversalFilter(t *testing.T) {
	a := Asset{ID: "anything"}
	if !GlobalScope.IsInScope(a) {
		t.Fatal("universal should match all")
	}
}

func TestNewScopeFilterAllowlist(t *testing.T) {
	f := NewAuditScopeFromAllowlist([]string{"bucket-1", "bucket-2"})
	if f.IsInScope(Asset{ID: "bucket-1"}) != true {
		t.Fatal("should match bucket-1")
	}
	if f.IsInScope(Asset{ID: "bucket-3"}) != false {
		t.Fatal("should not match bucket-3")
	}
}

func TestNewScopeFilterEmptyReturnsUniversal(t *testing.T) {
	f := NewAuditScope(nil, nil)
	if f != GlobalScope {
		t.Fatal("empty constraints should return universal")
	}
}

func TestFilterSnapshots(t *testing.T) {
	f := NewAuditScopeFromAllowlist([]string{"bucket-1"})
	snaps := []Snapshot{
		{Assets: []Asset{{ID: "bucket-1"}, {ID: "bucket-2"}}},
		{Assets: []Asset{{ID: "bucket-3"}}},
	}

	filtered := ApplyScopeToSnapshots(f, snaps)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered snapshot, got %d", len(filtered))
	}
	if len(filtered[0].Assets) != 1 || filtered[0].Assets[0].ID != "bucket-1" {
		t.Fatalf("filtered assets: %+v", filtered[0].Assets)
	}
}

func TestFilterSnapshotsNilOrUniversal(t *testing.T) {
	snaps := []Snapshot{{Assets: []Asset{{ID: "a"}}}}
	if got := ApplyScopeToSnapshots(nil, snaps); len(got) != 1 {
		t.Fatal("nil filter should pass through")
	}
	if got := ApplyScopeToSnapshots(GlobalScope, snaps); len(got) != 1 {
		t.Fatal("universal filter should pass through")
	}
}

// ---------------------------------------------------------------------------
// Delta Filter
// ---------------------------------------------------------------------------

func TestApplyFilter(t *testing.T) {
	delta := InfrastructureDrift{
		Changes: []AssetChange{
			{AssetID: "bucket-1", Action: DriftProvisioned, CurrentType: "aws_s3_bucket"},
			{AssetID: "bucket-2", Action: DriftDecommissioned, PreviousType: "aws_s3_bucket"},
			{AssetID: "vm-1", Action: DriftReconfigured, PreviousType: "aws_ec2_instance", CurrentType: "aws_ec2_instance"},
		},
	}

	// Filter by change type
	filtered := delta.ApplyFilter(FilterOptions{ChangeTypes: []DriftType{DriftProvisioned}})
	if filtered.Summary.Total() != 1 || filtered.Summary.Provisioned() != 1 {
		t.Fatalf("change type filter: %+v", filtered.Summary)
	}

	// Filter by asset type
	filtered = delta.ApplyFilter(FilterOptions{AssetTypes: []kernel.AssetType{"aws_ec2_instance"}})
	if filtered.Summary.Total() != 1 {
		t.Fatalf("asset type filter: %+v", filtered.Summary)
	}

	// Filter by asset ID substring
	filtered = delta.ApplyFilter(FilterOptions{AssetID: "vm"})
	if filtered.Summary.Total() != 1 {
		t.Fatalf("asset ID filter: %+v", filtered.Summary)
	}

	// No filters returns all
	filtered = delta.ApplyFilter(FilterOptions{})
	if filtered.Summary.Total() != 3 {
		t.Fatalf("no filter: total=%d", filtered.Summary.Total())
	}
}

// ---------------------------------------------------------------------------
// Asset helpers
// ---------------------------------------------------------------------------

func TestAssetMap(t *testing.T) {
	a := Asset{
		ID:         "bucket-1",
		Type:       "aws_s3_bucket",
		Vendor:     "aws",
		Properties: map[string]any{"key": "val"},
	}
	m := a.Map()
	if m["id"] != ID("bucket-1") {
		t.Fatal("id missing from map")
	}
	if m["type"] != kernel.AssetType("aws_s3_bucket") {
		t.Fatal("type missing from map")
	}
	if m["key"] != "val" {
		t.Fatal("property missing from map")
	}
}

func TestAssetIsProvablySafe(t *testing.T) {
	a := Asset{Properties: map[string]any{"safety_provable": true}}
	if !a.IsProvablySafe() {
		t.Fatal("should be provably safe")
	}
	a.Properties = map[string]any{}
	if a.IsProvablySafe() {
		t.Fatal("missing property should not be provably safe")
	}
}

func TestCloudIdentityMap(t *testing.T) {
	ci := CloudIdentity{
		ID:         "role-1",
		Type:       "iam_role",
		Vendor:     "aws",
		Properties: map[string]any{"owner": "admin"},
	}
	m := ci.Map()
	if m["id"] != ID("role-1") {
		t.Fatal("id")
	}
	if m["owner"] != "admin" {
		t.Fatal("owner")
	}
}
