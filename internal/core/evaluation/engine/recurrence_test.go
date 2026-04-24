package engine

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func recurrenceControl(id string, limit, windowDays int) *policy.ControlDefinition {
	params := policy.ControlParams{}
	params.Set("recurrence_limit", limit)
	params.Set("window_days", windowDays)
	ctl := &policy.ControlDefinition{
		ID:     kernel.ControlID(id),
		Name:   id,
		Type:   policy.TypeUnsafeRecurrence,
		Params: params,
	}
	_ = ctl.Prepare()
	return ctl
}

func recurrenceLifecycle(t *testing.T, exposureWindows []struct{ start, end time.Time }) *asset.ExposureLifecycle {
	t.Helper()
	a := asset.Asset{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}
	tl := asset.NewExposureLifecycle(a)

	for _, ep := range exposureWindows {
		// Record unsafe start
		if err := tl.RecordCheck(ep.start, true); err != nil {
			t.Fatalf("RecordObservation(unsafe): %v", err)
		}
		// Record safe end (closes the exposure window)
		if err := tl.RecordCheck(ep.end, false); err != nil {
			t.Fatalf("RecordObservation(safe): %v", err)
		}
	}
	return tl
}

// ---------------------------------------------------------------------------
// EvaluateRecurrenceForControl
// ---------------------------------------------------------------------------

func TestRecurrence_DisabledPolicy(t *testing.T) {
	ctl := recurrenceControl("CTL.REC.001", 0, 0) // disabled
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := recurrenceLifecycle(t, []struct{ start, end time.Time }{
		{base, base.Add(time.Hour)},
	})

	findings := EvaluateRecurrenceForControl(tl, ctl, base.Add(2*time.Hour))
	if len(findings) != 0 {
		t.Fatalf("disabled policy should produce 0 findings, got %d", len(findings))
	}
}

func TestRecurrence_BelowLimit(t *testing.T) {
	// Limit=3, window=7 days, but only 2 exposureWindows → no violation
	ctl := recurrenceControl("CTL.REC.001", 3, 7)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := recurrenceLifecycle(t, []struct{ start, end time.Time }{
		{base, base.Add(time.Hour)},
		{base.Add(24 * time.Hour), base.Add(25 * time.Hour)},
	})

	now := base.Add(48 * time.Hour)
	findings := EvaluateRecurrenceForControl(tl, ctl, now)
	if len(findings) != 0 {
		t.Fatalf("below limit should produce 0 findings, got %d", len(findings))
	}
}

func TestRecurrence_ExceedsLimit(t *testing.T) {
	// Limit=2, window=7 days, with 3 exposureWindows → violation
	ctl := recurrenceControl("CTL.REC.001", 2, 7)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := recurrenceLifecycle(t, []struct{ start, end time.Time }{
		{base, base.Add(time.Hour)},
		{base.Add(24 * time.Hour), base.Add(25 * time.Hour)},
		{base.Add(48 * time.Hour), base.Add(49 * time.Hour)},
	})

	now := base.Add(72 * time.Hour)
	findings := EvaluateRecurrenceForControl(tl, ctl, now)
	if len(findings) != 1 {
		t.Fatalf("expected 1 recurrence finding, got %d", len(findings))
	}
}

func TestRecurrence_ActiveWindowCountedTowardLimit(t *testing.T) {
	// Regression test: the active (unresolved) exposure window must be
	// counted toward the recurrence limit. Before the fix, only resolved
	// windows were counted, causing a false negative when the asset was
	// currently exposed.
	//
	// Limit=2, window=7 days, 2 resolved windows + 1 active = 3 > 2 → violation
	ctl := recurrenceControl("CTL.REC.001", 2, 7)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	a := asset.Asset{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}
	tl := asset.NewExposureLifecycle(a)

	// Window 1: resolved
	_ = tl.RecordCheck(base, true)
	_ = tl.RecordCheck(base.Add(time.Hour), false)

	// Window 2: resolved
	_ = tl.RecordCheck(base.Add(24*time.Hour), true)
	_ = tl.RecordCheck(base.Add(25*time.Hour), false)

	// Window 3: currently active (not resolved)
	_ = tl.RecordCheck(base.Add(48*time.Hour), true)

	if !tl.IsExposed() {
		t.Fatal("expected asset to be currently exposed")
	}

	now := base.Add(72 * time.Hour)
	findings := EvaluateRecurrenceForControl(tl, ctl, now)
	if len(findings) != 1 {
		t.Fatalf("expected 1 recurrence finding (active window should count), got %d", len(findings))
	}
	if findings[0].Evidence.ExposureWindowCount != 3 {
		t.Fatalf("ExposureWindowCount = %d, want 3 (2 resolved + 1 active)", findings[0].Evidence.ExposureWindowCount)
	}
}

func TestRecurrence_ActiveWindowOutsideRange(t *testing.T) {
	// Active window started before the recurrence time range — should not count.
	ctl := recurrenceControl("CTL.REC.001", 3, 7)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	a := asset.Asset{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}
	tl := asset.NewExposureLifecycle(a)

	// Active window started 30 days ago (before the 7-day range)
	_ = tl.RecordCheck(base, true)

	now := base.Add(30 * 24 * time.Hour)
	findings := EvaluateRecurrenceForControl(tl, ctl, now)
	if len(findings) != 0 {
		t.Fatalf("active window outside range should not count, got %d findings", len(findings))
	}
}

// ---------------------------------------------------------------------------
// CreateRecurrenceFinding
// ---------------------------------------------------------------------------

func TestCreateRecurrenceFinding_Fields(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := recurrenceControl("CTL.REC.001", 2, 7)

	a := asset.Asset{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}
	tl := asset.NewExposureLifecycle(a)
	_ = tl.RecordCheck(base, false)

	stats := RecurrenceStats{
		Count: 3,
		First: base,
		Last:  base.Add(48 * time.Hour),
	}

	finding := CreateRecurrenceFinding(tl, ctl, stats)
	if finding == nil {
		t.Fatal("expected non-nil finding")
	}
	if finding.ControlID != "CTL.REC.001" {
		t.Fatalf("ControlID = %v", finding.ControlID)
	}
	if finding.Evidence.ExposureWindowCount != 3 {
		t.Fatalf("ExposureWindowCount = %d, want 3", finding.Evidence.ExposureWindowCount)
	}
	if finding.Evidence.RecurrenceLimit != 2 {
		t.Fatalf("RecurrenceLimit = %d, want 2", finding.Evidence.RecurrenceLimit)
	}
	if finding.Evidence.WindowDays != 7 {
		t.Fatalf("WindowDays = %d, want 7", finding.Evidence.WindowDays)
	}
}

func TestRecurrence_ExactlyAtLimitFires(t *testing.T) {
	// `recurrence_limit: N` means "N occurrences is already too many".
	// count == limit fires; only count < limit is compliant.
	ctl := recurrenceControl("CTL.RECUR.BOUNDARY.001", 3, 90)
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	lc := recurrenceLifecycle(t, []struct{ start, end time.Time }{
		{now.AddDate(0, 0, -80), now.AddDate(0, 0, -75)},
		{now.AddDate(0, 0, -60), now.AddDate(0, 0, -55)},
		{now.AddDate(0, 0, -30), now.AddDate(0, 0, -25)},
	})

	findings := EvaluateRecurrenceForControl(lc, ctl, now)
	if len(findings) != 1 {
		t.Errorf("limit=3 with count=3 should fire (count >= limit), got %d findings", len(findings))
	}
}
