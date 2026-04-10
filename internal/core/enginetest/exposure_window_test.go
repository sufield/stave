package enginetest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestExposureWindowClose_FloorsEndBeforeStart(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	beforeStart := start.Add(-4 * time.Hour)

	ep := asset.NewActiveWindow(start)
	closed := ep.Resolve(beforeStart)
	if closed.IsActive() {
		t.Fatal("expected exposure window to be closed")
	}
	if !closed.OpenedAt().Equal(start) {
		t.Fatalf("start_at=%s, want %s", closed.OpenedAt(), start)
	}
	if !closed.EffectiveEndAt(time.Time{}).Equal(start) {
		t.Fatalf("effective_end_at=%s, want %s", closed.EffectiveEndAt(time.Time{}), start)
	}
}

func TestExposureWindowClose_IsIdempotentForClosedExposureWindow(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 1, 2, 0, 0, 0, time.UTC)
	alreadyClosed := asset.NewResolvedWindow(start, end)

	got := alreadyClosed.Resolve(end.Add(3 * time.Hour))
	if got.IsActive() {
		t.Fatal("expected exposure window to remain closed")
	}
	if !got.OpenedAt().Equal(start) {
		t.Fatalf("start_at=%s, want %s", got.OpenedAt(), start)
	}
	if !got.EffectiveEndAt(time.Time{}).Equal(end) {
		t.Fatalf("effective_end_at=%s, want %s", got.EffectiveEndAt(time.Time{}), end)
	}
}

func TestExposureWindowJSON_RoundTrip(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 1, 2, 0, 0, 0, time.UTC)
	want := asset.NewResolvedWindow(start, end)

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal exposure window: %v", err)
	}

	var got asset.ExposureWindow
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal exposure window: %v", err)
	}

	if got.IsActive() {
		t.Fatal("expected closed exposure window after round-trip")
	}
	if !got.OpenedAt().Equal(start) {
		t.Fatalf("start_at=%s, want %s", got.OpenedAt(), start)
	}
	if !got.ResolvedAt().Equal(end) {
		t.Fatalf("end_at=%s, want %s", got.ResolvedAt(), end)
	}
}

func TestExposureLifecycle_RecordObservation_FloorsArchivedExposureWindowEnd(t *testing.T) {
	start := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	outOfOrderSafe := start.Add(-1 * time.Hour)

	lifecycle := asset.NewExposureLifecycle(asset.Asset{ID: "res:test"})
	if err := lifecycle.RecordCheck(start, true); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.RecordCheck(outOfOrderSafe, false); err != nil {
		t.Fatal(err)
	}

	if lifecycle.HasActiveWindow() {
		t.Fatal("expected no open exposure window after safe transition")
	}
	if lifecycle.History().Count() != 1 {
		t.Fatalf("history count=%d, want 1", lifecycle.History().Count())
	}

	count, first, last := lifecycle.History().WindowSummary(kernel.TimeWindow{Start: start.Add(-2 * time.Hour), End: start.Add(2 * time.Hour)})
	if count != 1 {
		t.Fatalf("window count=%d, want 1", count)
	}
	if !first.Equal(start) {
		t.Fatalf("first=%s, want %s", first, start)
	}
	if !last.Equal(start) {
		t.Fatalf("last=%s, want %s (floored end)", last, start)
	}
}
