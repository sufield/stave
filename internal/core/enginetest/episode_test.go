package enginetest

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestEpisodeClose_FloorsEndBeforeStart(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	beforeStart := start.Add(-4 * time.Hour)

	ep, err := asset.NewActiveWindow(start)
	if err != nil {
		t.Fatalf("NewActiveWindow: %v", err)
	}
	closed := ep.Resolve(beforeStart)
	if closed.IsActive() {
		t.Fatal("expected episode to be closed")
	}
	if !closed.OpenedAt().Equal(start) {
		t.Fatalf("start_at=%s, want %s", closed.OpenedAt(), start)
	}
	if !closed.EffectiveEndAt(time.Time{}).Equal(start) {
		t.Fatalf("effective_end_at=%s, want %s", closed.EffectiveEndAt(time.Time{}), start)
	}
}

func TestEpisodeClose_IsIdempotentForClosedEpisode(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 1, 2, 0, 0, 0, time.UTC)
	alreadyClosed, err := asset.NewResolvedWindow(start, end)
	if err != nil {
		t.Fatalf("NewResolvedWindow: %v", err)
	}

	got := alreadyClosed.Resolve(end.Add(3 * time.Hour))
	if got.IsActive() {
		t.Fatal("expected episode to remain closed")
	}
	if !got.OpenedAt().Equal(start) {
		t.Fatalf("start_at=%s, want %s", got.OpenedAt(), start)
	}
	if !got.EffectiveEndAt(time.Time{}).Equal(end) {
		t.Fatalf("effective_end_at=%s, want %s", got.EffectiveEndAt(time.Time{}), end)
	}
}

func TestEpisodeJSON_RoundTrip(t *testing.T) {
	start := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 1, 2, 0, 0, 0, time.UTC)
	want, err := asset.NewResolvedWindow(start, end)
	if err != nil {
		t.Fatalf("NewResolvedWindow: %v", err)
	}

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal episode: %v", err)
	}

	var got asset.ExposureWindow
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal episode: %v", err)
	}

	if got.IsActive() {
		t.Fatal("expected closed episode after round-trip")
	}
	if !got.OpenedAt().Equal(start) {
		t.Fatalf("start_at=%s, want %s", got.OpenedAt(), start)
	}
	if !got.ResolvedAt().Equal(end) {
		t.Fatalf("end_at=%s, want %s", got.ResolvedAt(), end)
	}
}

func TestTimeline_RecordObservation_FloorsArchivedEpisodeEnd(t *testing.T) {
	start := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	outOfOrderSafe := start.Add(-1 * time.Hour)

	timeline, err := asset.NewExposureLifecycle(asset.Asset{ID: "res:test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := timeline.RecordCheck(start, true); err != nil {
		t.Fatal(err)
	}
	if err := timeline.RecordCheck(outOfOrderSafe, false); err != nil {
		t.Fatal(err)
	}

	if timeline.HasActiveWindow() {
		t.Fatal("expected no open episode after safe transition")
	}
	if timeline.History().Count() != 1 {
		t.Fatalf("history count=%d, want 1", timeline.History().Count())
	}

	count, first, last := timeline.History().WindowSummary(kernel.TimeWindow{Start: start.Add(-2 * time.Hour), End: start.Add(2 * time.Hour)})
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
