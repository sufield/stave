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

func recurrenceTimeline(t *testing.T, episodes []struct{ start, end time.Time }) *asset.Timeline {
	t.Helper()
	a := asset.Asset{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}
	tl, err := asset.NewTimeline(a)
	if err != nil {
		t.Fatalf("NewTimeline: %v", err)
	}

	for _, ep := range episodes {
		// Record unsafe start
		if err := tl.RecordObservation(ep.start, true); err != nil {
			t.Fatalf("RecordObservation(unsafe): %v", err)
		}
		// Record safe end (closes the episode)
		if err := tl.RecordObservation(ep.end, false); err != nil {
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
	tl := recurrenceTimeline(t, []struct{ start, end time.Time }{
		{base, base.Add(time.Hour)},
	})

	findings := EvaluateRecurrenceForControl(tl, ctl, base.Add(2*time.Hour))
	if len(findings) != 0 {
		t.Fatalf("disabled policy should produce 0 findings, got %d", len(findings))
	}
}

func TestRecurrence_BelowLimit(t *testing.T) {
	// Limit=3, window=7 days, but only 2 episodes → no violation
	ctl := recurrenceControl("CTL.REC.001", 3, 7)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := recurrenceTimeline(t, []struct{ start, end time.Time }{
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
	// Limit=2, window=7 days, with 3 episodes → violation
	ctl := recurrenceControl("CTL.REC.001", 2, 7)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tl := recurrenceTimeline(t, []struct{ start, end time.Time }{
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

// ---------------------------------------------------------------------------
// CreateRecurrenceFinding
// ---------------------------------------------------------------------------

func TestCreateRecurrenceFinding_Fields(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ctl := recurrenceControl("CTL.REC.001", 2, 7)

	a := asset.Asset{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}
	tl, _ := asset.NewTimeline(a)
	_ = tl.RecordObservation(base, false)

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
	if finding.Evidence.EpisodeCount != 3 {
		t.Fatalf("EpisodeCount = %d, want 3", finding.Evidence.EpisodeCount)
	}
	if finding.Evidence.RecurrenceLimit != 2 {
		t.Fatalf("RecurrenceLimit = %d, want 2", finding.Evidence.RecurrenceLimit)
	}
	if finding.Evidence.WindowDays != 7 {
		t.Fatalf("WindowDays = %d, want 7", finding.Evidence.WindowDays)
	}
}
