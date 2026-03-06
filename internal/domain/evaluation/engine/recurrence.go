package engine

import (
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// EpisodeWindowSummary is aggregate recurrence information for a time window.
type EpisodeWindowSummary struct {
	Count int
	First time.Time
	Last  time.Time
}

// SummarizeEpisodesInWindow computes recurrence summary for episodes started
// within the given window. Open episodes are not part of archived history.
func SummarizeEpisodesInWindow(timeline *asset.Timeline, w kernel.TimeWindow) EpisodeWindowSummary {
	count, first, last := timeline.History().WindowSummary(w)
	return EpisodeWindowSummary{Count: count, First: first, Last: last}
}

// EvaluateRecurrenceForControl checks for recurrence violations for a specific control.
func EvaluateRecurrenceForControl(
	timeline *asset.Timeline,
	ctl *policy.ControlDefinition,
	now time.Time,
) []evaluation.Finding {
	recurrence := ctl.RecurrencePolicy()
	if !recurrence.Configured() {
		return nil
	}

	summary := SummarizeEpisodesInWindow(timeline, recurrence.Window(now))
	if summary.Count < recurrence.Limit {
		return nil
	}

	return []evaluation.Finding{CreateRecurrenceFinding(timeline, ctl, summary)}
}

// CreateRecurrenceFinding generates a finding for a recurrence violation.
func CreateRecurrenceFinding(
	timeline *asset.Timeline,
	ctl *policy.ControlDefinition,
	summary EpisodeWindowSummary,
) evaluation.Finding {
	recurrence := ctl.RecurrencePolicy()

	f := baseFinding(ctl, timeline)
	f.Evidence = evaluation.Evidence{
		EpisodeCount:     summary.Count,
		WindowDays:       recurrence.WindowDays,
		RecurrenceLimit:  recurrence.Limit,
		FirstEpisodeAt:   summary.First,
		LastEpisodeAt:    summary.Last,
		FirstUnsafeAt:    summary.First,
		LastSeenUnsafeAt: summary.Last,
		ThresholdHours:   ctl.MaxUnsafeDuration().Hours(),
	}
	// NOTE: We do NOT set UnsafeDurationHours for recurrence findings because
	// the span between first and last episode includes safe time between episodes.
	// Recurrence is about episode count, not cumulative duration.
	return f
}
