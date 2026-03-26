package engine

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// RecurrenceStats captures aggregate frequency data for a specific time window.
type RecurrenceStats struct {
	Count int
	First time.Time
	Last  time.Time
}

// EvaluateRecurrenceForControl evaluates the timeline against recurrence limits.
// It returns a slice containing a violation finding if the recurrence limit is exceeded.
func EvaluateRecurrenceForControl(
	t *asset.Timeline,
	ctl *policy.ControlDefinition,
	now time.Time,
) []*evaluation.Finding {
	p := ctl.RecurrencePolicy()
	if !p.Enabled() {
		return nil
	}

	count, first, last := t.History().WindowSummary(p.Window(now))
	if count < p.Limit {
		return nil
	}

	stats := RecurrenceStats{Count: count, First: first, Last: last}
	return []*evaluation.Finding{CreateRecurrenceFinding(t, ctl, stats)}
}

// CreateRecurrenceFinding generates a finding based on the frequency of unsafe episodes.
func CreateRecurrenceFinding(
	t *asset.Timeline,
	ctl *policy.ControlDefinition,
	stats RecurrenceStats,
) *evaluation.Finding {
	p := ctl.RecurrencePolicy()

	f := newBaseFinding(ctl, t)
	f.Evidence = evaluation.Evidence{
		EpisodeCount:    stats.Count,
		WindowDays:      p.WindowDays,
		RecurrenceLimit: p.Limit,
		FirstEpisodeAt:  stats.First,
		LastEpisodeAt:   stats.Last,

		// For recurrence, the span of episodes defines the unsafe period.
		FirstUnsafeAt:    stats.First,
		LastSeenUnsafeAt: stats.Last,

		// Threshold represents the individual episode duration limit.
		ThresholdHours: ctl.MaxUnsafeDuration().Hours(),

		// UnsafeDurationHours is intentionally omitted.
		// Recurrence findings are triggered by count, not cumulative duration.
	}
	return f
}
