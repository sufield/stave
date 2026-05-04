package engine

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// RecurrenceStats captures aggregate frequency data for a specific time window.
type RecurrenceStats struct {
	Count int
	First time.Time
	Last  time.Time
}

// EvaluateRecurrenceForControl evaluates the lifecycle against recurrence limits.
// It returns a slice containing a violation finding if the recurrence limit is exceeded.
func EvaluateRecurrenceForControl(
	t *asset.ExposureLifecycle,
	ctl *policy.ControlDefinition,
	now time.Time,
) []*evaluation.Finding {
	p := ctl.RecurrencePolicy()
	if !p.Enabled() {
		return nil
	}

	w := p.Window(now)
	count, first, last := t.History().WindowSummary(w)

	// Include the currently active window if it overlaps the
	// recurrence time range. Uses the same overlap logic as
	// WindowSummary: started before period ended AND still active
	// (active windows have no end time, so they always overlap
	// if they started before the period ended).
	if t.HasActiveWindow() {
		start := t.FirstExposedAt()
		if start.Before(w.End) {
			count++
			if first.IsZero() || start.Before(first) {
				first = start
			}
			if last.IsZero() || now.After(last) {
				last = now
			}
		}
	}

	// p.Threshold is the inclusive violation threshold: a recurrence_threshold
	// of 3 means 3 OR MORE occurrences trigger a violation (count >=
	// Limit fires; count < Limit is within tolerance). Despite the
	// "limit" name, the field acts as a threshold; consider renaming
	// to recurrence_threshold in a future schema bump for clarity —
	// kept as-is here for backward compatibility with deployed control
	// YAML.
	if count < p.Threshold {
		return nil
	}

	stats := RecurrenceStats{Count: count, First: first, Last: last}
	return []*evaluation.Finding{CreateRecurrenceFinding(t, ctl, stats)}
}

// CreateRecurrenceFinding generates a finding based on the frequency of unsafe exposure windows.
func CreateRecurrenceFinding(
	t *asset.ExposureLifecycle,
	ctl *policy.ControlDefinition,
	stats RecurrenceStats,
) *evaluation.Finding {
	p := ctl.RecurrencePolicy()

	f := newBaseFinding(ctl, t)
	f.Evidence = evaluation.Evidence{
		ExposureWindowCount:   stats.Count,
		WindowDays:            p.WindowDays,
		RecurrenceThreshold:   p.Threshold,
		FirstExposureWindowAt: stats.First,
		LastExposureWindowAt:  stats.Last,

		// For recurrence, the span of exposure windows defines the unsafe period.
		FirstUnsafeAt:    stats.First,
		LastSeenUnsafeAt: stats.Last,

		// Threshold represents the individual exposure window duration limit.
		ThresholdHours: ctl.MaxUnsafeDuration().Hours(),

		// UnsafeDurationHours is intentionally omitted.
		// Recurrence findings are triggered by count, not cumulative duration.
	}
	return f
}
