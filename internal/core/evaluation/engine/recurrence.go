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
//
// ids carries the identity context observed during this assessment.
// Recurrence findings forward it so downstream evidence layers can
// correlate the offending lifecycle with the IAM principals /
// service accounts active at the time of the most recent
// observation, consistent with how duration and state findings
// already attach identity context. The current finding shape does
// not yet render the identity slice, but the parameter flows
// through so a future enrichment hook does not have to rewire the
// recurrence path.
func EvaluateRecurrenceForControl(
	t *asset.ExposureLifecycle,
	ctl *policy.ControlDefinition,
	now time.Time,
	ids IdentityIndex,
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
			// Use w.End (period end) as the effective last time for the
			// active window so the active-window path matches the
			// closed-window branch in ExposureHistory.WindowSummary.
			// The previous shape used `now` (audit time), which could
			// drift past w.End and surface confusing evidence
			// timestamps that don't fall inside the recurrence
			// analysis window.
			if last.IsZero() || w.End.After(last) {
				last = w.End
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
	f := CreateRecurrenceFinding(t, ctl, stats)
	if f == nil {
		// CreateRecurrenceFinding now returns nil for malformed
		// inputs (nil control / lifecycle). Drop the empty slot
		// rather than emitting a phantom finding the collector
		// would have to filter out downstream.
		return nil
	}
	return []*evaluation.Finding{f}
}

// CreateRecurrenceFinding generates a finding based on the frequency of unsafe exposure windows.
//
// Returns nil when newBaseFinding rejects nil control / lifecycle
// inputs. Callers must propagate (see strategyDeps callers, which
// drop nil entries from the returned slice).
func CreateRecurrenceFinding(
	t *asset.ExposureLifecycle,
	ctl *policy.ControlDefinition,
	stats RecurrenceStats,
) *evaluation.Finding {
	if ctl == nil {
		// Cannot read RecurrencePolicy off a nil control. Match
		// newBaseFinding's nil-input contract by failing fast here
		// instead of panicking on the policy deref below.
		return nil
	}
	p := ctl.RecurrencePolicy()

	f := newBaseFinding(ctl, t)
	if f == nil {
		return nil
	}
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
