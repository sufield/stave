package asset

import (
	"fmt"
	"math"
	"time"
)

// ExposureLifecycle tracks the security state transitions of an asset across scans.
// It records when an asset first became non-compliant, when it was last observed
// in that state, and maintains a history of resolved windows for dwell-time analysis.
type ExposureLifecycle struct {
	ID    ID
	asset Asset

	activeWindow   *ExposureWindow
	lastObservedAt time.Time

	history ExposureHistory
	stats   ObservationStats
}

// NewExposureLifecycle constructs a new lifecycle tracker for a cloud asset.
// Panics if the asset ID is empty — this is a programming error at the call site.
func NewExposureLifecycle(a Asset) *ExposureLifecycle {
	if a.ID.IsEmpty() {
		panic("contract violated: NewExposureLifecycle requires non-empty asset ID")
	}
	return &ExposureLifecycle{
		ID:    a.ID,
		asset: a,
	}
}

// Asset returns the latest observed state of the cloud asset.
func (l *ExposureLifecycle) Asset() Asset {
	return l.asset
}

// SetAsset updates the lifecycle with the most recent asset metadata.
func (l *ExposureLifecycle) SetAsset(a Asset) {
	if l.ID.IsEmpty() {
		l.ID = a.ID
	}
	l.asset = a
	l.checkContracts()
}

// Stats returns continuity and frequency metrics for this asset.
func (l *ExposureLifecycle) Stats() ObservationStats {
	return l.stats
}

// History returns a record of all previously resolved exposure windows.
func (l *ExposureLifecycle) History() ExposureHistory {
	return l.history
}

// RecordCheck updates the lifecycle based on a new scan result.
// It handles the transitions between compliant and non-compliant states.
func (l *ExposureLifecycle) RecordCheck(t time.Time, isExposed bool) error {
	if t.IsZero() {
		return ErrZeroTimestamp
	}

	if err := l.stats.RecordObservation(t); err != nil {
		return err
	}
	if isExposed {
		l.handleExposed(t)
	} else {
		l.handleSecure(t)
	}
	l.checkContracts()
	return nil
}

// RecordInconclusive records that a scan was attempted but the result
// was inconclusive (e.g., CEL evaluation error). Updates lastObservedAt
// so the lifecycle knows the asset was observed, but does NOT modify
// the exposure state — UnsafeSince and activeWindow are preserved.
// This prevents an inconclusive check from resetting the SLA clock.
func (l *ExposureLifecycle) RecordInconclusive(t time.Time) error {
	if t.IsZero() {
		return ErrZeroTimestamp
	}
	if err := l.stats.RecordObservation(t); err != nil {
		return err
	}
	if t.After(l.lastObservedAt) || l.lastObservedAt.IsZero() {
		l.lastObservedAt = t
	}
	return nil
}

// IsSecure reports whether the asset is currently in a compliant state.
func (l *ExposureLifecycle) IsSecure() bool {
	return l.activeWindow == nil
}

// IsExposed reports whether the asset is currently in a non-compliant state.
func (l *ExposureLifecycle) IsExposed() bool {
	return l.activeWindow != nil
}

// FirstExposedAt returns the timestamp when the current exposure window opened.
func (l *ExposureLifecycle) FirstExposedAt() time.Time {
	if l.activeWindow == nil {
		return time.Time{}
	}
	return l.activeWindow.OpenedAt()
}

// LastObservedAt returns the most recent timestamp where the asset was scanned.
func (l *ExposureLifecycle) LastObservedAt() time.Time {
	return l.lastObservedAt
}

// HasExposureTimestamps reports whether both FirstExposedAt and LastObservedAt are set.
func (l *ExposureLifecycle) HasExposureTimestamps() bool {
	return !l.FirstExposedAt().IsZero() && !l.lastObservedAt.IsZero()
}

// MissingExposureTimestamps reports whether either FirstExposedAt or LastObservedAt is unset.
func (l *ExposureLifecycle) MissingExposureTimestamps() bool {
	return !l.HasExposureTimestamps()
}

// HasActiveWindow reports whether the asset is currently in an active
// exposure window with a recorded start time.
func (l *ExposureLifecycle) HasActiveWindow() bool {
	return l.activeWindow != nil && l.activeWindow.IsActive()
}

func (l *ExposureLifecycle) handleExposed(t time.Time) {
	if l.activeWindow == nil {
		window := NewActiveWindow(t)
		l.activeWindow = &window
	}
	if t.After(l.lastObservedAt) || l.lastObservedAt.IsZero() {
		l.lastObservedAt = t
	}
}

func (l *ExposureLifecycle) handleSecure(at time.Time) {
	if l.activeWindow == nil {
		return
	}

	resolveAt := l.resolveTimestamp(at)
	if resolveAt.IsZero() {
		// No usable resolution timestamp — leave the active window open
		// rather than recording a degenerate zero-duration window that
		// would corrupt downstream dwell-time analysis.
		return
	}
	resolved := l.activeWindow.Resolve(resolveAt)
	l.history.Record(resolved)
	l.activeWindow = nil
	// Do not clear lastObservedAt — it records when asset was last seen
	// and is needed by RecordCheck() if the asset is re-exposed later.
}

func (l *ExposureLifecycle) resolveTimestamp(at time.Time) time.Time {
	// Prefer the secure-observation time itself: that is when the
	// asset returned to a compliant state, per ExposureWindow.ResolvedAt
	// docs. Falling back to lastObservedAt (the previous unsafe scan)
	// would close the window at the last unsafe scan instead of the
	// secure scan, undercounting dwell time by one scan interval.
	if !at.IsZero() {
		return at
	}
	if !l.lastObservedAt.IsZero() {
		return l.lastObservedAt
	}
	if l.activeWindow != nil {
		return l.activeWindow.OpenedAt()
	}
	return time.Time{}
}

// ExposureDuration calculates how long the asset has been non-compliant.
func (l *ExposureLifecycle) ExposureDuration(now time.Time) (time.Duration, error) {
	if !l.HasActiveWindow() {
		return 0, nil
	}
	if !now.IsZero() && now.Before(l.activeWindow.OpenedAt()) {
		return 0, fmt.Errorf("exposure duration: 'now' (%s) must not be before window start (%s)", now.Format(time.RFC3339), l.activeWindow.OpenedAt().Format(time.RFC3339))
	}
	return now.Sub(l.activeWindow.OpenedAt()), nil
}

// ExceedsSLA reports whether the asset has been exposed for at least the
// allowed threshold. The comparison is inclusive: an exposure of exactly
// `threshold` is treated as exceeding it, so a zero threshold (the most
// strict configuration) flags any non-zero exposure.
func (l *ExposureLifecycle) ExceedsSLA(now time.Time, threshold time.Duration) (bool, error) {
	d, err := l.ExposureDuration(now)
	if err != nil {
		return false, err
	}
	return d >= threshold, nil
}

// FormatExposureSummary provides a human-readable string for CLI output.
func (l *ExposureLifecycle) FormatExposureSummary(threshold time.Duration, now time.Time) string {
	if !l.HasActiveWindow() {
		return "Asset is currently in a non-compliant state."
	}

	d, dErr := l.ExposureDuration(now)
	if dErr != nil {
		return fmt.Sprintf(
			"Asset non-compliant (duration unavailable). Exposed since %s.",
			l.FirstExposedAt().Format(time.RFC3339))
	}
	return fmt.Sprintf(
		"Asset non-compliant for %d hours (SLA: %d hours). Exposed since %s.",
		int(math.Round(d.Hours())),
		int(math.Round(threshold.Hours())),
		l.FirstExposedAt().Format(time.RFC3339),
	)
}

func (l *ExposureLifecycle) checkContracts() {
	if l.ID.IsEmpty() {
		panic("contract violated: ExposureLifecycle.ID must be non-empty")
	}
}
