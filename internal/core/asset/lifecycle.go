package asset

import (
	"errors"
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

	// hasClampedWindow becomes true the first time any window in the
	// lifecycle's history was clamped to zero duration because the
	// resolver-supplied time was earlier than the open time
	// (out-of-order snapshots, clock skew). Sticky: stays true once
	// set so the engine can flag the verdict inconclusive even after
	// further well-ordered observations replace the active window.
	hasClampedWindow bool
}

// HasClampedWindow reports whether any window in this lifecycle was
// clamped to zero duration during Resolve. Engine callers branch on
// this to mark the resulting ResourceCheck inconclusive — the
// clamped window's "zero dwell" reading would otherwise feed
// duration math as if no exposure had occurred.
func (l *ExposureLifecycle) HasClampedWindow() bool {
	return l.hasClampedWindow
}

// ErrEmptyAssetID is returned by NewExposureLifecycle when the input
// Asset has an empty ID. Callers should log the offending observation
// and skip the asset rather than abort the whole evaluation, since a
// single malformed snapshot row should not invalidate the entire run.
var ErrEmptyAssetID = errors.New("asset ID must be non-empty")

// NewExposureLifecycle constructs a new lifecycle tracker for a cloud
// asset. Returns ErrEmptyAssetID when the asset ID is empty — the
// earlier shape panicked, which aborted the entire assessment if a
// single malformed observation slipped past upstream validation.
// Returning an error lets the lifecycle builder skip just the bad
// row and continue processing the rest of the snapshot.
func NewExposureLifecycle(a Asset) (*ExposureLifecycle, error) {
	if a.ID.IsEmpty() {
		return nil, ErrEmptyAssetID
	}
	return &ExposureLifecycle{
		ID:    a.ID,
		asset: a,
	}, nil
}

// Asset returns the latest observed state of the cloud asset.
func (l *ExposureLifecycle) Asset() Asset {
	return l.asset
}

// SetAsset updates the lifecycle with the most recent asset metadata.
//
// Returns ErrEmptyAssetID when the resulting lifecycle ID would be
// empty (the lifecycle had no ID and the incoming asset has no ID).
// The earlier shape called checkContracts() which panicked on the
// same condition; callers (currently engine/lifecycles.go) can now
// surface the failure via a normal error path, matching the
// error-returning style of NewExposureLifecycle.
func (l *ExposureLifecycle) SetAsset(a Asset) error {
	if l.ID.IsEmpty() {
		l.ID = a.ID
	}
	l.asset = a
	if l.ID.IsEmpty() {
		return ErrEmptyAssetID
	}
	return nil
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
	// lastObservedAt records when the asset was last seen, regardless
	// of compliance state. The previous shape only advanced it on
	// exposed observations, so a long secure run made LastObservedAt
	// look stale (frozen at the last unsafe scan), and downstream
	// freshness/staleness checks misread the asset as not-recently-
	// scanned. Update unconditionally before any early return.
	if !at.IsZero() && (at.After(l.lastObservedAt) || l.lastObservedAt.IsZero()) {
		l.lastObservedAt = at
	}

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
	if resolved.WasClamped() {
		// The window was clamped to a zero-duration result because
		// resolveAt landed earlier than openedAt — clock skew or a
		// snapshot reorder. Record the clamp on the lifecycle so the
		// engine can mark the resulting verdict inconclusive instead
		// of silently using the zero-dwell window for downstream
		// duration math.
		l.hasClampedWindow = true
	}
	// A non-clamped zero-duration window (resolveAt == openedAt) is
	// also unreliable for dwell-time math: same scan caught the
	// asset both unsafe and safe, which usually means flapping
	// state mid-scan or extractor-side ordering noise, not a
	// genuine "exposure for zero seconds." Mark it so coverage
	// validators can tell apart "exposure was real but resolved
	// instantly" (questionable) from the typical multi-scan
	// resolution where dwell time is meaningful.
	if resolved.OpenedAt().Equal(resolved.ResolvedAt()) {
		l.hasClampedWindow = true
	}
	l.history.Record(resolved)
	l.activeWindow = nil
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

// ExceedsSLA reports whether the asset has been exposed long enough to
// breach the configured threshold. Comparison rules:
//
//  1. threshold == 0 ("zero tolerance"): any active exposure window
//     breaches immediately. The previous strict-greater rule made the
//     first observation that opened a window read d == 0, which never
//     exceeded a zero threshold, so the strictest possible SLA was
//     paradoxically the most lenient at the first detection.
//     A no-active-window asset still does not breach: never-exposed
//     assets cannot violate any SLA.
//  2. threshold > 0: strict-greater. Tests in internal/core/enginetest
//     assert exposure of exactly the threshold is within bounds (e.g.
//     48h with a 48h SLA must not violate); only durations that exceed
//     the threshold are violations.
func (l *ExposureLifecycle) ExceedsSLA(now time.Time, threshold time.Duration) (bool, error) {
	d, err := l.ExposureDuration(now)
	if err != nil {
		return false, err
	}
	if threshold == 0 {
		return l.HasActiveWindow(), nil
	}
	return d > threshold, nil
}

// FormatExposureSummary provides a human-readable string for CLI output.
func (l *ExposureLifecycle) FormatExposureSummary(threshold time.Duration, now time.Time) string {
	if !l.HasActiveWindow() {
		return "Asset is currently in a compliant state."
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
