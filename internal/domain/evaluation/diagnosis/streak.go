package diagnosis

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// --- Streak primitives ---

// assetTimePoint pairs a capture timestamp with the asset state at that time.
type assetTimePoint struct {
	capturedAt time.Time
	observed   asset.Asset
}

// streakResult holds the outcome of analyzing a single asset's timeline
// against a single control's unsafe predicate.
type streakResult struct {
	matched   bool
	maxStreak time.Duration
}

// streakTracker tracks whether a contiguous unsafe period is in progress
// and when it started.
type streakTracker struct {
	start  time.Time
	active bool
}

type assetStreakRequest struct {
	Points    []assetTimePoint
	Predicate policy.UnsafePredicate
	Params    policy.ControlParams
	EndTime   time.Time
}

// markUnsafe begins a new streak if one is not already active.
func (t *streakTracker) markUnsafe(at time.Time) {
	if !t.active {
		t.start = at
		t.active = true
	}
}

// endStreak closes any active streak and returns its duration.
// Returns zero if no streak is active.
func (t *streakTracker) endStreak(at time.Time) time.Duration {
	if !t.active {
		return 0
	}
	d := at.Sub(t.start)
	t.active = false
	return d
}

// analyzeAssetStreak walks an asset's chronological timeline to find the
// longest contiguous unsafe period (streak). A streak starts when the predicate
// first matches and ends when it stops matching or at endTime if still unsafe.
func analyzeAssetStreak(req assetStreakRequest) streakResult {
	var result streakResult
	var streak streakTracker

	for _, pt := range req.Points {
		if req.Predicate.Evaluate(pt.observed, req.Params) {
			result.matched = true
			streak.markUnsafe(pt.capturedAt)
		} else {
			result.maxStreak = max(result.maxStreak, streak.endStreak(pt.capturedAt))
		}
	}

	result.maxStreak = max(result.maxStreak, streak.endStreak(req.EndTime))
	return result
}

// --- Streak reset detection ---

// assetResetState tracks the three-state machine for reset detection:
// never-unsafe -> currently-unsafe -> was-unsafe-now-safe -> currently-unsafe-again (reset).
type assetResetState struct {
	wasEverUnsafe bool
	currentlySafe bool
	lastSafeAt    time.Time
}

func newResetState(isUnsafe bool, t time.Time) assetResetState {
	return assetResetState{
		wasEverUnsafe: isUnsafe,
		currentlySafe: !isUnsafe,
		lastSafeAt:    t,
	}
}

// streakReset returns true when an asset transitions back to unsafe after
// a period of safety: unsafe -> safe -> unsafe. This means the violation clock
// was reset by the safe interval.
func (s assetResetState) streakReset(isUnsafe bool) bool {
	return isUnsafe && s.currentlySafe && s.wasEverUnsafe
}

// observe processes the next observation. Returns true if a streak reset occurred
// (unsafe -> safe -> unsafe transition).
func (s *assetResetState) observe(isUnsafe bool, t time.Time) bool {
	reset := s.streakReset(isUnsafe)
	s.currentlySafe = !isUnsafe
	if isUnsafe {
		s.wasEverUnsafe = true
	}
	s.lastSafeAt = t
	return reset
}

// resetEvent records a detected streak reset for a single asset.
type resetEvent struct {
	assetID string
	safeAt  time.Time
}

func collectAssetIDs(snapshots []asset.Snapshot) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, snap := range snapshots {
		for _, r := range snap.Assets {
			ids[r.ID.String()] = struct{}{}
		}
	}
	return ids
}

// findResets walks sorted snapshots and returns all streak resets found.
// Only assets present in scope are examined.
func findResets(snapshots []asset.Snapshot, unsafeIdx unsafeIndex, scope map[string]struct{}) []resetEvent {
	states := make(map[string]assetResetState, len(scope))
	var resets []resetEvent

	for snapIdx, snap := range snapshots {
		for _, r := range snap.Assets {
			assetID := r.ID.String()
			if _, inScope := scope[assetID]; !inScope {
				continue
			}

			isUnsafe := unsafeIdx.isUnsafe(snapIdx, assetID)

			s, exists := states[assetID]
			if !exists {
				states[assetID] = newResetState(isUnsafe, snap.CapturedAt)
				continue
			}

			if s.observe(isUnsafe, snap.CapturedAt) {
				resets = append(resets, resetEvent{
					assetID: assetID,
					safeAt:  s.lastSafeAt,
				})
			}
			states[assetID] = s
		}
	}

	return resets
}

// resetEntry formats a resetEvent into an Entry.
func resetEntry(e resetEvent) Entry {
	return Entry{
		Case:    ViolationEvidence,
		Signal:  "Streak reset detected",
		AssetID: asset.ID(e.assetID),
		Evidence: fmt.Sprintf("asset=%s became safe at %s then unsafe again",
			e.assetID, e.safeAt.Format(time.RFC3339)),
		Action: "Current violation reflects time since last reset, not total unsafe time",
	}
}

// detectStreakResets finds assets that became safe between unsafe periods.
// Only examines assets with existing findings.
func detectStreakResets(input Input) []Entry {
	if len(input.Snapshots) < 2 {
		return nil
	}

	snapshots := sortedSnapshotsByCapturedAt(input.Snapshots)
	unsafeIdx := buildUnsafeAnyControlBySnapshotAsset(snapshots, input.Controls)

	violated := make(map[string]struct{}, len(input.Findings))
	for _, f := range input.Findings {
		violated[string(f.AssetID)] = struct{}{}
	}

	resets := findResets(snapshots, unsafeIdx, violated)

	entries := make([]Entry, 0, len(resets))
	for _, e := range resets {
		entries = append(entries, resetEntry(e))
	}
	return entries
}

// detectAnyReset checks if any asset had a reset during the observation period.
// Examines all assets (not filtered by findings) because this is called when
// no findings exist to explain why assets didn't exceed the threshold.
func detectAnyReset(input Input) bool {
	if len(input.Snapshots) < 2 {
		return false
	}

	snapshots := sortedSnapshotsByCapturedAt(input.Snapshots)
	unsafeIdx := buildUnsafeAnyControlBySnapshotAsset(snapshots, input.Controls)

	allAssetIDs := collectAssetIDs(snapshots)
	return len(findResets(snapshots, unsafeIdx, allAssetIDs)) > 0
}
