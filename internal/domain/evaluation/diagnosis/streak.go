package diagnosis

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// --- Streak analysis ---

// observation pairs a capture timestamp with the asset state at that time.
type observation struct {
	at    time.Time
	state asset.Asset
}

// streakTracker tracks whether a contiguous unsafe period is in progress
// and when it started.
type streakTracker struct {
	start  time.Time
	active bool
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

type assetStreakRequest struct {
	Points    []observation
	Predicate policy.UnsafePredicate
	Params    policy.ControlParams
	EndTime   time.Time
}

// analyzeAssetStreak walks an asset's chronological timeline to find the
// longest contiguous unsafe period (streak). A streak starts when the predicate
// first matches and ends when it stops matching or at endTime if still unsafe.
func analyzeAssetStreak(req assetStreakRequest) (maxStreak time.Duration, matched bool) {
	var tracker streakTracker

	for _, pt := range req.Points {
		if req.Predicate.Evaluate(pt.state, req.Params) {
			matched = true
			tracker.markUnsafe(pt.at)
		} else {
			if d := tracker.endStreak(pt.at); d > maxStreak {
				maxStreak = d
			}
		}
	}

	if d := tracker.endStreak(req.EndTime); d > maxStreak {
		maxStreak = d
	}
	return maxStreak, matched
}

// --- Reset detection ---

// resetTracker implements a state machine to detect: Unsafe → Safe → Unsafe.
type resetTracker struct {
	wasEverUnsafe   bool
	isCurrentlySafe bool
	lastSafeAt      time.Time
}

// observe processes the next observation. Returns true if a streak reset occurred
// (unsafe → safe → unsafe transition).
func (rt *resetTracker) observe(isUnsafe bool, at time.Time) bool {
	resetDetected := isUnsafe && rt.isCurrentlySafe && rt.wasEverUnsafe

	rt.isCurrentlySafe = !isUnsafe
	if isUnsafe {
		rt.wasEverUnsafe = true
	} else {
		rt.lastSafeAt = at
	}

	return resetDetected
}

// resetEvent records a detected streak reset for a single asset.
type resetEvent struct {
	assetID asset.ID
	safeAt  time.Time
}

// findResets walks sorted snapshots and returns all streak resets found.
// If filter is nil, all assets are examined.
func findResets(snapshots []asset.Snapshot, unsafeIdx *unsafeIndex, filter map[asset.ID]struct{}) []resetEvent {
	trackers := make(map[asset.ID]*resetTracker)
	var events []resetEvent

	for sIdx, snap := range snapshots {
		for _, a := range snap.Assets {
			if filter != nil {
				if _, ok := filter[a.ID]; !ok {
					continue
				}
			}

			tracker, exists := trackers[a.ID]
			if !exists {
				tracker = &resetTracker{isCurrentlySafe: true}
				trackers[a.ID] = tracker
			}

			if tracker.observe(unsafeIdx.isUnsafe(sIdx, a.ID), snap.CapturedAt) {
				events = append(events, resetEvent{
					assetID: a.ID,
					safeAt:  tracker.lastSafeAt,
				})
			}
		}
	}

	return events
}

// detectStreakResets finds assets that became safe between unsafe periods.
// Only examines assets with existing findings.
func detectStreakResets(input Input) []Issue {
	if len(input.Snapshots) < 2 {
		return nil
	}

	snaps := sortedSnapshots(input.Snapshots)
	idx := buildUnsafeIndex(snaps, input.Controls)

	violated := make(map[asset.ID]struct{}, len(input.Findings))
	for _, f := range input.Findings {
		violated[f.AssetID] = struct{}{}
	}

	events := findResets(snaps, idx, violated)

	issues := make([]Issue, 0, len(events))
	for _, e := range events {
		issues = append(issues, Issue{
			Case:    ScenarioViolationEvidence,
			Signal:  "Streak reset detected",
			AssetID: e.assetID,
			Evidence: fmt.Sprintf("asset=%s became safe at %s then unsafe again",
				e.assetID, e.safeAt.Format(time.RFC3339)),
			Action: "Current violation reflects time since last reset, not total unsafe time",
		})
	}
	return issues
}

// detectAnyReset checks if any asset had a reset during the observation period.
// Examines all assets (not filtered by findings) because this is called when
// no findings exist to explain why assets didn't exceed the threshold.
func detectAnyReset(input Input) bool {
	if len(input.Snapshots) < 2 {
		return false
	}

	snaps := sortedSnapshots(input.Snapshots)
	idx := buildUnsafeIndex(snaps, input.Controls)

	return len(findResets(snaps, idx, nil)) > 0
}
