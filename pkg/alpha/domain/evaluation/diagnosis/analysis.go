package diagnosis

import (
	"fmt"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

const (
	topFindingLimit = 3

	msgNoPredicateMatches     = "No resources matched any unsafe_predicate"
	msgMatchesUnderThreshold  = "Matches exist but under threshold"
	msgAssetsResetBeforeMax   = "Assets became safe before exceeding threshold"
	msgSkewedEvaluationTime   = "Evaluation time before latest snapshot"
	msgContinuousUnsafeStreak = "Violation due to continuous unsafe streak"
)

type controlStat struct {
	maxStreak       time.Duration
	matchedAssetIDs map[asset.ID]struct{}
}

// session encapsulates the state required to diagnose a specific evaluation run.
type session struct {
	input       Input
	stats       map[kernel.ControlID]controlStat
	totalAssets int
}

func newSession(input Input, totalAssets int) *session {
	return &session{
		input:       input,
		stats:       computeStats(input),
		totalAssets: totalAssets,
	}
}

// diagnoseMissingFindings determines why zero violations were detected.
func (s *session) diagnoseMissingFindings() []Issue {
	var issues []Issue

	// 1. Temporal Constraints
	if tsIssue := checkTimeSpan(s.input); tsIssue != nil {
		issues = append(issues, *tsIssue)
	}

	// 2. Predicate Match Coverage
	issues = append(issues, s.diagnoseMatchCoverage()...)

	// 3. Duration/Threshold Analysis
	issues = append(issues, s.diagnoseThresholdGaps()...)

	return issues
}

func (s *session) diagnoseMatchCoverage() []Issue {
	var issues []Issue
	uniqueMatches := s.countUniqueMatches()

	// Global match failure
	if uniqueMatches == 0 && s.totalAssets > 0 {
		issues = append(issues, Issue{
			Case:     ScenarioEmptyFindings,
			Signal:   msgNoPredicateMatches,
			Evidence: fmt.Sprintf("0/%d unique resources matched any predicate across %d controls", s.totalAssets, len(s.input.Controls)),
			Action:   "Verify extractor writes expected properties or adjust predicate field paths",
		})
		return issues // Skip per-control if global is zero
	}

	// Per-control match failure
	for _, ctl := range s.input.Controls {
		stat, ok := s.stats[ctl.ID]
		if ok && len(stat.matchedAssetIDs) == 0 && s.totalAssets > 0 {
			issues = append(issues, Issue{
				Case:     ScenarioExpectedNone,
				Signal:   fmt.Sprintf("No resources matched predicate for %s", ctl.ID),
				Evidence: fmt.Sprintf("0/%d resources matched: %s", s.totalAssets, extractFieldPath(ctl.UnsafePredicate)),
				Action:   "Verify predicate field path matches resource properties",
			})
		}
	}

	return issues
}

func (s *session) diagnoseThresholdGaps() []Issue {
	var issues []Issue
	maxStreak, ctlID := s.globalMaxStreak()

	// Case: Matches found, but none long enough to trigger a violation.
	// Stave uses strict ">" so duration must exceed --max-unsafe, not equal it.
	if maxStreak > 0 && maxStreak <= s.input.MaxUnsafeDuration {
		issues = append(issues, Issue{
			Case:   ScenarioEmptyFindings,
			Signal: msgMatchesUnderThreshold,
			Evidence: fmt.Sprintf("Max observed streak: %s (control %s); threshold: %s",
				fmtd(maxStreak), ctlID, fmtd(s.input.MaxUnsafeDuration)),
			Action:  fmt.Sprintf("Lower --max-unsafe to below %s to trigger a violation", fmtd(maxStreak)),
			Command: fmt.Sprintf("stave apply --max-unsafe %s", fmtd(maxStreak)),
		})
	}

	// Case: Logic-reset check
	if detectAnyReset(s.input) {
		issues = append(issues, Issue{
			Case:     ScenarioEmptyFindings,
			Signal:   msgAssetsResetBeforeMax,
			Evidence: "Unsafe streaks were reset when resources became safe",
			Action:   "The unsafe window resets when an asset becomes safe; check if this is expected",
		})
	}

	return issues
}

// diagnoseExistingFindings explains existing findings (e.g., skew, resets).
func (s *session) diagnoseExistingFindings(maxCapturedAt time.Time) []Issue {
	if len(s.input.Snapshots) == 0 {
		return nil
	}

	var issues []Issue

	if skew := buildNowSkewIssue(s.input.Now, maxCapturedAt); skew != nil {
		issues = append(issues, *skew)
	}

	issues = append(issues, buildTopFindingIssues(s.input.Findings, topFindingLimit)...)
	issues = append(issues, detectStreakResets(s.input)...)

	return issues
}

// computeStats calculates the longest streak and asset match set for every control.
func computeStats(input Input) map[kernel.ControlID]controlStat {
	if len(input.Snapshots) == 0 || len(input.Controls) == 0 {
		return nil
	}

	snaps := sortedSnapshots(input.Snapshots)
	endTime := resolveFinalizationTime(input.Now, snaps[len(snaps)-1].CapturedAt)

	// Phase 1: Pivot data to Asset-Major order O(Snapshots * Assets)
	assetHistories := make(map[asset.ID][]observation)
	for _, snap := range snaps {
		for _, a := range snap.Assets {
			assetHistories[a.ID] = append(assetHistories[a.ID], observation{
				at:         snap.CapturedAt,
				state:      a,
				identities: snap.Identities,
			})
		}
	}

	// Phase 2: Analyze streaks per control O(Controls * Assets)
	stats := make(map[kernel.ControlID]controlStat, len(input.Controls))
	for _, ctl := range input.Controls {
		cs := controlStat{matchedAssetIDs: make(map[asset.ID]struct{})}

		for id, history := range assetHistories {
			streak, matched := analyzeAssetStreak(assetStreakRequest{
				Points:  history,
				Control: ctl,
				EndTime: endTime,
				Eval:    input.PredicateEval,
			})

			if matched {
				cs.matchedAssetIDs[id] = struct{}{}
			}
			if streak > cs.maxStreak {
				cs.maxStreak = streak
			}
		}
		stats[ctl.ID] = cs
	}

	return stats
}

// Helpers

func (s *session) globalMaxStreak() (time.Duration, string) {
	var best time.Duration
	var bestID string
	for _, ctl := range s.input.Controls {
		if stat, ok := s.stats[ctl.ID]; ok && stat.maxStreak > best {
			best = stat.maxStreak
			bestID = ctl.ID.String()
		}
	}
	return best, bestID
}

func (s *session) countUniqueMatches() int {
	unique := make(map[asset.ID]struct{})
	for _, stat := range s.stats {
		for id := range stat.matchedAssetIDs {
			unique[id] = struct{}{}
		}
	}
	return len(unique)
}
