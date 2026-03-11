package diagnosis

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// fmtd is a shorthand for timeutil.FormatDuration to keep diagnostic lines concise.
func fmtd(d time.Duration) string {
	return timeutil.FormatDuration(d)
}

const (
	topFindingDiagnosticLimit = 3

	signalThresholdExceedsObserved     = "Threshold exceeds observed unsafe duration"
	signalNoPredicateMatchesAny        = "No resources matched any unsafe_predicate"
	signalMatchesUnderThreshold        = "Matches exist but under threshold"
	signalAssetsResetBeforeMax         = "Assets became safe before exceeding threshold"
	signalInsufficientSnapshots        = "Insufficient snapshots for duration tracking"
	signalTimeSpanShorterThanThreshold = "Time span shorter than threshold"
	signalNowBeforeLatestSnapshot      = "Evaluation time before latest snapshot"
	signalContinuousUnsafeStreak       = "Violation due to continuous unsafe streak"
)

type controlStat struct {
	maxStreak       time.Duration
	matchedAssetIDs map[string]struct{}
}

// session holds precomputed control stats for a diagnostic run,
// avoiding redundant recomputation across diagnostic methods.
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
	unique := make(map[string]struct{})
	for _, stat := range s.stats {
		for id := range stat.matchedAssetIDs {
			unique[id] = struct{}{}
		}
	}
	return len(unique)
}

// diagnoseMissingFindings checks for issues when no violations were found.
func (s *session) diagnoseMissingFindings() []Issue {
	var issues []Issue

	// Threshold issues: streaks exist but are too short.
	maxStreak, ctlID := s.globalMaxStreak()
	if maxStreak > 0 && maxStreak < s.input.MaxUnsafe {
		issues = append(issues, Issue{
			Case:   ExpectedNone,
			Signal: signalThresholdExceedsObserved,
			Evidence: fmt.Sprintf("Max unsafe streak: %s (control %s); threshold: %s",
				fmtd(maxStreak), ctlID, fmtd(s.input.MaxUnsafe)),
			Action:  fmt.Sprintf("Lower --max-unsafe to %s or shorter", fmtd(maxStreak)),
			Command: fmt.Sprintf("stave apply --max-unsafe %s", fmtd(maxStreak)),
		})
	}

	// Predicate match issues.
	issues = append(issues, s.diagnosePredicateMatches()...)

	// Temporal issues: history is too short.
	if tsIssue := checkTimeSpan(s.input); tsIssue != nil {
		issues = append(issues, *tsIssue)
	}

	// Reset behavior.
	if detectAnyReset(s.input) {
		issues = append(issues, Issue{
			Case:     EmptyFindings,
			Signal:   signalAssetsResetBeforeMax,
			Evidence: "Unsafe streaks were reset when resources became safe",
			Action:   "This is expected behavior; unsafe window resets when asset becomes safe",
		})
	}

	return issues
}

func (s *session) diagnosePredicateMatches() []Issue {
	var issues []Issue

	uniqueMatches := s.countUniqueMatches()
	if uniqueMatches == 0 && s.totalAssets > 0 {
		issues = append(issues, Issue{
			Case:     EmptyFindings,
			Signal:   signalNoPredicateMatchesAny,
			Evidence: fmt.Sprintf("0/%d unique resources matched predicates across %d controls", s.totalAssets, len(s.input.Controls)),
			Action:   "Verify extractor writes expected properties, or adjust predicate field paths",
		})
	}

	// Per-control match check.
	for _, ctl := range s.input.Controls {
		stat, ok := s.stats[ctl.ID]
		if ok && len(stat.matchedAssetIDs) == 0 && s.totalAssets > 0 {
			issues = append(issues, Issue{
				Case:   ExpectedNone,
				Signal: fmt.Sprintf("No resources matched unsafe_predicate for %s", ctl.ID),
				Evidence: fmt.Sprintf("0/%d unique resources matched %s",
					s.totalAssets, extractFieldPath(ctl.UnsafePredicate)),
				Action: "Verify extractor writes expected properties, or adjust predicate field path",
			})
		}
	}

	// Under-threshold matches.
	if uniqueMatches > 0 {
		maxStreak, _ := s.globalMaxStreak()
		if maxStreak > 0 && maxStreak < s.input.MaxUnsafe {
			issues = append(issues, Issue{
				Case:   EmptyFindings,
				Signal: signalMatchesUnderThreshold,
				Evidence: fmt.Sprintf("%d unique resources matched; max streak %s; threshold %s",
					uniqueMatches, fmtd(maxStreak), fmtd(s.input.MaxUnsafe)),
				Action:  "Lower --max-unsafe or collect snapshots over longer time span",
				Command: fmt.Sprintf("stave apply --max-unsafe %s", fmtd(maxStreak)),
			})
		}
	}

	return issues
}

// diagnoseExistingFindings provides context for existing violations.
func (s *session) diagnoseExistingFindings(maxCapturedAt time.Time) []Issue {
	if len(s.input.Snapshots) == 0 {
		return nil
	}

	var issues []Issue

	if skew := buildNowSkewEntry(s.input.Now, maxCapturedAt); skew != nil {
		issues = append(issues, *skew)
	}

	issues = append(issues, buildTopFindingEntries(s.input.Findings, topFindingDiagnosticLimit)...)
	issues = append(issues, detectStreakResets(s.input)...)

	return issues
}

// computeMaxUnsafeStreakPerControl finds the longest unsafe streak per (asset, control).
func computeMaxUnsafeStreakPerControl(input Input) (time.Duration, string) {
	s := newSession(input, 0)
	return s.globalMaxStreak()
}

func computeStats(input Input) map[kernel.ControlID]controlStat {
	if len(input.Snapshots) == 0 {
		return nil
	}

	snapshots := sortedSnapshots(input.Snapshots)
	finalizationTime := resolveFinalizationTime(input.Now, snapshots[len(snapshots)-1].CapturedAt)

	// Build per-asset timelines from sorted snapshots in a single pass.
	history := make(map[string][]assetTimePoint)
	for _, snap := range snapshots {
		for _, r := range snap.Assets {
			assetID := r.ID.String()
			history[assetID] = append(history[assetID], assetTimePoint{snap.CapturedAt, r})
		}
	}

	// For each control, walk each asset's timeline to find the longest unsafe streak.
	stats := make(map[kernel.ControlID]controlStat, len(input.Controls))
	for _, ctl := range input.Controls {
		stat := controlStat{matchedAssetIDs: make(map[string]struct{})}

		for resID, points := range history {
			sr := analyzeAssetStreak(assetStreakRequest{
				Points:    points,
				Predicate: ctl.UnsafePredicate,
				Params:    ctl.Params,
				EndTime:   finalizationTime,
			})
			if sr.matched {
				stat.matchedAssetIDs[resID] = struct{}{}
			}
			stat.maxStreak = max(stat.maxStreak, sr.maxStreak)
		}

		stats[ctl.ID] = stat
	}

	return stats
}
