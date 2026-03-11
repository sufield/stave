package diagnosis

import (
	"fmt"
	"slices"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
)

func checkTimeSpan(input Input) *Issue {
	if len(input.Snapshots) < 2 {
		return &Issue{
			Case:     ExpectedNone,
			Signal:   signalInsufficientSnapshots,
			Evidence: fmt.Sprintf("Only %d snapshot(s); need at least 2 to compute duration", len(input.Snapshots)),
			Action:   "Collect more snapshots over time to enable duration-based detection",
		}
	}

	snapshots := sortedSnapshots(input.Snapshots)
	span := snapshots[len(snapshots)-1].CapturedAt.Sub(snapshots[0].CapturedAt)

	if span < input.MaxUnsafe {
		return &Issue{
			Case:   ExpectedNone,
			Signal: signalTimeSpanShorterThanThreshold,
			Evidence: fmt.Sprintf("Snapshots span %s; threshold is %s",
				fmtd(span), fmtd(input.MaxUnsafe)),
			Action:  "Collect snapshots over a longer period, or reduce --max-unsafe",
			Command: fmt.Sprintf("stave apply --max-unsafe %s", fmtd(span)),
		}
	}

	return nil
}

func buildNowSkewEntry(now, maxCapturedAt time.Time) *Issue {
	if now.IsZero() || maxCapturedAt.IsZero() || !now.Before(maxCapturedAt) {
		return nil
	}

	return &Issue{
		Case:   ViolationEvidence,
		Signal: signalNowBeforeLatestSnapshot,
		Evidence: fmt.Sprintf("--now=%s but latest captured_at=%s",
			fmtTime(now), fmtTime(maxCapturedAt)),
		Action:  "Set --now to a time after or equal to latest snapshot",
		Command: fmt.Sprintf("stave apply --now %s", fmtTime(maxCapturedAt)),
	}
}

func buildTopFindingEntries(findings []evaluation.Finding, limit int) []Issue {
	count := min(len(findings), limit)
	if count <= 0 {
		return nil
	}

	entries := make([]Issue, 0, count)
	for _, f := range findings[:count] {
		ev := f.Evidence
		entries = append(entries, Issue{
			Case:    ViolationEvidence,
			Signal:  signalContinuousUnsafeStreak,
			AssetID: f.AssetID,
			Evidence: fmt.Sprintf("asset=%s control=%s first_unsafe=%s last_unsafe=%s duration=%.1fh threshold=%.1fh",
				f.AssetID,
				f.ControlID,
				fmtTime(ev.FirstUnsafeAt),
				fmtTime(ev.LastSeenUnsafeAt),
				ev.UnsafeDurationHours,
				ev.ThresholdHours),
			Action: "If asset was safe briefly, ensure a snapshot captured that safe state",
		})
	}

	return entries
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format(time.RFC3339)
}

func sortedSnapshots(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := slices.Clone(snapshots)
	slices.SortFunc(sorted, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})
	return sorted
}

func resolveFinalizationTime(now, fallback time.Time) time.Time {
	if now.IsZero() || now.Before(fallback) {
		return fallback
	}
	return now
}

func extractFieldPath(pred policy.UnsafePredicate) string {
	var rules []policy.PredicateRule
	rules = append(rules, pred.Any...)
	rules = append(rules, pred.All...)

	var paths []string
	for _, r := range rules {
		if r.Field != "" {
			paths = append(paths, fmt.Sprintf("%s %s %v", r.Field, r.Op, r.Value))
		}
	}

	switch len(paths) {
	case 0:
		return "(complex predicate)"
	case 1:
		return paths[0]
	default:
		return paths[0] + " ..."
	}
}
