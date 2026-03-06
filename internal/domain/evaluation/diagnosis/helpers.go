package diagnosis

import (
	"fmt"
	"sort"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

func checkTimeSpan(input Input) *Entry {
	if len(input.Snapshots) < 2 {
		return &Entry{
			Case:     ExpectedNone,
			Signal:   signalInsufficientSnapshots,
			Evidence: fmt.Sprintf("Only %d snapshot(s); need at least 2 to compute duration", len(input.Snapshots)),
			Action:   "Collect more snapshots over time to enable duration-based detection",
		}
	}

	snapshots := sortedSnapshotsByCapturedAt(input.Snapshots)
	span := snapshots[len(snapshots)-1].CapturedAt.Sub(snapshots[0].CapturedAt)

	if span < input.MaxUnsafe {
		return &Entry{
			Case:   ExpectedNone,
			Signal: signalTimeSpanShorterThanThreshold,
			Evidence: fmt.Sprintf("Snapshots span %s; threshold is %s",
				timeutil.FormatDuration(span), timeutil.FormatDuration(input.MaxUnsafe)),
			Action:  "Collect snapshots over a longer period, or reduce --max-unsafe",
			Command: fmt.Sprintf("stave apply --max-unsafe %s", timeutil.FormatDuration(span)),
		}
	}

	return nil
}

func buildNowSkewEntry(now, maxCapturedAt time.Time) *Entry {
	if now.IsZero() || maxCapturedAt.IsZero() || !now.Before(maxCapturedAt) {
		return nil
	}

	return &Entry{
		Case:   ViolationEvidence,
		Signal: signalNowBeforeLatestSnapshot,
		Evidence: fmt.Sprintf("--now=%s but latest captured_at=%s",
			now.Format(time.RFC3339), maxCapturedAt.Format(time.RFC3339)),
		Action:  "Set --now to a time after or equal to latest snapshot",
		Command: fmt.Sprintf("stave apply --now %s", maxCapturedAt.Format(time.RFC3339)),
	}
}

func buildTopFindingEntries(findings []evaluation.Finding, limit int) []Entry {
	if limit <= 0 {
		return nil
	}

	var entries []Entry
	for i, f := range findings {
		if i >= limit {
			break
		}

		entries = append(entries, Entry{
			Case:    ViolationEvidence,
			Signal:  signalContinuousUnsafeStreak,
			AssetID: f.AssetID,
			Evidence: fmt.Sprintf("resource=%s control=%s first_unsafe=%s last_unsafe=%s duration=%.1fh threshold=%.1fh",
				f.AssetID,
				f.ControlID,
				formatOptionalRFC3339(f.Evidence.FirstUnsafeAt),
				formatOptionalRFC3339(f.Evidence.LastSeenUnsafeAt),
				f.Evidence.UnsafeDurationHours,
				f.Evidence.ThresholdHours),
			Action: "If resource was safe briefly, ensure a snapshot captured that safe state",
		})
	}

	return entries
}

func formatOptionalRFC3339(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format(time.RFC3339)
}

func sortedSnapshotsByCapturedAt(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := make([]asset.Snapshot, len(snapshots))
	copy(sorted, snapshots)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CapturedAt.Before(sorted[j].CapturedAt)
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
	var paths []string
	for _, rule := range pred.Any {
		if rule.Field != "" {
			paths = append(paths, fmt.Sprintf("%s %s %v", rule.Field, rule.Op, rule.Value))
		}
	}
	for _, rule := range pred.All {
		if rule.Field != "" {
			paths = append(paths, fmt.Sprintf("%s %s %v", rule.Field, rule.Op, rule.Value))
		}
	}
	if len(paths) == 0 {
		return "(complex predicate)"
	}
	if len(paths) == 1 {
		return paths[0]
	}
	return paths[0] + " ..."
}
