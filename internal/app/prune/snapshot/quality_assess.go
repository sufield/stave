package snapshot

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func assessQuality(params qualityParams) qualityReport {
	assessor := qualityAssessor{
		params: params,
		report: newQualityReport(params.Now, params.Strict, len(params.Snapshots)),
	}
	return assessor.assess()
}

func newQualityReport(now time.Time, strict bool, snapshots int) qualityReport {
	return qualityReport{
		SchemaVersion: kernel.SchemaSnapshotQuality,
		Kind:          kernel.KindSnapshotQuality,
		CheckedAt:     now,
		Strict:        strict,
		Summary: qualitySummary{
			Snapshots: snapshots,
		},
		Issues: []qualityIssue{},
	}
}

func (a *qualityAssessor) assess() qualityReport {
	params := a.params
	report := &a.report
	if len(params.Snapshots) == 0 {
		report.addIssue(
			"NO_SNAPSHOTS",
			severityError,
			"No snapshots found in observations directory.",
			nil,
		)
		return report.finalize()
	}

	a.sorted = sortSnapshots(params.Snapshots)
	a.setBounds()
	a.checkCount()
	a.checkStaleness()
	a.checkGap()
	a.checkRequiredAssets()
	return report.finalize()
}

func (a *qualityAssessor) setBounds() {
	summary := &a.report.Summary
	oldest := a.sorted[0].CapturedAt.UTC()
	latest := a.sorted[len(a.sorted)-1].CapturedAt.UTC()
	summary.OldestCapturedAt = oldest
	summary.LatestCapturedAt = latest
}

func (a *qualityAssessor) checkCount() {
	params := a.params
	snapshotCount := len(a.sorted)
	if snapshotCount >= params.MinSnapshots {
		return
	}

	a.report.addIssue(
		"TOO_FEW_SNAPSHOTS",
		severityError,
		fmt.Sprintf("Need at least %d snapshots, found %d.", params.MinSnapshots, snapshotCount),
		&issueEvidence{
			MinSnapshots: new(params.MinSnapshots),
			Actual:       new(snapshotCount),
		},
	)
}

func (a *qualityAssessor) checkStaleness() {
	params := a.params
	latest := a.sorted[len(a.sorted)-1].CapturedAt.UTC()
	age := params.Now.Sub(latest)
	if age <= params.MaxStaleness {
		return
	}

	a.report.addIssue(
		"LATEST_SNAPSHOT_STALE",
		severityError,
		"Latest snapshot is older than allowed staleness threshold.",
		&issueEvidence{
			LatestCapturedAt: latest.Format(time.RFC3339),
			Age:              timeutil.FormatDurationHuman(age),
			MaxStaleness:     timeutil.FormatDurationHuman(params.MaxStaleness),
		},
	)
}

func (a *qualityAssessor) checkGap() {
	params := a.params
	summary := &a.report.Summary
	maxObservedGap := calculateMaxGap(a.sorted)
	summary.MaxGap = timeutil.FormatDurationHuman(maxObservedGap)
	if maxObservedGap <= params.MaxGap {
		return
	}

	a.report.addIssue(
		"SNAPSHOT_GAP_TOO_LARGE",
		severityWarning,
		"Gap between snapshots exceeds recommended maximum.",
		&issueEvidence{
			MaxGapObserved: timeutil.FormatDurationHuman(maxObservedGap),
			MaxGapAllowed:  timeutil.FormatDurationHuman(params.MaxGap),
		},
	)
}

func (a *qualityAssessor) checkRequiredAssets() {
	params := a.params
	if len(params.RequiredResources) == 0 {
		return
	}

	missing := findMissingRequiredAssets(a.sorted[len(a.sorted)-1], params.RequiredResources)
	if len(missing) == 0 {
		return
	}

	a.report.addIssue(
		"MISSING_REQUIRED_RESOURCES",
		severityError,
		"Required resources are missing in latest snapshot.",
		&issueEvidence{MissingResources: missing},
	)
}

func (r *qualityReport) addIssue(code string, severity qualitySeverity, message string, evidence *issueEvidence) {
	if r == nil {
		return
	}
	r.Issues = append(r.Issues, qualityIssue{
		Code:     code,
		Severity: severity,
		Message:  message,
		Evidence: evidence,
	})
}

func (r qualityReport) finalize() qualityReport {
	hasErrors := false
	hasWarnings := false
	for _, issue := range r.Issues {
		switch issue.Severity {
		case severityError:
			hasErrors = true
		case severityWarning:
			hasWarnings = true
		}
	}

	r.Pass = !hasErrors && (!r.Strict || !hasWarnings)
	return r
}

func sortSnapshots(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := slices.Clone(snapshots)
	slices.SortFunc(sorted, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})
	return sorted
}

func calculateMaxGap(sorted []asset.Snapshot) time.Duration {
	maxObservedGap := time.Duration(0)
	for i := 1; i < len(sorted); i++ {
		gap := sorted[i].CapturedAt.Sub(sorted[i-1].CapturedAt)
		if gap > maxObservedGap {
			maxObservedGap = gap
		}
	}
	return maxObservedGap
}

func findMissingRequiredAssets(latest asset.Snapshot, requiredAssets []string) []string {
	latestIDs := make(map[string]struct{}, len(latest.Assets))
	for _, r := range latest.Assets {
		latestIDs[r.ID.String()] = struct{}{}
	}

	missing := make([]string, 0, len(requiredAssets))
	for _, id := range requiredAssets {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := latestIDs[id]; !ok {
			missing = append(missing, id)
		}
	}

	slices.Sort(missing)
	return missing
}
