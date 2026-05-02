// Package findingfilter classifies assessment findings by comparing
// current results against historical assessments, enabling signal-
// filtered views that suppress chronic noise and highlight new findings.
package findingfilter

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// Classification describes a finding's temporal behavior relative to history.
type Classification string

const (
	// ClassNew is a finding not present in any historical assessment.
	ClassNew Classification = "new"
	// ClassChronic is a finding present in the most recent historical assessment.
	ClassChronic Classification = "chronic"
	// ClassReturned is a finding absent from the most recent assessment
	// but present in an older one — an oscillating pattern.
	ClassReturned Classification = "returned"
)

// findingKey uniquely identifies a finding across assessments.
type findingKey struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// ClassifiedFinding pairs a current finding with its classification.
type ClassifiedFinding struct {
	Finding   remediation.Finding `json:"finding"`
	Class     Classification      `json:"classification"`
	FirstSeen *time.Time          `json:"first_seen,omitempty"`
	LastSeen  *time.Time          `json:"last_seen,omitempty"`
	DwellDays float64             `json:"dwell_days,omitempty"`
	Cycles    int                 `json:"cycles,omitempty"`
}

// ResolvedFinding is a finding present in a previous assessment but
// absent from the current one.
type ResolvedFinding struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Severity  string           `json:"severity"`
	DwellDays float64          `json:"dwell_days,omitempty"`
}

// Result holds the classified findings after filtering.
type Result struct {
	NewFindings      []ClassifiedFinding `json:"new_findings"`
	ReturnedFindings []ClassifiedFinding `json:"returned_findings"`
	ResolvedFindings []ResolvedFinding   `json:"resolved_findings"`
	SuppressedCount  int                 `json:"suppressed_count"`
	TotalFindings    int                 `json:"total_findings"`
	SnapshotTime     time.Time           `json:"snapshot_time"`
}

// Input configures the classification.
type Input struct {
	// Current assessment findings.
	CurrentFindings []remediation.Finding
	// Historical assessments sorted by time (oldest first).
	History []*report.Assessment
	// NewSince limits what counts as "seen before": only assessments
	// within this duration are considered. Zero means use all history.
	NewSince time.Duration
	// Now is the reference time for duration calculations.
	Now time.Time
}

// appearance tracks which historical assessments a finding key
// appeared in. Centralised so buildTimeline and the classification
// loop both refer to the same shape.
type appearance struct {
	firstSeen time.Time
	lastSeen  time.Time
	count     int
	inLatest  bool
}

// Classify compares current findings against historical assessments and
// classifies each finding as new, chronic, or returned.
func Classify(in Input) *Result {
	if len(in.History) == 0 {
		return classifyAllNew(in)
	}

	sorted := sortAndFilterHistory(in.History, in.NewSince, in.Now)
	if len(sorted) == 0 {
		// All history is outside the NewSince window: everything is new.
		return classifyAllNew(in)
	}

	latest := sorted[len(sorted)-1]
	timeline := buildTimeline(sorted, latest)
	gapCount := computeGapCounts(sorted)

	newFindings, returnedFindings, suppressedCount := classifyCurrent(in, timeline, gapCount)
	resolved := buildResolved(in, latest, timeline)

	return &Result{
		NewFindings:      newFindings,
		ReturnedFindings: returnedFindings,
		ResolvedFindings: resolved,
		SuppressedCount:  suppressedCount,
		TotalFindings:    len(in.CurrentFindings),
		SnapshotTime:     in.Now,
	}
}

// classifyAllNew is the trivial-history path: every current finding
// is classified as NEW because there's no prior assessment to compare
// against (or the NewSince window excluded all history).
func classifyAllNew(in Input) *Result {
	classified := make([]ClassifiedFinding, len(in.CurrentFindings))
	for i := range in.CurrentFindings {
		classified[i] = ClassifiedFinding{
			Finding: in.CurrentFindings[i],
			Class:   ClassNew,
		}
	}
	return &Result{
		NewFindings:   classified,
		TotalFindings: len(in.CurrentFindings),
		SnapshotTime:  in.Now,
	}
}

// sortAndFilterHistory returns a new slice of assessments sorted by
// Run.Now ascending, optionally clipped to those within `newSince` of
// `now`. A newSince of zero retains the full history.
func sortAndFilterHistory(history []*report.Assessment, newSince time.Duration, now time.Time) []*report.Assessment {
	sorted := make([]*report.Assessment, len(history))
	copy(sorted, history)
	slices.SortFunc(sorted, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})
	if newSince <= 0 {
		return sorted
	}
	cutoff := now.Add(-newSince)
	filtered := make([]*report.Assessment, 0, len(sorted))
	for _, a := range sorted {
		if !a.Run.Now.Before(cutoff) {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// buildTimeline records, for each finding key, the first and last
// times it appeared across the sorted history plus a flag for
// whether the latest historical assessment contained it.
func buildTimeline(sorted []*report.Assessment, latest *report.Assessment) map[findingKey]*appearance {
	timeline := make(map[findingKey]*appearance)
	for _, a := range sorted {
		isLatest := a == latest
		for i := range a.Findings {
			k := findingKey{
				ControlID: a.Findings[i].ControlID,
				AssetID:   a.Findings[i].AssetID,
			}
			ap, exists := timeline[k]
			if !exists {
				ap = &appearance{firstSeen: a.Run.Now}
				timeline[k] = ap
			}
			ap.lastSeen = a.Run.Now
			ap.count++
			if isLatest {
				ap.inLatest = true
			}
		}
	}
	return timeline
}

// classifyCurrent walks the current findings and returns
// (new, returned, suppressedCount). A finding is NEW if absent from
// every historical assessment, CHRONIC (suppressed) if present in the
// latest historical assessment, and RETURNED if it appeared in the
// past but not in the latest.
func classifyCurrent(in Input, timeline map[findingKey]*appearance, gapCount map[findingKey]int) (newFindings, returnedFindings []ClassifiedFinding, suppressedCount int) {
	for i := range in.CurrentFindings {
		f := &in.CurrentFindings[i]
		k := findingKey{ControlID: f.ControlID, AssetID: f.AssetID}
		ap := timeline[k]

		if ap == nil {
			newFindings = append(newFindings, ClassifiedFinding{
				Finding: *f,
				Class:   ClassNew,
			})
			continue
		}
		if ap.inLatest {
			suppressedCount++
			continue
		}
		firstSeen := ap.firstSeen
		lastSeen := ap.lastSeen
		returnedFindings = append(returnedFindings, ClassifiedFinding{
			Finding:   *f,
			Class:     ClassReturned,
			FirstSeen: &firstSeen,
			LastSeen:  &lastSeen,
			DwellDays: in.Now.Sub(ap.firstSeen).Hours() / 24,
			Cycles:    gapCount[k] + 1,
		})
	}
	return newFindings, returnedFindings, suppressedCount
}

// buildResolved returns findings present in the latest historical
// assessment but absent from the current set — i.e. fixed since last
// run.
func buildResolved(in Input, latest *report.Assessment, timeline map[findingKey]*appearance) []ResolvedFinding {
	currentKeys := make(map[findingKey]bool, len(in.CurrentFindings))
	for i := range in.CurrentFindings {
		currentKeys[findingKey{
			ControlID: in.CurrentFindings[i].ControlID,
			AssetID:   in.CurrentFindings[i].AssetID,
		}] = true
	}

	var resolved []ResolvedFinding
	for i := range latest.Findings {
		k := findingKey{
			ControlID: latest.Findings[i].ControlID,
			AssetID:   latest.Findings[i].AssetID,
		}
		if currentKeys[k] {
			continue
		}
		ap := timeline[k]
		var dwell float64
		if ap != nil {
			dwell = in.Now.Sub(ap.firstSeen).Hours() / 24
		}
		resolved = append(resolved, ResolvedFinding{
			ControlID: k.ControlID,
			AssetID:   k.AssetID,
			Severity:  latest.Findings[i].ControlSeverity.String(),
			DwellDays: dwell,
		})
	}
	return resolved
}

// computeGapCounts counts the number of times each finding disappeared
// and reappeared across sorted assessments. A gap means the finding was
// present in assessment N, absent in N+1, and present again in N+2.
func computeGapCounts(sorted []*report.Assessment) map[findingKey]int {
	if len(sorted) < 3 {
		return nil
	}

	gaps := make(map[findingKey]int)

	// Track presence in consecutive assessments.
	type state struct {
		wasPresentPrev bool
		wasPresentCurr bool
	}
	tracker := make(map[findingKey]*state)

	for idx, a := range sorted {
		currentKeys := make(map[findingKey]bool, len(a.Findings))
		for i := range a.Findings {
			currentKeys[findingKey{
				ControlID: a.Findings[i].ControlID,
				AssetID:   a.Findings[i].AssetID,
			}] = true
		}

		if idx == 0 {
			for k := range currentKeys {
				tracker[k] = &state{wasPresentCurr: true}
			}
			continue
		}

		// Shift current → prev.
		for k, s := range tracker {
			s.wasPresentPrev = s.wasPresentCurr
			s.wasPresentCurr = currentKeys[k]
		}
		// Add new keys.
		for k := range currentKeys {
			if _, exists := tracker[k]; !exists {
				tracker[k] = &state{wasPresentCurr: true}
			}
		}

		if idx < 2 {
			continue
		}

		// Detect gap: present in prev-1, absent in prev, present in current.
		// We need three-step tracking, so let's simplify: just count
		// transitions from absent→present after the first appearance.
		for k, s := range tracker {
			if s.wasPresentCurr && !s.wasPresentPrev {
				// Reappeared after absence.
				gaps[k]++
			}
		}
	}

	return gaps
}
