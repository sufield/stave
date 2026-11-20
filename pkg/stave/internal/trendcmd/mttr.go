package trendcmd

import (
	"time"

	"github.com/sufield/stave/internal/core/report"
)

// violationWindow tracks a single violation's lifecycle.
type violationWindow struct {
	key      string // controlID:assetID
	severity string
	openedAt time.Time
	closedAt time.Time
	closed   bool
}

// computeMTTR calculates mean time to remediate from a sequence of assessments.
func computeMTTR(assessments []*report.Assessment) map[string]mttrEntry {
	closedWindows := trackViolationWindows(assessments)

	// Aggregate closed windows by severity.
	type accumulator struct {
		totalDays float64
		count     int
	}
	bySev := make(map[string]*accumulator)

	for i := range closedWindows {
		w := &closedWindows[i]
		duration := w.closedAt.Sub(w.openedAt)
		days := duration.Hours() / 24.0

		acc, ok := bySev[w.severity]
		if !ok {
			acc = &accumulator{}
			bySev[w.severity] = acc
		}
		acc.totalDays += days
		acc.count++
	}

	result := make(map[string]mttrEntry, len(bySev))
	for sev, acc := range bySev {
		avg := 0.0
		if acc.count > 0 {
			avg = acc.totalDays / float64(acc.count)
		}
		result[sev] = mttrEntry{
			AvgDays:     avg,
			WindowCount: acc.count,
		}
	}

	return result
}

func trackViolationWindows(assessments []*report.Assessment) []violationWindow {
	windows := make(map[string]*violationWindow)
	var closed []violationWindow
	for _, a := range assessments {
		capturedAt := a.Run.EvalTime
		currentKeys := make(map[string]struct{})
		for i := range a.Findings {
			f := &a.Findings[i]
			key := string(f.ControlID) + ":" + string(f.AssetID)
			currentKeys[key] = struct{}{}
			sev := f.SeverityLabel()
			if sev == "" {
				sev = "unknown"
			}
			if _, exists := windows[key]; !exists {
				windows[key] = &violationWindow{
					key:      key,
					severity: sev,
					openedAt: capturedAt,
				}
			}
		}
		for key, w := range windows {
			if _, ok := currentKeys[key]; !ok {
				w.closedAt = capturedAt
				w.closed = true
				closed = append(closed, *w)
				delete(windows, key)
			}
		}
	}
	return closed
}
