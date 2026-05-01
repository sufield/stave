package trend

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
	// Track open windows by violation key.
	windows := make(map[string]*violationWindow)
	var closedWindows []violationWindow

	// Build severity index from findings.
	severityOf := make(map[string]string) // controlID:assetID → severity

	for _, a := range assessments {
		capturedAt := a.Run.Now
		currentKeys := make(map[string]bool)

		for i := range a.Findings {
			f := &a.Findings[i]
			key := string(f.ControlID) + ":" + string(f.AssetID)
			currentKeys[key] = true

			sev := f.ControlSeverity.String()
			if sev == "" {
				sev = "unknown"
			}
			severityOf[key] = sev

			// Open window if not already open.
			if _, exists := windows[key]; !exists {
				windows[key] = &violationWindow{
					key:      key,
					severity: sev,
					openedAt: capturedAt,
				}
			}
		}

		// Close windows for violations no longer present.
		for key, w := range windows {
			if !currentKeys[key] {
				w.closedAt = capturedAt
				w.closed = true
				closedWindows = append(closedWindows, *w)
				delete(windows, key)
			}
		}
	}

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
