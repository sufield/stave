// Package trendpredict projects compliance readiness achievement dates
// by combining MTTR from historical data with current framework gaps.
package trendpredict

import (
	"math"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// Prediction holds the readiness timeline projection.
type Prediction struct {
	Profile          string        `json:"profile"`
	TargetReadiness  float64       `json:"target_readiness_pct"`
	CurrentReadiness float64       `json:"current_readiness_pct"`
	ProjectedDate    time.Time     `json:"projected_date"`
	OptimisticDate   time.Time     `json:"optimistic_date"`
	PessimisticDate  time.Time     `json:"pessimistic_date"`
	Accelerators     []Accelerator `json:"accelerators,omitempty"`
}

// Accelerator describes a sprint-sized intervention that moves the date.
type Accelerator struct {
	Description string   `json:"description"`
	ControlIDs  []string `json:"control_ids"`
	DaysSaved   int      `json:"days_saved"`
}

// Input configures the prediction.
type Input struct {
	Assessments     []*report.Assessment
	Profile         string
	TargetReadiness float64
	Window          time.Duration
	Now             time.Time
}

// Predict computes the readiness timeline.
func Predict(in Input) *Prediction {
	if len(in.Assessments) == 0 {
		return &Prediction{
			Profile:         in.Profile,
			TargetReadiness: in.TargetReadiness,
		}
	}

	sorted := make([]*report.Assessment, len(in.Assessments))
	copy(sorted, in.Assessments)
	slices.SortFunc(sorted, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})

	latest := sorted[len(sorted)-1]

	// Compute per-severity MTTR from history.
	mttr := computeMTTR(sorted, in.Window, in.Now)

	// Count failing controls.
	totalFindings := len(latest.Findings)
	if totalFindings == 0 {
		return &Prediction{
			Profile:          in.Profile,
			TargetReadiness:  in.TargetReadiness,
			CurrentReadiness: 100,
			ProjectedDate:    in.Now,
			OptimisticDate:   in.Now,
			PessimisticDate:  in.Now,
		}
	}

	totalControls := max(latest.Summary.TotalAssets, 1)
	currentReadiness := (1.0 - float64(latest.Summary.Violations)/float64(totalControls)) * 100
	gap := in.TargetReadiness - currentReadiness
	if gap <= 0 {
		return &Prediction{
			Profile:          in.Profile,
			TargetReadiness:  in.TargetReadiness,
			CurrentReadiness: currentReadiness,
			ProjectedDate:    in.Now,
			OptimisticDate:   in.Now,
			PessimisticDate:  in.Now,
		}
	}

	// Estimate days to close gap based on MTTR.
	avgMTTRDays := weightedMTTR(latest.Findings, mttr)
	controlsToFix := int(math.Ceil(float64(totalFindings) * gap / 100))
	projectedDays := int(float64(controlsToFix) * avgMTTRDays)

	projected := in.Now.AddDate(0, 0, projectedDays)
	optimistic := in.Now.AddDate(0, 0, int(float64(projectedDays)*0.6))
	pessimistic := in.Now.AddDate(0, 0, int(float64(projectedDays)*1.4))

	// Acceleration: top critical findings.
	var accelerators []Accelerator
	criticals := findBySeverity(latest.Findings, "critical")
	if len(criticals) > 0 {
		limit := min(len(criticals), 4)
		ids := make([]string, limit)
		for i := range limit {
			ids[i] = string(criticals[i].ControlID)
		}
		saved := int(float64(limit) * avgMTTRDays)
		accelerators = append(accelerators, Accelerator{
			Description: "Fix critical findings this sprint",
			ControlIDs:  ids,
			DaysSaved:   saved,
		})
	}

	return &Prediction{
		Profile:          in.Profile,
		TargetReadiness:  in.TargetReadiness,
		CurrentReadiness: math.Round(currentReadiness*10) / 10,
		ProjectedDate:    projected,
		OptimisticDate:   optimistic,
		PessimisticDate:  pessimistic,
		Accelerators:     accelerators,
	}
}

func computeMTTR(sorted []*report.Assessment, lookback time.Duration, now time.Time) map[string]float64 {
	cutoff := now.Add(-lookback)
	type fkey struct{ ctl, ast string }
	type mttrWindow struct {
		sev     string
		openAt  time.Time
		closeAt time.Time
	}

	open := make(map[fkey]*mttrWindow)
	var closed []mttrWindow

	for _, a := range sorted {
		if a.Run.Now.Before(cutoff) {
			continue
		}
		currentKeys := make(map[fkey]struct{}, len(a.Findings))
		for i := range a.Findings {
			k := fkey{string(a.Findings[i].ControlID), string(a.Findings[i].AssetID)}
			currentKeys[k] = struct{}{}
			if _, exists := open[k]; !exists {
				open[k] = &mttrWindow{
					sev:    a.Findings[i].SeverityLabel(),
					openAt: a.Run.Now,
				}
			}
		}
		for k, w := range open {
			if _, ok := currentKeys[k]; !ok {
				w.closeAt = a.Run.Now
				closed = append(closed, *w)
				delete(open, k)
			}
		}
	}

	// Aggregate by severity.
	type agg struct {
		totalDays float64
		count     int
	}
	bySeV := make(map[string]*agg)
	for _, w := range closed {
		days := w.closeAt.Sub(w.openAt).Hours() / 24
		a, ok := bySeV[w.sev]
		if !ok {
			a = &agg{}
			bySeV[w.sev] = a
		}
		a.totalDays += days
		a.count++
	}

	result := make(map[string]float64, len(bySeV))
	for sev, a := range bySeV {
		if a.count > 0 {
			result[sev] = a.totalDays / float64(a.count)
		}
	}
	return result
}

func weightedMTTR(findings []remediation.Finding, mttr map[string]float64) float64 {
	if len(findings) == 0 {
		return 14 // default 14 days
	}
	total := 0.0
	for i := range findings {
		sev := findings[i].SeverityLabel()
		if days, ok := mttr[sev]; ok {
			total += days
		} else {
			total += 14
		}
	}
	return total / float64(len(findings))
}

func findBySeverity(findings []remediation.Finding, sev string) []remediation.Finding {
	var result []remediation.Finding
	for i := range findings {
		if findings[i].SeverityLabel() == sev {
			result = append(result, findings[i])
		}
	}
	return result
}
