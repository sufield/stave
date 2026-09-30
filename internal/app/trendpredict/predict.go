// Package trendpredict projects compliance readiness achievement dates
// by combining MTTR from historical data with current framework gaps.
package trendpredict

import (
	"math"
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// ReadinessPercentage encapsulates a compliance readiness percentage level in [0, 100].
type ReadinessPercentage float64

// Value returns the raw float64 readiness percentage.
func (r ReadinessPercentage) Value() float64 { return float64(r) }

// Clamp ensures the readiness percentage is bounded within [0, 100].
func (r ReadinessPercentage) Clamp() ReadinessPercentage {
	if r < 0 {
		return 0
	}
	if r > 100 {
		return 100
	}
	return r
}

// IsAchieved returns true if current readiness meets or exceeds the target.
func (r ReadinessPercentage) IsAchieved(target ReadinessPercentage) bool {
	return r >= target
}

// GapTo returns the percentage gap remaining to reach the target. Returns 0 if target is met.
func (r ReadinessPercentage) GapTo(target ReadinessPercentage) float64 {
	if r >= target {
		return 0
	}
	return float64(target - r)
}

// Prediction holds the readiness timeline projection.
type Prediction struct {
	Profile          policy.ComplianceFramework `json:"profile"`
	TargetReadiness  ReadinessPercentage        `json:"target_readiness_pct"`
	CurrentReadiness ReadinessPercentage        `json:"current_readiness_pct"`
	ProjectedDate    time.Time                  `json:"projected_date"`
	OptimisticDate   time.Time                  `json:"optimistic_date"`
	PessimisticDate  time.Time                  `json:"pessimistic_date"`
	Accelerators     Accelerators               `json:"accelerators,omitempty"`
}

// Accelerator describes a sprint-sized intervention that moves the date.
type Accelerator struct {
	Description string     `json:"description"`
	ControlIDs  ControlIDs `json:"control_ids"`
	DaysSaved   int        `json:"days_saved"`
}

// ControlIDs is a domain collection of control IDs with domain query methods.
type ControlIDs []kernel.ControlID

// Len returns the number of control IDs in the collection.
func (ids ControlIDs) Len() int {
	return len(ids)
}

// Contains returns true if target control ID is in the list.
func (ids ControlIDs) Contains(target kernel.ControlID) bool {
	return slices.Contains(ids, target)
}

// Accelerators is a domain collection of Accelerator items with querying methods.
type Accelerators []Accelerator

// Len returns the number of accelerators in the collection.
func (as Accelerators) Len() int {
	return len(as)
}

// TotalDaysSaved returns the aggregate days saved across all accelerators.
func (as Accelerators) TotalDaysSaved() int {
	total := 0
	for i := range as {
		total += as[i].DaysSaved
	}
	return total
}

// Input configures the prediction.
type Input struct {
	Assessments     []*report.Assessment
	Profile         policy.ComplianceFramework
	TargetReadiness ReadinessPercentage
	Window          time.Duration
	EvalTime        time.Time
}

// Predict computes the readiness timeline.
func Predict(in Input) *Prediction {
	valid := make([]*report.Assessment, 0, len(in.Assessments))
	for _, a := range in.Assessments {
		if a != nil {
			valid = append(valid, a)
		}
	}
	if len(valid) == 0 {
		return &Prediction{
			Profile:         in.Profile,
			TargetReadiness: in.TargetReadiness,
		}
	}

	sorted := make([]*report.Assessment, len(valid))
	copy(sorted, valid)
	slices.SortFunc(sorted, func(a, b *report.Assessment) int {
		return a.Run.EvalTime.Compare(b.Run.EvalTime)
	})

	latest := sorted[len(sorted)-1]

	// Compute per-severity MTTR from history.
	mttr := computeMTTR(sorted, in.Window, in.EvalTime)

	// Count failing controls.
	totalFindings := len(latest.Findings)
	if totalFindings == 0 {
		return &Prediction{
			Profile:          in.Profile,
			TargetReadiness:  in.TargetReadiness,
			CurrentReadiness: 100,
			ProjectedDate:    in.EvalTime,
			OptimisticDate:   in.EvalTime,
			PessimisticDate:  in.EvalTime,
		}
	}

	totalControls := max(latest.Summary.TotalAssets, 1)
	currentReadiness := ReadinessPercentage((1.0 - float64(latest.Summary.Violations)/float64(totalControls)) * 100).Clamp()
	gap := currentReadiness.GapTo(in.TargetReadiness)
	if gap <= 0 {
		return &Prediction{
			Profile:          in.Profile,
			TargetReadiness:  in.TargetReadiness,
			CurrentReadiness: currentReadiness,
			ProjectedDate:    in.EvalTime,
			OptimisticDate:   in.EvalTime,
			PessimisticDate:  in.EvalTime,
		}
	}

	// Estimate days to close gap based on MTTR.
	avgMTTRDays := weightedMTTR(latest.Findings, mttr)
	controlsToFix := min(int(math.Ceil(float64(totalFindings)*gap/100)), totalFindings)
	projectedDays := int(float64(controlsToFix) * avgMTTRDays)

	projected := in.EvalTime.AddDate(0, 0, projectedDays)
	optimistic := in.EvalTime.AddDate(0, 0, int(float64(projectedDays)*0.6))
	pessimistic := in.EvalTime.AddDate(0, 0, int(float64(projectedDays)*1.4))

	// Acceleration: top critical findings.
	var accelerators []Accelerator
	criticals := findBySeverity(latest.Findings, policy.SeverityCritical)
	if len(criticals) > 0 {
		limit := min(len(criticals), 4)
		ids := make([]kernel.ControlID, limit)
		for i := range limit {
			ids[i] = criticals[i].ControlID
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
		CurrentReadiness: ReadinessPercentage(math.Round(currentReadiness.Value()*10) / 10),
		ProjectedDate:    projected,
		OptimisticDate:   optimistic,
		PessimisticDate:  pessimistic,
		Accelerators:     accelerators,
	}
}

func computeMTTR(sorted []*report.Assessment, lookback time.Duration, now time.Time) map[policy.Severity]float64 {
	var cutoff time.Time
	if lookback > 0 {
		cutoff = now.Add(-lookback)
	}
	type fkey struct {
		ctl     kernel.ControlID
		ast     asset.ID
		astType kernel.AssetType
	}
	type mttrWindow struct {
		sev     policy.Severity
		openAt  time.Time
		closeAt time.Time
	}

	open := make(map[fkey]*mttrWindow)
	var closed []mttrWindow

	for _, a := range sorted {
		currentKeys := make(map[fkey]struct{}, len(a.Findings))
		for i := range a.Findings {
			k := fkey{a.Findings[i].ControlID, a.Findings[i].AssetID, a.Findings[i].AssetType}
			currentKeys[k] = struct{}{}
			if _, exists := open[k]; !exists {
				open[k] = &mttrWindow{
					sev:    a.Findings[i].ControlSeverity,
					openAt: a.Run.EvalTime,
				}
			}
		}
		for k, w := range open {
			if _, ok := currentKeys[k]; !ok {
				w.closeAt = a.Run.EvalTime
				if cutoff.IsZero() || !w.closeAt.Before(cutoff) {
					closed = append(closed, *w)
				}
				delete(open, k)
			}
		}
	}

	// Aggregate by severity.
	type agg struct {
		totalDays float64
		count     int
	}
	bySeV := make(map[policy.Severity]*agg)
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

	result := make(map[policy.Severity]float64, len(bySeV))
	for sev, a := range bySeV {
		if a.count > 0 {
			result[sev] = a.totalDays / float64(a.count)
		}
	}
	return result
}

func weightedMTTR(findings []remediation.Finding, mttr map[policy.Severity]float64) float64 {
	if len(findings) == 0 {
		return 14 // default 14 days
	}
	total := 0.0
	for i := range findings {
		if days, ok := mttr[findings[i].ControlSeverity]; ok {
			total += days
		} else {
			total += 14
		}
	}
	return total / float64(len(findings))
}

func findBySeverity(findings []remediation.Finding, sev policy.Severity) []remediation.Finding {
	var result []remediation.Finding
	for i := range findings {
		if findings[i].ControlSeverity == sev {
			result = append(result, findings[i])
		}
	}
	return result
}
