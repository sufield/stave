// Package oscillation classifies control violation oscillation patterns
// across assessment history: deploy-time, random, chronic, or seasonal.
package oscillation

import (
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// Pattern classifies violation behavior over time.
type Pattern string

const (
	PatternDeployTime Pattern = "deploy-time"
	PatternRandom     Pattern = "random"
	PatternChronic    Pattern = "chronic"
	PatternSeasonal   Pattern = "seasonal"
)

// FailureRate represents the ratio of failing assessments over total assessments evaluated (0.0 to 1.0).
type FailureRate float64

// Value returns the raw float64 ratio value (between 0.0 and 1.0).
func (fr FailureRate) Value() float64 {
	return float64(fr)
}

// IsChronic reports whether the failure rate exceeds the chronic threshold (80%).
func (fr FailureRate) IsChronic() bool {
	return fr > 0.8
}

// IsViolationFree reports whether there were zero observed failures.
func (fr FailureRate) IsViolationFree() bool {
	return fr == 0.0
}

// AlwaysPasses reports whether all observed evaluations passed (0.0 failure rate).
func (fr FailureRate) AlwaysPasses() bool {
	return fr == 0.0
}

// ConfidenceScore represents statistical confidence score in [0.0, 1.0].
type ConfidenceScore float64

// Value returns the raw float64 value.
func (c ConfidenceScore) Value() float64 { return float64(c) }

// Float64 returns the raw float64 value.
func (c ConfidenceScore) Float64() float64 { return float64(c) }

// IsHigh reports whether the confidence score meets or exceeds the given threshold.
func (c ConfidenceScore) IsHigh(threshold ConfidenceScore) bool {
	return c >= threshold
}

// Classification describes the oscillation pattern for a control-asset pair.
type Classification struct {
	ControlID   kernel.ControlID `json:"control_id"`
	AssetID     asset.ID         `json:"asset_id"`
	Pattern     Pattern          `json:"pattern"`
	Confidence  ConfidenceScore  `json:"confidence"`
	FailureRate FailureRate      `json:"failure_rate"`
	Cycles      int              `json:"cycles"`
}

// Classifications is a domain collection of Classification items with domain methods.
type Classifications []Classification

// Len returns the number of classifications in the collection.
func (cs Classifications) Len() int {
	return len(cs)
}

// IsEmpty reports whether the collection contains no classifications.
func (cs Classifications) IsEmpty() bool {
	return len(cs) == 0
}

// HasClassifications reports whether the collection contains at least one classification.
func (cs Classifications) HasClassifications() bool {
	return len(cs) > 0
}

// Input configures the oscillation classifier.
type Input struct {
	Assessments     []report.Assessment
	ControlID       kernel.ControlID
	AssetID         asset.ID
	AssetType       kernel.AssetType
	MinOscillations int // minimum state transitions to classify as deploy-time
}

// Classify analyzes a control-asset pair across assessment history
// and returns an oscillation pattern classification.
//
// Algorithm:
//   - Count appearances (failing) / absences (passing) across assessments
//   - If failure rate > 80%: chronic
//   - If cycles >= minOscillations: deploy-time
//   - Otherwise: random
func Classify(input Input) Classification {
	if len(input.Assessments) == 0 {
		return Classification{
			ControlID: input.ControlID,
			AssetID:   input.AssetID,
			Pattern:   PatternRandom,
		}
	}

	minOsc := input.MinOscillations
	if minOsc <= 0 {
		minOsc = 2
	}

	// Copy & sort assessments chronologically.
	assessments := make([]report.Assessment, len(input.Assessments))
	copy(assessments, input.Assessments)
	slices.SortFunc(assessments, func(a, b report.Assessment) int {
		return a.Run.EvalTime.Compare(b.Run.EvalTime)
	})

	totalAssessments := len(assessments)
	failCount := 0
	cycles := 0
	var prevFailing *bool

	for i := range assessments {
		a := &assessments[i]
		failing := hasFinding(a, input.ControlID, input.AssetID, input.AssetType)

		if failing {
			failCount++
		}

		// Count state transitions (pass->fail or fail->pass).
		if prevFailing != nil && *prevFailing != failing {
			cycles++
		}
		prevFailing = &failing
	}

	failureRate := FailureRate(0.0)
	if totalAssessments > 0 {
		failureRate = FailureRate(float64(failCount) / float64(totalAssessments))
	}

	pattern := PatternRandom
	confidence := ConfidenceScore(0.5)

	switch {
	case failureRate.IsChronic():
		pattern = PatternChronic
		confidence = ConfidenceScore(failureRate.Value())
	case cycles >= minOsc:
		pattern = PatternDeployTime
		confidence = ConfidenceScore(float64(cycles) / float64(totalAssessments))
		if confidence > 1 {
			confidence = 1
		}
	}

	return Classification{
		ControlID:   input.ControlID,
		AssetID:     input.AssetID,
		Pattern:     pattern,
		Confidence:  confidence,
		FailureRate: failureRate,
		Cycles:      cycles,
	}
}

// hasFinding checks if an assessment contains a finding for the given control, asset, and asset type.
func hasFinding(a *report.Assessment, ctlID kernel.ControlID, astID asset.ID, astType kernel.AssetType) bool {
	for i := range a.Findings {
		f := &a.Findings[i]
		if f.ControlID == ctlID && f.AssetID == astID {
			if astType == "" || f.AssetType == astType {
				return true
			}
		}
	}
	return false
}
