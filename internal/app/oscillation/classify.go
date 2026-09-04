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

// Classification describes the oscillation pattern for a control-asset pair.
type Classification struct {
	ControlID   kernel.ControlID `json:"control_id"`
	AssetID     asset.ID         `json:"asset_id"`
	Pattern     Pattern          `json:"pattern"`
	Confidence  float64          `json:"confidence"`
	FailureRate float64          `json:"failure_rate"`
	Cycles      int              `json:"cycles"`
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

	failureRate := 0.0
	if totalAssessments > 0 {
		failureRate = float64(failCount) / float64(totalAssessments)
	}

	pattern := PatternRandom
	confidence := 0.5

	switch {
	case failureRate > 0.8:
		pattern = PatternChronic
		confidence = failureRate
	case cycles >= minOsc:
		pattern = PatternDeployTime
		confidence = float64(cycles) / float64(totalAssessments)
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
