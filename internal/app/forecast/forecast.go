// Package forecast provides linear trend extrapolation for posture
// score and SLA projections.
package forecast

import (
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// Result holds forecast output.
type Result struct {
	Current   CurrentState    `json:"current"`
	Projected ProjectedState  `json:"projected"`
	SLAProj   []SLAProjection `json:"sla_projections,omitempty"`
	ModelNote string          `json:"model_note"`
}

// CurrentState holds current metrics.
type CurrentState struct {
	PostureScore float64 `json:"posture_score"`
	OpenFindings int     `json:"open_findings"`
	MTTRCritical float64 `json:"mttr_critical_hours"`
	MTTRHigh     float64 `json:"mttr_high_hours"`
}

// ProjectedState holds projected metrics.
type ProjectedState struct {
	HorizonDays  int     `json:"horizon_days"`
	PostureScore float64 `json:"posture_score"`
	ScoreSlope   float64 `json:"score_slope_per_day"`
}

// SLAStatus classifies the SLA projection status.
type SLAStatus string

// SLAProjection status vocabulary. Centralised here so producers
// (Compute) and consumers (cmd/trend/forecast renderer) cannot drift
// on the literal strings — adding a new tier or renaming one is
// one edit.
const (
	StatusOnTrack   SLAStatus = "ON_TRACK"
	StatusAtRisk    SLAStatus = "AT_RISK"
	StatusBreaching SLAStatus = "BREACHING"
)

// SLAProjection holds SLA forecast per severity.
type SLAProjection struct {
	Severity      policy.Severity `json:"severity"`
	CurrentMTTR   float64         `json:"current_mttr_hours"`
	ProjectedMTTR float64         `json:"projected_mttr_hours"`
	Deadline      float64         `json:"sla_deadline_hours"`
	Status        SLAStatus       `json:"status"` // see Status* constants above
}

// IsOnTrack reports whether the projection has the SLA-met status.
func (s *SLAProjection) IsOnTrack() bool {
	return s != nil && s.Status == StatusOnTrack
}

// IsAtRisk reports whether the projection is approaching the SLA
// deadline based on the MTTR trajectory.
func (s *SLAProjection) IsAtRisk() bool {
	return s != nil && s.Status == StatusAtRisk
}

// IsBreaching reports whether the projection has already crossed
// the SLA deadline at the current MTTR trajectory.
func (s *SLAProjection) IsBreaching() bool {
	return s != nil && s.Status == StatusBreaching
}

// StatusMarker returns the unicode glyph the trend renderer uses to
// flag this projection's state. Centralises the icon-selection
// branch so cmd/trend/forecast.go stops switching on s.Status
// directly. nil receiver returns the empty string.
func (s *SLAProjection) StatusMarker() string {
	if s == nil {
		return ""
	}
	switch s.Status {
	case StatusBreaching:
		return "✗"
	case StatusAtRisk:
		return "⚠"
	case StatusOnTrack:
		return "✓"
	default:
		return ""
	}
}

// Input holds data for forecasting.
type Input struct {
	ScoreHistory []float64 // one per day
	HorizonDays  int
	SLADeadlines map[string]float64   // severity → hours
	MTTRHistory  map[string][]float64 // severity → MTTR per day
}

// Compute produces a linear forecast.
func Compute(input Input) (*Result, error) {
	if input.HorizonDays < 0 {
		return nil, fmt.Errorf("invalid horizon: %d days (must be non-negative)", input.HorizonDays)
	}
	if len(input.ScoreHistory) < 7 {
		return nil, fmt.Errorf("insufficient history: %d days (minimum 7 required)", len(input.ScoreHistory))
	}

	// Linear regression on score history.
	n := len(input.ScoreHistory)
	slope, intercept := linearFit(input.ScoreHistory)
	currentScore := input.ScoreHistory[n-1]
	projectedScore := intercept + slope*float64(n+input.HorizonDays-1)

	// Clamp to 0-100.
	if projectedScore > 100 {
		projectedScore = 100
	}
	if projectedScore < 0 {
		projectedScore = 0
	}

	result := &Result{
		Current: CurrentState{
			PostureScore: currentScore,
		},
		Projected: ProjectedState{
			HorizonDays:  input.HorizonDays,
			PostureScore: projectedScore,
			ScoreSlope:   slope,
		},
		ModelNote: fmt.Sprintf("Linear projection from %d days of history. Accuracy decreases beyond 30-day horizon. Rerun weekly for updated projections.", n),
	}

	// SLA projections per severity.
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		history := input.MTTRHistory[sev]
		deadline := input.SLADeadlines[sev]
		if len(history) < 3 || deadline <= 0 {
			continue
		}
		mttrSlope, mttrIntercept := linearFit(history)
		currentMTTR := history[len(history)-1]
		projectedMTTR := mttrIntercept + mttrSlope*float64(len(history)+input.HorizonDays-1)
		if projectedMTTR < 0 {
			projectedMTTR = 0
		}

		status := StatusOnTrack
		if projectedMTTR > deadline {
			status = StatusBreaching
		} else if projectedMTTR > deadline*0.8 {
			status = StatusAtRisk
		}

		sevVal, _ := policy.ParseSeverity(sev)

		result.SLAProj = append(result.SLAProj, SLAProjection{
			Severity:      sevVal,
			CurrentMTTR:   currentMTTR,
			ProjectedMTTR: projectedMTTR,
			Deadline:      deadline,
			Status:        status,
		})
	}

	return result, nil
}

// linearFit computes y = a + b*t using least squares.
func linearFit(ys []float64) (slope, intercept float64) {
	n := float64(len(ys))
	if n <= 1 {
		if len(ys) == 1 {
			return 0, ys[0]
		}
		return 0, 0
	}
	var sumX, sumY, sumXY, sumX2 float64
	for i, y := range ys {
		x := float64(i)
		sumX += x
		sumY += y
		sumXY += x * y
		sumX2 += x * x
	}
	denom := n*sumX2 - sumX*sumX
	if denom == 0 {
		return 0, sumY / n
	}
	slope = (n*sumXY - sumX*sumY) / denom
	intercept = (sumY - slope*sumX) / n
	return slope, intercept
}
