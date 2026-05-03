// Package catalogquality analyzes control catalog metadata completeness
// and identifies blind spots in asset coverage and MITRE stage coverage.
package catalogquality

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// FieldStat tracks presence/absence counts for a single metadata field.
type FieldStat struct {
	Present int `json:"present"`
	Missing int `json:"missing"`
}

// BlindSpot identifies an asset type with observed resources but zero controls.
type BlindSpot struct {
	AssetType  string `json:"asset_type"`
	AssetCount int    `json:"asset_count"`
}

// Report summarizes catalog quality across all controls.
type Report struct {
	TotalControls int                  `json:"total_controls"`
	Completeness  map[string]FieldStat `json:"completeness"`
	OverallPct    float64              `json:"overall_pct"`
	BlindSpots    []BlindSpot          `json:"blind_spots"`
	MITREGaps     []string             `json:"mitre_gaps"`
}

// Input configures the quality analysis.
type Input struct {
	Controls   []policy.ControlDefinition
	AssetTypes map[kernel.AssetType]int // observed asset types with counts
}

// Analyze evaluates catalog metadata completeness and coverage gaps.
func Analyze(input Input) Report {
	total := len(input.Controls)
	completeness := map[string]FieldStat{
		"severity":           {},
		"remediation.action": {},
		"attack_stage":       {},
		"compliance":         {},
	}

	coveredTypes := make(map[kernel.AssetType]bool)
	stagesSeen := make(map[kernel.AttackStage]bool)

	for i := range input.Controls {
		ctl := &input.Controls[i]

		// severity
		if ctl.Severity.IsValid() {
			inc(&completeness, "severity", true)
		} else {
			inc(&completeness, "severity", false)
		}

		// remediation.action
		if ctl.Remediation.HasAction() {
			inc(&completeness, "remediation.action", true)
		} else {
			inc(&completeness, "remediation.action", false)
		}

		// attack_stage
		stage := ctl.AttackStage()
		if stage != "" {
			inc(&completeness, "attack_stage", true)
			stagesSeen[stage] = true
		} else {
			inc(&completeness, "attack_stage", false)
		}

		// compliance
		if len(ctl.Compliance) > 0 {
			inc(&completeness, "compliance", true)
		} else {
			inc(&completeness, "compliance", false)
		}

		// Track covered asset domains.
		if ctl.Domain != "" {
			coveredTypes[kernel.AssetType(ctl.Domain)] = true
		}
	}

	// Compute overall percentage.
	overallPct := 0.0
	if total > 0 {
		totalFields := 0
		presentFields := 0
		for _, fs := range completeness {
			totalFields += fs.Present + fs.Missing
			presentFields += fs.Present
		}
		if totalFields > 0 {
			overallPct = float64(presentFields) / float64(totalFields) * 100
		}
	}

	// Identify blind spots: asset types with resources but no controls.
	var blindSpots []BlindSpot
	for at, count := range input.AssetTypes {
		if !coveredTypes[at] {
			blindSpots = append(blindSpots, BlindSpot{
				AssetType:  string(at),
				AssetCount: count,
			})
		}
	}

	// MITRE stage gaps.
	allStages := []kernel.AttackStage{
		"initial_access", "credential_access", "persistence",
		"exfiltration", "detection_evasion", "resilience",
	}
	var mitreGaps []string
	for _, stage := range allStages {
		if !stagesSeen[stage] {
			mitreGaps = append(mitreGaps, string(stage))
		}
	}

	return Report{
		TotalControls: total,
		Completeness:  completeness,
		OverallPct:    overallPct,
		BlindSpots:    blindSpots,
		MITREGaps:     mitreGaps,
	}
}

func inc(m *map[string]FieldStat, key string, present bool) {
	fs := (*m)[key]
	if present {
		fs.Present++
	} else {
		fs.Missing++
	}
	(*m)[key] = fs
}
