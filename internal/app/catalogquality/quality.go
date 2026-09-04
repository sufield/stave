// Package catalogquality analyzes control catalog metadata completeness
// and identifies blind spots in asset coverage and MITRE stage coverage.
package catalogquality

import (
	"cmp"
	"slices"

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
	AssetType  kernel.AssetType `json:"asset_type"`
	AssetCount int              `json:"asset_count"`
}

// MetadataField identifies a control metadata field for completeness analysis.
type MetadataField string

const (
	FieldSeverity          MetadataField = "severity"
	FieldRemediationAction MetadataField = "remediation.action"
	FieldAttackStage       MetadataField = "attack_stage"
	FieldCompliance        MetadataField = "compliance"
)

// Report summarizes catalog quality across all controls.
type Report struct {
	TotalControls int                        `json:"total_controls"`
	Completeness  map[MetadataField]FieldStat `json:"completeness"`
	OverallPct    float64                    `json:"overall_pct"`
	BlindSpots    []BlindSpot                `json:"blind_spots"`
	MITREGaps     []kernel.AttackStage       `json:"mitre_gaps"`
}

// Input configures the quality analysis.
type Input struct {
	Controls   []policy.ControlDefinition
	AssetTypes map[kernel.AssetType]int // observed asset types with counts
}

// Analyze evaluates catalog metadata completeness and coverage gaps.
func Analyze(input Input) Report {
	total := len(input.Controls)
	completeness := map[MetadataField]FieldStat{
		FieldSeverity:          {},
		FieldRemediationAction: {},
		FieldAttackStage:       {},
		FieldCompliance:        {},
	}

	coveredTypes := make(map[kernel.AssetType]struct{})
	stagesSeen := make(map[kernel.AttackStage]struct{})

	for i := range input.Controls {
		ctl := &input.Controls[i]

		// severity
		if ctl.Severity.IsValid() {
			inc(completeness, FieldSeverity, true)
		} else {
			inc(completeness, FieldSeverity, false)
		}

		// remediation.action
		if ctl.Remediation.HasAction() {
			inc(completeness, FieldRemediationAction, true)
		} else {
			inc(completeness, FieldRemediationAction, false)
		}

		// attack_stage
		stage := ctl.AttackStage()
		if stage != "" {
			inc(completeness, FieldAttackStage, true)
			stagesSeen[stage] = struct{}{}
		} else {
			inc(completeness, FieldAttackStage, false)
		}

		// compliance
		if len(ctl.Compliance) > 0 {
			inc(completeness, FieldCompliance, true)
		} else {
			inc(completeness, FieldCompliance, false)
		}

		// Track covered asset domains.
		if ctl.Domain != "" {
			coveredTypes[kernel.AssetType(ctl.Domain)] = struct{}{}
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
		if _, isCovered := coveredTypes[at]; !isCovered {
			blindSpots = append(blindSpots, BlindSpot{
				AssetType:  at,
				AssetCount: count,
			})
		}
	}
	slices.SortFunc(blindSpots, func(a, b BlindSpot) int {
		return cmp.Compare(a.AssetType, b.AssetType)
	})

	// MITRE stage gaps.
	allStages := []kernel.AttackStage{
		"initial_access", "credential_access", "persistence",
		"exfiltration", "detection_evasion", "resilience",
	}
	var mitreGaps []kernel.AttackStage
	for _, stage := range allStages {
		if _, isSeen := stagesSeen[stage]; !isSeen {
			mitreGaps = append(mitreGaps, stage)
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

func inc(m map[MetadataField]FieldStat, key MetadataField, present bool) {
	fs := m[key]
	if present {
		fs.Present++
	} else {
		fs.Missing++
	}
	m[key] = fs
}
