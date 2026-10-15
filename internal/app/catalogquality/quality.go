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

// Total returns the total number of controls evaluated for this field.
func (fs FieldStat) Total() int {
	return fs.Present + fs.Missing
}

// Percentage returns the percentage of controls where this field is present (0.0 to 100.0).
func (fs FieldStat) Percentage() float64 {
	total := fs.Total()
	if total == 0 {
		return 0.0
	}
	return float64(fs.Present) / float64(total) * 100.0
}

// IsComplete returns true if all evaluated controls have this field present (and at least one control was evaluated).
func (fs FieldStat) IsComplete() bool {
	return fs.Present > 0 && fs.Missing == 0
}

// HasMissing returns true if any evaluated controls are missing this field.
func (fs FieldStat) HasMissing() bool {
	return fs.Missing > 0
}

// FieldCompleteness maps metadata fields to their presence/absence statistics.
type FieldCompleteness map[MetadataField]FieldStat

// ForField returns the FieldStat for a specific field, or a zero FieldStat if not present.
func (fc FieldCompleteness) ForField(f MetadataField) FieldStat {
	if fc == nil {
		return FieldStat{}
	}
	return fc[f]
}

// SortedFields returns all metadata fields present in the completeness map sorted alphabetically.
func (fc FieldCompleteness) SortedFields() []MetadataField {
	if len(fc) == 0 {
		return nil
	}
	fields := make([]MetadataField, 0, len(fc))
	for f := range fc {
		fields = append(fields, f)
	}
	slices.Sort(fields)
	return fields
}

// AllComplete returns true if every field tracked in the map is 100% complete (none missing).
func (fc FieldCompleteness) AllComplete() bool {
	if len(fc) == 0 {
		return false
	}
	for _, fs := range fc {
		if fs.HasMissing() || fs.Present == 0 {
			return false
		}
	}
	return true
}

// CompletenessPercentage calculates the overall metadata completeness percentage across all fields.
func (fc FieldCompleteness) CompletenessPercentage() QualityPercentage {
	if len(fc) == 0 {
		return QualityPercentage(0.0)
	}
	totalFields := 0
	presentFields := 0
	for _, fs := range fc {
		totalFields += fs.Total()
		presentFields += fs.Present
	}
	if totalFields == 0 {
		return QualityPercentage(0.0)
	}
	return QualityPercentage(float64(presentFields) / float64(totalFields) * 100.0)
}

// BlindSpot identifies an asset type with observed resources but zero controls.
type BlindSpot struct {
	AssetType  kernel.AssetType `json:"asset_type"`
	AssetCount int              `json:"asset_count"`
}

// BlindSpots is a domain collection of BlindSpot items with querying methods.
type BlindSpots []BlindSpot

// Len returns the number of blind spots in the collection.
func (bs BlindSpots) Len() int {
	return len(bs)
}

// ByAssetType returns the blind spot matching the given asset type, or nil if not found.
func (bs BlindSpots) ByAssetType(at kernel.AssetType) *BlindSpot {
	for i := range bs {
		if bs[i].AssetType == at {
			return &bs[i]
		}
	}
	return nil
}

// TotalUncoveredAssets returns the sum of asset counts across all blind spots.
func (bs BlindSpots) TotalUncoveredAssets() int {
	total := 0
	for i := range bs {
		total += bs[i].AssetCount
	}
	return total
}

// MetadataField identifies a control metadata field for completeness analysis.
type MetadataField string

const (
	FieldSeverity          MetadataField = "severity"
	FieldRemediationAction MetadataField = "remediation.action"
	FieldAttackStage       MetadataField = "attack_stage"
	FieldCompliance        MetadataField = "compliance"
)

// AttackStages is a domain collection of AttackStage items with querying methods.
type AttackStages []kernel.AttackStage

// Len returns the number of attack stages in the collection.
func (as AttackStages) Len() int {
	return len(as)
}

// Contains returns true if stage is present in the collection.
func (as AttackStages) Contains(stage kernel.AttackStage) bool {
	return slices.Contains(as, stage)
}

// QualityPercentage encapsulates a catalog metadata completeness percentage score (0.0 to 100.0).
type QualityPercentage float64

// Value returns the raw float64 percentage value.
func (qp QualityPercentage) Value() float64 {
	return float64(qp)
}

// IsHighQuality reports whether the completeness score meets or exceeds the standard catalog quality threshold (80%).
func (qp QualityPercentage) IsHighQuality() bool {
	return qp >= 80.0
}

// Gap returns the percentage gap required to reach 100% full catalog metadata completeness.
func (qp QualityPercentage) Gap() float64 {
	if qp >= 100.0 {
		return 0.0
	}
	return 100.0 - float64(qp)
}

// Report summarizes catalog quality across all controls.
type Report struct {
	TotalControls int               `json:"total_controls"`
	Completeness  FieldCompleteness `json:"completeness"`
	OverallPct    QualityPercentage `json:"overall_pct"`
	BlindSpots    BlindSpots        `json:"blind_spots"`
	MITREGaps     AttackStages      `json:"mitre_gaps"`
}

// Input configures the quality analysis.
type Input struct {
	Controls   []policy.ControlDefinition
	AssetTypes map[kernel.AssetType]int // observed asset types with counts
}

// Analyze evaluates catalog metadata completeness and coverage gaps.
func Analyze(input Input) Report {
	total := len(input.Controls)
	completeness := FieldCompleteness{
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

	// Compute overall percentage using domain collection method.
	overallPct := completeness.CompletenessPercentage()

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

func inc(m FieldCompleteness, key MetadataField, present bool) {
	fs := m[key]
	if present {
		fs.Present++
	} else {
		fs.Missing++
	}
	m[key] = fs
}
