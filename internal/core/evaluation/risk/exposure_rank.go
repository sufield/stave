package risk

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ExposureRank captures a finding's priority score with full factor
// breakdown for traceability. The breakdown lets operators understand
// WHY a finding ranks where it does — not just that it does.
type ExposureRank struct {
	FindingIndex  int              `json:"finding_index"`
	ControlID     kernel.ControlID `json:"control_id"`
	AssetID       asset.ID         `json:"asset_id"`
	ExposureScore float64          `json:"exposure_score"`
	Breakdown     ScoreBreakdown   `json:"breakdown"`
	SilentKiller  bool             `json:"silent_killer"`
}

// ScoreBreakdown provides the traceable factor decomposition.
type ScoreBreakdown struct {
	BaseScore          int     `json:"base_score"`
	DurationFactor     float64 `json:"duration_factor"`
	BlastMultiplier    float64 `json:"blast_multiplier"`
	ExposureMultiplier float64 `json:"exposure_multiplier"`
	ChainBonus         float64 `json:"chain_bonus"`
	DaysBlind          float64 `json:"days_blind"`
}

// RankInput carries the data needed to score one finding without
// importing the evaluation package (which already imports risk).
type RankInput struct {
	ControlID            kernel.ControlID
	AssetID              asset.ID
	ControlSeverity      policy.Severity
	Exposure             *policy.Exposure
	UnsafeDurationHours  float64
	ChainMembershipCount int
}

// ChainBonus returns the multiplicative boost applied to a finding
// based on how many fired chains it participates in. Defaults per
// docs/product/metrics.md § Metric 1: 1.0× for non-members,
// 1.5× for a single chain, 2.0× for two or more.
func ChainBonus(chainCount int) float64 {
	switch {
	case chainCount >= 2:
		return 2.0
	case chainCount == 1:
		return 1.5
	default:
		return 1.0
	}
}

// silentKillerDaysThreshold is the minimum days blind to flag a
// finding as a silent killer.
const silentKillerDaysThreshold = 300

// DurationFactor returns a stepped multiplier based on how long the
// finding has been unsafe. Stepped (not continuous) for traceability
// — users can look at the bracket and understand why their score
// changed.
func DurationFactor(unsafeHours float64) float64 {
	days := unsafeHours / 24.0
	switch {
	case days >= 1643: // 4.5 years — the "silent killer" threshold
		return 5.0
	case days >= 365: // 1+ year
		return 3.0
	case days >= 90: // 3+ months
		return 2.0
	case days >= 30: // 1+ month
		return 1.5
	default:
		return 1.0
	}
}

// SeverityToWeight maps a severity level to a base score for controls
// that do not define base_impact in their params.
func SeverityToWeight(sev policy.Severity) int {
	switch sev {
	case policy.SeverityCritical:
		return 100
	case policy.SeverityHigh:
		return 75
	case policy.SeverityMedium:
		return 50
	case policy.SeverityLow:
		return 25
	default:
		return 10
	}
}

// exposureMultiplier derives the exposure vector multiplier from the
// finding's exposure metadata.
func exposureMultiplier(exp *policy.Exposure) float64 {
	if exp == nil {
		return 1.0
	}
	if exp.IsPublic() {
		return LookupExposure("public_internet")
	}
	return 1.0
}

// RankExposures computes exposure scores for all findings and returns
// them ranked by score descending. The ranking is deterministic: ties
// are broken by ControlID then AssetID (lexicographic).
//
// controlLookup provides access to base_impact and blast_radius from
// the control definitions. topN <= 0 returns all findings ranked.
func RankExposures(
	inputs []RankInput,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
	topN int,
) []ExposureRank {
	if len(inputs) == 0 {
		return nil
	}

	ranks := make([]ExposureRank, 0, len(inputs))
	for i := range inputs {
		f := &inputs[i]

		base := SeverityToWeight(f.ControlSeverity)
		blast := 1.0
		if controlLookup != nil {
			if ctl, ok := controlLookup[f.ControlID]; ok {
				if bi := ctl.BaseImpact(); bi > 0 {
					base = bi
				}
				if bm := ctl.BlastMultiplier(); bm > 0 {
					blast = bm
				}
			}
		}

		daysBlind := f.UnsafeDurationHours / 24.0
		durFactor := DurationFactor(f.UnsafeDurationHours)
		expMult := exposureMultiplier(f.Exposure)
		chainBonus := ChainBonus(f.ChainMembershipCount)

		score := float64(base) * durFactor * blast * expMult * chainBonus

		ranks = append(ranks, ExposureRank{
			FindingIndex:  i,
			ControlID:     f.ControlID,
			AssetID:       f.AssetID,
			ExposureScore: score,
			SilentKiller:  daysBlind > silentKillerDaysThreshold,
			Breakdown: ScoreBreakdown{
				BaseScore:          base,
				DurationFactor:     durFactor,
				BlastMultiplier:    blast,
				ExposureMultiplier: expMult,
				ChainBonus:         chainBonus,
				DaysBlind:          daysBlind,
			},
		})
	}

	slices.SortFunc(ranks, func(a, b ExposureRank) int {
		// Descending by score.
		if c := cmp.Compare(b.ExposureScore, a.ExposureScore); c != 0 {
			return c
		}
		// Tie-break: ascending by ControlID then AssetID.
		if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
			return c
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})

	if topN > 0 && topN < len(ranks) {
		ranks = ranks[:topN]
	}
	return ranks
}
