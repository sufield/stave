package dto

import (
	"github.com/sufield/stave/internal/core/findings"
)

// fromCompoundFindings projects core chain findings into wire DTOs.
// Returns nil for an empty input to keep `omitempty` JSON shape.
func fromCompoundFindings(in []findings.CompoundFinding) []ChainFindingDTO {
	if len(in) == 0 {
		return nil
	}
	out := make([]ChainFindingDTO, len(in))
	for i, c := range in {
		out[i] = fromCompoundFinding(c)
	}
	return out
}

// fromCompoundFinding projects one core chain finding into the DTO.
// The Severity field is rendered via SeverityLabel() so consumers
// don't depend on policy.Severity's enum representation.
func fromCompoundFinding(c findings.CompoundFinding) ChainFindingDTO {
	return ChainFindingDTO{
		ChainID:            c.ChainID,
		AssetID:            c.AssetID,
		ScopeID:            c.ScopeID,
		ScopeField:         c.ScopeField,
		ContributingAssets: c.ContributingAssets,
		Description:        c.Description,
		ControlsFailing:    c.ControlsFailing,
		MissingSafeguards:  c.MissingSafeguards,
		CompoundScore:      c.CompoundScore,
		Severity:           c.SeverityLabel(),
		Narrative:          c.Narrative,
		AttackStages:       c.AttackStages,
	}
}

// fromExposureRanks projects core exposure ranks into wire DTOs.
func fromExposureRanks(in []findings.ExposureRank) []ExposureRankDTO {
	if len(in) == 0 {
		return nil
	}
	out := make([]ExposureRankDTO, len(in))
	for i, r := range in {
		out[i] = fromExposureRank(r)
	}
	return out
}

// fromExposureRank projects one core exposure rank into the DTO.
func fromExposureRank(r findings.ExposureRank) ExposureRankDTO {
	return ExposureRankDTO{
		FindingIndex:  r.FindingIndex,
		ControlID:     r.ControlID,
		AssetID:       r.AssetID,
		ExposureScore: r.ExposureScore,
		Breakdown:     fromScoreBreakdown(r.Breakdown),
		SilentKiller:  r.SilentKiller,
	}
}

func fromScoreBreakdown(b findings.ScoreBreakdown) ScoreBreakdownDTO {
	return ScoreBreakdownDTO{
		BaseScore:          b.BaseScore,
		DurationFactor:     b.DurationFactor,
		BlastMultiplier:    b.BlastMultiplier,
		ExposureMultiplier: b.ExposureMultiplier,
		ChainBonus:         b.ChainBonus,
		BlindMultiplier:    b.BlindMultiplier,
		DaysBlind:          b.DaysBlind,
	}
}
