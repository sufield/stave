package dto

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

type findingKey struct {
	controlID kernel.ControlID
	assetID   asset.ID
}

// fromCompoundFindings projects core chain findings into wire DTOs,
// enriching each with member evidence resolved from atomic findings.
func fromCompoundFindings(in []findings.CompoundFinding, atomics []remediation.Finding) []ChainFindingDTO {
	if len(in) == 0 {
		return nil
	}

	idx := make(map[findingKey]*remediation.Finding, len(atomics))
	for i := range atomics {
		idx[findingKey{atomics[i].ControlID, atomics[i].AssetID}] = &atomics[i]
	}

	out := make([]ChainFindingDTO, len(in))
	for i := range in {
		out[i] = fromCompoundFinding(&in[i], idx)
	}
	return out
}

func fromCompoundFinding(c *findings.CompoundFinding, idx map[findingKey]*remediation.Finding) ChainFindingDTO {
	dto := ChainFindingDTO{
		FindingID:          c.FindingID,
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

	assets := c.ContributingAssets
	if len(assets) == 0 && c.AssetID != "" {
		assets = []asset.ID{c.AssetID}
	}

	for _, ctrlID := range c.ControlsFailing {
		for _, astID := range assets {
			f, ok := idx[findingKey{ctrlID, astID}]
			if !ok {
				continue
			}
			me := ChainMemberEvidenceDTO{
				ControlID:         ctrlID,
				AssetID:           astID,
				Misconfigurations: f.Evidence.Misconfigurations,
			}
			if f.HasReasoningTrace() {
				me.ReasoningTrace = make([]MatchedClauseDTO, len(f.ReasoningTrace))
				for j, mc := range f.ReasoningTrace {
					me.ReasoningTrace[j] = MatchedClauseDTO{
						PredicateExpr:  mc.PredicateExpr,
						ObservationKey: mc.ObservationKey.String(),
						Operator:       string(mc.Operator),
						ExpectedValue:  mc.ExpectedValue,
						ObservedValue:  mc.ObservedValue,
					}
				}
			}
			me.Delta = fromDeltaPaths(f.Delta)
			dto.MemberEvidence = append(dto.MemberEvidence, me)
		}
	}

	return dto
}

func fromNearMissChains(in []findings.NearMissChain) []NearMissChainDTO {
	if len(in) == 0 {
		return nil
	}
	out := make([]NearMissChainDTO, len(in))
	for i := range in {
		out[i] = NearMissChainDTO{
			ChainID:         in[i].ChainID,
			Description:     in[i].Description,
			ControlsFailing: in[i].ControlsFailing,
			MissingControl:  in[i].MissingControl,
			Severity:        in[i].Severity.String(),
			ScopeID:         in[i].ScopeID,
		}
	}
	return out
}

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
