// Package remediationimpact compares before/after assessments to
// measure actual remediation effectiveness, including chain
// deactivations and predicted-vs-realized score delta.
package remediationimpact

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

type findingKey struct {
	ControlID kernel.ControlID
	AssetID   asset.ID
}

// ClosedFinding is a finding present in before but absent in after.
type ClosedFinding struct {
	ControlID kernel.ControlID `json:"control_id"`
	AssetID   asset.ID         `json:"asset_id"`
	Severity  string           `json:"severity"`
	DwellDays float64          `json:"dwell_days,omitempty"`
}

// DeactivatedChain is a chain active in before but inactive in after.
type DeactivatedChain struct {
	ChainID          string `json:"chain_id"`
	PreviousSeverity string `json:"previous_severity"`
}

// EfficiencyVerdict classifies the remediation outcome.
type EfficiencyVerdict string

const (
	VerdictComplete   EfficiencyVerdict = "COMPLETE"
	VerdictPartial    EfficiencyVerdict = "PARTIAL"
	VerdictIncomplete EfficiencyVerdict = "INCOMPLETE"
)

// Efficiency holds the predicted-vs-realized comparison.
type Efficiency struct {
	PredictedDelta float64           `json:"predicted_delta"`
	RealizedDelta  float64           `json:"realized_delta"`
	Ratio          float64           `json:"efficiency_ratio"`
	Verdict        EfficiencyVerdict `json:"verdict"`
	StillOpen      []string          `json:"still_open,omitempty"`
}

// Report holds the remediation impact analysis.
type Report struct {
	BeforeFindings    int                `json:"before_findings"`
	AfterFindings     int                `json:"after_findings"`
	Closed            []ClosedFinding    `json:"findings_closed"`
	ChainsDeactivated []DeactivatedChain `json:"chains_deactivated,omitempty"`
	ScoreBefore       float64            `json:"score_before"`
	ScoreAfter        float64            `json:"score_after"`
	ScoreDelta        float64            `json:"score_delta"`
	Efficiency        *Efficiency        `json:"efficiency,omitempty"`
}

// Input configures the impact analysis.
type Input struct {
	Before          *report.Assessment
	After           *report.Assessment
	PredictedDelta  float64  // from stave simulate, 0 if not provided
	PredictedClosed []string // control IDs predicted to close
}

// Analyze compares before and after assessments.
func Analyze(in Input) *Report {
	beforeKeys := buildKeySet(in.Before.Findings)
	afterKeys := buildKeySet(in.After.Findings)

	// Find closed findings.
	var closed []ClosedFinding
	for k := range beforeKeys {
		if _, stillOpen := afterKeys[k]; !stillOpen {
			f := beforeKeys[k]
			closed = append(closed, ClosedFinding{
				ControlID: k.ControlID,
				AssetID:   k.AssetID,
				Severity:  f.SeverityLabel(),
				DwellDays: f.DwellDays(),
			})
		}
	}

	// Find deactivated chains. Project (ChainID, severity-label)
	// off the assessment without naming findings.CompoundFinding —
	// the only fields read are c.ChainID and c.Severity.String().
	// Iterates Before first to build the set, then deletes any
	// chain still active in After, matching the original semantics
	// of two-map set difference (with the same non-deterministic
	// output ordering the original carried).
	beforeSev := make(map[kernel.ChainID]string, len(in.Before.ChainFindings))
	for i := range in.Before.ChainFindings {
		c := &in.Before.ChainFindings[i]
		beforeSev[c.ChainID] = c.Severity.String()
	}
	for i := range in.After.ChainFindings {
		delete(beforeSev, in.After.ChainFindings[i].ChainID)
	}
	var deactivated []DeactivatedChain
	for id, sev := range beforeSev {
		deactivated = append(deactivated, DeactivatedChain{
			ChainID:          string(id),
			PreviousSeverity: sev,
		})
	}

	// Score delta.
	scoreBefore := computeSimpleScore(in.Before)
	scoreAfter := computeSimpleScore(in.After)

	r := &Report{
		BeforeFindings:    len(in.Before.Findings),
		AfterFindings:     len(in.After.Findings),
		Closed:            closed,
		ChainsDeactivated: deactivated,
		ScoreBefore:       scoreBefore,
		ScoreAfter:        scoreAfter,
		ScoreDelta:        scoreAfter - scoreBefore,
	}

	// Efficiency metric.
	if in.PredictedDelta != 0 {
		realized := scoreAfter - scoreBefore
		ratio := realized / in.PredictedDelta
		if ratio < 0 {
			ratio = 0
		}

		verdict := VerdictComplete
		if ratio < 0.5 {
			verdict = VerdictIncomplete
		} else if ratio < 0.9 {
			verdict = VerdictPartial
		}

		var stillOpen []string
		for _, ctlID := range in.PredictedClosed {
			k := findingKey{ControlID: kernel.ControlID(ctlID)}
			for ak := range afterKeys {
				if ak.ControlID == k.ControlID {
					stillOpen = append(stillOpen, ctlID)
					break
				}
			}
		}

		r.Efficiency = &Efficiency{
			PredictedDelta: in.PredictedDelta,
			RealizedDelta:  realized,
			Ratio:          ratio,
			Verdict:        verdict,
			StillOpen:      stillOpen,
		}
	}

	return r
}

func buildKeySet(findings []remediation.Finding) map[findingKey]*remediation.Finding {
	m := make(map[findingKey]*remediation.Finding, len(findings))
	for i := range findings {
		k := findingKey{ControlID: findings[i].ControlID, AssetID: findings[i].AssetID}
		m[k] = &findings[i]
	}
	return m
}

func computeSimpleScore(a *report.Assessment) float64 {
	if a.Summary.TotalAssets == 0 {
		return 100
	}
	rate := float64(a.Summary.Violations) / float64(a.Summary.TotalAssets)
	score := (1.0 - rate) * 100
	if score < 0 {
		return 0
	}
	return score
}
