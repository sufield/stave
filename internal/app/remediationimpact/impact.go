package remediationimpact

import (
	"cmp"
	"errors"
	"slices"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
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
	Severity  policy.Severity  `json:"severity"`
	DwellDays float64          `json:"dwell_days,omitempty"`
}

// DeactivatedChain is a chain active in before but inactive in after.
type DeactivatedChain struct {
	ChainID          kernel.ChainID  `json:"chain_id"`
	PreviousSeverity policy.Severity `json:"previous_severity"`
	AssetID          asset.ID        `json:"asset_id,omitempty"`
	ScopeID          string          `json:"scope_id,omitempty"`
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
	PredictedDelta float64            `json:"predicted_delta"`
	RealizedDelta  float64            `json:"realized_delta"`
	Ratio          float64            `json:"efficiency_ratio"`
	Verdict        EfficiencyVerdict  `json:"verdict"`
	StillOpen      []kernel.ControlID `json:"still_open,omitempty"`
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
	PredictedDelta  float64            // from stave simulate, 0 if not provided
	PredictedClosed []kernel.ControlID // control IDs predicted to close
}

// Analyze compares before and after assessments. Before and After must
// both be non-nil — Analyze dereferences them throughout — so a nil input
// returns an error rather than panicking. Callers load both assessments
// up front, so in practice this guards a programming error at the package
// boundary.
//
// Outputs (closed, deactivated) are sorted deterministically so byte-identical
// input yields byte-identical reports.
func Analyze(in Input) (*Report, error) {
	if in.Before == nil || in.After == nil {
		return nil, errors.New("remediationimpact: Before and After assessments must both be non-nil")
	}
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
				Severity:  f.ControlSeverity,
				DwellDays: f.DwellDays(),
			})
		}
	}
	slices.SortFunc(closed, func(a, b ClosedFinding) int {
		if n := cmp.Compare(string(a.ControlID), string(b.ControlID)); n != 0 {
			return n
		}
		return cmp.Compare(string(a.AssetID), string(b.AssetID))
	})

	// Find deactivated chains. Project (ChainID, severity-label)
	// off the assessment without naming findings.CompoundFinding —
	// the only fields read are c.ChainID and c.Severity.String().
	// Iterates Before first to build the set, then deletes any
	// chain still active in After, matching the original semantics
	// of two-map set difference.
	type chainKey struct {
		chainID kernel.ChainID
		assetID asset.ID
		scopeID string
	}
	beforeSev := make(map[chainKey]policy.Severity, len(in.Before.ChainFindings))
	for i := range in.Before.ChainFindings {
		c := &in.Before.ChainFindings[i]
		k := chainKey{chainID: c.ChainID, assetID: c.AssetID, scopeID: c.ScopeID}
		beforeSev[k] = c.Severity
	}
	for i := range in.After.ChainFindings {
		c := &in.After.ChainFindings[i]
		k := chainKey{chainID: c.ChainID, assetID: c.AssetID, scopeID: c.ScopeID}
		delete(beforeSev, k)
	}
	var deactivated []DeactivatedChain
	for k, sev := range beforeSev {
		deactivated = append(deactivated, DeactivatedChain{
			ChainID:          k.chainID,
			PreviousSeverity: sev,
			AssetID:          k.assetID,
			ScopeID:          k.scopeID,
		})
	}
	slices.SortFunc(deactivated, func(a, b DeactivatedChain) int {
		if n := cmp.Compare(string(a.ChainID), string(b.ChainID)); n != 0 {
			return n
		}
		if n := cmp.Compare(string(a.AssetID), string(b.AssetID)); n != 0 {
			return n
		}
		return cmp.Compare(a.ScopeID, b.ScopeID)
	})

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

	if in.PredictedDelta != 0 || len(in.PredictedClosed) > 0 {
		r.Efficiency = computeEfficiency(in, scoreAfter-scoreBefore, afterKeys)
	}

	return r, nil
}

func computeEfficiency(in Input, realized float64, afterKeys map[findingKey]*remediation.Finding) *Efficiency {
	ratio, verdict := classifyEfficiency(in.PredictedDelta, realized)

	var stillOpen []kernel.ControlID
	for _, ctlID := range in.PredictedClosed {
		for ak := range afterKeys {
			if ak.ControlID == ctlID {
				stillOpen = append(stillOpen, ctlID)
				break
			}
		}
	}
	slices.SortFunc(stillOpen, func(a, b kernel.ControlID) int {
		return cmp.Compare(string(a), string(b))
	})
	stillOpen = slices.Compact(stillOpen)

	return &Efficiency{
		PredictedDelta: in.PredictedDelta,
		RealizedDelta:  realized,
		Ratio:          ratio,
		Verdict:        verdict,
		StillOpen:      stillOpen,
	}
}

func classifyEfficiency(predicted, realized float64) (float64, EfficiencyVerdict) {
	if predicted == 0 {
		return 0, ""
	}
	if realized <= 0 {
		return 0, VerdictIncomplete
	}
	ratio := max(realized/predicted, 0)
	switch {
	case ratio < 0.5:
		return ratio, VerdictIncomplete
	case ratio < 0.9:
		return ratio, VerdictPartial
	default:
		return ratio, VerdictComplete
	}
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
	if a == nil {
		// No assessment to score. Return 0 (a sentinel "no data" value)
		// rather than dereferencing a.Summary and panicking; Analyze
		// guards nil inputs before reaching here, so this is defensive.
		return 0
	}
	if a.Summary.TotalAssets == 0 {
		if a.Summary.Violations > 0 {
			return 0
		}
		return 100
	}
	rate := float64(a.Summary.Violations) / float64(a.Summary.TotalAssets)
	score := (1.0 - rate) * 100
	if score < 0 {
		return 0
	}
	return score
}
