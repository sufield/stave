package stave

import (
	"context"
	"errors"

	appscore "github.com/sufield/stave/internal/app/score"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

// Weights tunes the relative importance of each score dimension.
// Aliased from the internal scorer; ParseWeights and DefaultWeights
// are re-exported for callers that build weights from CLI strings.
type Weights = appscore.Weights

// ScoreResult is the full posture score breakdown. Aliased from the
// internal scorer because the wire format is already stable (the score
// command's --format json output is a public artifact); a pkg/stave
// mirror would duplicate ~150 lines of struct definitions for no gain.
// The shape remains stable across engine refactors because the JSON
// tags fix the contract.
type ScoreResult = appscore.Result

// DefaultWeights returns the standard weight distribution
// (Severity 0.45, SLA 0.25, Chain 0.20, Coverage 0.10).
func DefaultWeights() Weights {
	return appscore.DefaultWeights()
}

// ParseWeights parses a "severity=0.45,sla=0.25,chain=0.20,coverage=0.10"
// override string. Missing keys retain DefaultWeights values.
func ParseWeights(s string) (Weights, error) {
	return appscore.ParseWeights(s)
}

// ScoreConfig parameterizes a [Score] call.
//
// Assessment is required — it carries the evaluated findings, chain
// findings, SLA breach counts, and framework readiness the scorer
// needs. Build it via [Apply] or load from a persisted artifact.
//
// Weights default to [DefaultWeights] when nil. ChainDefs is the
// total chain definitions available for the chain-component
// max-weight calculation; zero falls back to the heuristic
// `len(chain findings) × 10`. ChainMaxWeight pre-computes the
// severity-weighted total chain budget — supply when the chain
// catalog is known, otherwise zero defers to ChainDefs heuristic.
//
// Compliance, when non-empty, requests coverage scoring against the
// listed framework names. The scorer averages each named framework's
// readiness percent from Assessment.Summary.FrameworkReadiness;
// frameworks not present in the assessment summary are silently
// dropped. SnapshotID, when set, is recorded on the result.
type ScoreConfig struct {
	Assessment     *Assessment
	Weights        *Weights
	ChainMaxWeight float64
	ChainDefs      int
	Compliance     []string
	SnapshotID     string
}

// Score computes the posture score for an assessment. Pure
// arithmetic — no I/O, no adapters, no goroutines. Equivalent to
// `stave score --output assessment.json` minus output formatting.
//
// Replicates the derivation cmd/score used to perform inline:
// SLA tally from per-finding flags, coverage averaged across
// requested frameworks via Assessment.Summary.FrameworkReadiness,
// total-check-weight estimated from violation severities plus a
// median weight per passing asset.
func Score(_ context.Context, cfg ScoreConfig) (*ScoreResult, error) {
	if cfg.Assessment == nil {
		return nil, errors.New("stave.Score: ScoreConfig.Assessment is required")
	}
	weights := DefaultWeights()
	if cfg.Weights != nil {
		weights = *cfg.Weights
	}

	findings := scoreFindingsFromAssessment(cfg.Assessment)
	chainFindings := scoreChainFindingsFromAssessment(cfg.Assessment)

	slaBreached, slaTotal, hasSLA := tallySLA(cfg.Assessment)
	coveragePct, hasCoverage := computeCoverage(cfg.Assessment, cfg.Compliance)
	totalCheckWeight := estimateTotalCheckWeight(cfg.Assessment, findings)

	in := appscore.Input{
		Findings:         findings,
		ChainFindings:    chainFindings,
		ChainDefs:        cfg.ChainDefs,
		MaxChainWeight:   cfg.ChainMaxWeight,
		SLABreached:      slaBreached,
		SLATotal:         slaTotal,
		CoveragePct:      coveragePct,
		TotalCheckWeight: totalCheckWeight,
		HasSLA:           hasSLA,
		HasCoverage:      hasCoverage,
		Weights:          weights,
		GeneratedAt:      cfg.Assessment.Run.Now,
		SnapshotID:       cfg.SnapshotID,
	}
	result := appscore.Compute(in)
	return &result, nil
}

// tallySLA returns (breached, total, hasSLA) over the assessment's
// findings. A finding contributes to the SLA tally only when the
// engine annotated it with a deadline; the total is therefore
// 'findings the SLA policy applied to', not 'all findings'.
func tallySLA(a *Assessment) (breached, total int, hasSLA bool) {
	for i := range a.Findings {
		f := &a.Findings[i]
		if f.SLADeadlineHours == nil {
			continue
		}
		hasSLA = true
		total++
		if f.SLABreached {
			breached++
		}
	}
	return breached, total, hasSLA
}

// computeCoverage averages the readiness percent across the
// requested frameworks. Frameworks not present in
// Summary.FrameworkReadiness are silently dropped — the average is
// taken over matched frameworks only, matching cmd/score's prior
// behavior. Empty compliance list disables the coverage component.
func computeCoverage(a *Assessment, compliance []string) (pct float64, has bool) {
	if len(compliance) == 0 || len(a.Summary.FrameworkReadiness) == 0 {
		return 0, false
	}
	var total float64
	var matched int
	for _, fr := range a.Summary.FrameworkReadiness {
		for _, want := range compliance {
			if fr.Framework == want {
				total += float64(fr.ReadinessPercent)
				matched++
				break
			}
		}
	}
	if matched == 0 {
		return 0, false
	}
	return total / float64(matched), true
}

// estimateTotalCheckWeight derives the severity-weighted total from
// the assessment. Failing findings contribute their exact severity
// weight; passing assets contribute a median weight (2.0) because
// per-severity passing data isn't carried in the persisted artifact.
//
// passingAssets = TotalAssets − distinct failing assets, clamped to
// zero. The previous shape mixed per-asset and per-finding scales
// (TotalAssets − len(Findings)), which produced negative-clamped
// counts on assets with multiple findings.
func estimateTotalCheckWeight(a *Assessment, findings []remediation.Finding) float64 {
	var violationWeight float64
	for i := range findings {
		violationWeight += appscore.SeverityWeightFor(findings[i].ControlSeverity)
	}
	failing := make(map[string]struct{}, len(findings))
	for i := range findings {
		failing[string(findings[i].AssetID)] = struct{}{}
	}
	passing := a.Summary.TotalAssets - len(failing)
	if passing < 0 {
		passing = 0
	}
	return violationWeight + float64(passing)*2.0
}

// scoreFindingsFromAssessment maps the public Finding slice to the
// remediation.Finding shape the scorer expects. Only the fields the
// scorer actually reads are populated — severity, exposure score,
// and SLA flags.
func scoreFindingsFromAssessment(a *Assessment) []remediation.Finding {
	out := make([]remediation.Finding, len(a.Findings))
	for i := range a.Findings {
		f := &a.Findings[i]
		// Reverse-resolve the severity string → Severity enum.
		// The scorer reads ControlSeverity directly; without this
		// the severity component would treat every finding as Info.
		sev := severityFromString(f.Severity)
		out[i] = remediation.Finding{
			Finding: evaluation.Finding{
				FindingID:        f.FindingID,
				ControlID:        f.ControlID,
				AssetID:          f.AssetID,
				ControlSeverity:  sev,
				ExposureScore:    f.ExposureScore,
				SLABreached:      f.SLABreached,
				SLADeadlineHours: f.SLADeadlineHours,
				SLAOverdueHours:  f.SLAOverdueHours,
			},
		}
	}
	return out
}

// scoreChainFindingsFromAssessment converts the public ChainFinding
// slice to the engine form the scorer reads. Only ChainID and
// Severity are needed for chain weighting.
func scoreChainFindingsFromAssessment(a *Assessment) []risk.CompoundFinding {
	if len(a.ChainFindings) == 0 {
		return nil
	}
	out := make([]risk.CompoundFinding, len(a.ChainFindings))
	for i := range a.ChainFindings {
		c := &a.ChainFindings[i]
		out[i] = risk.CompoundFinding{
			ChainID:  c.ChainID,
			Severity: severityFromString(c.Severity),
		}
	}
	return out
}

// severityFromString resolves the public string-form Severity back
// into the internal enum. ParseSeverity is case-insensitive and tolerates
// "" / "none" — both map to SeverityNone, which the scorer treats as
// "no contribution," so unknown / missing severities don't poison the
// score.
func severityFromString(s Severity) policy.Severity {
	parsed, _ := policy.ParseSeverity(string(s))
	return parsed
}
