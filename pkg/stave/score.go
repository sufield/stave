package stave

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	appscore "github.com/sufield/stave/internal/app/score"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// Weights tunes the relative importance of each score dimension.
// Aliased from the internal scorer; DefaultWeights is re-exported so
// callers can start from the standard distribution and adjust fields.
type Weights = appscore.Weights

// ScoreMover is a single entry in the score-movers list — the
// per-dimension delta between the latest score and the previous
// run, used by the table + JSON renderers to surface "what
// improved, what regressed." Aliased so cmd/score renderers
// don't need to reach into the internal scorer package.
type ScoreMover = appscore.ScoreMover

// TrendPoint is one (timestamp, score) sample in a score-history
// trend. Aliased so cmd/score's trend builder consumes a public
// type without bypassing the facade.
type TrendPoint = appscore.TrendPoint

// ParseWeights parses the `--weights` CLI flag value into a
// [Weights] struct. The wire format is the same one the score
// command has accepted since the beginning
// ("severity=0.45,sla=0.25,chain=0.20,coverage=0.10"); pass-through
// to the internal parser to keep that contract in one place.
func ParseWeights(s string) (Weights, error) {
	w, err := appscore.ParseWeights(s)
	if err != nil {
		return Weights{}, fmt.Errorf("parse weights: %w", err)
	}
	return w, nil
}

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
		if slices.Contains(compliance, fr.Framework) {
			total += float64(fr.ReadinessPercent)
			matched++
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
	passing := max(a.Summary.TotalAssets-len(failing), 0)
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
		// A non-empty input that resolves to SeverityNone signals a
		// data-quality issue upstream — wrong case, typo, or a value
		// outside the canonical set. ParseSeverity swallows those
		// silently, so log here so operators see when score input is
		// being downgraded to the no-contribution bucket.
		if sev == policy.SeverityNone && f.Severity != "" {
			slog.Warn("score: unknown finding severity coerced to none",
				"control_id", f.ControlID, "asset_id", f.AssetID, "severity", f.Severity)
		}
		ev := evaluation.Finding{
			FindingID:       f.FindingID,
			ControlID:       f.ControlID,
			AssetID:         f.AssetID,
			ControlSeverity: sev,
			ExposureScore:   kernel.ExposureScore(f.ExposureScore),
		}
		// SLA state is private on evaluation.Finding; rehydrate
		// via the package-internal setter. SLAEscalatedSeverity
		// and SLAPolicySource are not carried on the wire shape
		// score consumes here, so they pass through as zero —
		// sufficient for the scorer, which only reads the breach
		// + dwell signals.
		ev.RehydrateSLA(f.SLADeadlineHours, f.SLABreached, f.SLAOverdueHours, 0, "")
		out[i] = remediation.Finding{Finding: ev}
	}
	return out
}

// scoreChainFindingsFromAssessment converts the public ChainFinding
// slice to the engine form the scorer reads. Only ChainID and
// Severity are needed for chain weighting.
func scoreChainFindingsFromAssessment(a *Assessment) []findingsdata.CompoundFinding {
	if len(a.ChainFindings) == 0 {
		return nil
	}
	out := make([]findingsdata.CompoundFinding, len(a.ChainFindings))
	for i := range a.ChainFindings {
		c := &a.ChainFindings[i]
		sev := severityFromString(c.Severity)
		if sev == policy.SeverityNone && c.Severity != "" {
			slog.Warn("score: unknown chain severity coerced to none",
				"chain_id", c.ChainID, "severity", c.Severity)
		}
		out[i] = findingsdata.CompoundFinding{
			ChainID:  c.ChainID,
			Severity: sev,
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
