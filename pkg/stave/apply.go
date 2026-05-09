package stave

import (
	"context"
	"errors"
	"maps"
	"time"

	covadapter "github.com/sufield/stave/internal/adapters/coverage"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/coverage"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/pkg/stave/internal/applycore"
)

// Apply runs Stave's control evaluation against the snapshots in
// cfg.SnapshotsDir and returns the typed assessment. Equivalent to
// `./stave apply` on the command line, minus CLI concerns
// (formatting, team manifests, SLA overlays, output paths).
//
// CLI callers that need the full *evaluation.ComplianceReport (for
// rendering SARIF / JSON / text output) should use
// pkg/stave/cliapi.Apply instead — that path returns both the
// trimmed public Assessment and the raw internal report.
func Apply(ctx context.Context, cfg Config) (*Assessment, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("stave.Apply: Config.SnapshotsDir is required")
	}

	r, err := applycore.Run(ctx, applyInputs(cfg))
	if err != nil {
		return nil, err
	}
	return BuildAssessment(r.Report, r.Controls), nil
}

// applyInputs maps the public Config to the applycore.Inputs shape.
// SLAConfig conversion happens here so the internal pipeline only
// sees the engine form (evaluation.SLAConfig); the public type
// stays decoupled from the engine struct.
//
// GitMetadata, ProjectConfig, and Tracer are aliased types — they
// pass through unchanged. Library callers leave them nil; CLI
// callers populate them so the library run produces the same
// output as the direct cmd/apply path.
func applyInputs(cfg Config) applycore.Inputs {
	return applycore.Inputs{
		SnapshotsDir:        cfg.SnapshotsDir,
		ControlsDir:         cfg.ControlsDir,
		ChainsDir:           cfg.ChainsDir,
		IntegrityManifest:   cfg.IntegrityManifest,
		IntegrityPublicKey:  cfg.IntegrityPublicKey,
		MaxUnsafe:           cfg.MaxUnsafe,
		Now:                 cfg.Now,
		AllowUnknownInput:   cfg.AllowUnknownInput,
		ExemptionRules:      cfg.ExemptionRules,
		AcknowledgmentRules: cfg.AcknowledgmentRules,
		SLAConfig:           toEvalSLAConfig(cfg.SLAConfig),
		GitMetadata:         cfg.GitMetadata,
		ProjectConfig:       cfg.ProjectConfig,
		Tracer:              cfg.Tracer,
		ContextName:         cfg.ContextName,
	}
}

// ApplyInputsFromConfig is the package-internal hook used by
// pkg/stave/cliapi.Apply to build the same applycore.Inputs the
// public Apply uses. Exported so cliapi (a sibling sub-package)
// can call it without re-implementing the SLAConfig conversion.
//
// Not part of the public stable API — intended for cliapi only.
// External callers should use [Apply] and the public [Config] /
// [Assessment] surface.
func ApplyInputsFromConfig(cfg Config) applycore.Inputs {
	return applyInputs(cfg)
}

// toEvalSLAConfig converts the public SLAConfig into the internal
// evaluation form expected by AssessmentConfig. nil maps to nil so
// the engine's "no SLA evaluation" path activates correctly.
func toEvalSLAConfig(c *SLAConfig) *evaluation.SLAConfig {
	if c == nil {
		return nil
	}
	deadlines := make(map[string]float64, len(c.DeadlineBySeverity))
	maps.Copy(deadlines, c.DeadlineBySeverity)
	return &evaluation.SLAConfig{
		ProfileID:          c.ProfileID,
		DeadlineBySeverity: deadlines,
		EscalationFactor:   c.EscalationFactor,
	}
}

// BuildAssessment converts a *evaluation.ComplianceReport plus its
// active controls into the public *Assessment shape. Exported
// because pkg/stave/cliapi.Apply uses it after running its own
// orchestration; library consumers building Assessments from
// arbitrary reports may also call it directly.
//
// SLABreaches is computed by counting findings with SLABreached set.
// FrameworkReadiness is mirrored from the report's summary.
//
// Each Finding's [Finding.ContributingFactIDs] is copied from the
// internal evaluation.Finding when present. applycore.Run stamps
// those ids post-evaluation by building the SIR projection for
// the same controls/snapshots/now the evaluator consumed; callers
// that construct a ComplianceReport themselves may leave the
// internal field empty (the public Finding's slice will be nil)
// without breaking the call.
func BuildAssessment(report *evaluation.ComplianceReport, controls []policy.ControlDefinition) *Assessment {
	if report == nil {
		return nil
	}
	slaBreaches := 0
	for i := range report.Findings {
		if report.Findings[i].IsAnyBreach() {
			slaBreaches++
		}
	}
	return &Assessment{
		SchemaVersion: string(kernel.SchemaOutput),
		Status:        Status(report.SecurityState),
		Run: RunInfo{
			StaveVersion: report.Run.StaveVersion,
			Now:          report.Run.Now,
			MaxUnsafe:    time.Duration(report.Run.MaxUnsafeDuration),
			Snapshots:    report.Run.Snapshots,
		},
		Summary: Summary{
			TotalAssets:        report.Summary.TotalAssets,
			ExposedResources:   report.Summary.ExposedResources,
			Violations:         report.Summary.Violations,
			FrameworkReadiness: convertFrameworkReadiness(report.Summary.FrameworkReadiness),
		},
		Findings:       convertFindings(report.Findings),
		MarkerFindings: convertFindings(report.MarkerFindings),
		Issues:         report.Issues,
		Coverage:       buildCoverage(controls),
		ChainFindings:  convertChainFindings(report.ChainFindings),
		SLABreaches:    slaBreaches,
	}
}

// convertFrameworkReadiness mirrors evaluation.FrameworkReadiness
// into the public [FrameworkReadiness] shape.
func convertFrameworkReadiness(rs []evaluation.FrameworkReadiness) []FrameworkReadiness {
	if len(rs) == 0 {
		return nil
	}
	out := make([]FrameworkReadiness, len(rs))
	for i := range rs {
		out[i] = FrameworkReadiness{
			Framework:        rs[i].Framework,
			TotalControls:    rs[i].TotalControls,
			PassingControls:  rs[i].PassingControls,
			ReadinessPercent: rs[i].ReadinessPercent,
		}
	}
	return out
}

// convertChainFindings copies compound-finding records from the
// internal report into the library's typed ChainFinding slice,
// applying ChainID typing at the boundary.
func convertChainFindings(cfs []risk.CompoundFinding) []ChainFinding {
	if len(cfs) == 0 {
		return nil
	}
	out := make([]ChainFinding, len(cfs))
	for i := range cfs {
		out[i] = convertCompoundFinding(&cfs[i])
	}
	return out
}

func convertFindings(fs []evaluation.Finding) []Finding {
	out := make([]Finding, len(fs))
	for i := range fs {
		out[i] = convertFinding(&fs[i])
	}
	return out
}

func convertFinding(f *evaluation.Finding) Finding {
	out := Finding{
		FindingID:            f.FindingID,
		ControlID:            f.ControlID,
		ControlName:          f.ControlName,
		AssetID:              f.AssetID,
		AssetType:            f.AssetType,
		Severity:             Severity(f.SeverityLabel()),
		Classification:       f.Classification,
		ScopeTags:            f.ScopeTags,
		ControlCompliance:    convertCompliance(f.ControlCompliance),
		Remediation:          convertRemediation(f),
		ReasoningTrace:       f.ReasoningTrace,
		ChainMembership:      convertChainMembership(f.ChainMembership),
		ChainBonus:           chainBonusFromBreakdown(f),
		ExposureScore:        f.ExposureScore.Value(),
		Defect:               f.Defect,
		Infection:            f.Infection,
		Failure:              f.Failure,
		Delta:                convertDelta(f.Delta),
		SLABreached:          f.SLABreachedFlag(),
		SLADeadlineHours:     f.SLADeadlinePtr(),
		SLAOverdueHours:      f.SLAOverduePtr(),
		SLAEscalatedSeverity: Severity(f.SLAEscalatedSeverityValue().String()),
		FirstUnsafeAt:        f.Evidence.FirstUnsafeAt,
		LastSeenUnsafeAt:     f.Evidence.LastSeenUnsafeAt,
		UnsafeDurationHours:  f.Evidence.UnsafeDurationHours,
		SuggestedFix:         convertSuggestedFix(f.SuggestedFix),
		LogicalProof:         f.LogicalProof,
		ContributingFactIDs:  f.ContributingFactIDs,
	}
	if f.HasReachability() {
		out.Reachability = &Reachability{
			TotalReachablePrincipals:   f.Reachability.TotalReachablePrincipals,
			PrivilegedPrincipalCount:   f.Reachability.PrivilegedPrincipalCount,
			HighestPrivilegePrincipal:  f.Reachability.HighestPrivilegePrincipal.String(),
			ExternalPrincipalReachable: f.Reachability.ExternalPrincipalReachable,
			BlastRadiusScore:           f.Reachability.BlastRadiusScore.Value(),
		}
	}
	return out
}

// chainBonusFromBreakdown reads the chain-bonus multiplier off the
// internal finding's ScoreBreakdown. Default 1.0 when the breakdown
// hasn't been populated (pre-enrichment findings) or when the finding
// doesn't belong to any chain.
func chainBonusFromBreakdown(f *evaluation.Finding) float64 {
	if f.ScoreBreakdown == nil {
		return 1.0
	}
	if f.ScoreBreakdown.ChainBonus == 0 {
		return 1.0
	}
	return f.ScoreBreakdown.ChainBonus
}

func convertDelta(ds []policy.DeltaPath) []DeltaPath {
	if len(ds) == 0 {
		return nil
	}
	out := make([]DeltaPath, len(ds))
	for i, d := range ds {
		out[i] = DeltaPath{
			PropertyLabel: d.PropertyLabel,
			PropertyPath:  d.PropertyPath,
			CurrentValue:  d.CurrentValue,
			FixAction:     d.FixAction,
		}
	}
	return out
}

func convertCompliance(m policy.ComplianceMapping) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[string(k)] = string(v)
	}
	return out
}

// convertRemediation resolves the finding's remediation guidance
// the same way the enrichment pipeline does: catalog-authored spec
// first, class-based default as fallback. Consumers get a
// non-empty Remediation whenever the engine can produce one.
func convertRemediation(f *evaluation.Finding) Remediation {
	spec := remediationSpecFor(f)
	return Remediation{
		Description: spec.Description,
		Action:      spec.Action,
		Example:     spec.Example,
	}
}

func remediationSpecFor(f *evaluation.Finding) policy.RemediationSpec {
	if f.ControlRemediation != nil {
		return *f.ControlRemediation
	}
	return policy.DefaultRemediationForClass(f.ControlID.Classify())
}

// convertSuggestedFix lifts the internal solver-derived map into
// the typed SuggestedFix surface. Returns nil when the engine
// produced no fix — typical for CEL-only evaluation. Recognised
// keys: fix_type, description, current, replacement, confidence,
// confidence_reason. Unknown keys are silently dropped to keep
// the public surface stable as the internal schema evolves.
func convertSuggestedFix(raw map[string]any) *SuggestedFix {
	if len(raw) == 0 {
		return nil
	}
	out := &SuggestedFix{}
	if v, ok := raw["fix_type"].(string); ok {
		out.FixType = v
	}
	if v, ok := raw["description"].(string); ok {
		out.Description = v
	}
	if v, ok := raw["confidence"].(string); ok {
		out.Confidence = v
	}
	if v, ok := raw["confidence_reason"].(string); ok {
		out.ConfidenceReason = v
	}
	out.Current = raw["current"]
	out.Replacement = raw["replacement"]
	return out
}

// buildCoverage builds the per-tool, per-domain coverage posture
// using the same path the CLI uses: load the embedded alternative-
// tool inventories and aggregate them against the active controls.
// Inventory load errors are treated as absence — coverage posture
// is decorative, not load-bearing.
func buildCoverage(controls []policy.ControlDefinition) CoveragePosture {
	if len(controls) == 0 {
		return CoveragePosture{}
	}
	inventories, err := covadapter.LoadEmbedded()
	if err != nil {
		return CoveragePosture{}
	}
	return coverage.BuildCoverageIndex(controls, inventories)
}
