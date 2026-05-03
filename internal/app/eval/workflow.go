package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/util/sets"
)

// ObservationConfig holds the sources for security policies and cloud resource states.
type ObservationConfig struct {
	PolicySource      string
	ObservationSource string
	AcceptUnknownData bool
	Stderr            io.Writer
	ActivePolicies    []policy.ControlDefinition
}

// AssessmentConfig defines the parameters and environment for a security audit.
type AssessmentConfig struct {
	ObservationConfig
	SLAThreshold        time.Duration
	Clock               ports.Clock
	Hasher              ports.Digester
	Output              io.Writer
	ExemptionRules      *policy.ExemptionConfig
	ExceptionRules      *policy.ExceptionConfig
	AcknowledgmentRules *policy.AcknowledgmentConfig
	BuildVersion        string
	Metadata            evaluation.Metadata
	PredicateParser     func(any) (*policy.UnsafePredicate, error)
	PredicateEval       policy.PredicateEval
	Tracer              ports.Tracer
	ChainDefs           []policy.ChainDefinition // Optional chain definitions for risk reasoning
	SLAConfig           *evaluation.SLAConfig    // Optional SLA policy for deadline enforcement
}

// AuditWorkflow orchestrates the end-to-end security assessment process.
type AuditWorkflow struct {
	ObservationRepo appcontracts.ObservationRepository
	PolicyRepo      appcontracts.ControlRepository
	ReportPublisher appcontracts.FindingMarshaler
	ContextEnricher appcontracts.EnrichFunc
	Logger          *slog.Logger

	// loadedControls and loadedSnapshots cache the inputs used by the
	// most recent PerformAssessment call. Populated as a side effect
	// of running an assessment so callers can do post-assessment work
	// (coverage posture aggregation, reachability annotation that
	// needs the full snapshot graph) without re-loading from the
	// repos. Private now — the read-only Controls() / Snapshots()
	// accessors prevent external mutation between assessment runs.
	loadedControls  []policy.ControlDefinition
	loadedSnapshots []asset.Snapshot
}

// Controls returns the control definitions loaded by the most
// recent PerformAssessment call. Returns a copy so callers cannot
// mutate the workflow's cached slice in place.
func (w *AuditWorkflow) Controls() []policy.ControlDefinition {
	if len(w.loadedControls) == 0 {
		return nil
	}
	out := make([]policy.ControlDefinition, len(w.loadedControls))
	copy(out, w.loadedControls)
	return out
}

// Snapshots returns the asset snapshots loaded by the most recent
// PerformAssessment call. Returns a copy so callers cannot mutate
// the workflow's cached slice in place.
func (w *AuditWorkflow) Snapshots() []asset.Snapshot {
	if len(w.loadedSnapshots) == 0 {
		return nil
	}
	out := make([]asset.Snapshot, len(w.loadedSnapshots))
	copy(out, w.loadedSnapshots)
	return out
}

// NewAuditWorkflow initializes the workflow with required security connectors.
func NewAuditWorkflow(
	invRepo appcontracts.ObservationRepository,
	polRepo appcontracts.ControlRepository,
	publisher appcontracts.FindingMarshaler,
	enricher appcontracts.EnrichFunc,
) *AuditWorkflow {
	if invRepo == nil {
		panic("AuditWorkflow: ObservationRepo is required")
	}
	if polRepo == nil {
		panic("AuditWorkflow: PolicyRepo is required")
	}
	if publisher == nil {
		panic("AuditWorkflow: ReportPublisher is required")
	}
	if enricher == nil {
		panic("AuditWorkflow: ContextEnricher is required")
	}
	return &AuditWorkflow{
		ObservationRepo: invRepo,
		PolicyRepo:      polRepo,
		ReportPublisher: publisher,
		ContextEnricher: enricher,
	}
}

// PerformAssessment executes the security audit and returns the compliance report.
func (w *AuditWorkflow) PerformAssessment(ctx context.Context, cfg AssessmentConfig) (evaluation.ComplianceReport, evaluation.SecurityState, error) {
	auditData := w.prepareAuditData(ctx, cfg.ObservationConfig)
	if auditData.HasErrors() {
		return evaluation.ComplianceReport{}, "", auditData.FirstError()
	}
	w.loadedControls = auditData.Controls
	w.loadedSnapshots = auditData.Snapshots

	report, err := Evaluate(ctx, EvaluateInput{
		Controls:             auditData.Controls,
		Snapshots:            auditData.Snapshots,
		MaxUnsafeDuration:    cfg.SLAThreshold,
		Clock:                cfg.Clock,
		Hasher:               cfg.Hasher,
		ExemptionConfig:      cfg.ExemptionRules,
		ExceptionConfig:      cfg.ExceptionRules,
		AcknowledgmentConfig: cfg.AcknowledgmentRules,
		StaveVersion:         cfg.BuildVersion,
		InputHashes:          auditData.Hashes,
		PredicateParser:      cfg.PredicateParser,
		CELEvaluator:         cfg.PredicateEval,
		Metadata:             cfg.Metadata,
		Tracer:               cfg.Tracer,
	})
	if err != nil {
		return evaluation.ComplianceReport{}, "", fmt.Errorf("security assessment failed: %w", err)
	}

	// Run the risk reasoning engine: detect chain-based compound findings
	// and build an attack stage summary from the evaluation results.
	w.enrichWithRiskReasoning(&report, auditData.Controls, cfg.ChainDefs)

	// Annotate findings with SLA deadline data.
	if cfg.SLAConfig != nil {
		ctlLookup := make(map[kernel.ControlID]*policy.ControlDefinition, len(auditData.Controls))
		for i := range auditData.Controls {
			ctlLookup[auditData.Controls[i].ID] = &auditData.Controls[i]
		}
		for i := range report.Findings {
			ctl := ctlLookup[report.Findings[i].ControlID]
			if ctl == nil {
				// Orphan finding: the control ID emitted by the engine
				// is not in the loaded control catalog. Skip SLA
				// annotation rather than dereferencing nil — the
				// finding still surfaces, but without a deadline. Log
				// so operators can investigate the catalog drift
				// (typically a finding emitted by a chain definition
				// referencing a removed control).
				if w.Logger != nil {
					w.Logger.Warn("sla annotation skipped: control not in catalog",
						"control_id", report.Findings[i].ControlID,
						"asset_id", report.Findings[i].AssetID)
				}
				continue
			}
			report.Findings[i].AnnotateSLA(ctl, cfg.SLAConfig)
		}
	}

	return report, report.SecurityState, nil
}

func (w *AuditWorkflow) prepareAuditData(ctx context.Context, cfg ObservationConfig) IntentEvaluationResult {
	intent := NewIntentEvaluation(w.ObservationRepo, w.PolicyRepo)
	data := intent.LoadArtifacts(ctx, IntentEvaluationConfig{
		ControlsDir:       cfg.PolicySource,
		ObservationsDir:   cfg.ObservationSource,
		RequireControls:   cfg.ActivePolicies == nil,
		SkipControlsLoad:  cfg.ActivePolicies != nil,
		AllowUnknownInput: cfg.AcceptUnknownData,
		Stderr:            cfg.Stderr,
	})
	if cfg.ActivePolicies != nil {
		data.Controls = cfg.ActivePolicies
	}
	return data
}

// enrichWithRiskReasoning runs the chain detection engine and builds
// an attack stage summary from the evaluation results. This is the
// inference layer — it transforms individual findings into compound
// risk assessments.
func (w *AuditWorkflow) enrichWithRiskReasoning(
	report *evaluation.ComplianceReport,
	controls []policy.ControlDefinition,
	chainDefs []policy.ChainDefinition,
) {
	if len(report.Findings) == 0 {
		return
	}

	// Build per-asset failure list for asset-aware chain and attack-stage analysis.
	failures := make([]risk.FailingControl, len(report.Findings))
	for i := range report.Findings {
		failures[i] = report.Findings[i].ToFailingControl()
	}

	controlLookup := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		controlLookup[controls[i].ID] = &controls[i]
	}

	// Detect chain-based compound findings.
	if len(chainDefs) > 0 {
		report.ChainFindings = risk.DetectChains(failures, chainDefs, controlLookup)
		annotateChainMembership(report)
	}

	// Build attack stage summary.
	report.AttackStageSummary = risk.BuildAttackStageSummary(failures, controlLookup)

	// Rank findings by exposure score (silent killer detection).
	// ChainMembership must be annotated before this loop runs so the
	// chain-bonus factor feeds into per-finding scores.
	rankInputs := make([]risk.RankInput, len(report.Findings))
	for i := range report.Findings {
		rankInputs[i] = report.Findings[i].ToRankInput()
	}
	report.TopExposures = risk.RankExposures(rankInputs, controlLookup, 0)

	// Propagate the per-finding score + breakdown back onto each
	// Finding so downstream sorts and output can read the score
	// without a parallel lookup. Matches metrics.md § Metric 1
	// improvement signal: "score and breakdown are emitted on every
	// finding, not only on the top-N slice".
	for i := range report.TopExposures {
		er := &report.TopExposures[i]
		if er.FindingIndex < 0 || er.FindingIndex >= len(report.Findings) {
			continue
		}
		f := &report.Findings[er.FindingIndex]
		f.ExposureScore = er.ExposureScore
		breakdown := er.Breakdown
		f.ScoreBreakdown = &breakdown
	}

	// Re-sort findings by the newly-populated score.
	evaluation.SortFindings(report.Findings)

	// Build consolidated Issues from the scored findings. Runs after
	// ranking so ConsolidatedScore uses the final per-finding score
	// including chain bonus. See docs/product/metrics.md § Metric 2.
	report.Issues = evaluation.BuildIssues(report.Findings)
}

// annotateChainMembership cross-references fired chains with individual
// findings and populates ChainMembership on each contributing finding.
func annotateChainMembership(report *evaluation.ComplianceReport) {
	if len(report.ChainFindings) == 0 {
		return
	}

	// Build a lookup: controlID → list of chain membership entries.
	type entry struct {
		controlIDs sets.Set[kernel.ControlID]
		membership evaluation.ChainMembershipEntry
	}
	chainEntries := make([]entry, 0, len(report.ChainFindings))
	for i := range report.ChainFindings {
		cf := &report.ChainFindings[i]
		cidSet := sets.New[kernel.ControlID](cf.ControlsFailing...)
		chainEntries = append(chainEntries, entry{
			controlIDs: cidSet,
			membership: evaluation.ChainMembershipEntry{
				ChainID:       cf.ChainID,
				ChainSeverity: cf.Severity,
				StageSpan:     risk.SortStagesByKillChain(cf.AttackStages),
				Narrative:     cf.Description,
			},
		})
	}

	for i := range report.Findings {
		f := &report.Findings[i]
		for _, ce := range chainEntries {
			if ce.controlIDs.Contains(f.ControlID) {
				f.ChainMembership = append(f.ChainMembership, ce.membership)
			}
		}
	}
}

// EnrichReport applies risk reasoning (chains, attack stages, exposure
// ranking) to an evaluation report. Exported for use by the profile
// runner which bypasses the standard assessment workflow.
func EnrichReport(report *evaluation.ComplianceReport, controls []policy.ControlDefinition, chainDefs []policy.ChainDefinition) {
	w := &AuditWorkflow{}
	w.enrichWithRiskReasoning(report, controls, chainDefs)
}
