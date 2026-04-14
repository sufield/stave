package eval

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
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

	report, err := Evaluate(EvaluateInput{
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
			evaluation.AnnotateFindingSLA(&report.Findings[i], ctl, cfg.SLAConfig)
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

	// Build lookup structures.
	failingIDs := make(map[kernel.ControlID]bool, len(report.Findings))
	for i := range report.Findings {
		failingIDs[report.Findings[i].ControlID] = true
	}

	controlLookup := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		controlLookup[controls[i].ID] = &controls[i]
	}

	// Detect chain-based compound findings.
	if len(chainDefs) > 0 {
		report.ChainFindings = risk.DetectChains(failingIDs, chainDefs, controlLookup)
		annotateChainMembership(report)
	}

	// Build attack stage summary.
	report.AttackStageSummary = risk.BuildAttackStageSummary(failingIDs, controlLookup)

	// Rank findings by exposure score (silent killer detection).
	rankInputs := make([]risk.RankInput, len(report.Findings))
	for i := range report.Findings {
		f := &report.Findings[i]
		rankInputs[i] = risk.RankInput{
			ControlID:           f.ControlID,
			AssetID:             f.AssetID,
			ControlSeverity:     f.ControlSeverity,
			Exposure:            f.Exposure,
			UnsafeDurationHours: f.Evidence.UnsafeDurationHours,
		}
	}
	report.TopExposures = risk.RankExposures(rankInputs, controlLookup, 0)
}

// annotateChainMembership cross-references fired chains with individual
// findings and populates ChainMembership on each contributing finding.
func annotateChainMembership(report *evaluation.ComplianceReport) {
	if len(report.ChainFindings) == 0 {
		return
	}

	// Build a lookup: controlID → list of chain membership entries.
	type entry struct {
		controlIDs map[kernel.ControlID]bool
		membership evaluation.ChainMembershipEntry
	}
	chainEntries := make([]entry, 0, len(report.ChainFindings))
	for i := range report.ChainFindings {
		cf := &report.ChainFindings[i]
		cidSet := make(map[kernel.ControlID]bool, len(cf.ControlsFailing))
		for _, cid := range cf.ControlsFailing {
			cidSet[cid] = true
		}
		chainEntries = append(chainEntries, entry{
			controlIDs: cidSet,
			membership: evaluation.ChainMembershipEntry{
				ChainID:       cf.ChainID,
				ChainSeverity: cf.Severity.String(),
				StageSpan:     risk.SortStagesByKillChain(cf.AttackStages),
				Narrative:     cf.Description,
			},
		})
	}

	for i := range report.Findings {
		f := &report.Findings[i]
		for _, ce := range chainEntries {
			if ce.controlIDs[f.ControlID] {
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
