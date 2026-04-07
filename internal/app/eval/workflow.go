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
	"github.com/sufield/stave/internal/core/ports"
)

// InventoryConfig holds the sources for security policies and cloud resource states.
type InventoryConfig struct {
	PolicySource      string
	InventorySource   string
	AcceptUnknownData bool
	Stderr            io.Writer
	ActivePolicies    []policy.ControlDefinition
}

// AssessmentConfig defines the parameters and environment for a security audit.
type AssessmentConfig struct {
	InventoryConfig
	SLAThreshold    time.Duration
	Clock           ports.Clock
	Hasher          ports.Digester
	Output          io.Writer
	ExemptionRules  *policy.ExemptionConfig
	ExceptionRules  *policy.ExceptionConfig
	BuildVersion    string
	Metadata        evaluation.Metadata
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	PredicateEval   policy.PredicateEval
}

// AuditWorkflow orchestrates the end-to-end security assessment process.
type AuditWorkflow struct {
	InventoryRepo   appcontracts.ObservationRepository
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
		panic("AuditWorkflow: InventoryRepo is required")
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
		InventoryRepo:   invRepo,
		PolicyRepo:      polRepo,
		ReportPublisher: publisher,
		ContextEnricher: enricher,
	}
}

// PerformAssessment executes the security audit and returns the compliance report.
func (w *AuditWorkflow) PerformAssessment(ctx context.Context, cfg AssessmentConfig) (evaluation.ComplianceReport, evaluation.SecurityState, error) {
	auditData := w.prepareAuditData(ctx, cfg.InventoryConfig)
	if auditData.HasErrors() {
		return evaluation.ComplianceReport{}, "", auditData.FirstError()
	}

	report, err := Evaluate(EvaluateInput{
		Controls:          auditData.Controls,
		Snapshots:         auditData.Snapshots,
		MaxUnsafeDuration: cfg.SLAThreshold,
		Clock:             cfg.Clock,
		Hasher:            cfg.Hasher,
		ExemptionConfig:   cfg.ExemptionRules,
		ExceptionConfig:   cfg.ExceptionRules,
		StaveVersion:      cfg.BuildVersion,
		InputHashes:       auditData.Hashes,
		PredicateParser:   cfg.PredicateParser,
		CELEvaluator:      cfg.PredicateEval,
		Metadata:          cfg.Metadata,
	})
	if err != nil {
		return evaluation.ComplianceReport{}, "", fmt.Errorf("security assessment failed: %w", err)
	}

	return report, report.SecurityState, nil
}

func (w *AuditWorkflow) prepareAuditData(ctx context.Context, cfg InventoryConfig) IntentEvaluationResult {
	intent := NewIntentEvaluation(w.InventoryRepo, w.PolicyRepo)
	data := intent.LoadArtifacts(ctx, IntentEvaluationConfig{
		ControlsDir:       cfg.PolicySource,
		ObservationsDir:   cfg.InventorySource,
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
