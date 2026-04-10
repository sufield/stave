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
	Tracer          ports.Tracer
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
		Tracer:            cfg.Tracer,
	})
	if err != nil {
		return evaluation.ComplianceReport{}, "", fmt.Errorf("security assessment failed: %w", err)
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
