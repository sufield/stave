package diagnose

import (
	"context"
	"errors"
	"fmt"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// AuditRequest defines the parameters for generating security insights.
type AuditRequest struct {
	PolicySource      string
	ObservationSource string
	BaselineReport    *evaluation.ComplianceReport
	SLAThreshold      time.Duration
	Clock             ports.Clock
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
	PredicateEval     policy.PredicateEval
}

// DiagnosticEngine orchestrates the deep analysis of security policy evaluations.
type DiagnosticEngine struct {
	ObservationRepo appcontracts.ObservationRepository
	PolicyRepo      appcontracts.ControlRepository
	// BuiltinCatalog loads the embedded control catalog for the
	// "--controls absent" fallback. Wired by the composition root
	// (cmd/*); nil when the caller never exercises the empty-source
	// path. Keeps this package free of an adapters/* import.
	BuiltinCatalog appcontracts.BuiltinControlLoader
}

type auditContext struct {
	policies  []policy.ControlDefinition
	snapshots []asset.Snapshot
}

// NewEngine initializes a diagnostic engine with required data repositories.
func NewEngine(
	invRepo appcontracts.ObservationRepository,
	polRepo appcontracts.ControlRepository,
) (*DiagnosticEngine, error) {
	if invRepo == nil {
		return nil, errors.New("observation repository required")
	}
	if polRepo == nil {
		return nil, errors.New("policy repository required")
	}
	return &DiagnosticEngine{
		ObservationRepo: invRepo,
		PolicyRepo:      polRepo,
	}, nil
}

// Analyze performs a diagnostic analysis of the current security state.
func (e *DiagnosticEngine) Analyze(ctx context.Context, req AuditRequest) (*diagnosis.Report, error) {
	data, err := e.loadAuditData(ctx, req.PolicySource, req.ObservationSource)
	if err != nil {
		return nil, fmt.Errorf("load audit context: %w", err)
	}

	assessment, err := e.resolveAssessment(ctx, req, data)
	if err != nil {
		return nil, fmt.Errorf("resolve compliance assessment: %w", err)
	}

	input := diagnosis.NewInput(diagnosis.Input{
		Snapshots:         data.snapshots,
		Controls:          data.policies,
		Findings:          mapToDiagnosticFindings(assessment.Findings),
		ViolationsFound:   len(assessment.Findings),
		AttackSurface:     assessment.Summary.ExposedResources,
		MaxUnsafeDuration: req.SLAThreshold,
		Now:               req.Clock.Now(),
		PredicateEval:     req.PredicateEval,
	})

	report := diagnosis.Explain(input)
	return &report, nil
}

// InspectionRequest defines the parameters for a deep-dive analysis of a specific violation.
type InspectionRequest struct {
	AuditReq     AuditRequest
	TargetPolicy kernel.ControlID
	TargetAsset  asset.ID
	TraceBuilder evaluation.FindingTraceBuilder
	IDGen        ports.IdentityGenerator
}

// InspectViolation generates a detailed root-cause analysis for a single finding.
func (e *DiagnosticEngine) InspectViolation(ctx context.Context, req InspectionRequest) (*evaluation.FindingDetail, error) {
	data, err := e.loadAuditData(ctx, req.AuditReq.PolicySource, req.AuditReq.ObservationSource)
	if err != nil {
		return nil, fmt.Errorf("load audit context: %w", err)
	}

	assessment, err := e.resolveAssessment(ctx, req.AuditReq, data)
	if err != nil {
		return nil, fmt.Errorf("resolve compliance assessment: %w", err)
	}

	return BuildFindingDetail(FindingDetailInput{
		ControlID:    req.TargetPolicy,
		AssetID:      req.TargetAsset,
		Controls:     data.policies,
		Snapshots:    data.snapshots,
		Result:       assessment,
		TraceBuilder: req.TraceBuilder,
		IDGen:        req.IDGen,
	})
}

func (e *DiagnosticEngine) loadAuditData(
	ctx context.Context,
	policySrc string,
	observationSrc string,
) (auditContext, error) {
	// Empty policySrc selects the embedded built-in catalog (set by the
	// CLI's built-in-catalog fallback when --controls is absent).
	var policies []policy.ControlDefinition
	if policySrc == "" {
		if e.BuiltinCatalog == nil {
			return auditContext{}, errors.New("no controls source provided and no built-in catalog loader configured")
		}
		all, builtinErr := e.BuiltinCatalog()
		if builtinErr != nil {
			return auditContext{}, fmt.Errorf("load built-in control catalog: %w", builtinErr)
		}
		policies = all
	} else {
		loaded, err := appcontracts.LoadControls(ctx, e.PolicyRepo, policySrc)
		if err != nil {
			return auditContext{}, fmt.Errorf("fetch policies: %w", err)
		}
		policies = loaded
	}

	invResult, err := appcontracts.LoadSnapshots(ctx, e.ObservationRepo, observationSrc)
	if err != nil {
		return auditContext{}, fmt.Errorf("load observations: %w", err)
	}

	return auditContext{
		policies:  policies,
		snapshots: invResult.Snapshots,
	}, nil
}

func (e *DiagnosticEngine) resolveAssessment(
	ctx context.Context,
	req AuditRequest,
	data auditContext,
) (*evaluation.ComplianceReport, error) {
	if req.BaselineReport != nil {
		return req.BaselineReport, nil
	}

	assessment, err := appeval.Evaluate(ctx, appeval.EvaluateInput{
		Controls:          data.policies,
		Snapshots:         data.snapshots,
		MaxUnsafeDuration: req.SLAThreshold,
		Clock:             req.Clock,
		PredicateParser:   req.PredicateParser,
		CELEvaluator:      req.PredicateEval,
	})
	if err != nil {
		return nil, fmt.Errorf("evaluate compliance: %w", err)
	}
	return &assessment, nil
}

func mapToDiagnosticFindings(findings []evaluation.Finding) []diagnosis.DiagnosticFinding {
	out := make([]diagnosis.DiagnosticFinding, len(findings))
	for i := range findings {
		f := &findings[i]
		snap := f.Evidence.TemporalSnapshot()
		out[i] = diagnosis.DiagnosticFinding{
			AssetID:             f.AssetID,
			ControlID:           f.ControlID,
			FirstUnsafeAt:       snap.FirstUnsafeAt,
			LastSeenUnsafeAt:    snap.LastSeenUnsafeAt,
			UnsafeDurationHours: snap.UnsafeDurationHours,
			ThresholdHours:      snap.ThresholdHours,
		}
	}
	return out
}
