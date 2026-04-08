// Package attestation provides before/after evaluation comparison logic
// for remediation verification workflows.
package attestation

import (
	"context"
	"fmt"
	"io"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/report"
	staveversion "github.com/sufield/stave/internal/version"
)

// WorkflowDeps holds the infrastructure requirements for the attestation process.
type WorkflowDeps struct {
	LoadPolicies       func(ctx context.Context, dir string) ([]policy.ControlDefinition, error)
	NewInventoryRepo   func() (appcontracts.ObservationRepository, error)
	PublishAttestation func(w io.Writer, a *report.Attestation) error

	// BeginStage starts a visual progress indicator for a workflow stage.
	BeginStage func(label string) func()
}

// Request defines the parameters for a remediation attestation run.
type Request struct {
	BaselineSource string
	TargetSource   string
	PolicySource   string
	SLAThreshold   time.Duration
	Clock          ports.Clock
	AllowUnknown   bool
	Quiet          bool
	Sanitizer      kernel.Sanitizer
	Stdout         io.Writer
	PredicateEval  policy.PredicateEval
}

// PerformAttestation executes the baseline-vs-target comparison to verify remediation.
func PerformAttestation(ctx context.Context, deps WorkflowDeps, req Request) error {
	beginStage := deps.BeginStage
	if beginStage == nil {
		beginStage = func(string) func() { return func() {} }
	}

	// 1. Load security policies
	controls, err := deps.LoadPolicies(ctx, req.PolicySource)
	if err != nil {
		return err
	}
	if len(controls) == 0 {
		return fmt.Errorf("%w: no controls found in %s", appeval.ErrNoControls, req.PolicySource)
	}

	// 2. Conduct assessments
	baseline, err := executeStage(beginStage, "analyzing baseline inventory", func() (assessmentState, error) {
		return conductAssessment(ctx, deps, req, controls, req.BaselineSource)
	})
	if err != nil {
		return fmt.Errorf("baseline assessment failed: %w", err)
	}

	target, err := executeStage(beginStage, "analyzing target inventory", func() (assessmentState, error) {
		return conductAssessment(ctx, deps, req, controls, req.TargetSource)
	})
	if err != nil {
		return fmt.Errorf("target assessment failed: %w", err)
	}

	// 3. Compare states
	comparison, err := Compare(CompareRequest{
		BaselineFindings:  baseline.report.Findings,
		TargetFindings:    target.report.Findings,
		BaselineSnapshots: baseline.inventoryCount,
		TargetSnapshots:   target.inventoryCount,
		SLAThreshold:      req.SLAThreshold,
		Now:               req.Clock.Now(),
		Sanitizer:         req.Sanitizer,
	})
	if err != nil {
		return err
	}

	// 4. Publish the attestation report
	if err := deps.PublishAttestation(req.Stdout, comparison.Attestation); err != nil {
		return fmt.Errorf("failed to write attestation report: %w", err)
	}

	return evaluateSuccess(comparison)
}

// --- Internal ---

type assessmentState struct {
	report         *evaluation.ComplianceReport
	inventoryCount int
}

func conductAssessment(ctx context.Context, deps WorkflowDeps, req Request, controls []policy.ControlDefinition, src string) (assessmentState, error) {
	loader, err := deps.NewInventoryRepo()
	if err != nil {
		return assessmentState{}, err
	}

	res, count, err := appeval.RunDirectoryEvaluation(ctx, appeval.DirectoryEvaluationRequest{
		ObservationsDir:   src,
		Controls:          controls,
		MaxUnsafeDuration: req.SLAThreshold,
		Clock:             req.Clock,
		AllowUnknownType:  req.AllowUnknown,
		StaveVersion:      staveversion.String,
		ObservationLoader: loader,
		CELEvaluator:      req.PredicateEval,
	})
	if err != nil {
		return assessmentState{}, err
	}
	return assessmentState{report: res, inventoryCount: count}, nil
}

func evaluateSuccess(outcome CompareResult) error {
	if outcome.OpenCount == 0 && outcome.RegressionCount == 0 {
		return nil
	}
	return appcontracts.ErrViolationsFound
}

func executeStage[T any](beginStage func(string) func(), label string, fn func() (T, error)) (T, error) {
	done := beginStage(label)
	res, err := fn()
	done()
	return res, err
}
