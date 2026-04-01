package verify

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
	"github.com/sufield/stave/internal/safetyenvelope"
	staveversion "github.com/sufield/stave/internal/version"
)

// VerifyDeps holds injected infrastructure dependencies for the verify workflow.
type VerifyDeps struct {
	LoadControls       func(ctx context.Context, dir string) ([]policy.ControlDefinition, error)
	NewObservationRepo func() (appcontracts.ObservationRepository, error)
	WriteVerification  func(w io.Writer, v *safetyenvelope.Verification) error

	// BeginProgress starts a progress indicator with the given label and returns
	// a stop function. If nil, progress reporting is silently skipped.
	BeginProgress func(label string) func()
}

// VerifyRequest holds the fully-resolved parameters for a verify run.
type VerifyRequest struct {
	Ctx               context.Context
	BeforeDir         string
	AfterDir          string
	ControlsDir       string
	MaxUnsafeDuration time.Duration
	Clock             ports.Clock
	AllowUnknown      bool
	Quiet             bool
	Sanitizer         kernel.Sanitizer
	Stdout            io.Writer
	CELEvaluator      policy.PredicateEval
}

// RunVerify executes the before/after comparison workflow.
func RunVerify(deps VerifyDeps, req VerifyRequest) error {
	beginProgress := deps.BeginProgress
	if beginProgress == nil {
		beginProgress = func(string) func() { return func() {} }
	}

	// 1. Load controls
	controls, err := deps.LoadControls(req.Ctx, req.ControlsDir)
	if err != nil {
		return err
	}
	if len(controls) == 0 {
		return fmt.Errorf("%w: no controls found in %s", appeval.ErrNoControls, req.ControlsDir)
	}

	// 2. Run evaluations
	before, err := runStep(beginProgress, "apply before observations", func() (evalResult, error) {
		return runEvaluation(deps, req, controls, req.BeforeDir)
	})
	if err != nil {
		return fmt.Errorf("before evaluation: %w", err)
	}

	after, err := runStep(beginProgress, "apply after observations", func() (evalResult, error) {
		return runEvaluation(deps, req, controls, req.AfterDir)
	})
	if err != nil {
		return fmt.Errorf("after evaluation: %w", err)
	}

	// 3. Compare
	cmp, err := Compare(CompareRequest{
		BeforeFindings:    before.result.Findings,
		AfterFindings:     after.result.Findings,
		BeforeSnapshots:   before.snapshotCount,
		AfterSnapshots:    after.snapshotCount,
		MaxUnsafeDuration: req.MaxUnsafeDuration,
		Now:               req.Clock.Now(),
		Sanitizer:         req.Sanitizer,
	})
	if err != nil {
		return err
	}

	// 4. Write output
	if err := deps.WriteVerification(req.Stdout, cmp.Verification); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}

	return handleExit(cmp)
}

// --- Internal ---

type evalResult struct {
	result        *evaluation.Result
	snapshotCount int
}

func runEvaluation(deps VerifyDeps, req VerifyRequest, controls []policy.ControlDefinition, obsDir string) (evalResult, error) {
	loader, err := deps.NewObservationRepo()
	if err != nil {
		return evalResult{}, err
	}

	res, snaps, err := appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           req.Ctx,
		ObservationsDir:   obsDir,
		Controls:          controls,
		MaxUnsafeDuration: req.MaxUnsafeDuration,
		Clock:             req.Clock,
		AllowUnknownType:  req.AllowUnknown,
		StaveVersion:      staveversion.String,
		ObservationLoader: loader,
		CELEvaluator:      req.CELEvaluator,
	})
	if err != nil {
		return evalResult{}, err
	}
	return evalResult{result: res, snapshotCount: snaps}, nil
}

func handleExit(outcome CompareResult) error {
	if outcome.RemainingCount == 0 && outcome.IntroducedCount == 0 {
		return nil
	}
	return appcontracts.ErrViolationsFound
}

func runStep[T any](beginProgress func(string) func(), label string, fn func() (T, error)) (T, error) {
	done := beginProgress(label)
	res, err := fn()
	done()
	return res, err
}
