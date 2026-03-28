package fix

import (
	"context"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/fileout"
	evaljson "github.com/sufield/stave/internal/adapters/evaluation"
	"github.com/sufield/stave/internal/adapters/output"
	appfix "github.com/sufield/stave/internal/app/fix"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
)

// Runner is a thin CLI wrapper that delegates to internal/app/fix.Service.
type Runner struct {
	Clock       ports.Clock
	Sanitizer   kernel.Sanitizer
	FileOptions fileout.FileOptions
	service     *appfix.Service
	// Loop dependencies (set by caller before Loop()).
	NewCtlRepo compose.CtlRepoFactory
	NewObsRepo compose.ObsRepoFactory
}

// NewRunner initializes a runner with a pre-resolved CEL evaluator.
func NewRunner(celEval policy.PredicateEval, clock ports.Clock) *Runner {
	svc := appfix.NewService(clock, remediation.NewPlanner(crypto.NewHasher()))
	svc.ParseFindings = evaljson.ParseFindings
	svc.CELEvaluator = celEval
	return &Runner{
		Clock:   clock,
		service: svc,
	}
}

// Request defines the parameters for a single-finding fix operation.
type Request struct {
	InputPath  string
	FindingRef string
	Stdout     io.Writer
}

// Run delegates to the app-layer fix service.
func (r *Runner) Run(ctx context.Context, req Request) error {
	return r.service.Fix(ctx, appfix.FixRequest{
		InputPath:  req.InputPath,
		FindingRef: req.FindingRef,
		Stdout:     req.Stdout,
	})
}

// newEnvelopeBuilder creates an EnvelopeBuilder with adapter wiring.
func (r *Runner) newEnvelopeBuilder() *appfix.EnvelopeBuilder {
	return &appfix.EnvelopeBuilder{
		Sanitizer:     r.Sanitizer,
		IDGen:         crypto.NewHasher(),
		BuildEnvelope: output.BuildSafetyEnvelopeFromEnriched,
	}
}
