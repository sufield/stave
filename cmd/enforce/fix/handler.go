package fix

import (
	"context"
	"io"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	"github.com/sufield/stave/internal/adapters/output"
	appfix "github.com/sufield/stave/internal/app/fix"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/platform/crypto"
)

// Runner is a thin CLI wrapper that delegates to internal/app/fix.Service.
type Runner struct {
	Provider    *compose.Provider
	Clock       ports.Clock
	Sanitizer   kernel.Sanitizer
	FileOptions cmdutil.FileOptions
	service     *appfix.Service
}

// NewRunner initializes a runner with required dependencies.
func NewRunner(p *compose.Provider, clock ports.Clock) *Runner {
	svc := appfix.NewService(clock, remediation.NewPlanner(crypto.NewHasher()))
	svc.ParseFindings = evaljson.ParseFindings
	return &Runner{
		Provider: p,
		Clock:    clock,
		service:  svc,
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
	err := r.service.Fix(ctx, appfix.FixRequest{
		InputPath:  req.InputPath,
		FindingRef: req.FindingRef,
		Stdout:     req.Stdout,
	})
	if err != nil {
		return &ui.UserError{Err: err}
	}
	return nil
}

// newEnvelopeBuilder creates an EnvelopeBuilder with adapter wiring.
func (r *Runner) newEnvelopeBuilder() *appfix.EnvelopeBuilder {
	return &appfix.EnvelopeBuilder{
		Sanitizer:     r.Sanitizer,
		IDGen:         crypto.NewHasher(),
		BuildEnvelope: output.BuildSafetyEnvelopeFromEnriched,
	}
}
