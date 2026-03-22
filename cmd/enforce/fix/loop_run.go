package fix

import (
	"context"
	"io"
	"time"

	"github.com/sufield/stave/internal/app/contracts"
	appfix "github.com/sufield/stave/internal/app/fix"
	"github.com/sufield/stave/internal/cli/ui"
)

// LoopRequest defines the inputs for the fix-loop workflow.
type LoopRequest struct {
	BeforeDir         string
	AfterDir          string
	ControlsDir       string
	OutDir            string
	MaxUnsafeDuration time.Duration
	AllowUnknown      bool
	Stdout            io.Writer
	Stderr            io.Writer
}

// Loop delegates to the app-layer fix-loop service.
func (r *Runner) Loop(ctx context.Context, req LoopRequest) error {
	r.service.Sanitizer = r.Sanitizer

	controlRepo, err := r.Provider.NewControlRepo()
	if err != nil {
		return err
	}

	deps := appfix.LoopDeps{
		ObservationRepoFactory: func() (contracts.ObservationRepository, error) {
			return r.Provider.NewObservationRepo()
		},
		ControlRepo: controlRepo,
	}

	am := &appfix.ArtifactWriter{
		OutDir: req.OutDir,
		Options: appfix.WriteOptions{
			Overwrite:     r.FileOptions.Overwrite,
			AllowSymlinks: r.FileOptions.AllowSymlinks,
			DirPerms:      r.FileOptions.DirPerms,
		},
		Stdout: req.Stdout,
	}

	eb := r.newEnvelopeBuilder()

	err = r.service.Loop(ctx, appfix.LoopRequest{
		BeforeDir:         req.BeforeDir,
		AfterDir:          req.AfterDir,
		ControlsDir:       req.ControlsDir,
		OutDir:            req.OutDir,
		MaxUnsafeDuration: req.MaxUnsafeDuration,
		AllowUnknown:      req.AllowUnknown,
		Stdout:            req.Stdout,
		Stderr:            req.Stderr,
	}, deps, am, eb)

	if err == appfix.ErrViolationsRemaining {
		return ui.ErrViolationsFound
	}
	return err
}
