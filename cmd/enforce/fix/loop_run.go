package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/app/contracts"
	appfix "github.com/sufield/stave/internal/app/fix"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
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

// loopInfra holds the initialized dependencies for the fix-loop workflow.
type loopInfra struct {
	deps   appfix.LoopDeps
	writer *appfix.ArtifactWriter
	eb     *appfix.EnvelopeBuilder
}

// buildLoopInfra initializes all dependencies needed by the fix-loop.
func (r *Runner) buildLoopInfra(req LoopRequest) (loopInfra, error) {
	if r.NewCtlRepo == nil {
		return loopInfra{}, fmt.Errorf("fix-loop requires a control repository factory")
	}
	if r.NewObsRepo == nil {
		return loopInfra{}, fmt.Errorf("fix-loop requires an observation repository factory")
	}

	controlRepo, err := r.NewCtlRepo()
	if err != nil {
		return loopInfra{}, fmt.Errorf("init control repo: %w", err)
	}

	writer, err := appfix.NewArtifactWriter(
		req.OutDir,
		appfix.WriteOptions{
			Overwrite:     r.FileOptions.Overwrite,
			AllowSymlinks: r.FileOptions.AllowSymlinks,
			DirPerms:      r.FileOptions.DirPerms,
		},
		req.Stdout,
		fsutil.SafeFileSystem{
			Overwrite:    r.FileOptions.Overwrite,
			AllowSymlink: r.FileOptions.AllowSymlinks,
		},
	)
	if err != nil {
		return loopInfra{}, fmt.Errorf("init artifact writer: %w", err)
	}

	return loopInfra{
		deps: appfix.LoopDeps{
			ObservationRepoFactory: func() (contracts.ObservationRepository, error) {
				return r.NewObsRepo()
			},
			ControlRepo: controlRepo,
		},
		writer: writer,
		eb:     r.newEnvelopeBuilder(),
	}, nil
}

// Loop delegates to the app-layer fix-loop service.
func (r *Runner) Loop(ctx context.Context, req LoopRequest) error {
	r.service.Sanitizer = r.Sanitizer

	infra, err := r.buildLoopInfra(req)
	if err != nil {
		return err
	}

	err = r.service.Loop(ctx, appfix.LoopRequest{
		BeforeDir:         req.BeforeDir,
		AfterDir:          req.AfterDir,
		ControlsDir:       req.ControlsDir,
		OutDir:            req.OutDir,
		MaxUnsafeDuration: req.MaxUnsafeDuration,
		AllowUnknown:      req.AllowUnknown,
		Stdout:            req.Stdout,
		Stderr:            req.Stderr,
	}, infra.deps, infra.writer, infra.eb)

	if errors.Is(err, appfix.ErrViolationsRemaining) {
		return ui.ErrViolationsFound
	}
	return err
}
