package fix

import (
	"context"
	"io"
	"io/fs"
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

// Loop delegates to the app-layer fix-loop service.
func (r *Runner) Loop(ctx context.Context, req LoopRequest) error {
	r.service.Sanitizer = r.Sanitizer

	controlRepo, err := r.NewCtlRepo()
	if err != nil {
		return err
	}

	deps := appfix.LoopDeps{
		ObservationRepoFactory: func() (contracts.ObservationRepository, error) {
			return r.NewObsRepo()
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
		MkdirAllFn: func(path string, perm fs.FileMode) error {
			return fsutil.SafeMkdirAll(path, fsutil.WriteOptions{
				Perm:         perm,
				AllowSymlink: r.FileOptions.AllowSymlinks,
			})
		},
		WriteFileFn: func(path string, data []byte, perm fs.FileMode) error {
			return fsutil.SafeWriteFile(path, data, fsutil.WriteOptions{
				Perm:         perm,
				Overwrite:    r.FileOptions.Overwrite,
				AllowSymlink: r.FileOptions.AllowSymlinks,
			})
		},
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
