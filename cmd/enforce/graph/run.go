package graph

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

// runCoverage validates the input directories (exit 2), delegates the
// load → build → render pipeline to the facade, and writes the rendered
// coverage graph.
func runCoverage(ctx context.Context, opts *coverageOptions, gf cliflags.GlobalFlags, stdout io.Writer) error {
	controlsDir := fsutil.CleanUserPath(opts.ControlsDir)
	observationsDir := fsutil.CleanUserPath(opts.ObservationsDir)

	// Directory validation stays command-side so a missing/unreadable dir is
	// a user error (exit 2) rather than a plain load failure (exit 4).
	if err := dircheck.ValidateFlagDir("--controls", controlsDir, "", nil, nil); err != nil {
		return &ui.UserError{Err: fmt.Errorf("invalid controls directory: %w", err)}
	}
	if err := dircheck.ValidateFlagDir("--observations", observationsDir, "", nil, nil); err != nil {
		return &ui.UserError{Err: fmt.Errorf("invalid observations directory: %w", err)}
	}

	out, err := stave.CoverageGraph(ctx, stave.CoverageGraphConfig{
		ControlsDir:     controlsDir,
		ObservationsDir: observationsDir,
		Format:          opts.Format,
		SanitizeIDs:     gf.Sanitize,
		PathMode:        string(gf.PathMode),
	})
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("loading artifacts"/"render..."); preserve exit 4.
	}

	if _, werr := stdout.Write(out); werr != nil {
		return fmt.Errorf("write coverage graph: %w", werr)
	}
	return nil
}
