package diff

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// run builds the drift config from the flags + global settings, shows a
// progress span while the facade computes and renders the delta, and writes
// the rendered bytes (suppressed in quiet mode).
func run(ctx context.Context, opts *Options, gf cliflags.GlobalFlags, stdout, stderr io.Writer) error {
	// Quiet mode discards stdout (the diff report); the progress span on
	// stderr is suppressed separately via progress.Quiet.
	out := stdout
	if !gf.TextOutputEnabled() {
		out = io.Discard
	}

	progress := ui.NewRuntime(out, stderr)
	progress.Quiet = gf.Quiet
	stop := progress.BeginProgress("Computing observation delta")
	defer stop()

	rendered, err := stave.DiffObservationDrift(ctx, stave.ObservationDriftConfig{
		ObservationsDir: opts.ObservationsDir,
		Format:          opts.Format,
		ChangeTypes:     opts.ChangeTypes,
		AssetTypes:      opts.AssetTypes,
		AssetID:         opts.AssetID,
		SanitizeIDs:     gf.Sanitize,
		PathMode:        string(gf.PathMode),
	})
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("loading snapshots"/"render..."); preserve exit 4.
	}

	if _, werr := out.Write(rendered); werr != nil {
		return fmt.Errorf("write diff output: %w", werr)
	}
	return nil
}
