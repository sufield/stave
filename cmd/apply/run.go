package apply

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// runApply is the single dispatch function called by the thin RunE wrapper.
// All CLI state has already been extracted into cs. Context flows as the
// first parameter per Go convention.
func runApply(ctx context.Context, opts *Options, cs cobraState) error {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return fmt.Errorf("resolve project context: %w", err)
	}
	// ResolveSelected is called for its validation side-effect: it errors
	// out if no project context is selectable.
	if _, err = resolver.ResolveSelected(); err != nil {
		return fmt.Errorf("resolve selected context: %w", err)
	}

	if opts.DryRun {
		dryCfg, dryErr := ResolveDryRun(opts, cs)
		if dryErr != nil {
			return fmt.Errorf("resolve dry-run config: %w", dryErr)
		}
		return runDryRun(ctx, dryCfg)
	}

	if opts.Auto {
		if autoErr := printAutoPlan(cs.Stderr, opts); autoErr != nil {
			return fmt.Errorf("auto plan: %w", autoErr)
		}
	}

	if err = runStrictIntegrityCheck(cs.GlobalFlags.Strict, cs.Stdout, cs.Stderr); err != nil {
		return err // already wrapped inside runStrictIntegrityCheck
	}

	cfg, err := Resolve(opts, cs)
	if err != nil {
		return decorateError(err)
	}

	if cfg.IsProfileMode() {
		return runProfile(ctx, cs, cfg)
	}

	sio, err := ResolveStandardIO(opts, cs)
	if err != nil {
		return fmt.Errorf("resolve output config: %w", err)
	}
	return runStandardApply(ctx, cs, opts, sio, cfg)
}

// runStrictIntegrityCheck validates the embedded pack registry when --strict
// is set, under a progress span. The registry check itself lives in the
// facade (stave.StrictPackIntegrityCheck); the command adds the progress UI
// and the next-command hint.
func runStrictIntegrityCheck(strict bool, stdout, stderr io.Writer) error {
	if !strict {
		return nil
	}
	rt := ui.NewRuntime(stdout, stderr)
	done := rt.BeginProgress("perform strict integrity checks")
	defer done()
	if err := stave.StrictPackIntegrityCheck(); err != nil {
		return ui.WithNextCommand(err, "stave packs list")
	}
	return nil
}
