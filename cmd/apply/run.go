package apply

import (
	"context"
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// runApply is the single dispatch function called by the thin RunE wrapper.
// All CLI state has already been extracted into cs. Context flows as the
// first parameter per Go convention.
func runApply(ctx context.Context, p *compose.Provider, opts *ApplyOptions, cs cobraState) error {
	if err := opts.validate(); err != nil {
		return fmt.Errorf("validate options: %w", err)
	}

	resolver, err := projctx.NewResolver()
	if err != nil {
		return fmt.Errorf("resolve project context: %w", err)
	}
	if _, err = resolver.ResolveSelected(); err != nil {
		return fmt.Errorf("resolve selected context: %w", err)
	}

	if opts.DryRun {
		dryCfg, dryErr := ResolveDryRun(opts, cs)
		if dryErr != nil {
			return fmt.Errorf("resolve dry-run config: %w", dryErr)
		}
		return runDryRun(ctx, p, dryCfg)
	}

	if err = runStrictIntegrityCheck(cs.GlobalFlags.Strict, cs.Stdout, cs.Stderr); err != nil {
		return err // already wrapped inside runStrictIntegrityCheck
	}

	cfg, err := Resolve(opts, cs)
	if err != nil {
		return decorateError(err)
	}

	if cfg.Mode == runModeProfile {
		rt := ui.NewRuntime(cs.Stdout, cs.Stderr)
		rt.Quiet = cfg.Profile.Quiet
		runner := NewRunner(
			p.NewCELEvaluator,
			func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
				return compose.LoadControls(ctx, p, dir)
			},
			p.NewFindingWriter,
			WithClock(cfg.profileClock),
			WithUI(rt),
		)
		return runner.Run(ctx, *cfg.Profile)
	}

	sio, err := ResolveStandardIO(opts, cs)
	if err != nil {
		return fmt.Errorf("resolve output config: %w", err)
	}
	return runStandardApply(ctx, cs.Logger, p, opts, *cfg.Params, sio, cfg)
}
