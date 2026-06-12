package apply

import (
	"context"
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
)

// runApply is the single dispatch function called by the thin RunE wrapper.
// All CLI state has already been extracted into cs. Context flows as the
// first parameter per Go convention.
func runApply(ctx context.Context, deps Deps, opts *Options, cs cobraState) error {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return fmt.Errorf("resolve project context: %w", err)
	}
	// ResolveSelected is called for its validation side-effect: it
	// errors out if no project context is selectable. The resolved
	// Context value itself is not needed here because Resolve(opts, cs)
	// below threads through projctx separately when wiring the apply
	// pipeline; capturing it would force a downstream pass-through that
	// drifts out of sync with that pipeline's own resolution.
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
	return runStandardApply(ctx, cs.Logger, deps, opts, *cfg.Params, sio, cfg)
}
