package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// resolvePackAllowlist expands --pack and --services into the union of their
// control IDs via the pkg/stave facade. Returns nil when neither is set (the
// eval then runs every control, unchanged). An unknown pack surfaces as a
// UserError → exit 2.
func resolvePackAllowlist(opts *Options, cfg RunConfig) ([]string, error) {
	packIDs, err := stave.ResolvePackControls(opts.Packs, cfg.ControlsDir, cfg.UseBuiltinCatalog)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return nil, &ui.UserError{Err: err}
		}
		return nil, &ui.UserError{Err: fmt.Errorf("resolve --pack: %w", err)}
	}
	svcIDs, err := stave.ResolveServiceControls(opts.Services, cfg.ControlsDir, cfg.UseBuiltinCatalog)
	if err != nil {
		return nil, &ui.UserError{Err: fmt.Errorf("resolve --services: %w", err)}
	}
	if len(opts.Packs) == 0 && len(opts.Services) == 0 {
		return nil, nil // no scoping
	}
	// Union: a control runs if it's in any selected pack or any selected service.
	seen := map[string]bool{}
	var ids []string
	for _, id := range append(packIDs, svcIDs...) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		// Scoping was requested but matched nothing (e.g. a typo'd --services).
		// Fail loud rather than silently fall back to evaluating every control.
		return nil, &ui.UserError{Err: fmt.Errorf("%w: --pack/--services matched no controls in the catalog", stave.ErrInvalidInput)}
	}
	return ids, nil
}

// runStandardApply executes the standard evaluation through the pkg/stave
// facade. The command owns flag/path resolution, the progress runtime, the
// stdout/stderr writes, and exit-code routing; the load → evaluate → enrich →
// render pipeline (including --new-only and --assert-recent) lives in
// stave.EvaluateStandard.
func runStandardApply(ctx context.Context, cs cobraState, opts *Options, sio StandardIO, cfg RunConfig) error {
	pc, pcErr := resolveProjectContext()
	if pcErr != nil {
		return decorateError(pcErr)
	}

	packAllow, packErr := resolvePackAllowlist(opts, cfg)
	if packErr != nil {
		return packErr
	}

	// --all evaluates the full catalog and renders findings grouped per service
	// then compound, so any --pack/--services scoping is ignored and the report
	// format is JSON internally (re-rendered staged below).
	reportFormat := string(sio.Format)
	if opts.AllStaged {
		packAllow = nil
		reportFormat = "json"
	}

	rt := ui.NewRuntime(sio.Stdout, sio.Stderr)
	rt.Quiet = sio.Quiet

	done := rt.BeginProgress("apply controls against observations")
	res, err := stave.EvaluateStandard(ctx, stave.StandardRequest{
		ControlIDAllowlist: packAllow,
		ControlsDir:        cfg.ControlsDir,
		ObservationsDir:    cfg.ObservationsDir,
		MaxUnsafe:          opts.MaxUnsafeDuration,
		EvalTime:           opts.EvalTimeRaw,
		SanitizeIDs:        cs.GlobalFlags.Sanitize,
		PathMode:           string(cs.GlobalFlags.PathMode),
		Format:             reportFormat,
		Verbose:            opts.Verbose,
		ExemptionFile:      opts.ExemptionFile,
		AckFile:            opts.AcknowledgmentFile,
		IntegrityManifest:  opts.IntegrityManifest,
		IntegrityPublicKey: opts.IntegrityPublicKey,
		SLAProfile:         opts.SLAProfile,
		SLAProfileFile:     opts.SLAProfileFile,
		TeamManifest:       opts.TeamManifest,
		OwnerFilter:        opts.OwnerFilter,
		TracePath:          opts.TracePath,
		UseBuiltin:         cfg.UseBuiltinCatalog,
		ContextName:        pc.ContextName,
		ControlsFlagSet:    opts.controlsSet,
		AssertRecent:       opts.AssertRecent,
		FreshnessThreshold: opts.FreshnessThreshold,
		SkipFreshness:      opts.SkipFreshness,
		Stdin:              cs.Stdin,
		ProjectConfigPath:  cfg.projectConfigPath,
		NewOnly:            opts.IsNewOnlyMode(),
		NewSince:           opts.NewSince,
		HistoryDir:         opts.HistoryDir,
		GraphFindingsDir:   opts.GraphFindingsDir,
	})
	done()

	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return decorateError(err)
	}

	// --all: render the staged (per-service then compound) view over the JSON
	// findings, then apply the same violation + SLA gates as the normal path.
	if opts.AllStaged {
		if rerr := renderAllStaged(res.Output, sio.Stdout); rerr != nil {
			return decorateError(rerr)
		}
		for _, w := range res.Warnings {
			fmt.Fprintln(sio.Stderr, w)
		}
		if gateErr := gateViolations(res); gateErr != nil {
			return gateErr
		}
		return NewReporter(sio, rt).CheckSLAPolicy(SLAPolicy(opts.SLAPolicy), res)
	}

	if _, werr := sio.Stdout.Write(res.Output); werr != nil {
		return fmt.Errorf("write evaluation output: %w", werr)
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(sio.Stderr, w)
	}

	rep := NewReporter(sio, rt)

	// Signal-filtered (--new-only) view already rendered its own output;
	// skip the standard summary but keep the violation + SLA gates.
	if opts.IsNewOnlyMode() {
		if gateErr := gateViolations(res); gateErr != nil {
			return gateErr
		}
		return rep.CheckSLAPolicy(SLAPolicy(opts.SLAPolicy), res)
	}

	if reportErr := rep.ReportApply(res); reportErr != nil {
		return reportErr
	}
	return rep.CheckSLAPolicy(SLAPolicy(opts.SLAPolicy), res)
}
