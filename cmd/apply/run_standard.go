package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// resolvePackAllowlist expands --pack names into the union of their control IDs
// via the pkg/stave facade. Returns nil when no pack is set (the eval then runs
// every control, unchanged). An unknown pack surfaces as a UserError → exit 2.
func resolvePackAllowlist(opts *Options, cfg RunConfig) ([]string, error) {
	ids, err := stave.ResolvePackControls(opts.Packs, cfg.ControlsDir, cfg.UseBuiltinCatalog)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return nil, &ui.UserError{Err: err}
		}
		return nil, &ui.UserError{Err: fmt.Errorf("resolve --pack: %w", err)}
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

	rt := ui.NewRuntime(sio.Stdout, sio.Stderr)
	rt.Quiet = sio.Quiet

	done := rt.BeginProgress("apply controls against observations")
	res, err := stave.EvaluateStandard(ctx, stave.StandardRequest{
		ControlIDAllowlist: packAllow,
		ControlsDir:        cfg.ControlsDir,
		ObservationsDir:    cfg.ObservationsDir,
		MaxUnsafe:          opts.MaxUnsafeDuration,
		Now:                opts.NowTime,
		SanitizeIDs:        cs.GlobalFlags.Sanitize,
		PathMode:           string(cs.GlobalFlags.PathMode),
		Format:             string(sio.Format),
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
		Stdin:              cs.Stdin,
		ProjectConfigPath:  cfg.projectConfigPath,
		NewOnly:            opts.IsNewOnlyMode(),
		NewSince:           opts.NewSince,
		HistoryDir:         opts.HistoryDir,
	})
	done()

	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return decorateError(err)
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
