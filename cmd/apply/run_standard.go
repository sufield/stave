package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

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

	rt := ui.NewRuntime(sio.Stdout, sio.Stderr)
	rt.Quiet = sio.Quiet

	// Disclosed fallback: no --controls and no controls/ dir → embedded catalog.
	if cfg.UseBuiltinCatalog {
		fmt.Fprintf(sio.Stderr, "note: no --controls given and no controls/ directory found — "+
			"evaluating against the built-in control catalog. Pass --controls <dir> to use your own.\n")
	}

	done := rt.BeginProgress("apply controls against observations")
	res, err := stave.EvaluateStandard(ctx, stave.StandardRequest{
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

	if reportErr := rep.ReportApply(res, cfg.ControlsDir, cfg.ObservationsDir); reportErr != nil {
		return reportErr
	}
	return rep.CheckSLAPolicy(SLAPolicy(opts.SLAPolicy), res)
}
