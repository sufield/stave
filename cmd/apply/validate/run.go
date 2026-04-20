package validate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/app/staleness"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/config"
	"github.com/sufield/stave/internal/core/diag"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appvalidation "github.com/sufield/stave/internal/app/validation"
)

// validateDeps bundles the factory functions needed by the validate workflow,
// preventing the same 3 params from being repeated in every function signature.
type validateDeps struct {
	NewObsRepo      compose.ObsRepoFactory
	NewCtlRepo      compose.CtlRepoFactory
	NewCELEvaluator compose.CELEvaluatorFactory
}

// Input is the per-run payload for the validate command. All
// cobra-owned values (io, logger, global flags) are resolved at the
// RunE boundary so runValidate and its helpers stay off the cobra
// import graph. Context is passed as the first function argument
// per Go convention rather than stored on the struct.
type Input struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Logger *slog.Logger
	Global config.GlobalSettings
	Format appcontracts.OutputFormat
	Deps   validateDeps
	Rt     *ui.Runtime
	Opts   *options
}

// runValidate is the primary entry point for the cobra command.
func runValidate(ctx context.Context, in Input) error {
	// 1. Audit git status and log environment context.
	if err := in.Opts.auditGitStatus(ctx, in.Stderr, in.Global); err != nil {
		return err
	}
	in.Opts.logEnvironment()

	// 2. Initialize Reporter
	quiet := in.Global.Quiet
	in.Rt.Quiet = quiet
	out := compose.ResolveStdout(in.Stdout, quiet, in.Format)

	f := string(in.Format)
	if in.Opts.Template != "" {
		f = in.Opts.Template
	}
	rep := &Reporter{
		Writer:   out,
		Format:   f,
		Strict:   in.Opts.Strict,
		FixHints: in.Opts.FixHints,
	}

	// 3. Branch: Single File vs. Full Project
	if in.Opts.InputPath != "" {
		return runValidateSingleFile(in.Stdin, rep, in.Opts)
	}

	return runValidateProject(ctx, in, rep)
}

func runValidateProject(ctx context.Context, in Input, rep *Reporter) error {
	// Prepare parameters (MaxUnsafe, Time, etc)
	params := in.Opts.parseParams()
	if len(params.issues) > 0 {
		// If flag parsing itself generated diagnostic issues
		result := &appvalidation.Report{Diagnostics: &diag.Assessment{Findings: params.issues}}
		if err := rep.Write(result, in.Opts.hintCtx()); err != nil {
			return err
		}
		return rep.ExitStatus(result)
	}

	// Start progress UI
	done := in.Rt.BeginProgress("validate artifacts")
	result, err := executeValidateRun(ctx, in, params)
	done()

	if err != nil {
		return err
	}

	// Add dynamic issues (e.g. checking project config packs)
	result.Diagnostics.RecordAll(PackConfigIssues())

	// Write Output
	if err := rep.Write(result, in.Opts.hintCtx()); err != nil {
		return err
	}

	// Staleness check: --assert-recent.
	if in.Opts.AssertRecent != "" {
		threshold, parseErr := time.ParseDuration(in.Opts.AssertRecent)
		if parseErr != nil {
			return &ui.UserError{Err: fmt.Errorf("parse --assert-recent: %w", parseErr)}
		}
		now := time.Now().UTC()
		if params.nowTime != (time.Time{}) {
			now = params.nowTime
		}
		snapshots, snapErr := compose.LoadSnapshotsFrom(ctx, in.Deps.NewObsRepo, in.Opts.Observations)
		if snapErr != nil {
			return fmt.Errorf("load snapshots for staleness check: %w", snapErr)
		}
		sr := staleness.Check(snapshots, threshold, now)
		if sr.Stale {
			return &ui.UserError{Err: fmt.Errorf("%s", sr.Message)}
		}
	}

	// Print a helpful hint for the next step on success (if not quiet)
	exitErr := rep.ExitStatus(result)
	if exitErr == nil && !in.Rt.Quiet {
		ui.WriteHint(in.Stderr, fmt.Sprintf(
			"stave apply --controls %s --observations %s",
			in.Opts.Controls, in.Opts.Observations,
		))
	}

	return exitErr
}

func executeValidateRun(ctx context.Context, in Input, params validateParams) (*appvalidation.Report, error) {
	// Setup Repositories
	obsLoader, err := in.Deps.NewObsRepo()
	if err != nil {
		return nil, fmt.Errorf("failed to init observation repository: %w", err)
	}
	ctlLoader, err := in.Deps.NewCtlRepo()
	if err != nil {
		return nil, fmt.Errorf("failed to init control repository: %w", err)
	}
	celEval, err := in.Deps.NewCELEvaluator()
	if err != nil {
		return nil, fmt.Errorf("failed to init CEL evaluator: %w", err)
	}

	// Execute Domain Logic
	runner := appvalidation.NewRun(obsLoader, ctlLoader)
	cfg := appvalidation.Config{
		ControlsDir:       in.Opts.Controls,
		ObservationsDir:   in.Opts.Observations,
		MaxUnsafeDuration: *params.maxUnsafe,
		NowTime:           params.nowTime,
		SanitizePaths:     in.Global.Sanitize,
		PredicateParser:   ctlyaml.ParsePredicate,
		PredicateEval:     celEval,
	}

	return runner.Execute(ctx, cfg)
}
