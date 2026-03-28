package validate

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/diag"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appvalidation "github.com/sufield/stave/internal/app/validation"
)

// runValidate is the primary entry point for the cobra command.
func runValidate(cmd *cobra.Command, newObsRepo compose.ObsRepoFactory, newCtlRepo compose.CtlRepoFactory, newCELEvaluator compose.CELEvaluatorFactory, rt *ui.Runtime, opts *options) error {
	// 1. Audit git status and log environment context.
	if err := opts.auditGitStatus(cmd); err != nil {
		return err
	}
	opts.logEnvironment()

	// 2. Resolve format via shared helper
	gf := cliflags.GetGlobalFlags(cmd)
	resolvedFormat, fmtErr := compose.ResolveFormatValue(cmd, opts.Format)
	if fmtErr != nil {
		return fmtErr
	}

	// 3. Initialize Reporter
	quiet := gf.Quiet
	rt.Quiet = quiet
	out := compose.ResolveStdout(cmd.OutOrStdout(), quiet, resolvedFormat)

	f := string(resolvedFormat)
	if opts.Template != "" {
		f = opts.Template
	}
	rep := &Reporter{
		Writer:   out,
		Format:   f,
		Strict:   opts.Strict,
		FixHints: opts.FixHints,
	}

	// 4. Branch: Single File vs. Full Project
	if opts.InputPath != "" {
		return runValidateSingleFile(cmd.InOrStdin(), rep, opts)
	}

	return runValidateProject(cmd, newObsRepo, newCtlRepo, newCELEvaluator, rt, rep, opts)
}

func runValidateProject(cmd *cobra.Command, newObsRepo compose.ObsRepoFactory, newCtlRepo compose.CtlRepoFactory, newCELEvaluator compose.CELEvaluatorFactory, rt *ui.Runtime, rep *Reporter, opts *options) error {
	// Prepare parameters (MaxUnsafe, Time, etc)
	params := opts.parseParams()
	if len(params.issues) > 0 {
		// If flag parsing itself generated diagnostic issues
		result := &appvalidation.Result{Diagnostics: &diag.Result{Issues: params.issues}}
		if err := rep.Write(result, opts.hintCtx()); err != nil {
			return err
		}
		return rep.ExitStatus(result)
	}

	// Start progress UI
	done := rt.BeginProgress("validate artifacts")
	result, err := executeValidateRun(cmd, newObsRepo, newCtlRepo, newCELEvaluator, params, opts)
	done()

	if err != nil {
		return err
	}

	// Add dynamic issues (e.g. checking project config packs)
	result.Diagnostics.AddAll(PackConfigIssues())

	// Write Output
	if err := rep.Write(result, opts.hintCtx()); err != nil {
		return err
	}

	// Print a helpful hint for the next step on success (if not quiet)
	exitErr := rep.ExitStatus(result)
	if exitErr == nil && !rt.Quiet {
		ui.WriteHint(cmd.ErrOrStderr(), fmt.Sprintf(
			"stave apply --controls %s --observations %s",
			opts.Controls, opts.Observations,
		))
	}

	return exitErr
}

func executeValidateRun(cmd *cobra.Command, newObsRepo compose.ObsRepoFactory, newCtlRepo compose.CtlRepoFactory, newCELEvaluator compose.CELEvaluatorFactory, params validateParams, opts *options) (*appvalidation.Result, error) {
	// Setup Repositories
	obsLoader, err := newObsRepo()
	if err != nil {
		return nil, fmt.Errorf("failed to init observation repository: %w", err)
	}
	ctlLoader, err := newCtlRepo()
	if err != nil {
		return nil, fmt.Errorf("failed to init control repository: %w", err)
	}
	celEval, err := newCELEvaluator()
	if err != nil {
		return nil, fmt.Errorf("failed to init CEL evaluator: %w", err)
	}

	// Execute Domain Logic
	runner := appvalidation.NewRun(obsLoader, ctlLoader)
	cfg := appvalidation.Config{
		ControlsDir:       opts.Controls,
		ObservationsDir:   opts.Observations,
		MaxUnsafeDuration: *params.maxUnsafe,
		NowTime:           params.nowTime,
		SanitizePaths:     cliflags.GetGlobalFlags(cmd).Sanitize,
		PredicateParser:   ctlyaml.ParsePredicate,
		PredicateEval:     celEval,
	}

	return runner.Execute(compose.CommandContext(cmd), cfg)
}
