package validate

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/diag"

	appservice "github.com/sufield/stave/internal/app/service"
	appvalidation "github.com/sufield/stave/internal/app/validation"
)

// newReporter builds a Reporter from the resolved format and options.
func newReporter(out io.Writer, format ui.OutputFormat, opts *options) *Reporter {
	f := string(format)
	if opts.Template != "" {
		f = opts.Template
	}
	return &Reporter{
		Writer:   out,
		Format:   f,
		Strict:   opts.StrictMode,
		FixHints: opts.FixHints,
		IsJSON:   format.IsJSON(),
	}
}

// runValidateWithOptions parses flags, calls app layer, prints results, and sets exit code.
func runValidateWithOptions(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	format, err := prepareValidateCommand(cmd, opts)
	if err != nil {
		return err
	}

	quiet := opts.QuietMode || cmdutil.QuietEnabled(cmd)
	rt.Quiet = quiet
	out := compose.ResolveStdout(cmd, quiet, format)
	if opts.InFile != "" {
		return runValidateSingleFileWithOptions(cmd, out, opts, format)
	}
	if err := ensureValidateModeFlags(opts); err != nil {
		return err
	}

	r := newReporter(out, format, opts)

	params := parseValidateParams(opts)
	if len(params.issues) > 0 {
		result := &appservice.ValidationResult{Diagnostics: &diag.Result{Issues: params.issues}}
		if err := r.Write(result, opts); err != nil {
			return err
		}
		return r.ExitStatus(result)
	}

	done := rt.BeginProgress("validate artifacts")
	result, runErr := executeValidateRun(cmd, params, opts)
	done()
	if runErr != nil {
		return runErr
	}
	result.Diagnostics.AddAll(PackConfigIssues())

	return outputValidateResult(cmd, r, result, opts)
}

func executeValidateRun(cmd *cobra.Command, params validateParams, opts *options) (*appservice.ValidationResult, error) {
	obsLoader, err := compose.NewObservationRepository()
	if err != nil {
		return nil, err
	}
	ctlLoader, err := compose.NewControlRepository()
	if err != nil {
		return nil, err
	}

	validateRun := appvalidation.NewRun(obsLoader, ctlLoader)
	cfg := appvalidation.Config{
		ControlsDir:     opts.ControlsDir,
		ObservationsDir: opts.ObservationsDir,
		MaxUnsafe:       *params.maxUnsafe,
		NowTime:         params.nowTime,
		SanitizePaths:   cmdutil.SanitizeEnabled(cmd),
	}

	ctx := compose.CommandContext(cmd)
	return validateRun.Execute(ctx, cfg)
}

func outputValidateResult(cmd *cobra.Command, r *Reporter, result *appservice.ValidationResult, opts *options) error {
	if err := r.Write(result, opts); err != nil {
		return err
	}
	exitErr := r.ExitStatus(result)
	if exitErr == nil && !opts.QuietMode && !cmdutil.QuietEnabled(cmd) {
		stderr := io.Writer(os.Stderr)
		if cmd != nil {
			stderr = cmd.ErrOrStderr()
		}
		ui.WriteHint(stderr, fmt.Sprintf("stave apply --controls %s --observations %s",
			opts.ControlsDir, opts.ObservationsDir))
	}
	return exitErr
}
