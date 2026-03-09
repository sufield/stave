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

// runValidateWithOptions parses flags, calls app layer, prints results, and sets exit code.
func runValidateWithOptions(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	if opts == nil {
		opts = defaultOptions()
	}
	format, err := prepareValidateCommand(cmd, opts)
	if err != nil {
		return err
	}

	rt.Quiet = opts.QuietMode || cmdutil.QuietEnabled(cmd)
	out := validateOutputWithOptions(opts)
	if opts.InFile != "" {
		return runValidateSingleFileWithOptions(cmd, out, opts, format)
	}
	if err := ensureValidateModeFlags(opts); err != nil {
		return err
	}

	params := parseValidateParams(opts)
	if len(params.issues) > 0 {
		result := &appservice.ValidationResult{Diagnostics: &diag.Result{Issues: params.issues}}
		return outputAndExitWithOptions(cmd, out, result, format.IsJSON(), opts)
	}

	done := rt.BeginProgress("validate artifacts")
	result, runErr := executeValidateRun(cmd, params, opts)
	done()
	if runErr != nil {
		return runErr
	}
	result.Diagnostics.AddAll(PackConfigIssues())

	return outputValidateResult(cmd, out, result, format, opts)
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

func outputValidateResult(cmd *cobra.Command, out io.Writer, result *appservice.ValidationResult, format ui.OutputFormat, opts *options) error {
	exitErr := outputAndExitWithOptions(cmd, out, result, format.IsJSON(), opts)
	if exitErr == nil && !opts.QuietMode && !cmdutil.QuietEnabled(cmd) {
		stderr := io.Writer(os.Stderr)
		if cmd != nil {
			stderr = cmd.ErrOrStderr()
		}
		fmt.Fprintf(stderr, "Hint:\n  stave apply --controls %s --observations %s\n",
			opts.ControlsDir, opts.ObservationsDir)
	}
	return exitErr
}
