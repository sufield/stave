package doctor

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

// ErrDoctorRequiredIssues is returned when the doctor detects critical environment issues.
// It wraps ErrDiagnosticsFound so ExitCode maps it to exit 3 (violations/diagnostics).
var ErrDoctorRequiredIssues = fmt.Errorf("doctor found required issues: %w", ui.ErrDiagnosticsFound)

// NewCmd constructs the doctor command.
func NewCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local environment readiness for Stave workflows",
		Long: `Check local environment readiness for Stave workflows.

Doctor runs a quick local readiness check for first-time usage and day-to-day
developer workflows. It validates local prerequisites such as required tools,
file permissions, and project structure. When something is missing, it reports
copy-paste fixes so you can resolve issues without searching documentation.

Inputs:
  --format, -f   Output format: text or json (default: text)

Outputs:
  stdout         Readiness report listing each check with pass/fail status
  stderr         Error messages (if any)

Exit Codes:
  0   - All checks passed; environment is ready
  3   - One or more required checks failed
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Check environment readiness
  stave doctor

  # JSON output for automation
  stave doctor --format json`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, err := opts.resolveFormat()
			if err != nil {
				return err
			}

			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				return fmt.Errorf("resolve working directory: %w", cwdErr)
			}
			exe, exeErr := os.Executable()
			if exeErr != nil {
				return fmt.Errorf("resolve executable path: %w", exeErr)
			}

			out, allPassed, ucErr := stave.RunDoctor(cmd.Context(), cwd, exe, string(fmtValue))
			if ucErr != nil {
				return ucErr //nolint:wrapcheck // facade already wrapped ("run doctor checks"/render); preserve exit 4.
			}

			stdout := cliflags.GetGlobalFlags(cmd).ResolveStdout(cmd.OutOrStdout())
			if _, werr := stdout.Write(out); werr != nil {
				return fmt.Errorf("render doctor output: %w", werr)
			}

			if !allPassed {
				return ErrDoctorRequiredIssues
			}
			return nil
		},
		Annotations:   map[string]string{cmdutil.AnnotationConfigOptional: "true"},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}
