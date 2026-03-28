package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/setup"
	"github.com/sufield/stave/internal/metadata"
)

// ErrDoctorRequiredIssues is returned when the doctor detects critical environment issues.
// It wraps ErrDiagnosticsFound so ExitCode maps it to exit 3 (violations/diagnostics).
var ErrDoctorRequiredIssues = fmt.Errorf("doctor found required issues: %w", ui.ErrDiagnosticsFound)

// Deps groups the infrastructure implementations for the doctor command.
type Deps struct {
	UseCaseDeps setup.DoctorDeps
}

// NewCmd constructs the doctor command.
func NewCmd(deps Deps) *cobra.Command {
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

			req := setup.DoctorRequest{
				Cwd:        cwd,
				BinaryPath: exe,
				Format:     string(fmtValue),
			}

			resp, ucErr := setup.Doctor(cmd.Context(), req, deps.UseCaseDeps)
			if ucErr != nil {
				return ucErr
			}

			stdout := cmd.OutOrStdout()
			if cliflags.GetGlobalFlags(cmd).Quiet {
				stdout = io.Discard
			}

			if fmtValue.IsJSON() {
				if renderErr := reportJSON(stdout, resp); renderErr != nil {
					return renderErr
				}
			} else {
				if renderErr := reportText(stdout, resp); renderErr != nil {
					return renderErr
				}
			}

			if !resp.AllPassed {
				return ErrDoctorRequiredIssues
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}

func reportJSON(w io.Writer, resp setup.DoctorResponse) error {
	payload := struct {
		Ready  bool                `json:"ready"`
		Checks []setup.DoctorCheck `json:"checks"`
	}{
		Ready:  resp.AllPassed,
		Checks: resp.Checks,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func reportText(w io.Writer, resp setup.DoctorResponse) error {
	for _, c := range resp.Checks {
		if _, err := fmt.Fprintf(w, "[%s] %s: %s\n", c.Status, c.Name, c.Message); err != nil {
			return err
		}
		if c.Fix != "" {
			if _, err := fmt.Fprintf(w, "      Fix: %s\n", c.Fix); err != nil {
				return err
			}
		}
	}
	return nil
}
