package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/metadata"
	staveversion "github.com/sufield/stave/internal/version"
)

// ErrDoctorRequiredIssues is returned when the doctor detects critical environment issues.
// It wraps ErrDiagnosticsFound so ExitCode maps it to exit 3 (violations/diagnostics).
var ErrDoctorRequiredIssues = fmt.Errorf("doctor found required issues: %w", ui.ErrDiagnosticsFound)

// config holds the parameters for the environment check.
type config struct {
	Cwd        string
	BinaryPath string
	Format     ui.OutputFormat
	Quiet      bool
	Stdout     io.Writer
}

// runner handles the execution of environment readiness checks.
type runner struct {
	Version string
}

// newRunner initializes a doctor runner.
func newRunner() *runner {
	return &runner{
		Version: staveversion.String,
	}
}

// Run executes the doctor checks and reports the results based on the config.
// If Cwd or BinaryPath are empty, they are resolved from the current process.
func (r *runner) Run(cfg config) error {
	if cfg.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		cfg.Cwd = cwd
	}
	if cfg.BinaryPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve executable path: %w", err)
		}
		cfg.BinaryPath = exe
	}

	checks, ok := doctor.Run(&doctor.Context{
		Cwd:          cfg.Cwd,
		BinaryPath:   cfg.BinaryPath,
		StaveVersion: r.Version,
	})

	if cfg.Quiet {
		if !ok {
			return ErrDoctorRequiredIssues
		}
		return nil
	}

	if err := r.report(cfg, checks, ok); err != nil {
		return err
	}

	if !ok {
		return ErrDoctorRequiredIssues
	}
	return nil
}

func (r *runner) report(cfg config, checks []doctor.Check, ok bool) error {
	if cfg.Format.IsJSON() {
		return r.reportJSON(cfg.Stdout, checks, ok)
	}
	return r.reportText(cfg.Stdout, checks)
}

func (r *runner) reportJSON(w io.Writer, checks []doctor.Check, ok bool) error {
	payload := struct {
		Ready  bool           `json:"ready"`
		Checks []doctor.Check `json:"checks"`
	}{
		Ready:  ok,
		Checks: checks,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func (r *runner) reportText(w io.Writer, checks []doctor.Check) error {
	for _, c := range checks {
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

// --- CLI bridge ---

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
  130 - Interrupted (SIGINT)

Examples:
  stave doctor
  stave doctor --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, err := opts.resolveFormat(cmd)
			if err != nil {
				return err
			}

			return newRunner().Run(config{
				Format: fmtValue,
				Quiet:  cliflags.GetGlobalFlags(cmd).Quiet,
				Stdout: cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}
