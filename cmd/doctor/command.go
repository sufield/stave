package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/metadata"
	staveversion "github.com/sufield/stave/internal/version"
)

// ErrDoctorRequiredIssues is returned when doctor detects required issues.
var ErrDoctorRequiredIssues = errors.New("doctor found required issues")

// Config holds the parameters for the environment check.
type Config struct {
	Format ui.OutputFormat
	Quiet  bool
	Stdout io.Writer
	Stderr io.Writer
}

// Runner orchestrates the environment readiness checks.
type Runner struct {
	Version string
}

// NewRunner initializes a doctor runner.
func NewRunner() *Runner {
	return &Runner{
		Version: staveversion.Version,
	}
}

// Run executes the readiness checks and reports findings.
func (r *Runner) Run(_ context.Context, cfg Config) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}
	binaryPath, _ := os.Executable()

	checks, ok := doctor.Run(&doctor.Context{
		Cwd:          cwd,
		BinaryPath:   binaryPath,
		StaveVersion: r.Version,
	})

	if cfg.Quiet {
		if !ok {
			return ErrDoctorRequiredIssues
		}
		return nil
	}

	if cfg.Format.IsJSON() {
		return json.NewEncoder(cfg.Stdout).Encode(struct {
			Ready  bool           `json:"ready"`
			Checks []doctor.Check `json:"checks"`
		}{
			Ready:  ok,
			Checks: checks,
		})
	}

	for _, c := range checks {
		fmt.Fprintf(cfg.Stdout, "[%s] %s: %s\n", c.Status, c.Name, c.Message)
		if c.Fix != "" {
			fmt.Fprintf(cfg.Stdout, "      Fix: %s\n", c.Fix)
		}
	}

	if !ok {
		return ErrDoctorRequiredIssues
	}
	return nil
}

// --- CLI bridge ---

// NewCmd constructs the doctor command.
func NewCmd() *cobra.Command {
	var format string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local environment readiness for Stave workflows",
		Long: `Doctor runs a quick local readiness check for first-time usage and day-to-day
developer workflows.

It validates local prerequisites and reports copy-paste fixes when something is
missing.

Examples:
  stave doctor
  stave doctor --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}

			runner := NewRunner()
			return runner.Run(cmd.Context(), Config{
				Format: fmtValue,
				Quiet:  cmdutil.GetGlobalFlags(cmd).Quiet,
				Stdout: cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
