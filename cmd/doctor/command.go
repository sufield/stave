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

// ErrDoctorRequiredIssues is returned when the doctor detects critical environment issues.
var ErrDoctorRequiredIssues = errors.New("doctor found required issues")

// Config holds the parameters for the environment check.
type Config struct {
	Cwd        string
	BinaryPath string
	Format     ui.OutputFormat
	Quiet      bool
	Stdout     io.Writer
}

// Runner handles the execution of environment readiness checks.
type Runner struct {
	Version string
}

// NewRunner initializes a doctor runner.
func NewRunner() *Runner {
	return &Runner{
		Version: staveversion.Version,
	}
}

// Run executes the doctor checks and reports the results based on the config.
func (r *Runner) Run(_ context.Context, cfg Config) error {
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

func (r *Runner) report(cfg Config, checks []doctor.Check, ok bool) error {
	if cfg.Format.IsJSON() {
		return r.reportJSON(cfg.Stdout, checks, ok)
	}
	return r.reportText(cfg.Stdout, checks)
}

func (r *Runner) reportJSON(w io.Writer, checks []doctor.Check, ok bool) error {
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

func (r *Runner) reportText(w io.Writer, checks []doctor.Check) error {
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
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("resolve current directory: %w", err)
			}
			binaryPath, _ := os.Executable()

			fmtValue, fmtErr := compose.ResolveFormatValue(cmd, format)
			if fmtErr != nil {
				return fmtErr
			}

			runner := NewRunner()
			return runner.Run(cmd.Context(), Config{
				Cwd:        cwd,
				BinaryPath: binaryPath,
				Format:     fmtValue,
				Quiet:      cmdutil.GetGlobalFlags(cmd).Quiet,
				Stdout:     cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
