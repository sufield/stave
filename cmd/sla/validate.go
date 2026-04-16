package sla

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	infraSLA "github.com/sufield/stave/internal/adapters/sla"
	"github.com/sufield/stave/internal/cli/ui"
)

type validateOptions struct {
	File string
}

func newValidateCmd() *cobra.Command {
	opts := &validateOptions{}

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate an SLA policy file",
		Long: `Validate an SLA policy file against the schema.

Checks:
  - Required fields present (deadlines for all four severities)
  - Deadlines are valid durations
  - Deadlines are in ascending order (critical < high < medium < low)
  - Escalation factor between 1.0 and 3.0

Exit Codes:
  0   Valid
  2   Invalid`,
		Example:       `  stave sla validate --file sla-policy.yaml`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidate(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", "", "path to SLA policy YAML (required)")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func runValidate(stdout io.Writer, opts *validateOptions) error {
	pol, err := infraSLA.LoadFromFile(opts.File)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("validate %s: %w", opts.File, err)}
	}

	// Additional ordering check.
	crit := pol.DeadlineHoursFor("critical")
	high := pol.DeadlineHoursFor("high")
	med := pol.DeadlineHoursFor("medium")
	low := pol.DeadlineHoursFor("low")

	var warnings []string
	if crit > high {
		warnings = append(warnings, fmt.Sprintf("deadlines.critical (%.0fh) > deadlines.high (%.0fh) — critical should be shortest", crit, high))
	}
	if high > med {
		warnings = append(warnings, fmt.Sprintf("deadlines.high (%.0fh) > deadlines.medium (%.0fh) — high should be shorter than medium", high, med))
	}
	if med > low {
		warnings = append(warnings, fmt.Sprintf("deadlines.medium (%.0fh) > deadlines.low (%.0fh) — medium should be shorter than low", med, low))
	}

	if len(warnings) > 0 {
		fmt.Fprintf(stdout, "! %s has %d warning(s)\n\n", opts.File, len(warnings))
		for _, w := range warnings {
			fmt.Fprintf(stdout, "  WARNING: %s\n", w)
		}
		fmt.Fprintln(stdout)
	}

	fmt.Fprintf(stdout, "OK %s is valid\n\n", opts.File)
	if pol.Name != "" {
		fmt.Fprintf(stdout, "  Name:               %s\n", pol.Name)
	}
	fmt.Fprintf(stdout, "  ID:                 %s\n", pol.ID)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  Deadlines:")
	fmt.Fprintf(stdout, "    critical  %s\t(%.0f hours)\n", pol.Deadlines.Critical, crit)
	fmt.Fprintf(stdout, "    high      %s\t(%.0f hours)\n", pol.Deadlines.High, high)
	fmt.Fprintf(stdout, "    medium    %s\t(%.0f hours)\n", pol.Deadlines.Medium, med)
	fmt.Fprintf(stdout, "    low       %s\t(%.0f hours)\n", pol.Deadlines.Low, low)
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  Escalation factor:  %.1fx\n", pol.EscalationFactor)

	return nil
}
