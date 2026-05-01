package cmdutil

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// AddFormatFlag registers a `--format/-f` flag on cmd, writing into target.
// allowedValues, when non-empty, attaches a Cobra completion function and
// validates the value at parse time. Pass nil/empty to skip validation
// (some commands accept arbitrary format names).
func AddFormatFlag(cmd *cobra.Command, target *string, defaultVal string, allowedValues ...string) {
	usage := "output format"
	if len(allowedValues) > 0 {
		usage += " (" + strings.Join(allowedValues, " | ") + ")"
	}
	cmd.Flags().StringVarP(target, "format", "f", defaultVal, usage)
	if len(allowedValues) > 0 {
		_ = cmd.RegisterFlagCompletionFunc("format", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return allowedValues, cobra.ShellCompDirectiveNoFileComp
		})
		// Pre-run validation: surface invalid values before RunE.
		prev := cmd.PreRunE
		cmd.PreRunE = func(c *cobra.Command, args []string) error {
			for _, v := range allowedValues {
				if *target == v {
					if prev != nil {
						return prev(c, args)
					}
					return nil
				}
			}
			return fmt.Errorf("invalid --format %q (use: %s)", *target, strings.Join(allowedValues, ", "))
		}
	}
}

// HistoryOptions captures the canonical flags used by commands that
// read a directory of previous assessment artifacts plus an SLA policy
// profile (cmd/apply, cmd/budget, cmd/score, cmd/consolidate,
// cmd/trend/forecast, etc.).
type HistoryOptions struct {
	HistoryDir string
	SLAProfile string
}

// AddHistoryFlags registers `--history` and `--sla-profile` on cmd,
// writing into the supplied options struct.
func AddHistoryFlags(cmd *cobra.Command, opts *HistoryOptions) {
	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of past assessment artifacts")
	cmd.Flags().StringVar(&opts.SLAProfile, "sla-profile", "", "embedded SLA profile name")
}
