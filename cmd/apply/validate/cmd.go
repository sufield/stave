package validate

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

const validateLongHelp = `Validate checks controls, observations, and configuration for correctness
without running the full evaluation.

What it checks:
  - Control schema (id, name, description)
  - Observation schema and timestamps
  - Cross-file consistency and time sanity
  - Duration format and feasibility` + metadata.OfflineHelpSuffix

// NewCmd builds the validate command.
// Panics if rt is nil — command wiring is a programming error, not a user error.
func NewCmd(p *compose.Provider, rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		panic("validate.NewCmd: nil runtime")
	}

	opts := newOptions()

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate inputs without evaluation",
		Long:  validateLongHelp,
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidate(cmd, p, rt, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
