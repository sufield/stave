package validate

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd builds the validate command.
func NewCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.DefaultRuntime()
	}

	opts := &options{
		ControlsDir:     "controls/s3",
		ObservationsDir: "observations",
		MaxUnsafe:       projconfig.ResolveMaxUnsafeDefault(),
		Format:          "text",
		QuietMode:       projconfig.ResolveQuietDefault(),
	}

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate inputs without evaluation",
		Long: `Validate checks controls, observations, and configuration for correctness
without running the full evaluation.

What it checks:
  - Control schema (id, name, description)
  - Observation schema and timestamps
  - Cross-file consistency and time sanity
  - Duration format and feasibility` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		// 1. Validation and Normalization
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.validate()
		},
		// 2. Main Execution
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidate(cmd, rt, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}

func runValidate(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	// Sync global flags/runtime state
	rt.Quiet = cmdutil.QuietEnabled(cmd)

	// Delegate to internal business logic
	return runValidateWithOptions(cmd, rt, opts)
}
