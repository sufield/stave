package gate

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the CI gate command.
func NewCmd() *cobra.Command {
	opts := DefaultOptions()

	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Enforce CI failure policy modes from config or flags",
		Long: `Gate applies a CI failure policy and returns exit code 3 when the policy fails.

Supported policies:
  - fail_on_any_violation
  - fail_on_new_violation
  - fail_on_overdue_upcoming

Examples:
  # Fail on any findings in evaluation output
  stave ci gate --policy fail_on_any_violation --in output/evaluation.json

  # Fail only on newly introduced findings
  stave ci gate --policy fail_on_new_violation --in output/evaluation.json --baseline output/baseline.json

  # Fail when any upcoming action is already overdue
  stave ci gate --policy fail_on_overdue_upcoming --controls ./controls --observations ./observations` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := opts.ToConfig(cmd)
			if err != nil {
				return err
			}
			runner := NewRunner(compose.ActiveProvider())
			return runner.Run(cmd.Context(), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	registerCompletions(cmd)

	return cmd
}

func registerCompletions(cmd *cobra.Command) {
	_ = cmd.RegisterFlagCompletionFunc("policy", cmdutil.CompleteFixed(
		string(projconfig.GatePolicyAny),
		string(projconfig.GatePolicyNew),
		string(projconfig.GatePolicyOverdue),
	))
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
}
