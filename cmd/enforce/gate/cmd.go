package gate

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the CI gate command.
func NewCmd(loadAssets compose.AssetLoaderFunc, newCELEvaluator compose.CELEvaluatorFactory) *cobra.Command {
	opts := DefaultOptions()

	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Enforce CI failure policy modes from config or flags",
		Long: `Gate applies a CI failure policy and returns exit code 3 when the policy fails.

Supported policies:
  - fail_on_any_violation
  - fail_on_new_violation
  - fail_on_overdue_upcoming

Inputs:
  --policy          CI failure policy mode (default: from project config)
  --in              Path to evaluation JSON (required for fail_on_any/new)
  --baseline        Path to baseline JSON (required for fail_on_new_violation)
  --controls, -i    Path to control definitions directory (used by fail_on_overdue_upcoming)
  --observations, -o Path to observation snapshots directory (used by fail_on_overdue_upcoming)
  --max-unsafe      Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)
  --now             Reference time (RFC3339). If omitted, uses wall clock
  --format, -f      Output format: text or json (default: text)

Outputs:
  stdout            Gate result summary (text or JSON)
  stderr            Error messages (if any)

Exit Codes:
  0   - Policy passed; no violations detected
  2   - Invalid input or configuration error
  3   - Policy failed; violations detected
  130 - Interrupted (SIGINT)

Examples:
  # Fail on any findings in evaluation output
  stave ci gate --policy fail_on_any_violation --in output/evaluation.json

  # Fail only on newly introduced findings
  stave ci gate --policy fail_on_new_violation --in output/evaluation.json --baseline output/baseline.json

  # Fail when any upcoming action is already overdue
  stave ci gate --policy fail_on_overdue_upcoming --controls ./controls --observations ./observations` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := opts.ToConfig(cmd)
			if err != nil {
				return err
			}
			runner := newRunner(loadAssets, newCELEvaluator)
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
	_ = cmd.RegisterFlagCompletionFunc("policy", cliflags.CompleteFixed(
		string(appconfig.GatePolicyAny),
		string(appconfig.GatePolicyNew),
		string(appconfig.GatePolicyOverdue),
	))
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("text", "json"))
}
