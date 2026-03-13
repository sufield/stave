package gate

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewCmd constructs the CI gate command.
func NewCmd() *cobra.Command {
	var (
		policyRaw string
		inPath    string
		basePath  string
		ctlDir    string
		obsDir    string
		maxUnsafe string
		nowRaw    string
		formatRaw string
	)

	defaults := projconfig.Global()

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
			gf := cmdutil.GetGlobalFlags(cmd)

			policy, err := projconfig.ParseGatePolicy(policyRaw)
			if err != nil {
				return err
			}

			clock, err := compose.ResolveClock(nowRaw)
			if err != nil {
				return err
			}

			format, err := compose.ResolveFormatValue(cmd, formatRaw)
			if err != nil {
				return err
			}

			var maxUnsafeDur time.Duration
			if policy == projconfig.GatePolicyOverdue {
				maxUnsafeDur, err = timeutil.ParseDurationFlag(maxUnsafe, "--max-unsafe")
				if err != nil {
					return err
				}
			}

			runner := NewRunner(compose.ActiveProvider(), clock)
			runner.Sanitizer = gf.GetSanitizer()
			runner.Stdout = cmd.OutOrStdout()

			return runner.Run(cmd.Context(), Config{
				Policy:          policy,
				InPath:          fsutil.CleanUserPath(inPath),
				BaselinePath:    fsutil.CleanUserPath(basePath),
				ControlsDir:     fsutil.CleanUserPath(ctlDir),
				ObservationsDir: fsutil.CleanUserPath(obsDir),
				MaxUnsafe:       maxUnsafeDur,
				Format:          format,
				Quiet:           gf.Quiet,
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVar(&policyRaw, "policy", string(defaults.CIFailurePolicy()), cmdutil.WithDynamicDefaultHelp("CI failure policy mode: fail_on_any_violation, fail_on_new_violation, fail_on_overdue_upcoming"))
	f.StringVar(&inPath, "in", "output/evaluation.json", "Path to evaluation JSON (required for fail_on_any_violation and fail_on_new_violation)")
	f.StringVar(&basePath, "baseline", "output/baseline.json", "Path to baseline JSON (required for fail_on_new_violation)")
	f.StringVarP(&ctlDir, "controls", "i", "controls/s3", "Path to control definitions directory (used by fail_on_overdue_upcoming)")
	f.StringVarP(&obsDir, "observations", "o", "observations", "Path to observation snapshots directory (used by fail_on_overdue_upcoming)")
	f.StringVar(&maxUnsafe, "max-unsafe", defaults.MaxUnsafe(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)"))
	f.StringVar(&nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&formatRaw, "format", "f", "text", "Output format: text or json")

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
