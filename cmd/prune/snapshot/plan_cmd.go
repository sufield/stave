package snapshot

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appsnapshot "github.com/sufield/stave/internal/app/prune/snapshot"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewPlanCmd constructs the plan command.
//
// The command is read-only: it inspects the observations root,
// classifies each snapshot under the configured retention tiers,
// and emits a plan describing what would be kept and what is
// eligible for action. Stave does not execute deletes, moves, or
// archive operations — that is an external tool's responsibility.
// The plan output is the integration contract: external tools
// (cron scripts, Terraform null_resource, CI cleanup jobs) parse
// the JSON form and decide how to act on each entry.
func NewPlanCmd(newSnapshotRepo compose.SnapshotRepoFactory) *cobra.Command {
	var (
		obsRoot    string
		nowRaw     string
		formatFlag string
	)

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Plan multi-tier snapshot retention across directories",
		Long: `Plan inspects an observations root recursively, assigns each snapshot to a retention
tier based on observation_tier_mapping rules, and generates a unified retention plan.

The plan shows which files fall under each tier's older_than / keep_min policy and
which are eligible for action (delete or archive). Stave does not execute the
plan: external tools consume the JSON output and run the actions themselves.

Exit Codes:
  0   - Success
  2   - Invalid input or configuration error
  4   - Internal error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  stave snapshot plan --observations-root ./observations --now 2026-02-23T00:00:00Z
  stave snapshot plan --observations-root ./observations --format json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cliflags.GetGlobalFlags(cmd)
			now, err := compose.ResolveNow(nowRaw)
			if err != nil {
				return err
			}
			format, err := compose.ResolveFormatValue(formatFlag)
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			cleanObsRoot := fsutil.CleanUserPath(obsRoot)

			files, err := listPlanFiles(ctx, newSnapshotRepo, cleanObsRoot)
			if err != nil {
				return err
			}

			tiers, tierRules, defaultTier, err := resolvePlanRetentionConfig(cmdctx.ResolverFromCmd(cmd))
			if err != nil {
				return err
			}

			runner := appsnapshot.NewPlanRunner()
			return runner.Run(appsnapshot.PlanConfig{
				Files:            files,
				Tiers:            tiers,
				TierRules:        tierRules,
				DefaultTier:      defaultTier,
				Now:              now,
				ObservationsRoot: cleanObsRoot,
				Format:           format,
				Quiet:            gf.Quiet,
				Stdout:           cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&obsRoot, "observations-root", "o", "observations", "Root directory (inspected recursively)")
	f.StringVar(&nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))

	return cmd
}
