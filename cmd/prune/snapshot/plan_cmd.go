package snapshot

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/pruner/plan"
	appsnapshot "github.com/sufield/stave/internal/app/prune/snapshot"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	snapshotdomain "github.com/sufield/stave/pkg/alpha/domain/snapshot"
)

// NewPlanCmd constructs the plan command.
func NewPlanCmd(p *compose.Provider) *cobra.Command {
	var (
		obsRoot    string
		archiveDir string
		nowRaw     string
		formatFlag string
		apply      bool
	)

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Preview or execute multi-tier snapshot retention across directories",
		Long: `Plan inspects an observations root recursively, assigns each snapshot to a retention
tier based on observation_tier_mapping rules, and generates a unified retention plan.

The plan shows which files will be kept, pruned, or archived based on per-tier
older_than and keep_min settings.

Execution requires --apply --force.

Examples:
  # Preview multi-tier plan
  stave snapshot plan --observations-root ./observations --now 2026-02-23T00:00:00Z

  # JSON output
  stave snapshot plan --observations-root ./observations --format json

  # Execute the plan (prune mode)
  stave snapshot plan --observations-root ./observations --apply --force

  # Execute the plan (archive mode)
  stave snapshot plan --observations-root ./observations --archive-dir ./observations/archive --apply --force` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gf := cmdutil.GetGlobalFlags(cmd)
			now, err := compose.ResolveNow(nowRaw)
			if err != nil {
				return err
			}
			format, err := compose.ResolveFormatValue(cmd, formatFlag)
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			cleanObsRoot := fsutil.CleanUserPath(obsRoot)
			cleanArchiveDir := fsutil.CleanUserPath(archiveDir)

			// Load files via factory
			files, err := listPlanFiles(ctx, p.NewSnapshotRepo, cleanObsRoot, cleanArchiveDir)
			if err != nil {
				return err
			}

			// Load retention config
			tiers, tierRules, defaultTier, err := resolvePlanRetentionConfig(cmdctx.EvaluatorFromCmd(cmd))
			if err != nil {
				return err
			}

			// Delegate to internal runner
			runner := appsnapshot.NewPlanRunner(adaptPlanApply)
			return runner.Run(ctx, appsnapshot.PlanConfig{
				Files:            files,
				Tiers:            tiers,
				TierRules:        tierRules,
				DefaultTier:      defaultTier,
				Now:              now,
				ObservationsRoot: cleanObsRoot,
				ArchiveDir:       cleanArchiveDir,
				Apply:            apply,
				Force:            gf.Force,
				AllowSymlink:     gf.AllowSymlinkOut,
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
	f.StringVar(&archiveDir, "archive-dir", "", "Archive directory (empty = prune mode)")
	f.StringVar(&nowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	f.BoolVar(&apply, "apply", false, "Execute the plan (requires --force)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

// adaptPlanApply bridges the domain PlanEntry type to the adapter's
// ApplySnapshotPlan function, keeping the app layer adapter-free.
func adaptPlanApply(entries []snapshotdomain.PlanEntry, obsRoot, archiveDir string, allowSymlink bool) error {
	_, err := plan.ApplySnapshotPlan(plan.SnapshotPlanApplyInput{
		Entries:          entries,
		ObservationsRoot: obsRoot,
		ArchiveDir:       archiveDir,
		AllowSymlink:     allowSymlink,
	})
	return err
}
