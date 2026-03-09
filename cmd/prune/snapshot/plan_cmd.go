package snapshot

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

// NewPlanCmd constructs the plan command with closure-scoped flags.
func NewPlanCmd() *cobra.Command {
	var flags planFlagsType

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
			return runPlan(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&flags.observationsRoot, "observations-root", "o", "observations", "Root directory (inspected recursively)")
	cmd.Flags().StringVar(&flags.archiveDir, "archive-dir", "", "Archive directory (empty = prune mode)")
	cmd.Flags().StringVar(&flags.now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&flags.apply, "apply", false, "Execute the plan (requires --force)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}
