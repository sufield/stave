package diff

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the snapshot diff command.
func NewCmd(loadSnapshots compose.SnapshotLoader) *cobra.Command {
	opts := DefaultOptions()

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare the latest two observation snapshots",
		Long: `Diff compares the latest two snapshots in the observations directory and
reports asset-level changes (added, removed, modified) including property-level
differences for modified assets.

Inputs:
  --observations, -o  Path to observation snapshots directory (default: observations)
  --format, -f        Output format: text or json (default: text)
  --change-type       Filter changes: added, removed, modified (repeatable)
  --asset-type        Filter by asset type (repeatable)
  --asset-id          Filter by asset ID substring

Outputs:
  stdout              Diff report showing added, removed, and modified assets
  stderr              Error messages (if any)

Exit Codes:
  0   - Diff completed successfully
  2   - Invalid input or configuration error
  4   - Internal error
  130 - Interrupted (SIGINT)

Examples:
  # Human-readable summary
  stave snapshot diff --observations ./observations

  # Machine-readable output
  stave snapshot diff --observations ./observations --format json

  # Write report to file
  stave snapshot diff --observations ./observations --format json > output/diff.json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := opts.ToConfig(cmd)
			if err != nil {
				return err
			}
			runner := newRunner(loadSnapshots)
			return runner.Run(cmd.Context(), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("change-type", cmdutil.CompleteFixed("added", "removed", "modified"))

	return cmd
}
