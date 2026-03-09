package bugreport

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the bug-report command with closure-scoped flags.
func NewCmd() *cobra.Command {
	var flags reportFlags

	cmd := &cobra.Command{
		Use:   "bug-report",
		Short: "Collect a sanitized diagnostic bundle for support and issue filing",
		Long: `Bug-report collects a local diagnostics bundle that is safe to share in most
cases. The bundle includes doctor checks, build info, selected environment
variables, and optional sanitized project config/log tail.

Examples:
  # Generate bundle in current directory
  stave bug-report

  # Write bundle to a specific path
  stave bug-report --out ./artifacts/stave-diag.zip

  # Include only last 200 log lines
  stave bug-report --tail-lines 200` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&flags.out, "out", "", "Path to output bundle zip (default: ./stave-diag-<timestamp>.zip)")
	cmd.Flags().IntVar(&flags.tailLines, "tail-lines", 1000, "Number of trailing log lines to include")
	cmd.Flags().BoolVar(&flags.includeConfig, "include-config", true, "Include project stave.yaml with sensitive values sanitized")
	cmd.AddCommand(newInspectCmd())

	return cmd
}

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <bundle.zip>",
		Short: "Dump diagnostic bundle contents to stdout",
		Long: `Inspect opens a bug-report bundle zip and prints each file with a separator
header. Output goes to stdout so it can be piped to less, grep, jq, etc.

Examples:
  stave bug-report inspect stave-diag-20260306T120000Z.zip
  stave bug-report inspect bundle.zip | grep -A5 manifest
  stave bug-report inspect bundle.zip | less` + metadata.OfflineHelpSuffix,
		Args:          cobra.ExactArgs(1),
		RunE:          runInspect,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}
