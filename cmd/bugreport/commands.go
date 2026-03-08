package bugreport

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

var Cmd = &cobra.Command{
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
	Args:          cobra.NoArgs,
	RunE:          runReport,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	Cmd.Flags().StringVar(&reportOut, "out", "", "Path to output bundle zip (default: ./stave-diag-<timestamp>.zip)")
	Cmd.Flags().IntVar(&tailLines, "tail-lines", 1000, "Number of trailing log lines to include")
	Cmd.Flags().BoolVar(&includeConfig, "include-config", true, "Include project stave.yaml with sensitive values sanitized")
	Cmd.AddCommand(InspectCmd)
}

var InspectCmd = &cobra.Command{
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
