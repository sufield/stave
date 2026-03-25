package bugreport

import (
	"archive/zip"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// reportOptions maps CLI flags to the report logic.
type reportOptions struct {
	out           string
	tailLines     int
	includeConfig bool
}

// NewCmd constructs the bug-report command.
func NewCmd() *cobra.Command {
	opts := reportOptions{}

	cmd := &cobra.Command{
		Use:   "bug-report",
		Short: "Collect a sanitized diagnostic bundle for support and issue filing",
		Long: `Bug-report collects a local diagnostics bundle that is safe to share
in issue reports and support requests. The bundle includes doctor checks,
build info, selected environment variables, and optional sanitized project
config/log tail.

Inputs:
  --out              Path to output bundle zip (default: ./stave-diag-<timestamp>.zip)
  --tail-lines       Number of trailing log lines to include (default: 1000)
  --include-config   Include project stave.yaml with sensitive values sanitized (default: true)

Outputs:
  file               Diagnostic bundle zip at the --out path
  stdout             Bundle path confirmation

Exit Codes:
  0   - Bundle created successfully
  2   - Invalid input or configuration error
  4   - Internal error
  130 - Interrupted (SIGINT)

Examples:
  # Generate bundle in current directory
  stave bug-report

  # Write bundle to a specific path
  stave bug-report --out ./artifacts/stave-diag.zip

  # Include only last 200 log lines
  stave bug-report --tail-lines 200` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVar(&opts.out, "out", "", "Path to output bundle zip (default: ./stave-diag-<timestamp>.zip)")
	cmd.Flags().IntVar(&opts.tailLines, "tail-lines", 1000, "Number of trailing log lines to include")
	cmd.Flags().BoolVar(&opts.includeConfig, "include-config", true, "Include project stave.yaml with sensitive values sanitized")
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
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zr, err := zip.OpenReader(args[0])
			if err != nil {
				return fmt.Errorf("open bundle: %w", err)
			}
			defer func() { _ = zr.Close() }()

			ins := NewInspector(InspectConfig{
				Stdout:  cmd.OutOrStdout(),
				Stderr:  cmd.ErrOrStderr(),
				MaxSize: DefaultMaxInspectSize,
			})
			return ins.Inspect(&zr.Reader)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}
