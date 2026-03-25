package artifacts

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	appartifacts "github.com/sufield/stave/internal/app/artifacts"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewFmtCmd constructs the fmt command with closure-scoped flags.
func NewFmtCmd() *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "fmt <path>",
		Short: "Format control and observation files deterministically",
		Long: `Fmt normalizes file formatting for control YAML and observation JSON.

Rules:
  - .yaml/.yml files are parsed as ctrl.v1 controls and emitted in canonical field order
  - .json files are parsed as obs.v0.1 snapshots and emitted with stable indentation

Use --check to verify formatting without writing files.` + metadata.OfflineHelpSuffix,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			allowSymlinks := cliflags.GetGlobalFlags(cmd).AllowSymlinkOut

			cfg := appartifacts.FormatConfig{
				Target:    fsutil.CleanUserPath(args[0]),
				CheckOnly: checkOnly,
				Stdout:    cmd.OutOrStdout(),
				ReadFile:  fsutil.ReadFileLimited,
				WriteFile: func(path string, data []byte) error {
					opts := fsutil.ConfigWriteOpts()
					opts.AllowSymlink = allowSymlinks
					return fsutil.SafeWriteFile(path, data, opts)
				},
			}
			formatter := &appartifacts.Formatter{}
			_, err := formatter.Run(cfg)
			return err
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "Check formatting only; do not write files")

	return cmd
}
