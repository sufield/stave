package generate

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/fileout"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// NewCmd constructs the generate enforce command.
func NewCmd() *cobra.Command {
	var (
		inPath  string
		outDir  string
		modeRaw string
		dryRun  bool
	)

	cmd := &cobra.Command{
		Use:   "enforce",
		Short: "Generate deterministic enforcement templates from evaluation output",
		Long: `Enforce reads evaluation JSON and generates deterministic remediation templates.

Supported Modes:
  pab - Generates AWS Public Access Block Terraform (.tf)
  scp - Generates AWS Service Control Policy JSON (.json)` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := ParseMode(modeRaw)
			if err != nil {
				return err
			}

			gf := cliflags.GetGlobalFlags(cmd)
			runner := &Runner{}
			runner.FileOptions = fileout.FileOptions{
				Overwrite:     gf.Force,
				AllowSymlinks: gf.AllowSymlinkOut,
				DirPerms:      0o700,
			}

			return runner.Run(cmd.Context(), Config{
				InputPath: fsutil.CleanUserPath(inPath),
				OutDir:    fsutil.CleanUserPath(outDir),
				Mode:      mode,
				DryRun:    dryRun,
				Stdout:    cmd.OutOrStdout(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	f := cmd.Flags()
	f.StringVarP(&inPath, "in", "i", "", "Path to evaluation JSON input (required)")
	f.StringVar(&outDir, "out", "output", "Output directory for generated templates")
	f.StringVar(&modeRaw, "mode", string(ModePAB), "Enforcement mode: pab|scp")
	f.BoolVar(&dryRun, "dry-run", false, "Preview planned paths without writing files")

	_ = cmd.MarkFlagRequired("in")
	_ = cmd.RegisterFlagCompletionFunc("mode", cliflags.CompleteFixed(string(ModePAB), string(ModeSCP)))

	return cmd
}
