package generate

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/fileout"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	InPath  string
	OutDir  string
	ModeRaw string
	DryRun  bool
}

func defaultOptions() options {
	return options{
		OutDir:  "output",
		ModeRaw: string(ModePAB),
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.InPath, "in", "i", "", "Path to evaluation JSON input (required)")
	f.StringVar(&o.OutDir, "out", o.OutDir, "Output directory for generated templates")
	f.StringVar(&o.ModeRaw, "mode", o.ModeRaw, "Enforcement mode: pab|scp")
	f.BoolVar(&o.DryRun, "dry-run", o.DryRun, "Preview planned paths without writing files")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.RegisterFlagCompletionFunc("mode", cliflags.CompleteFixed(string(ModePAB), string(ModeSCP)))
}

func (o *options) ToConfig(cmd *cobra.Command) (Config, error) {
	mode, err := ParseMode(o.ModeRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid mode: %w", err)
	}
	return Config{
		InputPath: fsutil.CleanUserPath(o.InPath),
		OutDir:    fsutil.CleanUserPath(o.OutDir),
		Mode:      mode,
		DryRun:    o.DryRun,
		Stdout:    cmd.OutOrStdout(),
	}, nil
}

// NewCmd constructs the generate enforce command.
func NewCmd() *cobra.Command {
	opts := defaultOptions()

	cmd := &cobra.Command{
		Use:   "enforce",
		Short: "Generate deterministic enforcement templates from evaluation output",
		Long: `Enforce reads evaluation JSON and generates deterministic remediation templates.

Supported Modes:
  pab - Generates AWS Public Access Block Terraform (.tf)
  scp - Generates AWS Service Control Policy JSON (.json)

Exit Codes:
  0   - Success
  2   - Input error
  4   - Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave enforce --input evaluation.json --mode terraform`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := opts.ToConfig(cmd)
			if err != nil {
				return err
			}
			gf := cliflags.GetGlobalFlags(cmd)
			runner := &Runner{
				FileOptions: fileout.FileOptions{
					Overwrite:     gf.Force,
					AllowSymlinks: gf.AllowSymlinkOut,
					DirPerms:      0o700,
				},
			}
			return runner.Run(cmd.Context(), cfg)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}
