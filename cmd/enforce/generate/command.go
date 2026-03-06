package generate

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/metadata"
)

type options struct {
	InputPath string
	OutDir    string
	Mode      string
	DryRun    bool
}

func defaultOptions() *options {
	return &options{
		OutDir: "output",
		Mode:   "pab",
	}
}

func NewCmd() *cobra.Command {
	opts := defaultOptions()

	cmd := &cobra.Command{
		Use:   "enforce",
		Short: "Generate deterministic enforcement templates from evaluation output",
		Long: `Enforce reads evaluation JSON and generates deterministic remediation templates.

Mode "pab" generates:
  <out>/enforcement/aws/pab.tf

Mode "scp" generates:
  <out>/enforcement/aws/scp.json` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
	}

	cmd.Flags().StringVarP(&opts.InputPath, "in", "i", "", "Path to evaluation JSON input")
	cmd.Flags().StringVar(&opts.OutDir, "out", opts.OutDir, "Output directory")
	cmd.Flags().StringVar(&opts.Mode, "mode", opts.Mode, "Enforcement mode: pab|scp")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", opts.DryRun, "Print planned output path and summary without writing files")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}
