package generate

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

// Mode represents a validated enforcement mode.
type Mode string

const (
	// ModePAB selects Public Access Block enforcement.
	ModePAB Mode = "pab"
	// ModeSCP selects Service Control Policy enforcement.
	ModeSCP Mode = "scp"
)

// ParseMode validates and returns a Mode value. It stays in the command
// (not the facade) because it reports invalid input via ui.EnumError, and
// pkg/stave must not import internal/cli/ui.
func ParseMode(s string) (Mode, error) {
	normalized := Mode(ui.NormalizeToken(s))
	switch normalized {
	case ModePAB, ModeSCP:
		return normalized, nil
	default:
		return "", ui.EnumError("--mode", s, []string{string(ModePAB), string(ModeSCP)})
	}
}

// String implements fmt.Stringer.
func (m Mode) String() string {
	return string(m)
}

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
			mode, err := ParseMode(opts.ModeRaw)
			if err != nil {
				return fmt.Errorf("invalid mode: %w", err)
			}
			gf := cliflags.GetGlobalFlags(cmd)
			out, err := stave.GenerateEnforcement(cmd.Context(), stave.GenerateEnforcementConfig{
				InputPath:     fsutil.CleanUserPath(opts.InPath),
				OutDir:        fsutil.CleanUserPath(opts.OutDir),
				Mode:          mode.String(),
				DryRun:        opts.DryRun,
				Overwrite:     gf.Force,
				AllowSymlinks: gf.AllowSymlinkOut,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; all generate errors are exit-4 plain.
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write output: %w", werr)
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}
