package fix

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// loopOptions holds the raw CLI flag values for the fix-loop command.
type loopOptions struct {
	BeforeDir    string
	AfterDir     string
	ControlsDir  string
	MaxUnsafeRaw string
	EvalTimeRaw  string
	OutDir       string
}

// BindFlags attaches the options to a Cobra command.
func (o *loopOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.BeforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	f.StringVarP(&o.AfterDir, "after", "a", "", "Path to after-remediation observations (required)")
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")
	f.StringVar(&o.MaxUnsafeRaw, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.EvalTimeRaw, "eval-time", "", "Evaluation reference timestamp (RFC3339). Durations and temporal risk are measured against this time. Defaults to wall clock.")
	f.StringVar(&o.EvalTimeRaw, "now", "", "Alias for --eval-time")
	_ = f.MarkDeprecated("now", "please use --eval-time instead")
	f.StringVar(&o.OutDir, "out", "", "Write remediation artifacts to this directory")
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")
}

// Prepare resolves config defaults and normalizes paths. Called from PreRunE.
func (o *loopOptions) Prepare(cmd *cobra.Command) error {
	o.resolveConfigDefaults(cmdctx.ResolverFromCmd(cmd), cmd.Flags())
	return o.normalize()
}

func (o *loopOptions) resolveConfigDefaults(defaults *appconfig.GovernanceResolver, flags *pflag.FlagSet) {
	if defaults == nil {
		return
	}
	if !flags.Changed("max-unsafe") {
		o.MaxUnsafeRaw = defaults.MaxUnsafeDuration()
	}
}

// normalize cleans user-supplied paths and validates the output directory.
func (o *loopOptions) normalize() error {
	o.BeforeDir = fsutil.CleanUserPath(o.BeforeDir)
	o.AfterDir = fsutil.CleanUserPath(o.AfterDir)
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
	o.OutDir = fsutil.CleanUserPath(o.OutDir)

	if o.OutDir != "" {
		if err := os.MkdirAll(o.OutDir, 0o700); err != nil {
			return fmt.Errorf("create output directory %s: %w", o.OutDir, err)
		}
	}
	return nil
}
