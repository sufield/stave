package fix

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// loopOptions holds the raw CLI flag values for the fix-loop command.
type loopOptions struct {
	BeforeDir    string
	AfterDir     string
	ControlsDir  string
	MaxUnsafeRaw string
	NowRaw       string
	AllowUnknown bool
	OutDir       string
}

// BindFlags attaches the options to a Cobra command.
func (o *loopOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.BeforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	f.StringVarP(&o.AfterDir, "after", "a", "", "Path to after-remediation observations (required)")
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")
	f.StringVar(&o.MaxUnsafeRaw, "max-unsafe", "", cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowRaw, "now", "", "Override current time (RFC3339). Required for deterministic output")
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", false, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown source types"))
	f.StringVar(&o.OutDir, "out", "", "Write remediation artifacts to this directory")
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")
}

// Prepare resolves config defaults and normalizes paths. Called from PreRunE.
func (o *loopOptions) Prepare(cmd *cobra.Command) error {
	o.resolveConfigDefaults(cmd)
	o.normalize()
	return nil
}

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *loopOptions) resolveConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.EvaluatorFromCmd(cmd)
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeRaw = eval.MaxUnsafeDuration()
	}
	if !cmd.Flags().Changed("allow-unknown-input") {
		o.AllowUnknown = eval.AllowUnknownInput()
	}
}

// normalize cleans user-supplied paths.
func (o *loopOptions) normalize() {
	o.BeforeDir = fsutil.CleanUserPath(o.BeforeDir)
	o.AfterDir = fsutil.CleanUserPath(o.AfterDir)
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
	o.OutDir = fsutil.CleanUserPath(o.OutDir)
}
