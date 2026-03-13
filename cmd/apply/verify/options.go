package verify

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	BeforeDir    string
	AfterDir     string
	ControlsDir  string
	MaxUnsafe    string
	NowTime      string
	AllowUnknown bool
	Quiet        bool
}

func newOptions() *options {
	return &options{
		ControlsDir:  "controls",
		MaxUnsafe:    projconfig.ResolveMaxUnsafeDefault(),
		AllowUnknown: projconfig.ResolveAllowUnknownInputDefault(),
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.BeforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	f.StringVarP(&o.AfterDir, "after", "a", "", "Path to after-remediation observations (required)")
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")
	f.StringVar(&o.MaxUnsafe, "max-unsafe", o.MaxUnsafe, cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", o.AllowUnknown, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown source types"))
	f.BoolVar(&o.Quiet, "quiet", false, "Suppress progress output")
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")
}

// normalize cleans user input and applies project-root inference.
func (o *options) normalize(cmd *cobra.Command) {
	o.BeforeDir = fsutil.CleanUserPath(o.BeforeDir)
	o.AfterDir = fsutil.CleanUserPath(o.AfterDir)
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)

	log := projctx.NewInferenceLog()
	o.ControlsDir = log.InferControlsDir(cmd, o.ControlsDir)
}

// validate performs logical checks on flag combinations.
func (o *options) validate() error {
	if err := cmdutil.ValidateDir("--before", o.BeforeDir, nil); err != nil {
		return err
	}
	if err := cmdutil.ValidateDir("--after", o.AfterDir, nil); err != nil {
		return err
	}
	if err := cmdutil.ValidateDir("--controls", o.ControlsDir, ui.ErrHintControlsNotAccessible); err != nil {
		return err
	}
	return nil
}
