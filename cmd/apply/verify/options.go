package verify

import (
	"context"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// options represents the raw CLI flag inputs.
type options struct {
	BeforeDir         string
	AfterDir          string
	ControlsDir       string
	MaxUnsafeDuration string
	Now               string
	AllowUnknown      bool
}

// newOptions initializes options with zero values for config-derived fields.
// Call resolveConfigDefaults after flag parsing to fill in project-config defaults.
func newOptions() *options {
	return &options{
		ControlsDir: "controls",
	}
}

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *options) resolveConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.EvaluatorFromCmd(cmd)
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
	if !cmd.Flags().Changed("allow-unknown-input") {
		o.AllowUnknown = eval.AllowUnknownInput()
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	f.StringVarP(&o.BeforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	f.StringVarP(&o.AfterDir, "after", "a", "", "Path to after-remediation observations (required)")
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")

	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.Now, "now", "", "Override current time (RFC3339) for deterministic output")
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", false, cliflags.WithDynamicDefaultHelp("Allow observations with unknown source types"))

	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")
}

// normalize cleans user-supplied paths.
func (o *options) normalize() {
	o.BeforeDir = fsutil.CleanUserPath(o.BeforeDir)
	o.AfterDir = fsutil.CleanUserPath(o.AfterDir)
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
}

// validate ensures all required paths exist and are accessible.
func (o *options) validate() error {
	if err := dircheck.ValidateFlagDir("--before", o.BeforeDir, "", nil, nil); err != nil {
		return err
	}
	if err := dircheck.ValidateFlagDir("--after", o.AfterDir, "", nil, nil); err != nil {
		return err
	}
	if err := dircheck.ValidateFlagDir("--controls", o.ControlsDir, "", ui.ErrHintControlsNotAccessible, nil); err != nil {
		return err
	}
	return nil
}

// Execution contains the resolved domain objects ready for the application layer.
type Execution struct {
	Context           context.Context
	BeforeDir         string
	AfterDir          string
	ControlsDir       string
	MaxUnsafeDuration time.Duration
	Clock             ports.Clock
	AllowUnknown      bool
}

// Complete transforms the raw options into a validated Execution object.
func (o *options) Complete(ctx context.Context) (Execution, error) {
	maxDuration, err := cliflags.ParseDurationFlag(o.MaxUnsafeDuration, "--max-unsafe")
	if err != nil {
		return Execution{}, err
	}

	clock, err := compose.ResolveClock(o.Now)
	if err != nil {
		return Execution{}, err
	}

	return Execution{
		Context:           ctx,
		BeforeDir:         o.BeforeDir,
		AfterDir:          o.AfterDir,
		ControlsDir:       o.ControlsDir,
		MaxUnsafeDuration: maxDuration,
		Clock:             clock,
		AllowUnknown:      o.AllowUnknown,
	}, nil
}
