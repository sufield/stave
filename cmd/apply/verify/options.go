package verify

import (
	"context"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// options represents the raw CLI flag inputs.
type options struct {
	BeforeDir    string
	AfterDir     string
	ControlsDir  string
	MaxUnsafe    string
	Now          string
	AllowUnknown bool
}

// newOptions initializes options with project-aware defaults.
func newOptions() *options {
	return &options{
		ControlsDir:  "controls",
		MaxUnsafe:    projconfig.Global().MaxUnsafe(),
		AllowUnknown: projconfig.Global().AllowUnknownInput(),
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	f.StringVarP(&o.BeforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	f.StringVarP(&o.AfterDir, "after", "a", "", "Path to after-remediation observations (required)")
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")

	f.StringVar(&o.MaxUnsafe, "max-unsafe", o.MaxUnsafe, cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.Now, "now", "", "Override current time (RFC3339) for deterministic output")
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", o.AllowUnknown, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown source types"))

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
	if err := cmdutil.ValidateFlagDir("--before", o.BeforeDir, "", nil, nil); err != nil {
		return err
	}
	if err := cmdutil.ValidateFlagDir("--after", o.AfterDir, "", nil, nil); err != nil {
		return err
	}
	if err := cmdutil.ValidateFlagDir("--controls", o.ControlsDir, "", ui.ErrHintControlsNotAccessible, nil); err != nil {
		return err
	}
	return nil
}

// Execution contains the resolved domain objects ready for the application layer.
type Execution struct {
	Context      context.Context
	BeforeDir    string
	AfterDir     string
	ControlsDir  string
	MaxUnsafe    time.Duration
	Clock        ports.Clock
	AllowUnknown bool
}

// Complete transforms the raw options into a validated Execution object.
func (o *options) Complete(ctx context.Context) (Execution, error) {
	maxDuration, err := timeutil.ParseDurationFlag(o.MaxUnsafe, "--max-unsafe")
	if err != nil {
		return Execution{}, err
	}

	clock, err := compose.ResolveClock(o.Now)
	if err != nil {
		return Execution{}, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return Execution{
		Context:      ctx,
		BeforeDir:    o.BeforeDir,
		AfterDir:     o.AfterDir,
		ControlsDir:  o.ControlsDir,
		MaxUnsafe:    maxDuration,
		Clock:        clock,
		AllowUnknown: o.AllowUnknown,
	}, nil
}
