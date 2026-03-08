package verify

import (
	"context"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	BeforeDir    string
	AfterDir     string
	ControlsDir  string
	MaxUnsafe    string
	Now          string
	AllowUnknown bool
}

func defaultOptions() *options {
	return &options{
		ControlsDir:  "controls",
		MaxUnsafe:    cmdutil.ResolveMaxUnsafeDefault(),
		AllowUnknown: cmdutil.ResolveAllowUnknownInputDefault(),
	}
}

func (o *options) BindFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVarP(&o.BeforeDir, "before", "b", "", "Path to before-remediation observations (required)")
	flags.StringVarP(&o.AfterDir, "after", "a", "", "Path to after-remediation observations (required)")
	flags.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory")
	flags.StringVar(&o.MaxUnsafe, "max-unsafe", o.MaxUnsafe, cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	flags.StringVar(&o.Now, "now", "", "Override current time (RFC3339). Required for deterministic output")
	flags.BoolVar(&o.AllowUnknown, "allow-unknown-input", o.AllowUnknown, cmdutil.WithDynamicDefaultHelp("Allow observations with unknown source types"))
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")
}

type verifyDirs struct {
	before   string
	after    string
	controls string
}

type verifyExecution struct {
	ctx          context.Context
	beforeDir    string
	afterDir     string
	controlsDir  string
	maxUnsafe    time.Duration
	clock        ports.Clock
	allowUnknown bool
}

func (o *options) prepareExecution(ctx context.Context) (verifyExecution, error) {
	dirs := o.normalizeDirs()
	if err := validateVerifyDirs(dirs); err != nil {
		return verifyExecution{}, err
	}
	maxUnsafe, clock, err := o.parseRuntime()
	if err != nil {
		return verifyExecution{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return verifyExecution{
		ctx:          ctx,
		beforeDir:    dirs.before,
		afterDir:     dirs.after,
		controlsDir:  dirs.controls,
		maxUnsafe:    maxUnsafe,
		clock:        clock,
		allowUnknown: o.AllowUnknown,
	}, nil
}

func (o *options) normalizeDirs() verifyDirs {
	o.BeforeDir = fsutil.CleanUserPath(o.BeforeDir)
	o.AfterDir = fsutil.CleanUserPath(o.AfterDir)
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
	return verifyDirs{before: o.BeforeDir, after: o.AfterDir, controls: o.ControlsDir}
}

func validateVerifyDirs(dirs verifyDirs) error {
	for _, dir := range []struct {
		flag string
		path string
		hint error
	}{
		{"--before", dirs.before, nil},
		{"--after", dirs.after, nil},
		{"--controls", dirs.controls, ui.ErrHintControlsNotAccessible},
	} {
		if err := cmdutil.ValidateDir(dir.flag, dir.path, dir.hint); err != nil {
			return err
		}
	}
	return nil
}

func (o *options) parseRuntime() (time.Duration, ports.Clock, error) {
	maxDuration, err := timeutil.ParseDurationFlag(o.MaxUnsafe, "--max-unsafe")
	if err != nil {
		return 0, nil, err
	}
	clock, err := cmdutil.ResolveClock(o.Now)
	if err != nil {
		return 0, nil, err
	}
	return maxDuration, clock, nil
}
