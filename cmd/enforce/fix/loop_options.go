package fix

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// configDefaults provides project-level defaults for loop options.
type configDefaults interface {
	MaxUnsafeDuration() string
	AllowUnknownInput() bool
}

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
	f.StringVar(&o.MaxUnsafeRaw, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowRaw, "now", "", "Override current time (RFC3339). Required for deterministic output")
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", false, cliflags.WithDynamicDefaultHelp("Allow observations with unknown source types"))
	f.StringVar(&o.OutDir, "out", "", "Write remediation artifacts to this directory")
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")
}

// Prepare resolves config defaults and normalizes paths. Called from PreRunE.
func (o *loopOptions) Prepare(cmd *cobra.Command) error {
	o.resolveConfigDefaults(cmdctx.EvaluatorFromCmd(cmd), cmd.Flags())
	return o.normalize()
}

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *loopOptions) resolveConfigDefaults(defaults configDefaults, flags *pflag.FlagSet) {
	if defaults == nil {
		return
	}
	if !flags.Changed("max-unsafe") {
		o.MaxUnsafeRaw = defaults.MaxUnsafeDuration()
	}
	if !flags.Changed("allow-unknown-input") {
		o.AllowUnknown = defaults.AllowUnknownInput()
	}
}

// loopResolved holds the parsed runtime values from flag resolution.
type loopResolved struct {
	Request LoopRequest
	Clock   ports.Clock
}

// toRequest resolves raw flag values into a validated LoopRequest and Clock.
func toRequest(o *loopOptions, stdout, stderr io.Writer) (loopResolved, error) {
	maxUnsafe, err := cliflags.ParseDurationFlag(o.MaxUnsafeRaw, "--max-unsafe")
	if err != nil {
		return loopResolved{}, err
	}
	clock, err := compose.ResolveClock(o.NowRaw)
	if err != nil {
		return loopResolved{}, err
	}
	return loopResolved{
		Request: LoopRequest{
			BeforeDir:         o.BeforeDir,
			AfterDir:          o.AfterDir,
			ControlsDir:       o.ControlsDir,
			OutDir:            o.OutDir,
			MaxUnsafeDuration: maxUnsafe,
			AllowUnknown:      o.AllowUnknown,
			Stdout:            stdout,
			Stderr:            stderr,
		},
		Clock: clock,
	}, nil
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
