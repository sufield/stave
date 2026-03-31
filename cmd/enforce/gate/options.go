package gate

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// gateOptions holds the raw CLI flag values before validation.
type gateOptions struct {
	Policy            string
	InPath            string
	BaselinePath      string
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration string
	Now               string
	Format            string
	formatChanged     bool // set by Prepare from cmd.Flags().Changed
}

// DefaultOptions returns the standard defaults for the gate command.
// Config-derived fields (Policy, MaxUnsafeDuration) start as zero values;
// call resolveConfigDefaults after flag parsing to fill them from project config.
func DefaultOptions() gateOptions {
	return gateOptions{
		InPath:          "output/evaluation.json",
		BaselinePath:    "output/baseline.json",
		ControlsDir:     cliflags.DefaultControlsDir,
		ObservationsDir: "observations",
		Format:          "text",
	}
}

// Prepare resolves config defaults from project config. Called from PreRunE.
func (o *gateOptions) Prepare(cmd *cobra.Command) error {
	eval := cmdctx.EvaluatorFromCmd(cmd)
	if eval == nil {
		return nil
	}
	if !cmd.Flags().Changed("policy") {
		o.Policy = string(eval.CIFailurePolicy())
	}
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
	o.formatChanged = cmd.Flags().Changed("format")
	return nil
}

// BindFlags attaches the options to a Cobra command.
func (o *gateOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.Policy, "policy", "", cliflags.WithDynamicDefaultHelp("CI failure policy mode: fail_on_any_violation, fail_on_new_violation, fail_on_overdue_upcoming"))
	f.StringVar(&o.InPath, "in", o.InPath, "Path to evaluation JSON (required for fail_on_any_violation and fail_on_new_violation)")
	f.StringVar(&o.BaselinePath, "baseline", o.BaselinePath, "Path to baseline JSON (required for fail_on_new_violation)")
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory (used by fail_on_overdue_upcoming)")
	f.StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory (used by fail_on_overdue_upcoming)")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)"))
	f.StringVar(&o.Now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
}

// toConfig converts raw CLI options into a validated Config.
// Standalone function — does not depend on cobra.
func toConfig(o *gateOptions, gf cliflags.GlobalFlags, stdout, stderr io.Writer) (config, error) {
	policy, err := appconfig.ParseGatePolicy(o.Policy)
	if err != nil {
		return config{}, fmt.Errorf("invalid policy: %w", err)
	}

	ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:       o.ControlsDir,
		ObservationsDir:   o.ObservationsDir,
		MaxUnsafeDuration: o.MaxUnsafeDuration,
		NowTime:           o.Now,
		Format:            o.Format,
		FormatChanged:     o.formatChanged,
		SkipPathInference: true,
		SkipMaxUnsafe:     policy != appconfig.GatePolicyOverdue,
	})
	if err != nil {
		return config{}, fmt.Errorf("prepare evaluation context: %w", err)
	}

	return config{
		Policy:            policy,
		InPath:            fsutil.CleanUserPath(o.InPath),
		BaselinePath:      fsutil.CleanUserPath(o.BaselinePath),
		ControlsDir:       ec.ControlsDir,
		ObservationsDir:   ec.ObservationsDir,
		MaxUnsafeDuration: ec.MaxUnsafe,
		Format:            ec.Format,
		Quiet:             gf.Quiet,
		Clock:             ec.Clock,
		Sanitizer:         gf.GetSanitizer(),
		Stdout:            stdout,
		Stderr:            stderr,
	}, nil
}
