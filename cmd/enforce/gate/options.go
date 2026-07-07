package gate

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
)

// Options holds the raw CLI flag values before validation.
type Options struct {
	Policy            string
	InPath            string
	BaselinePath      string
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration string
	EvalTime          string
	Format            string
	Team              string
	TeamManifest      string
}

// DefaultOptions returns the standard defaults for the gate command.
// Config-derived fields (Policy, MaxUnsafeDuration) start as zero values;
// call Prepare after flag parsing to fill them from project config.
func DefaultOptions() Options {
	return Options{
		InPath:          "output/evaluation.json",
		BaselinePath:    "output/baseline.json",
		ControlsDir:     cliflags.DefaultControlsDir,
		ObservationsDir: "observations",
		Format:          "text",
	}
}

// Prepare resolves config defaults from project config. Called from PreRunE.
func (o *Options) Prepare(cmd *cobra.Command) error {
	eval := cmdctx.ResolverFromCmd(cmd)
	if eval == nil {
		return nil
	}
	if !cmd.Flags().Changed("policy") {
		o.Policy = string(eval.CIFailurePolicy())
	}
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
	return nil
}

// BindFlags attaches the options to a Cobra command.
func (o *Options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.Policy, "policy", "", cliflags.WithDynamicDefaultHelp("CI failure policy mode: fail_on_any_violation, fail_on_new_violation, fail_on_overdue_upcoming"))
	f.StringVar(&o.InPath, "in", o.InPath, "Path to evaluation JSON (required for fail_on_any_violation and fail_on_new_violation)")
	f.StringVar(&o.BaselinePath, "baseline", o.BaselinePath, "Path to baseline JSON (required for fail_on_new_violation)")
	f.StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory (used by fail_on_overdue_upcoming)")
	f.StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory (used by fail_on_overdue_upcoming)")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)"))
	f.StringVar(&o.EvalTime, "eval-time", "", "Evaluation reference timestamp (RFC3339). Durations and temporal risk are measured against this time. Defaults to wall clock.")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
	f.StringVar(&o.Team, "team", "", "Filter gate to findings owned by this team")
	f.StringVar(&o.TeamManifest, "team-manifest", "", "Team manifest YAML for ownership routing")
}
