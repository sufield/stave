package diagnose

import (
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// diagnoseOptions holds the raw CLI flag values before validation.
type diagnoseOptions struct {
	ControlsDir       string
	ObservationsDir   string
	PreviousOutput    string
	MaxUnsafeDuration string
	NowTime           string
	Format            string
	Cases             []string
	SignalContains    string
	Template          string
	ControlID         string
	AssetID           string

	// Captured in Prepare from cmd.Flags().Changed() so ToConfig
	// does not need *cobra.Command.
	controlsSet bool
	obsSet      bool
	formatSet   bool
}

// BindFlags attaches the options to a Cobra command.
func (o *diagnoseOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.ControlsDir, "controls", "i", cliflags.DefaultControlsDir, "Path to control definitions directory (inferred from project root if omitted)")
	f.StringVarP(&o.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	f.StringVarP(&o.PreviousOutput, "previous-output", "p", "", "Path to existing apply output JSON (optional; if omitted, runs apply internally)")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	f.StringVarP(&o.Format, "format", "f", "text", "Output format: text or json")
	f.StringSliceVar(&o.Cases, "case", nil, "Filter to one or more diagnostic case values")
	f.StringVar(&o.SignalContains, "signal-contains", "", "Filter diagnostics by signal substring (case-insensitive)")
	f.StringVar(&o.Template, "template", "", "Template string for custom output formatting (supports {{.Field}}, {{range}}, {{json}})")
	f.StringVar(&o.ControlID, "control-id", "", "Control ID for single-finding detail mode (requires --asset-id)")
	f.StringVar(&o.AssetID, "asset-id", "", "Asset ID for single-finding detail mode (requires --control-id)")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))
	_ = cmd.RegisterFlagCompletionFunc("case", cliflags.CompleteFixed(
		string(diagnosis.ScenarioExpectedNone),
		string(diagnosis.ScenarioViolationEvidence),
		string(diagnosis.ScenarioEmptyFindings),
	))
}

// Prepare captures flag-changed state and resolves config defaults.
// Called from PreRunE — this is the only place that touches *cobra.Command.
func (o *diagnoseOptions) Prepare(cmd *cobra.Command) error {
	o.controlsSet = cmd.Flags().Changed("controls")
	o.obsSet = cmd.Flags().Changed("observations")
	o.formatSet = cmd.Flags().Changed("format")
	eval := cmdctx.EvaluatorFromCmd(cmd)
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
	return nil
}

// ToConfig converts raw CLI options into a validated Config.
// Does not take *cobra.Command — all Cobra state was captured in Prepare.
func toConfig(o *diagnoseOptions, flags cliflags.GlobalFlags, stdout, stderr io.Writer, stdin io.Reader) (Config, error) {
	ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:       o.ControlsDir,
		ObservationsDir:   o.ObservationsDir,
		ControlsChanged:   o.controlsSet,
		ObsChanged:        o.obsSet,
		MaxUnsafeDuration: o.MaxUnsafeDuration,
		NowTime:           o.NowTime,
		Format:            o.Format,
		FormatChanged:     o.formatSet,
	})
	if err != nil {
		return Config{}, err
	}

	return Config{
		ControlsDir:       ec.ControlsDir,
		ObservationsDir:   ec.ObservationsDir,
		PreviousOutput:    fsutil.CleanUserPath(o.PreviousOutput),
		MaxUnsafeDuration: ec.MaxUnsafe,
		Format:            ec.Format,
		Quiet:             flags.Quiet,
		Cases:             o.Cases,
		SignalContains:    o.SignalContains,
		Template:          o.Template,
		ControlID:         strings.TrimSpace(o.ControlID),
		AssetID:           strings.TrimSpace(o.AssetID),
		Stdout:            stdout,
		Stderr:            stderr,
		Stdin:             stdin,
		Clock:             ec.Clock,
		Sanitizer:         flags.GetSanitizer(),
	}, nil
}
