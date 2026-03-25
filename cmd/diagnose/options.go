package diagnose

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
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
}

// BindFlags attaches the options to a Cobra command.
func (o *diagnoseOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.ControlsDir, "controls", "i", "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	f.StringVarP(&o.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	f.StringVarP(&o.PreviousOutput, "previous-output", "p", "", "Path to existing apply output JSON (optional; if omitted, runs apply internally)")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	f.StringVarP(&o.Format, "format", "f", "text", "Output format: text or json")
	f.StringSliceVar(&o.Cases, "case", nil, "Filter to one or more diagnostic case values")
	f.StringVar(&o.SignalContains, "signal-contains", "", "Filter diagnostics by signal substring (case-insensitive)")
	f.StringVar(&o.Template, "template", "", "Template string for custom output formatting (supports {{.Field}}, {{range}}, {{json}})")
	f.StringVar(&o.ControlID, "control-id", "", "Control ID for single-finding detail mode (requires --asset-id)")
	f.StringVar(&o.AssetID, "asset-id", "", "Asset ID for single-finding detail mode (requires --control-id)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("case", cmdutil.CompleteFixed(
		string(diagnosis.ScenarioExpectedNone),
		string(diagnosis.ScenarioViolationEvidence),
		string(diagnosis.ScenarioEmptyFindings),
	))
}

// Prepare resolves config defaults. Called from PreRunE.
func (o *diagnoseOptions) Prepare(cmd *cobra.Command) error {
	o.resolveConfigDefaults(cmd)
	return nil
}

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *diagnoseOptions) resolveConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.EvaluatorFromCmd(cmd)
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
}

// ToConfig converts raw CLI options into a validated Config.
func (o *diagnoseOptions) ToConfig(cmd *cobra.Command) (Config, error) {
	ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:       o.ControlsDir,
		ObservationsDir:   o.ObservationsDir,
		ControlsChanged:   cmd.Flags().Changed("controls"),
		ObsChanged:        cmd.Flags().Changed("observations"),
		MaxUnsafeDuration: o.MaxUnsafeDuration,
		NowTime:           o.NowTime,
		Format:            o.Format,
		FormatChanged:     cmd.Flags().Changed("format"),
	})
	if err != nil {
		return Config{}, err
	}

	flags := cmdutil.GetGlobalFlags(cmd)

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
		Stdout:            cmd.OutOrStdout(),
		Stderr:            cmd.ErrOrStderr(),
		Stdin:             cmd.InOrStdin(),
		Clock:             ec.Clock,
		Sanitizer:         flags.GetSanitizer(),
	}, nil
}
