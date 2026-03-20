package diagnose

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
)

// diagnoseOptions holds the raw CLI flag values before validation.
type diagnoseOptions struct {
	ControlsDir     string
	ObservationsDir string
	PreviousOutput  string
	MaxUnsafe       string
	NowTime         string
	Format          string
	Quiet           bool
	Cases           []string
	SignalContains  string
	Template        string
	ControlID       string
	AssetID         string
}

// BindFlags attaches the options to a Cobra command.
func (o *diagnoseOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.ControlsDir, "controls", "i", "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	f.StringVarP(&o.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	f.StringVarP(&o.PreviousOutput, "previous-output", "p", "", "Path to existing apply output JSON (optional; if omitted, runs apply internally)")
	f.StringVar(&o.MaxUnsafe, "max-unsafe", projconfig.Global().MaxUnsafe(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	f.StringVarP(&o.Format, "format", "f", "text", "Output format: text or json")
	f.BoolVar(&o.Quiet, "quiet", projconfig.Global().Quiet(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))
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

// ToConfig converts raw CLI options into a validated Config.
func (o *diagnoseOptions) ToConfig(cmd *cobra.Command) (Config, error) {
	resolver, resolverErr := projctx.NewResolver()
	if resolverErr != nil {
		return Config{}, fmt.Errorf("resolve project context: %w", resolverErr)
	}
	engine := projctx.NewInferenceEngine(resolver)

	clock, err := compose.ResolveClock(o.NowTime)
	if err != nil {
		return Config{}, err
	}

	controlsDir := fsutil.CleanUserPath(o.ControlsDir)
	obsDir := fsutil.CleanUserPath(o.ObservationsDir)
	if !cmd.Flags().Changed("controls") {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			controlsDir = inferred
		}
	}
	if !cmd.Flags().Changed("observations") {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			obsDir = inferred
		}
	}

	if dirErr := cmdutil.ValidateFlagDir("--controls", controlsDir, "controls", ui.ErrHintControlsNotAccessible, engine.Log); dirErr != nil {
		return Config{}, dirErr
	}
	if dirErr := cmdutil.ValidateFlagDir("--observations", obsDir, "observations", ui.ErrHintObservationsNotAccessible, engine.Log); dirErr != nil {
		return Config{}, dirErr
	}

	fmtValue, err := compose.ResolveFormatValue(cmd, o.Format)
	if err != nil {
		return Config{}, err
	}

	maxUnsafe, err := timeutil.ParseDurationFlag(o.MaxUnsafe, "--max-unsafe")
	if err != nil {
		return Config{}, err
	}

	flags := cmdutil.GetGlobalFlags(cmd)

	return Config{
		ControlsDir:     controlsDir,
		ObservationsDir: obsDir,
		PreviousOutput:  fsutil.CleanUserPath(o.PreviousOutput),
		MaxUnsafe:       maxUnsafe,
		Format:          fmtValue,
		Quiet:           o.Quiet,
		Cases:           o.Cases,
		SignalContains:  o.SignalContains,
		Template:        o.Template,
		ControlID:       strings.TrimSpace(o.ControlID),
		AssetID:         strings.TrimSpace(o.AssetID),
		Stdout:          cmd.OutOrStdout(),
		Stderr:          cmd.ErrOrStderr(),
		Stdin:           cmd.InOrStdin(),
		Clock:           clock,
		Sanitizer:       flags.GetSanitizer(),
		EnvelopeMode:    flags.IsJSONMode(),
	}, nil
}
