package diagnose

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	"github.com/sufield/stave/internal/adapters/output"
	appdiagnose "github.com/sufield/stave/internal/app/diagnose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/trace"
)

// Config holds the inputs for the diagnostic engine.
type Config struct {
	ControlsDir     string
	ObservationsDir string
	PreviousOutput  string
	MaxUnsafe       string
	Format          ui.OutputFormat
	Quiet           bool
	Cases           []string
	SignalContains  string
	Template        string

	// Detail Mode (single-finding deep dive)
	ControlID string
	AssetID   string

	// IO streams
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader

	// Global flag state passed through from the CLI layer.
	Sanitizer    kernel.Sanitizer
	EnvelopeMode bool
}

// IsDetailMode returns true if both IDs are provided for a deep-dive analysis.
func (c Config) IsDetailMode() bool {
	return c.ControlID != "" && c.AssetID != ""
}

// Runner orchestrates the diagnostic analysis.
type Runner struct {
	Provider *compose.Provider
	Clock    ports.Clock
}

// NewRunner initializes a runner with the required dependencies.
func NewRunner(p *compose.Provider, clock ports.Clock) *Runner {
	return &Runner{
		Provider: p,
		Clock:    clock,
	}
}

// Run executes the diagnostic workflow.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	if err := r.validate(cfg); err != nil {
		return err
	}
	if cfg.IsDetailMode() {
		return r.runDetailMode(ctx, cfg)
	}
	return r.runStandardDiagnosis(ctx, cfg)
}

func (r *Runner) validate(cfg Config) error {
	if (cfg.ControlID != "" && cfg.AssetID == "") || (cfg.ControlID == "" && cfg.AssetID != "") {
		return fmt.Errorf("detail mode requires both --control-id AND --asset-id")
	}
	return nil
}

func (r *Runner) runStandardDiagnosis(ctx context.Context, cfg Config) error {
	maxDuration, err := timeutil.ParseDurationFlag(cfg.MaxUnsafe, "--max-unsafe")
	if err != nil {
		return err
	}

	diagnoseRun, err := r.newDiagnoseRun()
	if err != nil {
		return err
	}

	baseCfg := r.buildAppConfig(cfg, maxDuration)
	report, err := diagnoseRun.Execute(ctx, baseCfg)
	if err != nil {
		return err
	}

	report = output.SanitizeReport(cfg.Sanitizer, report)
	report = FilterReport(report, Filter{
		Cases:          cfg.Cases,
		SignalContains: cfg.SignalContains,
	})

	p := r.newPresenter(cfg)
	if err := p.RenderReport(report); err != nil {
		return err
	}
	if len(report.Issues) > 0 {
		return ui.ErrDiagnosticsFound
	}
	return nil
}

func (r *Runner) runDetailMode(ctx context.Context, cfg Config) error {
	maxDuration, err := timeutil.ParseDurationFlag(cfg.MaxUnsafe, "--max-unsafe")
	if err != nil {
		return err
	}

	diagnoseRun, err := r.newDiagnoseRun()
	if err != nil {
		return err
	}

	baseCfg := r.buildAppConfig(cfg, maxDuration)
	detail, err := diagnoseRun.ExecuteFindingDetail(ctx, appdiagnose.FindingDetailConfig{
		DiagnoseConfig: baseCfg,
		ControlID:      kernel.ControlID(cfg.ControlID),
		AssetID:        asset.ID(cfg.AssetID),
		TraceBuilder:   trace.NewFindingTraceBuilder(ctlyaml.ParsePredicate),
		IDGen:          crypto.NewHasher(),
	})
	if err != nil {
		return err
	}

	p := r.newPresenter(cfg)
	if err := p.RenderDetail(detail); err != nil {
		return err
	}
	if !cfg.Format.IsJSON() {
		return ui.ErrViolationsFound
	}
	return nil
}

func (r *Runner) newDiagnoseRun() (*appdiagnose.Run, error) {
	obsLoader, err := r.Provider.NewObservationRepo()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	ctlLoader, err := r.Provider.NewControlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	evalLoader := evaljson.NewLoader()
	return appdiagnose.NewRun(obsLoader, ctlLoader, evalLoader)
}

func (r *Runner) buildAppConfig(cfg Config, maxDuration time.Duration) appdiagnose.Config {
	appCfg := appdiagnose.Config{
		ControlsDir:     cfg.ControlsDir,
		ObservationsDir: cfg.ObservationsDir,
		MaxUnsafe:       maxDuration,
		Clock:           r.Clock,
		PredicateParser: ctlyaml.ParsePredicate,
	}
	if cfg.PreviousOutput == "-" {
		appCfg.OutputReader = cfg.Stdin
	} else {
		appCfg.OutputFile = cfg.PreviousOutput
	}
	return appCfg
}

func (r *Runner) newPresenter(cfg Config) *Presenter {
	return &Presenter{
		Stdout:       cfg.Stdout,
		Format:       cfg.Format,
		Quiet:        cfg.Quiet,
		Template:     cfg.Template,
		EnvelopeMode: cfg.EnvelopeMode,
	}
}

// --- Internal Helper: CLI Options ---

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

// NewDiagnoseCmd constructs the diagnose command.
func NewDiagnoseCmd() *cobra.Command {
	var opts diagnoseOptions

	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Diagnose evaluation inputs and results",
		Long: `Diagnose analyzes evaluation inputs and results to identify likely causes
when results don't match expectations.

Purpose: Understand why evaluation produced (or didn't produce) certain findings.

Inputs:
  --controls      Directory containing YAML control definitions
  --observations    Directory containing JSON observation snapshots
  --previous-output Optional path to existing apply output JSON

Outputs:
  stdout            Diagnostic report (text or JSON with --format json)
  stderr            Error messages (if any)

What it explains:
  - Expected violations but got none (threshold too high, time span too short)
  - Unexpected violations (clock skew, streak reset)
  - Empty findings (no predicate matches, under threshold)
  - Configuration mismatches

Finding Detail mode (--control-id + --asset-id):
  When both flags are set, diagnose switches to a single-finding deep dive
  showing control metadata, predicate evaluation trace, evidence,
  remediation guidance, and next steps.

Exit Codes:
  0   - No diagnostic issues found
  2   - Invalid input or error
  3   - Diagnostic issues detected
  130 - Interrupted (SIGINT)

Examples:
  # Basic diagnosis
  stave diagnose --controls ./controls --observations ./obs

  # Automation/CI mode (exit code only)
  stave diagnose --controls ./controls --observations ./obs --quiet

  # Troubleshooting an existing apply output
  stave diagnose --previous-output previous-run.json --controls ./controls --observations ./obs

  # JSON output for scripting
  stave diagnose --controls ./controls --observations ./obs --format json

  # Show only threshold/span diagnostics
  stave diagnose --controls ./controls --observations ./obs --case expected_violations_none

  # Diagnose from stdin (pipe evaluation output)
  stave apply --controls ./controls --observations ./obs | stave diagnose --previous-output - --controls ./controls --observations ./obs

  # Deep dive into a single finding (finding detail mode)
  stave diagnose --controls ./controls --observations ./obs \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id res:aws:s3:bucket:my-bucket

  # Same with existing evaluation output
  stave diagnose --previous-output output/evaluation.json \
    --controls ./controls --observations ./obs \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id res:aws:s3:bucket:my-bucket \
    --format json
` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// 1. Resolve environment and defaults
			resolver, _ := projctx.NewResolver()
			engine := projctx.NewInferenceEngine(resolver)
			clock, err := compose.ResolveClock(opts.NowTime)
			if err != nil {
				return err
			}

			// 2. Resolve paths with inference
			controlsDir := fsutil.CleanUserPath(opts.ControlsDir)
			obsDir := fsutil.CleanUserPath(opts.ObservationsDir)
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

			// 3. Validate directories
			if dirErr := cmdutil.ValidateFlagDir("--controls", controlsDir, "controls", ui.ErrHintControlsNotAccessible, engine.Log); dirErr != nil {
				return dirErr
			}
			if dirErr := cmdutil.ValidateFlagDir("--observations", obsDir, "observations", ui.ErrHintObservationsNotAccessible, engine.Log); dirErr != nil {
				return dirErr
			}

			// 4. Resolve formatting
			fmtValue, err := compose.ResolveFormatValue(cmd, opts.Format)
			if err != nil {
				return err
			}

			flags := cmdutil.GetGlobalFlags(cmd)

			// 5. Build Config
			cfg := Config{
				ControlsDir:     controlsDir,
				ObservationsDir: obsDir,
				PreviousOutput:  fsutil.CleanUserPath(opts.PreviousOutput),
				MaxUnsafe:       opts.MaxUnsafe,
				Format:          fmtValue,
				Quiet:           opts.Quiet,
				Cases:           opts.Cases,
				SignalContains:  opts.SignalContains,
				Template:        opts.Template,
				ControlID:       strings.TrimSpace(opts.ControlID),
				AssetID:         strings.TrimSpace(opts.AssetID),
				Stdout:          cmd.OutOrStdout(),
				Stderr:          cmd.ErrOrStderr(),
				Stdin:           cmd.InOrStdin(),
				Sanitizer:       flags.GetSanitizer(),
				EnvelopeMode:    flags.IsJSONMode(),
			}

			// 6. Execute
			runner := NewRunner(compose.ActiveProvider(), clock)
			return runner.Run(cmd.Context(), cfg)
		},
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	cmd.Flags().StringVarP(&opts.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	cmd.Flags().StringVarP(&opts.PreviousOutput, "previous-output", "p", "", "Path to existing apply output JSON (optional; if omitted, runs apply internally)")
	cmd.Flags().StringVar(&opts.MaxUnsafe, "max-unsafe", projconfig.Global().MaxUnsafe(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	cmd.Flags().StringVar(&opts.NowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().BoolVar(&opts.Quiet, "quiet", projconfig.Global().Quiet(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))
	cmd.Flags().StringSliceVar(&opts.Cases, "case", nil, "Filter to one or more diagnostic case values")
	cmd.Flags().StringVar(&opts.SignalContains, "signal-contains", "", "Filter diagnostics by signal substring (case-insensitive)")
	cmd.Flags().StringVar(&opts.Template, "template", "", "Template string for custom output formatting (supports {{.Field}}, {{range}}, {{json}})")
	cmd.Flags().StringVar(&opts.ControlID, "control-id", "", "Control ID for single-finding detail mode (requires --asset-id)")
	cmd.Flags().StringVar(&opts.AssetID, "asset-id", "", "Asset ID for single-finding detail mode (requires --control-id)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("case", cmdutil.CompleteFixed(
		string(diagnosis.ScenarioExpectedNone),
		string(diagnosis.ScenarioViolationEvidence),
		string(diagnosis.ScenarioEmptyFindings),
	))

	return cmd
}
