package diagnose

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewFindingCmd constructs the diagnose finding subcommand for single-finding deep dives.
func NewFindingCmd(newObsRepo compose.ObsRepoFactory, newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	var (
		controlsDir     string
		observationsDir string
		previousOutput  string
		maxUnsafe       string
		nowTime         string
		format          string
		template        string
		controlID       string
		assetID         string
		// Flag-explicitness bits captured in PreRunE so RunE
		// (and PrepareEvaluationContext) stay off cobra.
		controlsChanged bool
		obsChanged      bool
		formatChanged   bool
	)

	cmd := &cobra.Command{
		Use:   "finding",
		Short: "Deep-dive analysis of a single finding",
		Long: `Finding generates a detailed root-cause analysis for a specific control/asset
violation. It shows control metadata, predicate evaluation trace, evidence,
remediation guidance, and next steps.

Inputs:
  --control-id     Control ID to inspect (required)
  --asset-id       Asset ID to inspect (required)
  --controls       Directory containing YAML control definitions
  --observations   Directory containing JSON observation snapshots
  --previous-output  Optional path to existing apply output JSON

Outputs:
  stdout           Finding detail (text or JSON with --format json)

Exit Codes:
  0   - Finding detail rendered successfully
  2   - Invalid input or error
  3   - Violation confirmed

Examples:
  # Deep dive into a specific finding
  stave diagnose finding \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id res:aws:s3:bucket:my-bucket \
    --controls ./controls --observations ./obs

  # Using existing evaluation output
  stave diagnose finding \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id res:aws:s3:bucket:my-bucket \
    --previous-output output/evaluation.json \
    --controls ./controls --observations ./obs

  # JSON output for scripting
  stave diagnose finding \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id res:aws:s3:bucket:my-bucket \
    --controls ./controls --observations ./obs \
    --format json` + metadata.OfflineHelpSuffix,
		Example: `  stave diagnose finding --control-id CTL.S3.PUBLIC.001 --asset-id my-bucket \
    --controls ./controls --observations ./obs`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(controlID) == "" || strings.TrimSpace(assetID) == "" {
				return errors.New("both --control-id and --asset-id are required")
			}
			eval := cmdctx.ResolverFromCmd(cmd)
			if !cmd.Flags().Changed("max-unsafe") {
				maxUnsafe = eval.MaxUnsafeDuration()
			}
			controlsChanged = cmd.Flags().Changed("controls")
			obsChanged = cmd.Flags().Changed("observations")
			formatChanged = cmd.Flags().Changed("format")
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := cliflags.GetGlobalFlags(cmd)

			ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
				ControlsDir:       controlsDir,
				ObservationsDir:   observationsDir,
				ControlsChanged:   controlsChanged,
				ObsChanged:        obsChanged,
				MaxUnsafeDuration: maxUnsafe,
				NowTime:           nowTime,
				Format:            format,
				FormatChanged:     formatChanged,
			})
			if err != nil {
				return err
			}

			obsRepo, err := newObsRepo()
			if err != nil {
				return fmt.Errorf("create observation loader: %w", err)
			}
			ctlRepo, err := newCtlRepo()
			if err != nil {
				return fmt.Errorf("create control loader: %w", err)
			}

			cfg := Config{
				ControlsDir:       ec.ControlsDir,
				ObservationsDir:   ec.ObservationsDir,
				PreviousOutput:    previousOutput,
				MaxUnsafeDuration: ec.MaxUnsafe,
				Format:            ec.Format,
				Quiet:             flags.Quiet,
				Template:          template,
				ControlID:         strings.TrimSpace(controlID),
				AssetID:           strings.TrimSpace(assetID),
				Stdout:            cmd.OutOrStdout(),
				Stderr:            cmd.ErrOrStderr(),
				Stdin:             cmd.InOrStdin(),
				Clock:             ec.Clock,
				Sanitizer:         flags.GetSanitizer(),
			}

			runner := NewRunner(obsRepo, ctlRepo, cfg.Clock)
			return runner.runDetailMode(cmd.Context(), cfg)
		},
	}

	f := cmd.Flags()
	f.StringVar(&controlID, "control-id", "", "Control ID to inspect (required)")
	f.StringVar(&assetID, "asset-id", "", "Asset ID to inspect (required)")
	f.StringVarP(&controlsDir, "controls", "i", cliflags.DefaultControlsDir, "Path to control definitions directory")
	f.StringVarP(&observationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVarP(&previousOutput, "previous-output", "p", "", "Path to existing apply output JSON")
	f.StringVar(&maxUnsafe, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&nowTime, "now", "", "Override current time (RFC3339)")
	f.StringVarP(&format, "format", "f", "text", "Output format: text or json")
	f.StringVar(&template, "template", "", "Template string for custom output formatting")
	_ = cmd.MarkFlagRequired("control-id")
	_ = cmd.MarkFlagRequired("asset-id")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))

	return cmd
}
