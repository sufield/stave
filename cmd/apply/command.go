package apply

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

// applyFlagsType groups all CLI flags for the apply command.
type applyFlagsType struct {
	controlsDir, observationsDir, maxUnsafe, nowTime string
	allowUnknownInput                                bool
	profileIncludeAll                                bool
	outputFormat, ignoreFile, applyProfile           string
	profileInputFile                                 string
	profileBucketAllowlist                           []string
	applyControlsFlagSet                             bool
	applyIntegrityManifest, applyIntegrityPublicKey  string
}

type readinessInput struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	Now             string
	ControlsFlagSet bool
}

// planFlagsType groups all CLI flags for the plan command.
type planFlagsType struct {
	controlsDir, observationsDir, maxUnsafe, nowTime, format string
}

// NewPlanCmd constructs the plan command with closure-scoped flags.
func NewPlanCmd() *cobra.Command {
	var flags planFlagsType

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Readiness gate before apply",
		Long: `Plan checks whether your project is ready to run apply.

It validates prerequisite health and input readiness so teams can move through
a clear phase gate with minimal trial-and-error.

What plan verifies:
  - Local environment prerequisites (doctor checks)
  - Control source selection is unambiguous
  - Controls and observations pass validate checks
  - Snapshot set is sufficient for time-based evaluation

Examples:
  stave plan
  stave plan --controls ./controls --observations ./observations
  stave plan --format json` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlan(cmd, &flags)
		},
	}

	cmdutil.RegisterControlsFlag(cmd, &flags.controlsDir, "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	cmd.Flags().StringVarP(&flags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	cmd.Flags().StringVar(&flags.maxUnsafe, "max-unsafe", cmdutil.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	cmd.Flags().StringVar(&flags.nowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

// NewApplyCmd constructs the apply command with closure-scoped flags.
func NewApplyCmd() *cobra.Command {
	var flags applyFlagsType

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Run control evaluation after plan checks pass",
		Long: `Apply executes control evaluation only after readiness checks pass.

Purpose: Execute the control engine against prepared inputs.

Inputs:
  --controls            Directory containing YAML control definitions (ctrl.v1)
  --observations        Directory containing observation snapshots (obs.v0.1)
  --max-unsafe          Maximum time an asset may remain unsafe before violation

Outputs:
  stdout          Findings report (json/text/sarif based on --format)
  stderr          Readiness failures and execution diagnostics

Exit Codes:
  0   - Success, no violations found
  2   - Readiness or input validation failed
  3   - Violations detected
  130 - Interrupted (SIGINT)

Examples:
  # Step 1: Run readiness gate
  stave plan --controls ./controls --observations ./observations

  # Step 2: Execute control engine
  stave apply --controls ./controls --observations ./observations --format json

  # Profile mode: evaluate a bundled observations file against built-in controls
  stave apply --profile aws-s3 --input observations.json --now 2026-01-15T00:00:00Z

If readiness checks fail, apply exits early with concrete next steps.` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(cmd, args, &flags)
		},
	}

	cmdutil.RegisterControlsFlag(cmd, &flags.controlsDir, "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	cmd.Flags().StringVarP(&flags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	cmd.Flags().StringVar(&flags.maxUnsafe, "max-unsafe", cmdutil.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	cmd.Flags().StringVar(&flags.nowTime, "now", "", "Override current time (RFC3339 format). Required for deterministic output")
	cmd.Flags().BoolVar(&flags.allowUnknownInput, "allow-unknown-input", cmdutil.ResolveAllowUnknownInputDefault(), cmdutil.WithDynamicDefaultHelp("Allow observations with unknown or missing source types"))
	cmd.Flags().StringVarP(&flags.outputFormat, "format", "f", "json", "Output format: json, text, or sarif")
	cmd.Flags().StringVar(&flags.ignoreFile, "ignore", "", "Path to asset ignore list YAML file")
	cmd.Flags().StringVar(&flags.applyIntegrityManifest, "integrity-manifest", "", "Path to manifest JSON containing expected observation hashes")
	cmd.Flags().StringVar(&flags.applyIntegrityPublicKey, "integrity-public-key", "", "Path to Ed25519 public key for signed manifests")
	cmd.Flags().StringVarP(&flags.applyProfile, "profile", "p", "", "Evaluation profile (e.g. aws-s3)")
	cmd.Flags().StringVar(&flags.profileInputFile, "input", "", "Path to observations bundle file (required with --profile)")
	cmd.Flags().StringSliceVar(&flags.profileBucketAllowlist, "bucket-allowlist", nil, "Bucket names/ARNs to include (can specify multiple)")
	cmd.Flags().BoolVar(&flags.profileIncludeAll, "include-all", false, "Disable health scope filtering (extract all buckets)")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("json", "text", "sarif"))

	return cmd
}
