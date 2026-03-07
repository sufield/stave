package apply

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/metadata"
)

// applyFlagsType groups all CLI flags for the apply command.
type applyFlagsType struct {
	controlsDir, observationsDir, maxUnsafe, nowTime    string
	allowUnknownInput, quietMode, applyDryRun          bool
	applyExplain, profileIncludeAll                    bool
	outputFormat, ignoreFile, applyProfile             string
	profileInputFile, profileScopeFile                 string
	profileBucketAllowlist, applyExcludeControlIDs     []string
	applyTemplateStr, applyMinSeverity                 string
	applyControlID, applyCompliance                    string
	applyControlsFlagSet                               bool
	applyIntegrityManifest, applyIntegrityPublicKey    string
}

var applyFlags applyFlagsType

func init() {
	cmdutil.RegisterControlsFlag(ApplyCmd, &applyFlags.controlsDir, "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	ApplyCmd.Flags().StringVarP(&applyFlags.observationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	ApplyCmd.Flags().StringVar(&applyFlags.maxUnsafe, "max-unsafe", cmdutil.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	ApplyCmd.Flags().StringVar(&applyFlags.nowTime, "now", "", "Override current time (RFC3339 format). Required for deterministic output")
	ApplyCmd.Flags().BoolVar(&applyFlags.allowUnknownInput, "allow-unknown-input", cmdutil.ResolveAllowUnknownInputDefault(), cmdutil.WithDynamicDefaultHelp("Allow observations with unknown or missing source types"))
	ApplyCmd.Flags().StringVarP(&applyFlags.outputFormat, "format", "f", "json", "Output format: json, text, or sarif")
	ApplyCmd.Flags().BoolVar(&applyFlags.quietMode, "quiet", cmdutil.ResolveQuietDefault(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))
	ApplyCmd.Flags().StringVar(&applyFlags.ignoreFile, "ignore", "", "Path to asset ignore list YAML file")
	ApplyCmd.Flags().StringVar(&applyFlags.applyIntegrityManifest, "integrity-manifest", "", "Path to manifest JSON containing expected observation hashes")
	ApplyCmd.Flags().StringVar(&applyFlags.applyIntegrityPublicKey, "integrity-public-key", "", "Path to Ed25519 public key for signed manifests")
	ApplyCmd.Flags().StringVarP(&applyFlags.applyProfile, "profile", "p", "", "Evaluation profile (e.g. aws-s3)")
	ApplyCmd.Flags().StringVar(&applyFlags.profileInputFile, "input", "", "Path to observations bundle file (required with --profile)")
	ApplyCmd.Flags().StringVar(&applyFlags.profileScopeFile, "scope", "", "Path to health scope config YAML file")
	ApplyCmd.Flags().StringSliceVar(&applyFlags.profileBucketAllowlist, "bucket-allowlist", nil, "Bucket names/ARNs to include (can specify multiple)")
	ApplyCmd.Flags().BoolVar(&applyFlags.profileIncludeAll, "include-all", false, "Disable health scope filtering (extract all buckets)")
	_ = ApplyCmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("json", "text", "sarif"))
}

var (
	readinessPlanControlsDir     string
	readinessPlanObservationsDir string
	readinessPlanMaxUnsafe       string
	readinessPlanNowTime         string
	readinessPlanFormat          string
	readinessPlanQuiet           bool
)

type readinessInput struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	Now             string
	ControlsFlagSet bool
}

// PlanCmd is the plan command.
var PlanCmd = &cobra.Command{
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
	RunE:          runPlan,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// ApplyCmd is the apply command.
var ApplyCmd = &cobra.Command{
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
	RunE:          runApply,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	cmdutil.RegisterControlsFlag(PlanCmd, &readinessPlanControlsDir, "controls/s3", "Path to control definitions directory (inferred from project root if omitted)")
	PlanCmd.Flags().StringVarP(&readinessPlanObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory (inferred from project root if omitted)")
	PlanCmd.Flags().StringVar(&readinessPlanMaxUnsafe, "max-unsafe", cmdutil.ResolveMaxUnsafeDefault(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	PlanCmd.Flags().StringVar(&readinessPlanNowTime, "now", "", "Override current time (RFC3339). Required for deterministic output")
	PlanCmd.Flags().StringVarP(&readinessPlanFormat, "format", "f", "text", "Output format: text or json")
	PlanCmd.Flags().BoolVar(&readinessPlanQuiet, "quiet", cmdutil.ResolveQuietDefault(), cmdutil.WithDynamicDefaultHelp("Suppress output (exit code only)"))
	_ = PlanCmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
}
