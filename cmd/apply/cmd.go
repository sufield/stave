package apply

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *SharedOptions) resolveConfigDefaults(cmd *cobra.Command, eval *appconfig.Evaluator) {
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
}

// resolveApplyConfigDefaults fills apply-specific flag values from project
// config when the user did not set them explicitly on the command line.
func (o *ApplyOptions) resolveApplyConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.EvaluatorFromCmd(cmd)
	o.resolveConfigDefaults(cmd, eval)
	if !cmd.Flags().Changed("allow-unknown-input") {
		o.AllowUnknown = eval.AllowUnknownInput()
	}
}

// SharedOptions contains flags common to both plan and apply.
type SharedOptions struct {
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration string
	NowTime           string
	Format            string

	// controlsSet tracks whether --controls was explicitly set by the user.
	// Derived from Cobra in PreRunE; not a user-facing flag.
	controlsSet bool
}

func (o *SharedOptions) bindCommon(cmd *cobra.Command, defaultFormat string) {
	f := cmd.Flags()
	cliflags.RegisterControlsFlag(cmd, &o.ControlsDir, "controls/s3", "Path to control definitions directory")

	f.StringVarP(&o.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339) for deterministic output")
	f.StringVarP(&o.Format, "format", "f", defaultFormat, "Output format (text, json, or sarif)")
}

func (o *SharedOptions) normalize() {
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
	o.ObservationsDir = fsutil.CleanUserPath(o.ObservationsDir)
}

// ApplyOptions configuration for the apply command.
type ApplyOptions struct {
	SharedOptions
	DryRun             bool
	AllowUnknown       bool
	ExemptionFile      string
	IntegrityManifest  string
	IntegrityPublicKey string
	Profile            string
	InputFile          string
	BucketAllowlist    []string
	IncludeAll         bool
}

// normalize cleans all user-supplied paths in one pass.
func (o *ApplyOptions) normalize() {
	o.SharedOptions.normalize()
	o.ExemptionFile = fsutil.CleanUserPath(o.ExemptionFile)
	o.IntegrityManifest = fsutil.CleanUserPath(o.IntegrityManifest)
	o.IntegrityPublicKey = fsutil.CleanUserPath(o.IntegrityPublicKey)
	o.InputFile = fsutil.CleanUserPath(o.InputFile)
}

// NewApplyCmd constructs the apply command.
func NewApplyCmd(p *compose.Provider) *cobra.Command {
	opts := &ApplyOptions{}

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Run control evaluation after plan checks pass",
		Long: `Apply executes control evaluation and produces safety findings.

Modes:
  Default        Evaluate observations against controls in a project directory.
  --dry-run      Run readiness checks only, without evaluating controls.
  --profile      Evaluate a bundled observations file against a built-in control pack.
                 Requires --input. Example: stave apply --profile aws-s3 --input obs.json

Inputs:
  --controls, -i            Path to control definitions directory (default: controls/s3)
  --observations, -o        Path to observation snapshots directory (default: observations)
  --profile, -p             Evaluation profile (e.g., aws-s3)
  --input                   Path to observations bundle file (required with --profile)
  --max-unsafe              Maximum allowed unsafe duration (default: from project config)
  --now                     Override current time (RFC3339) for deterministic output
  --format, -f              Output format: json, text, or sarif (default: json)
  --dry-run                 Run readiness checks only
  --allow-unknown-input     Allow observations with unknown source types

Outputs:
  stdout                    Evaluation findings (JSON, text, or SARIF)
  stderr                    Progress and diagnostic messages

Exit Codes:
  0   - Evaluation completed with no violations
  2   - Invalid input or configuration error
  3   - Violations found
  4   - Internal error
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Standard evaluation
  stave apply --controls ./controls --observations ./obs --format json

  # Readiness check only (dry run)
  stave apply --dry-run

  # Profile-based evaluation with bundled observations
  stave apply --profile aws-s3 --input observations.json --now 2026-01-15T00:00:00Z`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			opts.controlsSet = cliflags.ControlsFlagChanged(cmd)
			opts.normalize()
			opts.resolveApplyConfigDefaults(cmd)
			return opts.validate()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cs := cobraState{
				Logger:        cmdctx.LoggerFromCmd(cmd),
				Stdout:        cmd.OutOrStdout(),
				Stderr:        cmd.ErrOrStderr(),
				Stdin:         cmd.InOrStdin(),
				GlobalFlags:   cliflags.GetGlobalFlags(cmd),
				FormatChanged: cmd.Flags().Changed("format"),
				ObsChanged:    cmd.Flags().Changed("observations"),
			}
			return runApply(cmd.Context(), p, opts, cs)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Run readiness checks only, without evaluating controls")
	opts.bindCommon(cmd, "json")
	opts.bindApplySpecific(cmd)
	// Completion registration is best-effort — if it fails, help output
	// loses tab completion but the command still works.
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("json", "text", "sarif"))

	return cmd
}

func (o *ApplyOptions) bindApplySpecific(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", false, cliflags.WithDynamicDefaultHelp("Allow unknown source types"))
	f.StringVar(&o.ExemptionFile, "exemption-file", "", "Path to asset exemption list YAML file")
	f.StringVar(&o.IntegrityManifest, "integrity-manifest", "", "Path to manifest JSON containing expected hashes")
	f.StringVar(&o.IntegrityPublicKey, "integrity-public-key", "", "Path to Ed25519 public key for signed manifests")
	f.StringVarP(&o.Profile, "profile", "p", "", "Evaluation profile (e.g. aws-s3)")
	f.StringVar(&o.InputFile, "input", "", "Path to observations bundle file (required with --profile)")
	f.StringSliceVar(&o.BucketAllowlist, "bucket-allowlist", nil, "Bucket names/ARNs to include")
	f.BoolVar(&o.IncludeAll, "include-all", false, "Disable health scope filtering")
}

func (o *ApplyOptions) validate() error {
	if o.Profile != "" && o.InputFile == "" {
		return fmt.Errorf("flag --input is required when using --profile")
	}
	return nil
}
