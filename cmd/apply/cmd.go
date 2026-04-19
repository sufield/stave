package apply

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// resolveEnvVarDefaults fills shared flag values from STAVE_* environment
// variables when the user did not set them explicitly on the command line.
// Precedence: CLI flag > env var > config file > default.
func (o *Options) resolveEnvVarDefaults(cmd *cobra.Command) {
	o.Format = cliflags.ResolveFormatEnv(cmd, o.Format)
	o.ControlsDir = cliflags.ResolveControlsEnv(cmd, o.ControlsDir)
	o.ObservationsDir = cliflags.ResolveObservationsEnv(cmd, o.ObservationsDir)
	o.NowTime = cliflags.ResolveNowEnv(cmd, o.NowTime)
}

// resolveApplyConfigDefaults fills apply-specific flag values from project
// config when the user did not set them explicitly on the command line.
// Called from PreRunE — the only place that touches *cobra.Command.
func (o *Options) resolveApplyConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.ResolverFromCmd(cmd)
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafeDuration = eval.MaxUnsafeDuration()
	}
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
	cliflags.RegisterControlsFlag(cmd, &o.ControlsDir, cliflags.DefaultControlsDir, "Path to control definitions directory")

	f.StringVarP(&o.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339) for deterministic output")
	f.StringVarP(&o.Format, "format", "f", defaultFormat, "Output format (text, json, or sarif)")
}

func (o *SharedOptions) normalize() {
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
	o.ObservationsDir = fsutil.CleanUserPath(o.ObservationsDir)
}

// Options configuration for the apply command.
type Options struct {
	SharedOptions
	DryRun             bool
	AllowUnknown       bool
	ExemptionFile      string
	AcknowledgmentFile string
	IntegrityManifest  string
	IntegrityPublicKey string
	Profile            string
	InputFile          string
	BucketAllowlist    []string
	IncludeAll         bool
	TracePath          string
	SLAProfile         string
	SLAProfileFile     string
	SLAPolicy          string
	TeamManifest       string
	OwnerFilter        string
	ProfileFiles       []string
	OverlayPath        string
	ShowSuppressed     bool
	AssetsManifest     string
	HistoryDir         string
	NewOnly            bool
	NewSince           string
	SARIFBaseline      string
	AssertRecent       string
}

// normalize cleans all user-supplied paths in one pass.
func (o *Options) normalize() {
	o.SharedOptions.normalize()
	o.ExemptionFile = fsutil.CleanUserPath(o.ExemptionFile)
	o.AcknowledgmentFile = fsutil.CleanUserPath(o.AcknowledgmentFile)
	o.TeamManifest = fsutil.CleanUserPath(o.TeamManifest)
	o.IntegrityManifest = fsutil.CleanUserPath(o.IntegrityManifest)
	o.IntegrityPublicKey = fsutil.CleanUserPath(o.IntegrityPublicKey)
	o.InputFile = fsutil.CleanUserPath(o.InputFile)
	o.HistoryDir = fsutil.CleanUserPath(o.HistoryDir)
	o.SARIFBaseline = fsutil.CleanUserPath(o.SARIFBaseline)
}

// NewApplyCmd constructs the apply command.
func NewApplyCmd(deps Deps) *cobra.Command {
	opts := &Options{}

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
			opts.resolveEnvVarDefaults(cmd)
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
			return runApply(cmd.Context(), deps, opts, cs)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Run readiness checks only, without evaluating controls")
	opts.bindCommon(cmd, "json")
	opts.bindApplySpecific(cmd)
	opts.markMutuallyExclusive(cmd)
	// Completion registration is best-effort — if it fails, help output
	// loses tab completion but the command still works.
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSONSARIF...))

	return cmd
}

func (o *Options) bindApplySpecific(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", false, cliflags.WithDynamicDefaultHelp("Allow unknown source types"))
	f.StringVar(&o.ExemptionFile, "exemption-file", "", "Path to asset exemption list YAML file")
	f.StringVar(&o.AcknowledgmentFile, "acknowledgment-file", "", "Path to acknowledgment config YAML file")
	f.StringVar(&o.IntegrityManifest, "integrity-manifest", "", "Path to manifest JSON containing expected hashes")
	f.StringVar(&o.IntegrityPublicKey, "integrity-public-key", "", "Path to Ed25519 public key for signed manifests")
	f.StringVarP(&o.Profile, "profile", "p", "", "Evaluation profile (e.g. aws-s3)")
	f.StringVar(&o.InputFile, "input", "", "Path to observations bundle file (required with --profile)")
	f.StringSliceVar(&o.BucketAllowlist, "bucket-allowlist", nil, "Bucket names/ARNs to include")
	f.BoolVar(&o.IncludeAll, "include-all", false, "Disable health scope filtering")
	f.StringVar(&o.TracePath, "trace", "", "Write full step-by-step audit trace to file. The compact reasoning trace (matched clauses + observed values) is already emitted inline on every finding by default; this flag writes the full Assessment.Steps[] superset to a separate file for deep-dive.")
	f.StringSliceVar(&o.ProfileFiles, "profile-file", nil, "custom compliance profile YAML (can be repeated)")
	f.StringVar(&o.OverlayPath, "overlay", "", "environment-specific severity overlay YAML")
	f.BoolVar(&o.ShowSuppressed, "show-suppressed", false, "include overlay-suppressed controls in output")
	f.StringVar(&o.AssetsManifest, "assets", "", "asset sensitivity classification manifest YAML")
	f.StringVar(&o.SLAProfile, "sla-profile", "", "SLA policy profile (pci_dss_v4, hipaa, soc2, fedramp_moderate, default)")
	f.StringVar(&o.SLAProfileFile, "sla-profile-file", "", "path to custom SLA policy YAML file")
	f.StringVar(&o.SLAPolicy, "sla-policy", "warn", "SLA breach exit code behavior: warn, strict, critical-only")
	f.StringVar(&o.TeamManifest, "team-manifest", "", "Path to stave-teams.yaml for owner routing")
	f.StringVar(&o.OwnerFilter, "owner-filter", "", "Comma-separated team IDs to filter findings")
	f.StringVar(&o.HistoryDir, "history", "", "Directory of historical assessment JSON files (for --new-only)")
	f.BoolVar(&o.NewOnly, "new-only", false, "Show only findings not present in previous assessment")
	f.StringVar(&o.NewSince, "new-since", "", "Show only findings not present in assessments within this window (e.g. 7d)")
	f.StringVar(&o.SARIFBaseline, "baseline", "", "SARIF baseline file for baseline state comparison")
	f.StringVar(&o.AssertRecent, "assert-recent", "", "Fail if no snapshot newer than this duration (e.g. 48h)")
}

func (o *Options) validate() error {
	if o.Profile != "" && o.InputFile == "" {
		return &ui.UserError{Err: errors.New("flag --input is required when using --profile")}
	}
	if (o.NewOnly || o.NewSince != "") && o.HistoryDir == "" {
		return &ui.UserError{Err: errors.New("--history is required when using --new-only or --new-since")}
	}
	return nil
}

// markMutuallyExclusive registers flag groups that cannot be combined.
func (o *Options) markMutuallyExclusive(cmd *cobra.Command) {
	cmd.MarkFlagsMutuallyExclusive("profile", "controls")
	cmd.MarkFlagsMutuallyExclusive("profile", "observations")
}
