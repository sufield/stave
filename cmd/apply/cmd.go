package apply

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/app/staleness"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/metadata"
)

// resolveEnvVarDefaults fills shared flag values from STAVE_* environment
// variables when the user did not set them explicitly on the command line.
// Precedence: CLI flag > env var > config file > default.
func (o *Options) resolveEnvVarDefaults(cmd *cobra.Command) {
	o.Format = contracts.OutputFormat(cliflags.ResolveFormatEnv(cmd, string(o.Format)))
	o.ControlsDir = cliflags.ResolveControlsEnv(cmd, o.ControlsDir)
	o.ObservationsDir = cliflags.ResolveObservationsEnv(cmd, o.ObservationsDir)
	o.NowTime = cliflags.ResolveNowEnv(cmd, o.NowTime)
}

// resolveApplyConfigDefaults fills apply-specific flag values from project
// config when the user did not set them explicitly on the command line.
// Called from PreRunE — the only place that touches *cobra.Command.
func (o *Options) resolveApplyConfigDefaults(cmd *cobra.Command) {
	eval := cmdctx.ResolverFromCmd(cmd)
	// Defensive nil guard. ResolverFromCmd returns nil when the
	// PreRunE chain ran without injecting a resolver (test
	// harnesses that drive the command without bootstrap, future
	// code paths that build cobra.Command directly). Mirrors the
	// early-return pattern in resolveConfigurableLimits and
	// resolveGlobalFlagDefaults so a nil resolver no longer
	// panics on the first method call below.
	if eval == nil {
		return
	}
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
	Format            contracts.OutputFormat

	// controlsSet / formatSet / obsSet track whether the respective
	// flag was explicitly set by the user. All three are derived
	// from Cobra in PreRunE and read thereafter as plain data;
	// downstream code never calls cmd.Flags().Changed() itself.
	controlsSet bool
	formatSet   bool
	obsSet      bool
}

func (o *SharedOptions) bindCommon(cmd *cobra.Command, defaultFormat contracts.OutputFormat) {
	f := cmd.Flags()
	cliflags.RegisterControlsFlag(cmd, &o.ControlsDir, cliflags.DefaultControlsDir, "Path to control definitions directory")

	f.StringVarP(&o.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&o.MaxUnsafeDuration, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339) for deterministic output")
	o.Format = defaultFormat
	f.VarP(&o.Format, "format", "f", "Output format (text, json, or sarif)")
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
	OwnerFilter        []string
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

// IsNewOnlyMode reports whether the run is in new-only mode —
// either --new-only is set or --new-since carries a window. Used
// by the standard-apply pipeline to gate the post-evaluation
// classification step. Centralised so the OR pair stays in one
// place; adding a future "new-X" flag is a single-line change on
// this method.
func (o *Options) IsNewOnlyMode() bool {
	return o != nil && (o.NewOnly || o.NewSince != "")
}

// HasStalenessCheck reports whether --assert-recent was set.
// Used by the apply runner to gate the snapshot-load + staleness
// evaluation; replaces the tuple-unpack the runner used to do
// inline.
func (o *Options) HasStalenessCheck() bool {
	return o != nil && o.AssertRecent != ""
}

// CheckStaleness evaluates the --assert-recent flag against the
// supplied snapshots. Returns nil when:
//
//   - The flag was not set (no assertion requested), or
//   - The flag was set and the staleness check passed.
//
// Returns a UserError when the flag is malformed or when the
// snapshots are stale relative to the configured threshold. The
// "should I check?" decision lives inside the method so the
// caller branches on a single error value.
func (o *Options) CheckStaleness(snapshots []asset.Snapshot, now time.Time) error {
	if !o.HasStalenessCheck() {
		return nil
	}
	d, err := time.ParseDuration(o.AssertRecent)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse --assert-recent %q: %w", o.AssertRecent, err)}
	}
	result := staleness.Check(snapshots, d, now)
	if result.Stale {
		return &ui.UserError{Err: fmt.Errorf("%s", result.Message)}
	}
	return nil
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
  130 - Interrupted (SIGINT)

Remediation scope:
  Stave produces findings with structured remediation data
  (asset-parameterized CLI in findings[].fix_plan.command,
  property-level changes in findings[].remediation_context.changes,
  AI-prompt-ready context in findings[].remediation_context). It
  does NOT execute remediation. Pipe apply output to downstream
  tooling — AI prompts, CI/CD pipelines, ticket systems — for fix
  generation. There is no --apply-fixes flag and no auto-fix mode;
  the boundary is the data, not the change.` + metadata.OfflineHelpSuffix,
		Example: `  # Standard evaluation
  stave apply --controls ./controls --observations ./obs --format json

  # Readiness check only (dry run)
  stave apply --dry-run

  # Profile-based evaluation with bundled observations
  stave apply --profile aws-s3 --input observations.json --now 2026-01-15T00:00:00Z`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			opts.controlsSet = cliflags.ControlsFlagChanged(cmd)
			opts.formatSet = cmd.Flags().Changed("format")
			opts.obsSet = cmd.Flags().Changed("observations")
			opts.normalize()
			opts.resolveEnvVarDefaults(cmd)
			opts.resolveApplyConfigDefaults(cmd)
			return opts.validate()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cs := cobraState{
				Logger:      cmdctx.LoggerFromCmd(cmd),
				Stdout:      cmd.OutOrStdout(),
				Stderr:      cmd.ErrOrStderr(),
				Stdin:       cmd.InOrStdin(),
				GlobalFlags: cliflags.GetGlobalFlags(cmd),
			}
			return runApply(cmd.Context(), deps, opts, cs)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Run readiness checks only, without evaluating controls")
	opts.bindCommon(cmd, contracts.FormatJSON)
	opts.bindApplySpecific(cmd)
	opts.markMutuallyExclusive(cmd)
	// Completion registration is best-effort — if it fails, help output
	// loses tab completion but the command still works.
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSONSARIF...))
	_ = cmd.RegisterFlagCompletionFunc("sla-policy", cliflags.CompleteFixed(validSLAPolicyValues...))

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
	f.StringVar(&o.TracePath, "trace", "", "Write full step-by-step audit trace to file. Every finding already emits a compact reasoning_trace inline (rendered as prose in text output, as raw DSL in JSON/SARIF); this flag writes the full Assessment.Steps[] superset to a separate file for users who want the precise predicate-DSL form or per-step timing.")
	f.StringSliceVar(&o.ProfileFiles, "profile-file", nil, "custom compliance profile YAML (can be repeated)")
	f.StringVar(&o.OverlayPath, "overlay", "", "environment-specific severity overlay YAML")
	f.BoolVar(&o.ShowSuppressed, "show-suppressed", false, "include overlay-suppressed controls in output")
	f.StringVar(&o.AssetsManifest, "assets", "", "asset sensitivity classification manifest YAML")
	f.StringVar(&o.SLAProfile, "sla-profile", "", "SLA policy profile (pci_dss_v4, hipaa, soc2, fedramp_moderate, default)")
	f.StringVar(&o.SLAProfileFile, "sla-profile-file", "", "path to custom SLA policy YAML file")
	f.StringVar(&o.SLAPolicy, "sla-policy", "warn", "SLA breach exit code behavior: warn, strict, critical-only")
	f.StringVar(&o.TeamManifest, "team-manifest", "", "Path to stave-teams.yaml for owner routing")
	f.StringSliceVar(&o.OwnerFilter, "owner-filter", nil, "Team IDs to filter findings (repeatable or comma-separated)")
	f.StringVar(&o.HistoryDir, "history", "", "Directory of historical assessment JSON files (for --new-only)")
	f.BoolVar(&o.NewOnly, "new-only", false, "Show only findings not present in previous assessment")
	f.StringVar(&o.NewSince, "new-since", "", "Show only findings not present in assessments within this window (e.g. 7d)")
	f.StringVar(&o.SARIFBaseline, "baseline", "", "SARIF baseline file for baseline state comparison")
	f.StringVar(&o.AssertRecent, "assert-recent", "", "Fail if no snapshot newer than this duration (e.g. 48h)")
}

// validSLAPolicyValues is the closed set of accepted --sla-policy
// values. Kept in one place so the validate() check, the help
// text on the flag, and the Cobra completion function can't drift.
var validSLAPolicyValues = []string{"warn", "strict", "critical-only"}

// hasSupportedSLAPolicy reports whether the configured policy mode
// is recognised by the engine. Encapsulates the slice-membership
// check so the validate() body reads as a business-rule chain
// instead of mechanical string comparisons — and a future move
// from a static slice to a richer registry edits one place.
func (o *Options) hasSupportedSLAPolicy() bool {
	return slices.Contains(validSLAPolicyValues, o.SLAPolicy)
}

func (o *Options) validate() error {
	if o.Profile != "" && o.InputFile == "" {
		return &ui.UserError{Err: errors.New("flag --input is required when using --profile")}
	}
	if o.InputFile != "" && o.Profile == "" {
		// --input is only meaningful in profile mode (the bundled
		// observations file feeds the built-in control pack).
		// Outside profile mode the input would be ignored, so an
		// operator who set it without --profile thinks they're
		// running a different evaluation than they are. Reject
		// explicitly — symmetric to the --profile-without-input
		// case above.
		return &ui.UserError{Err: errors.New("flag --input requires --profile (use --observations instead for non-profile mode)")}
	}
	if (o.NewOnly || o.NewSince != "") && o.HistoryDir == "" {
		return &ui.UserError{Err: errors.New("--history is required when using --new-only or --new-since")}
	}
	if !o.hasSupportedSLAPolicy() {
		return &ui.UserError{Err: fmt.Errorf("--sla-policy %q invalid (allowed: %s)",
			o.SLAPolicy, strings.Join(validSLAPolicyValues, ", "))}
	}
	return nil
}

// markMutuallyExclusive registers flag groups that cannot be combined.
func (o *Options) markMutuallyExclusive(cmd *cobra.Command) {
	cmd.MarkFlagsMutuallyExclusive("profile", "controls")
	cmd.MarkFlagsMutuallyExclusive("profile", "observations")
	// --new-only collapses to "new-since-the-last-assessment", so
	// combining it with --new-since (which provides an explicit
	// window) is contradictory: one says "diff against latest", the
	// other says "diff against everything in the window". Reject
	// the combination at flag parse so operators don't silently get
	// one mode's output while believing they configured the other.
	cmd.MarkFlagsMutuallyExclusive("new-only", "new-since")
}
