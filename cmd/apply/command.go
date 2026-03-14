package apply

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// SharedOptions contains flags common to both plan and apply.
type SharedOptions struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	NowTime         string
	Format          string

	// ControlsSet tracks whether --controls was explicitly set by the user.
	ControlsSet bool
}

func (o *SharedOptions) bindCommon(cmd *cobra.Command, defaultFormat string) {
	f := cmd.Flags()
	cmdutil.RegisterControlsFlag(cmd, &o.ControlsDir, "controls/s3", "Path to control definitions directory")

	f.StringVarP(&o.ObservationsDir, "observations", "o", "observations", "Path to observation snapshots directory")
	f.StringVar(&o.MaxUnsafe, "max-unsafe", projconfig.Global().MaxUnsafe(), cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration"))
	f.StringVar(&o.NowTime, "now", "", "Override current time (RFC3339) for deterministic output")
	f.StringVarP(&o.Format, "format", "f", defaultFormat, "Output format (text, json, or sarif)")
}

func (o *SharedOptions) normalize() {
	o.ControlsDir = fsutil.CleanUserPath(o.ControlsDir)
	o.ObservationsDir = fsutil.CleanUserPath(o.ObservationsDir)
}

// PlanOptions configuration for the plan command.
type PlanOptions struct {
	SharedOptions
}

// NewPlanCmd constructs the plan command.
func NewPlanCmd() *cobra.Command {
	opts := &PlanOptions{}

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Readiness gate before apply",
		Long:  `Plan checks whether your project is ready to run apply.` + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			opts.ControlsSet = cmdutil.ControlsFlagChanged(cmd)
			opts.normalize()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlan(cmd, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.bindCommon(cmd, "text")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

// ApplyOptions configuration for the apply command.
type ApplyOptions struct {
	SharedOptions
	AllowUnknown       bool
	ExemptionFile      string
	IntegrityManifest  string
	IntegrityPublicKey string
	Profile            string
	InputFile          string
	BucketAllowlist    []string
	IncludeAll         bool
}

// NewApplyCmd constructs the apply command.
func NewApplyCmd() *cobra.Command {
	opts := &ApplyOptions{}

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Run control evaluation after plan checks pass",
		Long: `Apply executes control evaluation only after readiness checks pass.
Run stave plan first to preview what will be evaluated.` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			opts.ControlsSet = cmdutil.ControlsFlagChanged(cmd)
			opts.normalize()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.validate(); err != nil {
				return err
			}
			return runApply(cmd, args, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.bindCommon(cmd, "json")
	opts.bindApplySpecific(cmd)
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("json", "text", "sarif"))

	return cmd
}

func (o *ApplyOptions) bindApplySpecific(cmd *cobra.Command) {
	f := cmd.Flags()
	f.BoolVar(&o.AllowUnknown, "allow-unknown-input", projconfig.Global().AllowUnknownInput(), cmdutil.WithDynamicDefaultHelp("Allow unknown source types"))
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
