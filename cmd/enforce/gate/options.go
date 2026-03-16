package gate

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// gateOptions holds the raw CLI flag values before validation.
type gateOptions struct {
	PolicyRaw string
	InPath    string
	BasePath  string
	CtlDir    string
	ObsDir    string
	MaxUnsafe string
	NowRaw    string
	FormatRaw string
}

// DefaultOptions returns the standard defaults for the gate command.
func DefaultOptions() gateOptions {
	defaults := projconfig.Global()
	return gateOptions{
		PolicyRaw: string(defaults.CIFailurePolicy()),
		InPath:    "output/evaluation.json",
		BasePath:  "output/baseline.json",
		CtlDir:    "controls/s3",
		ObsDir:    "observations",
		MaxUnsafe: defaults.MaxUnsafe(),
		FormatRaw: "text",
	}
}

// BindFlags attaches the options to a Cobra command.
func (o *gateOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.PolicyRaw, "policy", o.PolicyRaw, cmdutil.WithDynamicDefaultHelp("CI failure policy mode: fail_on_any_violation, fail_on_new_violation, fail_on_overdue_upcoming"))
	f.StringVar(&o.InPath, "in", o.InPath, "Path to evaluation JSON (required for fail_on_any_violation and fail_on_new_violation)")
	f.StringVar(&o.BasePath, "baseline", o.BasePath, "Path to baseline JSON (required for fail_on_new_violation)")
	f.StringVarP(&o.CtlDir, "controls", "i", o.CtlDir, "Path to control definitions directory (used by fail_on_overdue_upcoming)")
	f.StringVarP(&o.ObsDir, "observations", "o", o.ObsDir, "Path to observation snapshots directory (used by fail_on_overdue_upcoming)")
	f.StringVar(&o.MaxUnsafe, "max-unsafe", o.MaxUnsafe, cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)"))
	f.StringVar(&o.NowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.StringVarP(&o.FormatRaw, "format", "f", o.FormatRaw, "Output format: text or json")
}

// ToConfig converts raw CLI options into a validated Config.
func (o *gateOptions) ToConfig(cmd *cobra.Command) (Config, error) {
	policy, err := appconfig.ParseGatePolicy(o.PolicyRaw)
	if err != nil {
		return Config{}, err
	}

	clock, err := compose.ResolveClock(o.NowRaw)
	if err != nil {
		return Config{}, err
	}

	format, err := compose.ResolveFormatValue(cmd, o.FormatRaw)
	if err != nil {
		return Config{}, err
	}

	var maxUnsafeDur time.Duration
	if policy == appconfig.GatePolicyOverdue {
		maxUnsafeDur, err = timeutil.ParseDurationFlag(o.MaxUnsafe, "--max-unsafe")
		if err != nil {
			return Config{}, err
		}
	}

	gf := cmdutil.GetGlobalFlags(cmd)

	return Config{
		Policy:          policy,
		InPath:          fsutil.CleanUserPath(o.InPath),
		BaselinePath:    fsutil.CleanUserPath(o.BasePath),
		ControlsDir:     fsutil.CleanUserPath(o.CtlDir),
		ObservationsDir: fsutil.CleanUserPath(o.ObsDir),
		MaxUnsafe:       maxUnsafeDur,
		Format:          format,
		Quiet:           gf.Quiet,
		Clock:           clock,
		Sanitizer:       gf.GetSanitizer(),
		Stdout:          cmd.OutOrStdout(),
		Stderr:          cmd.ErrOrStderr(),
	}, nil
}
