package apply

import (
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
)

func resolveProfileMode(o *Options, cs cobraState) (RunConfig, error) {
	profiles, err := ParseProfiles(o.Profile)
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}
	if len(profiles) == 0 {
		// Defensive: ParseProfiles is meant to either return a
		// non-empty slice or an error. The bounds check guards
		// against profiles[0] panicking if a future ParseProfiles
		// edit introduces an empty-slice success path.
		return RunConfig{}, &ui.UserError{Err: fmt.Errorf("--profile %q resolved to no profiles", o.Profile)}
	}

	if o.InputFile == "" {
		return RunConfig{}, &ui.UserError{Err: fmt.Errorf("--input is required when using --profile %s", o.Profile)}
	}

	format, err := compose.ResolveFormatValue(string(o.Format))
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}

	// --max-unsafe is parsed in the facade (stave.EvaluateProfile), using the
	// same kernel.ParseDuration grammar standard apply uses (accepts the 'd'
	// day unit). The command passes the raw flag string through unchanged.

	// Compute Quiet once and pass the same value to both Config.Quiet
	// and ResolveStdout. The previous shape passed
	// `cs.GlobalFlags.Quiet` to ResolveStdout while Config.Quiet
	// also folded in machine-format detection — so JSON / SARIF
	// runs had Config.Quiet=true but Stdout was still cs.Stdout
	// rather than the machine-output writer ResolveStdout would
	// have selected with the same input.
	quiet := cs.GlobalFlags.Quiet || isMachineFormat(format)
	cfg := &Config{
		InputFile:         o.InputFile,
		Profile:           profiles[0], // Primary profile for output labeling.
		Profiles:          profiles,    // Full list — used for control loading.
		BucketAllowlist:   o.BucketAllowlist,
		IncludeAll:        o.IncludeAll,
		MaxUnsafeDuration: o.MaxUnsafeDuration,
		OutputFormat:      format,
		Quiet:             quiet,
		Stdout:            compose.ResolveStdout(cs.Stdout, quiet, format),
		Stderr:            cs.Stderr,
		NowTime:           o.NowTime,
	}
	return RunConfig{Mode: runModeProfile, Profile: cfg}, nil
}
