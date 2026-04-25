package apply

import (
	"fmt"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
)

func resolveProfileMode(o *Options, cs cobraState) (RunConfig, error) {
	profiles, err := ParseProfiles(o.Profile)
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}

	if o.InputFile == "" {
		return RunConfig{}, &ui.UserError{Err: fmt.Errorf("--input is required when using --profile %s", o.Profile)}
	}

	clock, err := compose.ResolveClock(o.NowTime)
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}

	format, err := compose.ResolveFormatValue(o.Format)
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}

	// Parse --max-unsafe in profile mode so the same duration semantic
	// applies whether the user runs profile or standard mode. Without
	// this, profile mode silently passed MaxUnsafeDuration: 0 to the
	// evaluator regardless of the flag, producing immediate findings
	// where standard mode would have given the workload a remediation
	// window. Empty value parses to 0 (immediate firing).
	var maxUnsafe time.Duration
	if o.MaxUnsafeDuration != "" {
		maxUnsafe, err = time.ParseDuration(o.MaxUnsafeDuration)
		if err != nil {
			return RunConfig{}, &ui.UserError{Err: fmt.Errorf("parse --max-unsafe %q: %w", o.MaxUnsafeDuration, err)}
		}
	}

	cfg := &Config{
		InputFile:         o.InputFile,
		Profile:           profiles[0], // Primary profile for output labeling.
		Profiles:          profiles,    // Full list — used for control loading.
		BucketAllowlist:   o.BucketAllowlist,
		IncludeAll:        o.IncludeAll,
		MaxUnsafeDuration: maxUnsafe,
		OutputFormat:      format,
		Quiet:             cs.GlobalFlags.Quiet || isMachineFormat(format),
		Stdout:            compose.ResolveStdout(cs.Stdout, cs.GlobalFlags.Quiet, format),
		Stderr:            cs.Stderr,
		Sanitizer:         cs.GlobalFlags.GetSanitizer(),
	}
	return RunConfig{Mode: runModeProfile, Profile: cfg, profileClock: clock}, nil
}
