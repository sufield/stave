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
	prof := profiles[0] // Primary profile for Config.Profile field

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

	cfg := &Config{
		InputFile:       o.InputFile,
		Profile:         prof,
		BucketAllowlist: o.BucketAllowlist,
		IncludeAll:      o.IncludeAll,
		OutputFormat:    format,
		Quiet:           cs.GlobalFlags.Quiet || isMachineFormat(format),
		Stdout:          compose.ResolveStdout(cs.Stdout, cs.GlobalFlags.Quiet, format),
		Stderr:          cs.Stderr,
		Sanitizer:       cs.GlobalFlags.GetSanitizer(),
	}
	return RunConfig{Mode: runModeProfile, Profile: cfg, profileClock: clock}, nil
}
