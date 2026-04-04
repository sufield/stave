package apply

import (
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/cli/ui"
)

// ResolveDryRun converts raw CLI options into a ReadinessConfig for dry-run mode.
// Flag strings are parsed to native types here so the config struct is ready to use.
func ResolveDryRun(o *Options, cs cobraState) (ReadinessConfig, error) {
	ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:                o.ControlsDir,
		ObservationsDir:            o.ObservationsDir,
		ControlsChanged:            o.controlsSet,
		ObsChanged:                 cs.ObsChanged || o.ObservationsDir == "-",
		MaxUnsafeDuration:          o.MaxUnsafeDuration,
		NowTime:                    o.NowTime,
		Format:                     o.Format,
		FormatChanged:              cs.FormatChanged,
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
	})
	if err != nil {
		return ReadinessConfig{}, err
	}

	hasPacks := false
	cfg, ok, cfgErr := projconfig.FindProjectConfig()
	if cfgErr != nil {
		return ReadinessConfig{}, ui.WithHint(
			fmt.Errorf("load project config: %w", cfgErr),
			ui.ErrHintProjectConfig,
		)
	}
	if ok && len(cfg.EnabledControlPacks) > 0 {
		hasPacks = true
	}

	prereqs, prereqErr := doctorPrereqs()
	if prereqErr != nil {
		return ReadinessConfig{}, prereqErr
	}

	return ReadinessConfig{
		ControlsDir:            ec.ControlsDir,
		ObservationsDir:        ec.ObservationsDir,
		MaxUnsafeDuration:      ec.MaxUnsafe,
		Now:                    ec.Now,
		Format:                 ec.Format,
		Quiet:                  cs.GlobalFlags.Quiet,
		Sanitize:               cs.GlobalFlags.Sanitize,
		Stdout:                 cs.Stdout,
		Stderr:                 cs.Stderr,
		ControlsFlagSet:        o.controlsSet,
		HasEnabledControlPacks: hasPacks,
		PrereqChecks:           prereqs,
	}, nil
}
