package apply

import (
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appapply "github.com/sufield/stave/internal/app/apply"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// resolvePathInference resolves controls and observations directories using
// PrepareEvaluationContext. Dir validation is deferred to validateDirsWithConfig
// because it depends on the loaded project config (pack awareness).
func resolvePathInference(controlsDir, observationsDir string, controlsSet, obsChanged bool) (compose.EvalContext, error) {
	return compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:                controlsDir,
		ObservationsDir:            observationsDir,
		ControlsChanged:            controlsSet,
		ObsChanged:                 obsChanged || observationsDir == "-",
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
		SkipMaxUnsafe:              true,
		SkipClock:                  true,
		SkipFormat:                 true,
	})
}

// --- Standard mode resolution ---

// Resolve transforms raw CLI options into a RunConfig.
// Pure function — reads from o and cs, writes nothing.
func Resolve(o *Options, cs cobraState) (RunConfig, error) {
	if o.Profile != "" {
		return resolveProfileMode(o, cs)
	}

	ec, err := resolvePathInference(o.ControlsDir, o.ObservationsDir, o.controlsSet, cs.ObsChanged)
	if err != nil {
		return RunConfig{}, err
	}
	controlsDir := ec.ControlsDir
	observationsDir := ec.ObservationsDir

	// IntegrityManifest and IntegrityPublicKey are already cleaned by
	// normalize() in PreRunE — no duplicate cleaning needed here.

	parsed, err := parseDomainOptions(o.MaxUnsafeDuration, o.NowTime, observationsDir, o.IntegrityManifest, o.IntegrityPublicKey)
	if err != nil {
		return RunConfig{}, err
	}

	// Load project config once — shared by validateDirs, buildEvaluatorInput, and Build.
	projCfg, cfgPath, err := projconfig.FindProjectConfigWithPath("")
	if err != nil {
		return RunConfig{}, ui.WithHint(
			fmt.Errorf("load project config: %w", err),
			ui.ErrHintProjectConfig,
		)
	}

	if err := validateDirsWithConfig(controlsDir, observationsDir, o.controlsSet, projCfg); err != nil {
		return RunConfig{}, err
	}

	params := &applyParams{
		maxUnsafeDuration: parsed.MaxUnsafeDuration,
		clock:             buildClock(parsed.Now),
		source:            parsed.Source,
	}
	return RunConfig{
		Mode:              runModeStandard,
		Params:            params,
		ControlsDir:       controlsDir,
		ObservationsDir:   observationsDir,
		projectConfig:     projCfg,
		projectConfigPath: cfgPath,
	}, nil
}

// projectContext holds resolved project-level paths and identity.
type projectContext struct {
	Root           string
	ContextName    string
	UserConfigPath string
}

// resolveProjectContext discovers the project root, active context, and
// user config path. Pure I/O — no dependency on Options.
func resolveProjectContext() (projectContext, error) {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return projectContext{}, ui.WithHint(
			fmt.Errorf("resolve project context: %w", err),
			ui.ErrHintProjectContext,
		)
	}
	root := resolver.ProjectRoot()

	_, userPath, _, uErr := projconfig.FindUserConfigWithPath()
	if uErr != nil {
		return projectContext{}, ui.WithHint(
			fmt.Errorf("load user config: %w", uErr),
			ui.ErrHintProjectConfig,
		)
	}

	selectedContext := ""
	if sc, scErr := resolver.ResolveSelected(); scErr == nil && sc.Active {
		selectedContext = sc.Name
	}

	return projectContext{
		Root:           root,
		ContextName:    appapply.ResolveContextName(root, selectedContext),
		UserConfigPath: userPath,
	}, nil
}

// buildEvaluatorInput assembles the domain-layer options from resolved
// paths and CLI flags. No project context resolution — that's done by
// resolveProjectContext.
func buildEvaluatorInput(o *Options, pc projectContext, controlsDir, observationsDir, cfgPath string) appeval.Options {
	return appeval.Options{
		ContextName:        pc.ContextName,
		ProjectRoot:        pc.Root,
		ControlsDir:        controlsDir,
		ConfigPath:         cfgPath,
		UserConfigPath:     pc.UserConfigPath,
		MaxUnsafeDuration:  o.MaxUnsafeDuration,
		NowTime:            o.NowTime,
		ObservationsSource: appeval.ObservationSource(observationsDir),
		IntegrityManifest:  o.IntegrityManifest,
		IntegrityPublicKey: o.IntegrityPublicKey,
		Hasher:             fsutil.FSContentHasher{},
	}
}

// parseDomainOptions validates and parses domain-specific flag values
// without constructing a full appeval.Options struct.
func parseDomainOptions(maxUnsafe, nowTime, observationsDir, manifest, pubKey string) (appeval.ParsedOptions, error) {
	opts := appeval.Options{
		MaxUnsafeDuration:  maxUnsafe,
		NowTime:            nowTime,
		ObservationsSource: appeval.ObservationSource(observationsDir),
		IntegrityManifest:  manifest,
		IntegrityPublicKey: pubKey,
	}
	parsed, err := opts.Validate()
	if err != nil {
		return appeval.ParsedOptions{}, &ui.UserError{Err: err}
	}
	return parsed, nil
}

// validateDirsWithConfig ensures directories exist unless using packs or stdin.
// Uses a pre-loaded project config to check for enabled packs without re-reading disk.
func validateDirsWithConfig(controlsDir, observationsDir string, controlsSet bool, projCfg *appconfig.ProjectConfig) error {
	hasPacks := !controlsSet && projCfg != nil && len(projCfg.EnabledControlPacks) > 0
	if !hasPacks {
		if err := dircheck.ValidateFlagDir("--controls", controlsDir, "controls", ui.ErrHintControlsNotAccessible, nil); err != nil {
			return err
		}
	}

	if observationsDir != "-" {
		if err := dircheck.ValidateFlagDir("--observations", observationsDir, "observations", ui.ErrHintObservationsNotAccessible, nil); err != nil {
			return err
		}
	}

	return nil
}
