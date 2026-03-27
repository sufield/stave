package apply

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appapply "github.com/sufield/stave/internal/app/apply"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// cobraState holds all values extracted from *cobra.Command.
// Populated once in RunE; all downstream functions are cobra-free.
// Context is not stored here — it flows through function parameters.
type cobraState struct {
	Logger        *slog.Logger
	Stdout        io.Writer
	Stderr        io.Writer
	Stdin         io.Reader
	GlobalFlags   cliflags.GlobalFlags
	FormatChanged bool
	ObsChanged    bool
}

type runMode string

const (
	runModeStandard runMode = "standard"
	runModeProfile  runMode = "profile"
)

// RunConfig holds the fully resolved execution state.
// Exactly one of Params or Profile is meaningful, determined by Mode.
// All resolved values live here — no downstream code reads back from ApplyOptions.
type RunConfig struct {
	Mode         runMode
	Params       *applyParams // non-nil in standard mode
	Profile      *Config      // non-nil in profile mode
	profileClock ports.Clock  // used by profile mode

	// Resolved directory paths from inference. Used by buildEvaluatorInput
	// instead of reading back from the mutable ApplyOptions receiver.
	ControlsDir     string
	ObservationsDir string

	// Pre-loaded project config, resolved once during Resolve().
	// Shared by buildEvaluatorInput and Build to avoid repeated disk reads.
	projectConfig     *appconfig.ProjectConfig
	projectConfigPath string
}

// applyParams holds validated and parsed domain types.
type applyParams struct {
	maxUnsafeDuration time.Duration
	clock             ports.Clock
	source            appeval.ObservationSource
}

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
func (o *ApplyOptions) Resolve(cs cobraState) (RunConfig, error) {
	if o.Profile != "" {
		return o.resolveProfileMode(cs)
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

func (o *ApplyOptions) resolveProfileMode(cs cobraState) (RunConfig, error) {
	prof, err := ParseProfile(o.Profile)
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}

	if prof == ProfileAWSS3 && o.InputFile == "" {
		return RunConfig{}, &ui.UserError{Err: fmt.Errorf("--input is required when using --profile %s", o.Profile)}
	}

	clock, err := compose.ResolveClock(o.NowTime)
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}

	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, false)
	if err != nil {
		return RunConfig{}, &ui.UserError{Err: err}
	}

	cfg := &Config{
		InputFile:       o.InputFile,
		BucketAllowlist: o.BucketAllowlist,
		IncludeAll:      o.IncludeAll,
		OutputFormat:    format,
		Quiet:           cs.GlobalFlags.Quiet,
		Stdout:          compose.ResolveStdout(cs.Stdout, cs.GlobalFlags.Quiet, format),
		Stderr:          cs.Stderr,
		Sanitizer:       cs.GlobalFlags.GetSanitizer(),
	}
	return RunConfig{Mode: runModeProfile, Profile: cfg, profileClock: clock}, nil
}

// buildEvaluatorInput bridges CLI flags to the internal application layer options.
// controlsDir and observationsDir are the resolved paths from RunConfig.
// cfgPath is the pre-resolved project config path from Resolve().
func (o *ApplyOptions) buildEvaluatorInput(controlsDir, observationsDir, cfgPath string) (appeval.Options, error) {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return appeval.Options{}, ui.WithHint(
			fmt.Errorf("resolve project context: %w", err),
			ui.ErrHintProjectContext,
		)
	}
	root := resolver.ProjectRoot()

	_, userPath, _, uErr := projconfig.FindUserConfigWithPath()
	if uErr != nil {
		return appeval.Options{}, ui.WithHint(
			fmt.Errorf("load user config: %w", uErr),
			ui.ErrHintProjectConfig,
		)
	}

	selectedContext := ""
	if sc, scErr := resolver.ResolveSelected(); scErr == nil && sc.Active {
		selectedContext = sc.Name
	}

	return appeval.Options{
		ContextName:        appapply.ResolveContextName(root, selectedContext),
		ProjectRoot:        root,
		ControlsDir:        controlsDir,
		ConfigPath:         cfgPath,
		UserConfigPath:     userPath,
		MaxUnsafeDuration:  o.MaxUnsafeDuration,
		NowTime:            o.NowTime,
		ObservationsSource: appeval.ObservationSource(observationsDir),
		IntegrityManifest:  o.IntegrityManifest,
		IntegrityPublicKey: o.IntegrityPublicKey,
		Hasher:             fsutil.FSContentHasher{},
	}, nil
}

// parseDomainOptions handles the conversion of strings to domain-specific types.
func parseDomainOptions(maxUnsafe, nowTime, observationsDir, manifest, pubKey string) (appeval.ParsedOptions, error) {
	parsed, err := (appeval.Options{
		MaxUnsafeDuration:  maxUnsafe,
		NowTime:            nowTime,
		ObservationsSource: appeval.ObservationSource(observationsDir),
		IntegrityManifest:  manifest,
		IntegrityPublicKey: pubKey,
	}).Validate()
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

// standardIO holds resolved IO and format state for the standard apply path.
type standardIO struct {
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Sanitizer kernel.Sanitizer
	Format    ui.OutputFormat
	Quiet     bool
}

// ResolveStandardIO extracts IO and format state for the standard apply path.
func (o *ApplyOptions) ResolveStandardIO(cs cobraState) (standardIO, error) {
	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, false)
	if err != nil {
		return standardIO{}, err
	}
	return standardIO{
		Stdout:    compose.ResolveStdout(cs.Stdout, cs.GlobalFlags.Quiet, format),
		Stderr:    cs.Stderr,
		Stdin:     cs.Stdin,
		Sanitizer: cs.GlobalFlags.GetSanitizer(),
		Format:    format,
		Quiet:     cs.GlobalFlags.Quiet,
	}, nil
}

func buildClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}

// ResolveDryRun converts raw CLI options into a ReadinessConfig for dry-run mode.
// Flag strings are parsed to native types here so the config struct is ready to use.
func (o *ApplyOptions) ResolveDryRun(cs cobraState) (ReadinessConfig, error) {
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
