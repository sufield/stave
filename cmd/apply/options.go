package apply

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appapply "github.com/sufield/stave/internal/app/apply"
	appconfig "github.com/sufield/stave/internal/app/config"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// cobraState holds all values extracted from *cobra.Command.
// Populated once in RunE; all downstream functions are cobra-free.
type cobraState struct {
	Ctx           context.Context
	Logger        *slog.Logger
	Stdout        io.Writer
	Stderr        io.Writer
	Stdin         io.Reader
	GlobalFlags   cmdutil.GlobalFlags
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
type RunConfig struct {
	Mode         runMode
	Params       *applyParams // non-nil in standard mode
	Profile      *Config      // non-nil in profile mode
	profileClock ports.Clock  // used by profile mode

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

// --- Path inference (shared by standard + dry-run) ---

// inferredDirs resolves controls and observations directories from the project
// root when the user did not set them explicitly via flags.
func (o *ApplyOptions) inferredDirs(obsChanged bool) (ctlDir, obsDir string, err error) {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return "", "", ui.WithHint(
			fmt.Errorf("resolve project context: %w", err),
			ui.ErrHintProjectContext,
		)
	}
	engine := projctx.NewInferenceEngine(resolver)

	ctlDir = fsutil.CleanUserPath(o.ControlsDir)
	if !o.controlsSet {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			ctlDir = inferred
		}
	}

	obsDir = fsutil.CleanUserPath(o.ObservationsDir)
	if o.ObservationsDir != "-" && !obsChanged {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			obsDir = inferred
		}
	}

	return ctlDir, obsDir, nil
}

// --- Standard mode resolution ---

// Resolve transforms raw CLI options into a RunConfig.
func (o *ApplyOptions) Resolve(cs cobraState) (RunConfig, error) {
	if o.Profile != "" {
		return o.resolveProfileMode(cs)
	}

	ctlDir, obsDir, err := o.inferredDirs(cs.ObsChanged)
	if err != nil {
		return RunConfig{}, err
	}
	// Intentional receiver mutation: parseDomain, validateDirs, and
	// buildEvaluatorInput (called later in the run pipeline) all read
	// ControlsDir/ObservationsDir from the receiver.
	o.ControlsDir = ctlDir
	o.ObservationsDir = obsDir

	// IntegrityManifest and IntegrityPublicKey are already cleaned by
	// normalize() in PreRunE — no duplicate cleaning needed here.

	parsed, err := o.parseDomain()
	if err != nil {
		return RunConfig{}, err
	}

	// Load project config once — shared by validateDirs, buildEvaluatorInput, and Build.
	projCfg, cfgPath, cfgErr := projconfig.FindProjectConfigWithPath("")
	if cfgErr != nil {
		return RunConfig{}, ui.WithHint(
			fmt.Errorf("load project config: %w", cfgErr),
			ui.ErrHintProjectConfig,
		)
	}

	if err := o.validateDirsWithConfig(projCfg); err != nil {
		return RunConfig{}, err
	}

	params := &applyParams{
		maxUnsafeDuration: parsed.MaxUnsafeDuration,
		clock:             o.buildClock(parsed.Now),
		source:            parsed.Source,
	}
	return RunConfig{
		Mode:              runModeStandard,
		Params:            params,
		projectConfig:     projCfg,
		projectConfigPath: cfgPath,
	}, nil
}

func (o *ApplyOptions) resolveProfileMode(cs cobraState) (RunConfig, error) {
	prof, err := ParseProfile(o.Profile)
	if err != nil {
		return RunConfig{}, err
	}

	if prof == ProfileAWSS3 && o.InputFile == "" {
		return RunConfig{}, fmt.Errorf("--input is required when using --profile %s", o.Profile)
	}

	clock, err := compose.ResolveClock(o.NowTime)
	if err != nil {
		return RunConfig{}, err
	}

	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, false)
	if err != nil {
		return RunConfig{}, err
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
// cfgPath is the pre-resolved project config path from Resolve().
func (o *ApplyOptions) buildEvaluatorInput(cfgPath string) (appeval.Options, error) {
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
		ControlsDir:        o.ControlsDir,
		ConfigPath:         cfgPath,
		UserConfigPath:     userPath,
		MaxUnsafeDuration:  o.MaxUnsafeDuration,
		NowTime:            o.NowTime,
		ObservationsSource: appeval.ObservationSource(o.ObservationsDir),
		IntegrityManifest:  o.IntegrityManifest,
		IntegrityPublicKey: o.IntegrityPublicKey,
		Hasher:             fsutil.FSContentHasher{},
	}, nil
}

// parseDomain handles the conversion of strings to domain-specific types.
func (o *ApplyOptions) parseDomain() (appeval.ParsedOptions, error) {
	parsed, err := (appeval.Options{
		MaxUnsafeDuration:  o.MaxUnsafeDuration,
		NowTime:            o.NowTime,
		ObservationsSource: appeval.ObservationSource(o.ObservationsDir),
		IntegrityManifest:  o.IntegrityManifest,
		IntegrityPublicKey: o.IntegrityPublicKey,
	}).Validate()
	if err != nil {
		return appeval.ParsedOptions{}, &ui.UserError{Err: err}
	}
	return parsed, nil
}

// validateDirsWithConfig ensures directories exist unless using packs or stdin.
// Uses a pre-loaded project config to check for enabled packs without re-reading disk.
func (o *ApplyOptions) validateDirsWithConfig(projCfg *appconfig.ProjectConfig) error {
	hasPacks := !o.controlsSet && projCfg != nil && len(projCfg.EnabledControlPacks) > 0
	if !hasPacks {
		if err := dircheck.ValidateFlagDir("--controls", o.ControlsDir, "controls", ui.ErrHintControlsNotAccessible, nil); err != nil {
			return err
		}
	}

	if o.ObservationsDir != "-" {
		if err := dircheck.ValidateFlagDir("--observations", o.ObservationsDir, "observations", ui.ErrHintObservationsNotAccessible, nil); err != nil {
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

func (o *ApplyOptions) buildClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}

// ResolveDryRun converts raw CLI options into a ReadinessConfig for dry-run mode.
// Flag strings are parsed to native types here so the config struct is ready to use.
func (o *ApplyOptions) ResolveDryRun(cs cobraState) (ReadinessConfig, error) {
	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, false)
	if err != nil {
		return ReadinessConfig{}, err
	}

	ctlDir, obsDir, err := o.inferredDirs(cs.ObsChanged)
	if err != nil {
		return ReadinessConfig{}, err
	}

	maxUnsafe, err := timeutil.ParseDurationFlag(o.MaxUnsafeDuration, "--max-unsafe")
	if err != nil {
		return ReadinessConfig{}, ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)
	}
	now, err := compose.ResolveNow(o.NowTime)
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
		ControlsDir:            ctlDir,
		ObservationsDir:        obsDir,
		MaxUnsafeDuration:      maxUnsafe,
		Now:                    now,
		Format:                 format,
		Quiet:                  cs.GlobalFlags.Quiet,
		Sanitize:               cs.GlobalFlags.Sanitize,
		Stdout:                 cs.Stdout,
		Stderr:                 cs.Stderr,
		ControlsFlagSet:        o.controlsSet,
		HasEnabledControlPacks: hasPacks,
		PrereqChecks:           prereqs,
	}, nil
}
