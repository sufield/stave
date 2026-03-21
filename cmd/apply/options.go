package apply

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appapply "github.com/sufield/stave/internal/app/apply"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// cobraState holds all values extracted from *cobra.Command.
// Populated once in RunE; all downstream functions are cobra-free.
type cobraState struct {
	Ctx           context.Context
	Stdout        io.Writer
	Stderr        io.Writer
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
type RunConfig struct {
	Mode    runMode
	Params  applyParams
	Profile Config

	// profileClock is used by profile mode; ignored otherwise.
	profileClock ports.Clock
}

// applyParams holds validated and parsed domain types.
type applyParams struct {
	maxDuration time.Duration
	clock       ports.Clock
	source      appeval.ObservationSource
}

// Resolve transforms raw CLI options into a RunConfig.
func (o *ApplyOptions) Resolve(cs cobraState) (RunConfig, error) {
	if o.Profile != "" {
		return o.resolveProfileMode(cs)
	}

	if err := o.normalizeApplyPaths(cs.ObsChanged); err != nil {
		return RunConfig{}, err
	}

	parsed, err := o.parseDomain()
	if err != nil {
		return RunConfig{}, err
	}

	if err := o.validateDirs(); err != nil {
		return RunConfig{}, err
	}

	return RunConfig{
		Mode: runModeStandard,
		Params: applyParams{
			maxDuration: parsed.MaxDuration,
			clock:       o.buildClock(parsed.Now),
			source:      parsed.Source,
		},
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

	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, cs.GlobalFlags.IsJSONMode())
	if err != nil {
		return RunConfig{}, err
	}

	return RunConfig{
		Mode: runModeProfile,
		Profile: Config{
			InputFile:       o.InputFile,
			BucketAllowlist: o.BucketAllowlist,
			IncludeAll:      o.IncludeAll,
			OutputFormat:    format,
			Quiet:           cs.GlobalFlags.Quiet,
			Stdout:          compose.ResolveStdout(cs.Stdout, cs.GlobalFlags.Quiet, format),
			Stderr:          cs.Stderr,
			IsJSONMode:      cs.GlobalFlags.IsJSONMode(),
			Sanitizer:       cs.GlobalFlags.GetSanitizer(),
		},
		profileClock: clock,
	}, nil
}

// buildEvaluatorInput bridges CLI flags to the internal application layer options.
func (o *ApplyOptions) buildEvaluatorInput() (appeval.Options, error) {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return appeval.Options{}, ui.WithHint(
			fmt.Errorf("resolve project context: %w", err),
			ui.ErrHintProjectContext,
		)
	}
	root := resolver.ProjectRoot()

	_, cfgPath, err := projconfig.FindProjectConfigWithPath("")
	if err != nil {
		return appeval.Options{}, ui.WithHint(
			fmt.Errorf("load project config: %w", err),
			ui.ErrHintProjectConfig,
		)
	}
	_, userPath, _, uErr := projconfig.FindUserConfigWithPath()
	if uErr != nil {
		return appeval.Options{}, fmt.Errorf("load user config: %w", uErr)
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
		MaxUnsafe:          o.MaxUnsafe,
		NowTime:            o.NowTime,
		ObservationsSource: appeval.ObservationSource(o.ObservationsDir),
		IntegrityManifest:  o.IntegrityManifest,
		IntegrityPublicKey: o.IntegrityPublicKey,
		Hasher:             fsutil.FSContentHasher{},
	}, nil
}

// normalizeApplyPaths cleans user-supplied paths and applies project-root
// inference for controls and observations directories.
func (o *ApplyOptions) normalizeApplyPaths(obsChanged bool) error {
	o.IntegrityManifest = fsutil.CleanUserPath(o.IntegrityManifest)
	o.IntegrityPublicKey = fsutil.CleanUserPath(o.IntegrityPublicKey)

	resolver, err := projctx.NewResolver()
	if err != nil {
		return fmt.Errorf("resolve project context: %w", err)
	}
	engine := projctx.NewInferenceEngine(resolver)
	if !o.ControlsSet {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			o.ControlsDir = inferred
		}
	}
	if o.ObservationsDir != "-" && !obsChanged {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			o.ObservationsDir = inferred
		}
	}
	return nil
}

// parseDomain handles the conversion of strings to domain-specific types.
func (o *ApplyOptions) parseDomain() (appeval.ParsedOptions, error) {
	parsed, err := (appeval.Options{
		MaxUnsafe:          o.MaxUnsafe,
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

// validateDirs ensures directories exist unless using packs or stdin.
func (o *ApplyOptions) validateDirs() error {
	packs, err := o.isUsingPacks()
	if err != nil {
		return err
	}
	if !packs {
		if err := cmdutil.ValidateFlagDir("--controls", o.ControlsDir, "controls", ui.ErrHintControlsNotAccessible, nil); err != nil {
			return err
		}
	}

	if o.ObservationsDir != "-" {
		if err := cmdutil.ValidateFlagDir("--observations", o.ObservationsDir, "observations", ui.ErrHintObservationsNotAccessible, nil); err != nil {
			return err
		}
	}

	return nil
}

func (o *ApplyOptions) isUsingPacks() (bool, error) {
	if o.ControlsSet {
		return false, nil
	}
	cfg, ok, err := projconfig.FindProjectConfig()
	if err != nil {
		return false, fmt.Errorf("load project config: %w", err)
	}
	return ok && len(cfg.EnabledControlPacks) > 0, nil
}

// standardIO holds resolved IO and format state for the standard apply path.
type standardIO struct {
	Stdout    io.Writer
	Stderr    io.Writer
	Sanitizer kernel.Sanitizer
	Format    ui.OutputFormat
	IsJSON    bool
	Quiet     bool
}

// ResolveStandardIO extracts IO and format state for the standard apply path.
func (o *ApplyOptions) ResolveStandardIO(cs cobraState) (standardIO, error) {
	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, cs.GlobalFlags.IsJSONMode())
	if err != nil {
		return standardIO{}, err
	}
	return standardIO{
		Stdout:    compose.ResolveStdout(cs.Stdout, cs.GlobalFlags.Quiet, format),
		Stderr:    cs.Stderr,
		Sanitizer: cs.GlobalFlags.GetSanitizer(),
		Format:    format,
		IsJSON:    cs.GlobalFlags.IsJSONMode(),
		Quiet:     cs.GlobalFlags.Quiet,
	}, nil
}

func (o *ApplyOptions) buildClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}

// ResolveDryRun converts raw CLI options into a PlanConfig for dry-run mode.
func (o *ApplyOptions) ResolveDryRun(cs cobraState) (PlanConfig, error) {
	format, err := compose.ResolveFormatValuePure(o.Format, cs.FormatChanged, cs.GlobalFlags.IsJSONMode())
	if err != nil {
		return PlanConfig{}, err
	}

	resolver, err := projctx.NewResolver()
	if err != nil {
		return PlanConfig{}, err
	}
	engine := projctx.NewInferenceEngine(resolver)
	ctlDir := fsutil.CleanUserPath(o.ControlsDir)
	if !o.ControlsSet {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			ctlDir = inferred
		}
	}
	obsDir := fsutil.CleanUserPath(o.ObservationsDir)
	if !cs.ObsChanged {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			obsDir = inferred
		}
	}

	hasPacks := false
	cfg, ok, cfgErr := projconfig.FindProjectConfig()
	if cfgErr != nil {
		return PlanConfig{}, fmt.Errorf("load project config: %w", cfgErr)
	}
	if ok && len(cfg.EnabledControlPacks) > 0 {
		hasPacks = true
	}

	prereqs, prereqErr := doctorPrereqs()
	if prereqErr != nil {
		return PlanConfig{}, prereqErr
	}

	return PlanConfig{
		ControlsDir:     ctlDir,
		ObservationsDir: obsDir,
		MaxUnsafe:       o.MaxUnsafe,
		Now:             o.NowTime,
		Format:          format,
		Quiet:           cs.GlobalFlags.Quiet,
		Sanitize:        cs.GlobalFlags.Sanitize,
		Stdout:          cs.Stdout,
		Stderr:          cs.Stderr,
		ControlsFlagSet: o.ControlsSet,
		HasEnabledPacks: hasPacks,
		PrereqChecks:    prereqs,
	}, nil
}
