package apply

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
)

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
func (o *ApplyOptions) Resolve(cmd *cobra.Command) (RunConfig, error) {
	if o.Profile != "" {
		return o.resolveProfileMode(cmd)
	}

	o.normalizeApplyPaths(cmd)

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

func (o *ApplyOptions) resolveProfileMode(cmd *cobra.Command) (RunConfig, error) {
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

	format, err := compose.ResolveFormatValue(cmd, o.Format)
	if err != nil {
		return RunConfig{}, err
	}

	gf := cmdutil.GetGlobalFlags(cmd)

	return RunConfig{
		Mode: runModeProfile,
		Profile: Config{
			InputFile:       o.InputFile,
			BucketAllowlist: o.BucketAllowlist,
			IncludeAll:      o.IncludeAll,
			OutputFormat:    format.String(),
			NowTime:         o.NowTime,
			Quiet:           gf.Quiet,
			Stdout:          compose.ResolveStdout(cmd.OutOrStdout(), gf.Quiet, format),
			Stderr:          cmd.ErrOrStderr(),
			IsJSONMode:      gf.IsJSONMode(),
			Sanitizer:       gf.GetSanitizer(),
		},
		profileClock: clock,
	}, nil
}

// buildEvaluatorInput bridges CLI flags to the internal application layer options.
func (o *ApplyOptions) buildEvaluatorInput() appeval.Options {
	resolver, _ := projctx.NewResolver()
	root := ""
	if resolver != nil {
		root = resolver.ProjectRoot()
	}
	_, cfgPath, _ := projconfig.FindProjectConfigWithPath("")
	_, userPath, _ := projconfig.FindUserConfigWithPath()

	selectedContext := ""
	if resolver != nil {
		if sc, err := resolver.ResolveSelected(); err == nil && sc.Active {
			selectedContext = sc.Name
		}
	}

	return appeval.Options{
		ContextName:        ResolveContextName(root, selectedContext),
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
	}
}

// normalizeApplyPaths cleans user-supplied paths and applies project-root
// inference for controls and observations directories.
func (o *ApplyOptions) normalizeApplyPaths(cmd *cobra.Command) {
	o.IntegrityManifest = fsutil.CleanUserPath(o.IntegrityManifest)
	o.IntegrityPublicKey = fsutil.CleanUserPath(o.IntegrityPublicKey)

	resolver, _ := projctx.NewResolver()
	engine := projctx.NewInferenceEngine(resolver)
	if !cmd.Flags().Changed("controls") {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			o.ControlsDir = inferred
		}
	}
	if o.ObservationsDir != "-" && !cmd.Flags().Changed("observations") {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			o.ObservationsDir = inferred
		}
	}
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
	if !o.isUsingPacks() {
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

func (o *ApplyOptions) isUsingPacks() bool {
	if o.ControlsSet {
		return false
	}
	cfg, ok := projconfig.FindProjectConfig()
	return ok && len(cfg.EnabledControlPacks) > 0
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

// ResolveStandardIO extracts IO and format state from the command for the standard apply path.
func (o *ApplyOptions) ResolveStandardIO(cmd *cobra.Command) (standardIO, error) {
	format, err := compose.ResolveFormatValue(cmd, o.Format)
	if err != nil {
		return standardIO{}, err
	}
	gf := cmdutil.GetGlobalFlags(cmd)
	return standardIO{
		Stdout:    compose.ResolveStdout(cmd.OutOrStdout(), gf.Quiet, format),
		Stderr:    cmd.ErrOrStderr(),
		Sanitizer: gf.GetSanitizer(),
		Format:    format,
		IsJSON:    gf.IsJSONMode(),
		Quiet:     gf.Quiet,
	}, nil
}

func (o *ApplyOptions) buildClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}

// ResolveDryRun converts raw CLI options into a PlanConfig for dry-run mode.
func (o *ApplyOptions) ResolveDryRun(cmd *cobra.Command) (PlanConfig, error) {
	format, err := compose.ResolveFormatValue(cmd, o.Format)
	if err != nil {
		return PlanConfig{}, err
	}

	resolver, err := projctx.NewResolver()
	if err != nil {
		return PlanConfig{}, err
	}
	engine := projctx.NewInferenceEngine(resolver)
	ctlDir := fsutil.CleanUserPath(o.ControlsDir)
	if !cmd.Flags().Changed("controls") {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			ctlDir = inferred
		}
	}
	obsDir := fsutil.CleanUserPath(o.ObservationsDir)
	if !cmd.Flags().Changed("observations") {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			obsDir = inferred
		}
	}

	hasPacks := false
	if cfg, ok := projconfig.FindProjectConfig(); ok && len(cfg.EnabledControlPacks) > 0 {
		hasPacks = true
	}

	gf := cmdutil.GetGlobalFlags(cmd)

	return PlanConfig{
		ControlsDir:     ctlDir,
		ObservationsDir: obsDir,
		MaxUnsafe:       o.MaxUnsafe,
		Now:             o.NowTime,
		Format:          format,
		Quiet:           gf.Quiet,
		Sanitize:        gf.Sanitize,
		Stdout:          cmd.OutOrStdout(),
		Stderr:          cmd.ErrOrStderr(),
		ControlsFlagSet: o.ControlsSet,
		HasEnabledPacks: hasPacks,
		PrereqChecks:    doctorPrereqs(),
	}, nil
}
