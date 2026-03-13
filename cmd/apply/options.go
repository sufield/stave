package apply

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
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

	return RunConfig{
		Mode: runModeProfile,
		Profile: Config{
			InputFile:       o.InputFile,
			BucketAllowlist: o.BucketAllowlist,
			IncludeAll:      o.IncludeAll,
			OutputFormat:    o.Format,
			NowTime:         o.NowTime,
			Quiet:           cmdutil.GetGlobalFlags(cmd).Quiet,
		},
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

func (o *ApplyOptions) buildClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}
