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

// applyParams holds validated and parsed flag values for the apply command.
type applyParams struct {
	maxDuration time.Duration
	clock       ports.Clock
	source      appeval.ObservationSource
}

type runMode string

const (
	runModeStandard runMode = "standard"
	runModeProfile  runMode = "profile"
)

func gatherRunOptions(cmd *cobra.Command, opts *ApplyOptions) (applyParams, runMode, error) {
	if opts.Profile != "" {
		profile, err := ParseApplyProfile(opts.Profile)
		if err != nil {
			return applyParams{}, "", err
		}
		if profile == ApplyProfileAWSS3 && opts.InputFile == "" {
			return applyParams{}, "", fmt.Errorf("--input is required when using --profile aws-s3")
		}
		return applyParams{}, runModeProfile, nil
	}

	params, err := validateApplyFlags(cmd, opts)
	if err != nil {
		return applyParams{}, "", err
	}

	return params, runModeStandard, nil
}

// toProfileOptions converts ApplyOptions to profile-specific options.
func (o *ApplyOptions) toProfileOptions(cmd *cobra.Command) applyProfileOptions {
	return applyProfileOptions{
		inputFile:       o.InputFile,
		bucketAllowlist: o.BucketAllowlist,
		includeAll:      o.IncludeAll,
		outputFormat:    o.Format,
		nowTime:         o.NowTime,
		quiet:           cmdutil.QuietEnabled(cmd),
	}
}

func buildEvaluatorOptions(opts *ApplyOptions) appeval.Options {
	root := projctx.RootForContextName()
	_, cfgPath, _ := projconfig.FindProjectConfigWithPath()
	_, userPath, _ := projconfig.FindUserConfigWithPath()
	return appeval.Options{
		ContextName:        resolveApplyContextName(root),
		ProjectRoot:        root,
		ControlsDir:        opts.ControlsDir,
		ConfigPath:         cfgPath,
		UserConfigPath:     userPath,
		MaxUnsafe:          opts.MaxUnsafe,
		NowTime:            opts.NowTime,
		ObservationsSource: appeval.ObservationSource(opts.ObservationsDir),
		IntegrityManifest:  opts.IntegrityManifest,
		IntegrityPublicKey: opts.IntegrityPublicKey,
		Hasher:             fsutil.FSContentHasher{},
	}
}

// checkDirsExist verifies that the controls and observations directories
// exist and are accessible. When the source is stdin the observations
// directory check is skipped.
func checkDirsExist(opts *ApplyOptions, source appeval.ObservationSource, log *projctx.InferenceLog) error {
	usePackMode := shouldUseConfiguredPacks(opts)
	if !usePackMode {
		if err := cmdutil.ValidateDirWithInference("--controls", opts.ControlsDir, "controls", ui.ErrHintControlsNotAccessible, log); err != nil {
			return err
		}
	}
	if !source.IsStdin() {
		if err := cmdutil.ValidateDirWithInference("--observations", opts.ObservationsDir, "observations", ui.ErrHintObservationsNotAccessible, log); err != nil {
			return err
		}
	}
	return nil
}

func shouldUseConfiguredPacks(opts *ApplyOptions) bool {
	if opts.ControlsSet {
		return false
	}
	cfg, ok := projconfig.FindProjectConfig()
	if !ok {
		return false
	}
	return len(cfg.EnabledControlPacks) > 0
}

// validateApplyFlags validates command-line flags and returns parsed parameters.
// It normalizes paths, validates domain constraints, and checks directory
// existence. Returns an error for any invalid or inaccessible input.
func validateApplyFlags(cmd *cobra.Command, opts *ApplyOptions) (applyParams, error) {
	log := normalizeApplyFlags(cmd, opts)

	parsed, err := validateApplyDomain(opts)
	if err != nil {
		return applyParams{}, err
	}

	if err := checkDirsExist(opts, parsed.Source, log); err != nil {
		return applyParams{}, err
	}

	return applyParams{
		maxDuration: parsed.MaxDuration,
		clock:       newClock(parsed.Now),
		source:      parsed.Source,
	}, nil
}

// normalizeApplyFlags cleans user-supplied paths and applies project-root
// inference for controls and observations directories.
func normalizeApplyFlags(cmd *cobra.Command, opts *ApplyOptions) *projctx.InferenceLog {
	log := projctx.NewInferenceLog()

	opts.IntegrityManifest = fsutil.CleanUserPath(opts.IntegrityManifest)
	opts.IntegrityPublicKey = fsutil.CleanUserPath(opts.IntegrityPublicKey)

	opts.ControlsDir = log.InferControlsDir(cmd, opts.ControlsDir)
	if opts.ObservationsDir != "-" {
		opts.ObservationsDir = log.InferObservationsDir(cmd, opts.ObservationsDir)
	}
	return log
}

// validateApplyDomain validates parsed flag values against domain constraints
// (duration format, time format, integrity key pairing).
func validateApplyDomain(opts *ApplyOptions) (appeval.ParsedOptions, error) {
	parsed, err := (appeval.Options{
		MaxUnsafe:          opts.MaxUnsafe,
		NowTime:            opts.NowTime,
		ObservationsSource: appeval.ObservationSource(opts.ObservationsDir),
		IntegrityManifest:  opts.IntegrityManifest,
		IntegrityPublicKey: opts.IntegrityPublicKey,
	}).Validate()
	if err != nil {
		return appeval.ParsedOptions{}, &ui.InputError{Err: err}
	}
	return parsed, nil
}

// newClock returns a FixedClock if now is non-zero, otherwise a RealClock.
func newClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}
