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

type runOptions struct {
	mode           runMode
	params         applyParams
	format         ui.OutputFormat
	profile        applyProfileOptions
	evaluatorInput appeval.Options
}

func gatherRunOptions(cmd *cobra.Command, flags *applyFlagsType) (runOptions, error) {
	if flags.applyProfile != "" {
		profile, err := ParseApplyProfile(flags.applyProfile)
		if err != nil {
			return runOptions{}, err
		}
		switch profile {
		case ApplyProfileAWSS3:
			if flags.profileInputFile == "" {
				return runOptions{}, fmt.Errorf("--input is required when using --profile aws-s3")
			}
			return runOptions{
				mode: runModeProfile,
				profile: applyProfileOptions{
					inputFile:       flags.profileInputFile,
					bucketAllowlist: flags.profileBucketAllowlist,
					includeAll:      flags.profileIncludeAll,
					outputFormat:    flags.outputFormat,
					nowTime:         flags.nowTime,
					quiet:           cmdutil.QuietEnabled(cmd),
				},
			}, nil
		}
	}

	if strictErr := runStrictIntegrityCheck(cmd); strictErr != nil {
		return runOptions{}, strictErr
	}

	params, err := validateApplyFlags(cmd, flags)
	if err != nil {
		return runOptions{}, err
	}
	format, err := ui.ParseOutputFormat(flags.outputFormat)
	if err != nil {
		return runOptions{}, err
	}

	return runOptions{
		mode:           runModeStandard,
		params:         params,
		format:         format,
		evaluatorInput: buildEvaluatorOptions(flags),
	}, nil
}

func buildEvaluatorOptions(flags *applyFlagsType) appeval.Options {
	root := projctx.RootForContextName()
	_, cfgPath, _ := projconfig.FindProjectConfigWithPath()
	_, userPath, _ := projconfig.FindUserConfigWithPath()
	return appeval.Options{
		ContextName:        resolveApplyContextName(root),
		ProjectRoot:        root,
		ControlsDir:        flags.controlsDir,
		ConfigPath:         cfgPath,
		UserConfigPath:     userPath,
		MaxUnsafe:          flags.maxUnsafe,
		NowTime:            flags.nowTime,
		ObservationsSource: appeval.ObservationSource(flags.observationsDir),
		IntegrityManifest:  flags.applyIntegrityManifest,
		IntegrityPublicKey: flags.applyIntegrityPublicKey,
	}
}

// checkDirsExist verifies that the controls and observations directories
// exist and are accessible. When the source is stdin the observations
// directory check is skipped.
func checkDirsExist(flags *applyFlagsType, source appeval.ObservationSource, log *projctx.InferenceLog) error {
	usePackMode := shouldUseConfiguredPacks(flags)
	if !usePackMode {
		if err := cmdutil.ValidateDirWithInference("--controls", flags.controlsDir, "controls", ui.ErrHintControlsNotAccessible, log); err != nil {
			return err
		}
	}
	if !source.IsStdin() {
		if err := cmdutil.ValidateDirWithInference("--observations", flags.observationsDir, "observations", ui.ErrHintObservationsNotAccessible, log); err != nil {
			return err
		}
	}
	return nil
}

func shouldUseConfiguredPacks(flags *applyFlagsType) bool {
	if flags.applyControlsFlagSet {
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
func validateApplyFlags(cmd *cobra.Command, flags *applyFlagsType) (applyParams, error) {
	log := normalizeApplyFlags(cmd, flags)

	parsed, err := validateApplyDomain(flags)
	if err != nil {
		return applyParams{}, err
	}

	if err := checkDirsExist(flags, parsed.Source, log); err != nil {
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
func normalizeApplyFlags(cmd *cobra.Command, flags *applyFlagsType) *projctx.InferenceLog {
	log := projctx.NewInferenceLog()
	flags.applyControlsFlagSet = cmdutil.ControlsFlagChanged(cmd)

	flags.controlsDir = fsutil.CleanUserPath(flags.controlsDir)
	flags.observationsDir = fsutil.CleanUserPath(flags.observationsDir)
	flags.applyIntegrityManifest = fsutil.CleanUserPath(flags.applyIntegrityManifest)
	flags.applyIntegrityPublicKey = fsutil.CleanUserPath(flags.applyIntegrityPublicKey)

	flags.controlsDir = log.InferControlsDir(cmd, flags.controlsDir)
	if flags.observationsDir != "-" {
		flags.observationsDir = log.InferObservationsDir(cmd, flags.observationsDir)
	}
	return log
}

// validateApplyDomain validates parsed flag values against domain constraints
// (duration format, time format, integrity key pairing).
func validateApplyDomain(flags *applyFlagsType) (appeval.ParsedOptions, error) {
	parsed, err := (appeval.Options{
		MaxUnsafe:          flags.maxUnsafe,
		NowTime:            flags.nowTime,
		ObservationsSource: appeval.ObservationSource(flags.observationsDir),
		IntegrityManifest:  flags.applyIntegrityManifest,
		IntegrityPublicKey: flags.applyIntegrityPublicKey,
	}).Validate()
	if err != nil {
		return appeval.ParsedOptions{}, &ui.InputError{Err: err}
	}
	return parsed, nil
}

// newClock returns a FixedClock if now is non-zero, otherwise a RealClock.
func newClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock{Time: now}
	}
	return ports.RealClock{}
}
