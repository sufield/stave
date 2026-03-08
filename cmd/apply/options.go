package apply

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
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

func gatherRunOptions(cmd *cobra.Command) (runOptions, error) {
	if applyFlags.applyProfile != "" {
		profile, err := ParseApplyProfile(applyFlags.applyProfile)
		if err != nil {
			return runOptions{}, err
		}
		switch profile {
		case ApplyProfileAWSS3:
			if applyFlags.profileInputFile == "" {
				return runOptions{}, fmt.Errorf("--input is required when using --profile aws-s3")
			}
			return runOptions{
				mode: runModeProfile,
				profile: applyProfileOptions{
					inputFile:       applyFlags.profileInputFile,
					bucketAllowlist: applyFlags.profileBucketAllowlist,
					includeAll:      applyFlags.profileIncludeAll,
					outputFormat:    applyFlags.outputFormat,
					nowTime:         applyFlags.nowTime,
					quiet:           cmdutil.QuietEnabled(cmd),
				},
			}, nil
		}
	}

	if strictErr := runStrictIntegrityCheck(cmd); strictErr != nil {
		return runOptions{}, strictErr
	}

	params, err := validateApplyFlags(cmd)
	if err != nil {
		return runOptions{}, err
	}
	format, err := ui.ParseOutputFormat(applyFlags.outputFormat)
	if err != nil {
		return runOptions{}, err
	}

	return runOptions{
		mode:           runModeStandard,
		params:         params,
		format:         format,
		evaluatorInput: buildEvaluatorOptions(),
	}, nil
}

func buildEvaluatorOptions() appeval.Options {
	root := cmdutil.RootForContextName()
	_, cfgPath, _ := cmdutil.FindProjectConfigWithPath()
	_, userPath, _ := cmdutil.FindUserConfigWithPath()
	return appeval.Options{
		ContextName:        resolveApplyContextName(root),
		ProjectRoot:        root,
		ControlsDir:        applyFlags.controlsDir,
		ConfigPath:         cfgPath,
		UserConfigPath:     userPath,
		MaxUnsafe:          applyFlags.maxUnsafe,
		NowTime:            applyFlags.nowTime,
		ObservationsSource: appeval.ObservationSource(applyFlags.observationsDir),
		IntegrityManifest:  applyFlags.applyIntegrityManifest,
		IntegrityPublicKey: applyFlags.applyIntegrityPublicKey,
	}
}

// checkDirsExist verifies that the controls and observations directories
// exist and are accessible. When the source is stdin the observations
// directory check is skipped.
func checkDirsExist(source appeval.ObservationSource) error {
	usePackMode := shouldUseConfiguredPacks()
	if !usePackMode {
		if err := cmdutil.ValidateDirWithInference("--controls", applyFlags.controlsDir, "controls", ui.ErrHintControlsNotAccessible); err != nil {
			return err
		}
	}
	if !source.IsStdin() {
		if err := cmdutil.ValidateDirWithInference("--observations", applyFlags.observationsDir, "observations", ui.ErrHintObservationsNotAccessible); err != nil {
			return err
		}
	}
	return nil
}

func shouldUseConfiguredPacks() bool {
	if applyFlags.applyControlsFlagSet {
		return false
	}
	cfg, ok := cmdutil.FindProjectConfig()
	if !ok {
		return false
	}
	return len(cfg.EnabledControlPacks) > 0
}

// validateApplyFlags validates command-line flags and returns parsed parameters.
// It normalizes paths, validates domain constraints, and checks directory
// existence. Returns an error for any invalid or inaccessible input.
func validateApplyFlags(cmd *cobra.Command) (applyParams, error) {
	normalizeApplyFlags(cmd)

	parsed, err := validateApplyDomain()
	if err != nil {
		return applyParams{}, err
	}

	if err := checkDirsExist(parsed.Source); err != nil {
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
func normalizeApplyFlags(cmd *cobra.Command) {
	cmdutil.ResetInferAttempts()
	applyFlags.applyControlsFlagSet = cmdutil.ControlsFlagChanged(cmd)

	applyFlags.controlsDir = fsutil.CleanUserPath(applyFlags.controlsDir)
	applyFlags.observationsDir = fsutil.CleanUserPath(applyFlags.observationsDir)
	applyFlags.applyIntegrityManifest = fsutil.CleanUserPath(applyFlags.applyIntegrityManifest)
	applyFlags.applyIntegrityPublicKey = fsutil.CleanUserPath(applyFlags.applyIntegrityPublicKey)

	applyFlags.controlsDir = cmdutil.InferControlsDir(cmd, applyFlags.controlsDir)
	if applyFlags.observationsDir != "-" {
		applyFlags.observationsDir = cmdutil.InferObservationsDir(cmd, applyFlags.observationsDir)
	}
}

// validateApplyDomain validates parsed flag values against domain constraints
// (duration format, time format, integrity key pairing).
func validateApplyDomain() (appeval.ParsedOptions, error) {
	parsed, err := (appeval.Options{
		MaxUnsafe:          applyFlags.maxUnsafe,
		NowTime:            applyFlags.nowTime,
		ObservationsSource: appeval.ObservationSource(applyFlags.observationsDir),
		IntegrityManifest:  applyFlags.applyIntegrityManifest,
		IntegrityPublicKey: applyFlags.applyIntegrityPublicKey,
	}).Validate()
	if err != nil {
		if strings.HasPrefix(err.Error(), "invalid --max-unsafe") {
			return appeval.ParsedOptions{}, &ui.InputError{Err: ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)}
		}
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
