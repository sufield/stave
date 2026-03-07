package apply

import (
	"fmt"
	"os"
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
	runModeTemplate runMode = "template"
)

type runOptions struct {
	mode           runMode
	params         applyParams
	format         ui.OutputFormat
	dryRun         bool
	explain        bool
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
					scopeFile:       applyFlags.profileScopeFile,
					bucketAllowlist: applyFlags.profileBucketAllowlist,
					includeAll:      applyFlags.profileIncludeAll,
					outputFormat:    applyFlags.outputFormat,
					nowTime:         applyFlags.nowTime,
					quiet:           applyFlags.quietMode,
				},
			}, nil
		}
	}

	params, err := validateApplyFlags(cmd)
	if err != nil {
		return runOptions{}, err
	}
	format, err := ui.ParseOutputFormat(applyFlags.outputFormat)
	if err != nil {
		return runOptions{}, err
	}
	mode := runModeStandard
	if applyFlags.applyTemplateStr != "" {
		mode = runModeTemplate
	}

	return runOptions{
		mode:           mode,
		params:         params,
		format:         format,
		dryRun:         applyFlags.applyDryRun,
		explain:        applyFlags.applyExplain,
		evaluatorInput: buildEvaluatorOptions(),
	}, nil
}

func buildEvaluatorOptions() appeval.Options {
	root := rootForContextName()
	_, cfgPath, _ := findProjectConfigWithPath()
	_, userPath, _ := findUserConfigWithPath()
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
		Explain:            applyFlags.applyExplain,
		DryRun:             applyFlags.applyDryRun,
		Format:             applyFlags.outputFormat,
	}
}

// checkDirsExist verifies that the controls and observations directories
// exist and are accessible. When the source is stdin the observations
// directory check is skipped.
func checkDirsExist(source appeval.ObservationSource) error {
	usePackMode := shouldUseConfiguredPacks()
	if !usePackMode {
		if fi, err := os.Stat(applyFlags.controlsDir); err != nil {
			baseErr := ui.DirectoryAccessError("--controls", applyFlags.controlsDir, err, ui.ErrHintControlsNotAccessible)
			if detail := explainInferenceFailure("controls"); detail != "" {
				return fmt.Errorf("%w\n%s", baseErr, detail)
			}
			return baseErr
		} else if !fi.IsDir() {
			return fmt.Errorf("--controls must be a directory: %s", applyFlags.controlsDir)
		}
	}
	if !source.IsStdin() {
		if fi, err := os.Stat(applyFlags.observationsDir); err != nil {
			baseErr := ui.DirectoryAccessError("--observations", applyFlags.observationsDir, err, ui.ErrHintObservationsNotAccessible)
			if detail := explainInferenceFailure("observations"); detail != "" {
				return fmt.Errorf("%w\n%s", baseErr, detail)
			}
			return baseErr
		} else if !fi.IsDir() {
			return fmt.Errorf("--observations must be a directory: %s", applyFlags.observationsDir)
		}
	}
	return nil
}

func shouldUseConfiguredPacks() bool {
	if applyFlags.applyControlsFlagSet {
		return false
	}
	cfg, ok := findProjectConfig()
	if !ok {
		return false
	}
	return len(cfg.EnabledControlPacks) > 0
}

// validateApplyFlags validates command-line flags and returns parsed parameters.
// It checks directory existence, parses duration and time flags, and loads the
// evaluation context. Returns an error for any invalid or inaccessible input.
func validateApplyFlags(cmd *cobra.Command) (applyParams, error) {
	resetInferAttempts()
	applyFlags.applyControlsFlagSet = cmdutil.ControlsFlagChanged(cmd)

	applyFlags.controlsDir = fsutil.CleanUserPath(applyFlags.controlsDir)
	applyFlags.observationsDir = fsutil.CleanUserPath(applyFlags.observationsDir)
	applyFlags.applyIntegrityManifest = fsutil.CleanUserPath(applyFlags.applyIntegrityManifest)
	applyFlags.applyIntegrityPublicKey = fsutil.CleanUserPath(applyFlags.applyIntegrityPublicKey)

	applyFlags.controlsDir = inferControlsDir(cmd, applyFlags.controlsDir)
	if applyFlags.observationsDir != "-" {
		applyFlags.observationsDir = inferObservationsDir(cmd, applyFlags.observationsDir)
	}

	parsed, err := (appeval.Options{
		MaxUnsafe:          applyFlags.maxUnsafe,
		NowTime:            applyFlags.nowTime,
		ObservationsSource: appeval.ObservationSource(applyFlags.observationsDir),
		IntegrityManifest:  applyFlags.applyIntegrityManifest,
		IntegrityPublicKey: applyFlags.applyIntegrityPublicKey,
	}).Validate()
	if err != nil {
		if strings.HasPrefix(err.Error(), "invalid --max-unsafe") {
			return applyParams{}, &ui.InputError{Err: ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)}
		}
		return applyParams{}, &ui.InputError{Err: err}
	}

	if err := checkDirsExist(parsed.Source); err != nil {
		return applyParams{}, err
	}

	var clock ports.Clock = ports.RealClock{}
	if !parsed.Now.IsZero() {
		clock = ports.FixedClock{Time: parsed.Now}
	}

	return applyParams{
		maxDuration: parsed.MaxDuration,
		clock:       clock,
		source:      parsed.Source,
	}, nil
}
