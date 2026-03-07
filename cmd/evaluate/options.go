package evaluate

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

// evaluateParams holds validated and parsed flag values for the apply (evaluate) command.
type evaluateParams struct {
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
	params         evaluateParams
	format         ui.OutputFormat
	dryRun         bool
	explain        bool
	profile        evaluateProfileOptions
	evaluatorInput appeval.Options
}

func gatherRunOptions(cmd *cobra.Command) (runOptions, error) {
	if applyFlags.evalProfile != "" {
		profile, err := ParseEvalProfile(applyFlags.evalProfile)
		if err != nil {
			return runOptions{}, err
		}
		switch profile {
		case EvalProfileAWSS3:
			if applyFlags.profileInputFile == "" {
				return runOptions{}, fmt.Errorf("--input is required when using --profile aws-s3")
			}
			return runOptions{
				mode: runModeProfile,
				profile: evaluateProfileOptions{
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

	params, err := validateEvaluateFlags(cmd)
	if err != nil {
		return runOptions{}, err
	}
	format, err := ui.ParseOutputFormat(applyFlags.outputFormat)
	if err != nil {
		return runOptions{}, err
	}
	mode := runModeStandard
	if applyFlags.evaluateTemplateStr != "" {
		mode = runModeTemplate
	}

	return runOptions{
		mode:           mode,
		params:         params,
		format:         format,
		dryRun:         applyFlags.evaluateDryRun,
		explain:        applyFlags.evaluateExplain,
		evaluatorInput: buildEvaluatorOptions(),
	}, nil
}

func buildEvaluatorOptions() appeval.Options {
	root := rootForContextName()
	_, cfgPath, _ := findProjectConfigWithPath()
	_, userPath, _ := findUserConfigWithPath()
	return appeval.Options{
		ContextName:        resolveEvaluateContextName(root),
		ProjectRoot:        root,
		ControlsDir:        applyFlags.controlsDir,
		ConfigPath:         cfgPath,
		UserConfigPath:     userPath,
		MaxUnsafe:          applyFlags.maxUnsafe,
		NowTime:            applyFlags.nowTime,
		ObservationsSource: appeval.ObservationSource(applyFlags.observationsDir),
		IntegrityManifest:  applyFlags.evaluateIntegrityManifest,
		IntegrityPublicKey: applyFlags.evaluateIntegrityPublicKey,
		Explain:            applyFlags.evaluateExplain,
		DryRun:             applyFlags.evaluateDryRun,
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
	if applyFlags.evaluateControlsFlagSet {
		return false
	}
	cfg, ok := findProjectConfig()
	if !ok {
		return false
	}
	return len(cfg.EnabledControlPacks) > 0
}

// validateEvaluateFlags validates command-line flags and returns parsed parameters.
// It checks directory existence, parses duration and time flags, and loads the
// evaluation context. Returns an error for any invalid or inaccessible input.
func validateEvaluateFlags(cmd *cobra.Command) (evaluateParams, error) {
	resetInferAttempts()
	applyFlags.evaluateControlsFlagSet = cmdutil.ControlsFlagChanged(cmd)

	applyFlags.controlsDir = fsutil.CleanUserPath(applyFlags.controlsDir)
	applyFlags.observationsDir = fsutil.CleanUserPath(applyFlags.observationsDir)
	applyFlags.evaluateIntegrityManifest = fsutil.CleanUserPath(applyFlags.evaluateIntegrityManifest)
	applyFlags.evaluateIntegrityPublicKey = fsutil.CleanUserPath(applyFlags.evaluateIntegrityPublicKey)

	applyFlags.controlsDir = inferControlsDir(cmd, applyFlags.controlsDir)
	if applyFlags.observationsDir != "-" {
		applyFlags.observationsDir = inferObservationsDir(cmd, applyFlags.observationsDir)
	}

	parsed, err := (appeval.Options{
		MaxUnsafe:          applyFlags.maxUnsafe,
		NowTime:            applyFlags.nowTime,
		ObservationsSource: appeval.ObservationSource(applyFlags.observationsDir),
		IntegrityManifest:  applyFlags.evaluateIntegrityManifest,
		IntegrityPublicKey: applyFlags.evaluateIntegrityPublicKey,
	}).Validate()
	if err != nil {
		if strings.HasPrefix(err.Error(), "invalid --max-unsafe") {
			return evaluateParams{}, &ui.InputError{Err: ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)}
		}
		return evaluateParams{}, &ui.InputError{Err: err}
	}

	if err := checkDirsExist(parsed.Source); err != nil {
		return evaluateParams{}, err
	}

	var clock ports.Clock = ports.RealClock{}
	if !parsed.Now.IsZero() {
		clock = ports.FixedClock{Time: parsed.Now}
	}

	return evaluateParams{
		maxDuration: parsed.MaxDuration,
		clock:       clock,
		source:      parsed.Source,
	}, nil
}
