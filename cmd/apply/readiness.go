package apply

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	jsonout "github.com/sufield/stave/internal/adapters/output/json"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/validation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func runPlan(cmd *cobra.Command, _ []string) error {
	if err := cmdutil.EnsureContextSelectionValid(); err != nil {
		return err
	}

	format, err := ui.ParseOutputFormat(strings.TrimSpace(readinessPlanFormat))
	if err != nil {
		return err
	}

	report, err := assessReadiness(cmd, readinessInput{
		ControlsDir:     readinessPlanControlsDir,
		ObservationsDir: readinessPlanObservationsDir,
		MaxUnsafe:       readinessPlanMaxUnsafe,
		Now:             readinessPlanNowTime,
		ControlsFlagSet: cmdutil.ControlsFlagChanged(cmd),
	})
	if err != nil {
		return err
	}

	if !readinessPlanQuiet && !cmdutil.QuietEnabled(cmd) {
		if err := writeReadinessReport(cmd.OutOrStdout(), report, format); err != nil {
			return err
		}
	}

	return readinessExitError(report)
}

func runApply(cmd *cobra.Command, args []string) error {
	if err := cmdutil.EnsureContextSelectionValid(); err != nil {
		return err
	}

	// Profile mode bypasses standard readiness checks — it uses its own
	// input validation inside runApplyCoreProfileWithOptions.
	if applyFlags.applyProfile != "" {
		return runApplyCore(cmd, args)
	}

	report, err := assessReadiness(cmd, readinessInput{
		ControlsDir:     applyFlags.controlsDir,
		ObservationsDir: applyFlags.observationsDir,
		MaxUnsafe:       applyFlags.maxUnsafe,
		Now:             applyFlags.nowTime,
		ControlsFlagSet: cmdutil.ControlsFlagChanged(cmd),
	})
	if err != nil {
		return &ui.InputError{Err: ui.EvaluateErrorWithHint(err)}
	}
	if !report.Ready {
		if ui.ShouldEmitOutput(applyFlags.quietMode, cmdutil.QuietEnabled(cmd)) {
			_ = writeReadinessText(os.Stderr, report)
		}
		return ui.WithNextCommand(fmt.Errorf("%w: readiness checks failed; apply not executed", ui.ErrValidationFailed), "stave plan")
	}
	return runApplyCore(cmd, args)
}

func assessReadiness(cmd *cobra.Command, in readinessInput) (validation.ReadinessReport, error) {
	resetInferAttempts()
	ctlDir, obsDir := resolveReadinessDirs(cmd, in)

	report, err := service.AssessReadiness(validation.ReadinessInput{
		ControlsDir:           ctlDir,
		ObservationsDir:       obsDir,
		MaxUnsafe:             in.MaxUnsafe,
		Now:                   in.Now,
		ControlsFlagSet:       in.ControlsFlagSet,
		HasEnabledControlPack: readinessHasEnabledPacks(),
		PrereqChecks:          cmdutil.DoctorPrereqChecks(),
		Validate:              buildReadinessValidateFn(cmd, ctlDir, obsDir),
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidMaxUnsafe) {
			return validation.ReadinessReport{}, ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)
		}
		return validation.ReadinessReport{}, err
	}
	return report, nil
}

func resolveReadinessDirs(cmd *cobra.Command, in readinessInput) (string, string) {
	ctlDir := fsutil.CleanUserPath(in.ControlsDir)
	obsDir := fsutil.CleanUserPath(in.ObservationsDir)
	ctlDir = inferControlsDir(cmd, ctlDir)
	obsDir = inferObservationsDir(cmd, obsDir)
	return ctlDir, obsDir
}

// writeReadinessReport writes the readiness report in the requested format.
func writeReadinessReport(w io.Writer, report validation.ReadinessReport, format ui.OutputFormat) error {
	if format.IsJSON() {
		return jsonout.WriteReadinessJSON(w, report)
	}
	return writeReadinessText(w, report)
}

// readinessExitError returns an error if the readiness report indicates failure.
func readinessExitError(report validation.ReadinessReport) error {
	if !report.Ready {
		return ui.ErrValidationFailed
	}
	return nil
}

func readinessHasEnabledPacks() bool {
	if cfg, ok := findProjectConfig(); ok && len(cfg.EnabledControlPacks) > 0 {
		return true
	}
	return false
}

func buildReadinessValidateFn(cmd *cobra.Command, ctlDir, obsDir string) func(time.Duration, time.Time) (validation.ReadinessValidationResult, error) {
	return applyvalidate.NewReadinessValidateFn(cmd, ctlDir, obsDir)
}
