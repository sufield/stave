package apply

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	jsonout "github.com/sufield/stave/internal/adapters/output/json"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/validation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func runPlan(cmd *cobra.Command, flags *planFlagsType) error {
	if err := projctx.EnsureContextSelectionValid(); err != nil {
		return err
	}

	format, err := compose.ResolveFormatValue(cmd, flags.format)
	if err != nil {
		return err
	}

	report, err := assessReadiness(cmd, readinessInput{
		ControlsDir:     flags.controlsDir,
		ObservationsDir: flags.observationsDir,
		MaxUnsafe:       flags.maxUnsafe,
		Now:             flags.nowTime,
		ControlsFlagSet: cmdutil.ControlsFlagChanged(cmd),
	})
	if err != nil {
		return err
	}

	if !cmdutil.QuietEnabled(cmd) {
		if err := writeReadinessReport(cmd.OutOrStdout(), report, format); err != nil {
			return err
		}
	}

	return readinessExitError(report)
}

func runApply(cmd *cobra.Command, _ []string, flags *applyFlagsType) error {
	if err := projctx.EnsureContextSelectionValid(); err != nil {
		return err
	}

	// Profile mode bypasses standard readiness checks — it uses its own
	// input validation inside runApplyCoreProfileWithOptions.
	if flags.applyProfile != "" {
		return runApplyCore(cmd, flags)
	}

	report, err := assessReadiness(cmd, readinessInput{
		ControlsDir:     flags.controlsDir,
		ObservationsDir: flags.observationsDir,
		MaxUnsafe:       flags.maxUnsafe,
		Now:             flags.nowTime,
		ControlsFlagSet: cmdutil.ControlsFlagChanged(cmd),
	})
	if err != nil {
		return &ui.InputError{Err: ui.EvaluateErrorWithHint(err)}
	}
	if !report.Ready {
		if !cmdutil.QuietEnabled(cmd) {
			_ = writeReadinessText(cmd.ErrOrStderr(), report)
		}
		return ui.WithNextCommand(fmt.Errorf("%w: readiness checks failed; apply not executed", ui.ErrValidationFailed), "stave plan")
	}
	return runApplyCore(cmd, flags)
}

func assessReadiness(cmd *cobra.Command, in readinessInput) (validation.ReadinessReport, error) {
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
	log := projctx.NewInferenceLog()
	ctlDir := fsutil.CleanUserPath(in.ControlsDir)
	obsDir := fsutil.CleanUserPath(in.ObservationsDir)
	ctlDir = log.InferControlsDir(cmd, ctlDir)
	obsDir = log.InferObservationsDir(cmd, obsDir)
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
	if cfg, ok := projconfig.FindProjectConfig(); ok && len(cfg.EnabledControlPacks) > 0 {
		return true
	}
	return false
}

func buildReadinessValidateFn(cmd *cobra.Command, ctlDir, obsDir string) func(time.Duration, time.Time) (validation.ReadinessValidationResult, error) {
	return applyvalidate.NewReadinessValidateFn(cmd, ctlDir, obsDir)
}
