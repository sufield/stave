package apply

import (
	"errors"
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

func runPlan(cmd *cobra.Command, opts *PlanOptions) error {
	if err := projctx.EnsureContextSelectionValid(); err != nil {
		return err
	}

	format, err := compose.ResolveFormatValue(cmd, opts.Format)
	if err != nil {
		return err
	}

	report, err := assessReadiness(cmd, opts.toReadinessInput())
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
	rep := &Reporter{Stdout: w, Stderr: w}
	return rep.ReportPlan(report)
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

func buildReadinessValidateFn(cmd *cobra.Command, ctlDir, obsDir string) func(time.Duration, time.Time) (validation.ValidationResult, error) {
	return applyvalidate.NewReadinessValidator(ctlDir, obsDir, cmdutil.SanitizeEnabled(cmd))
}
