package apply

import (
	"io"
	"os"
	"time"

	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	jsonout "github.com/sufield/stave/internal/adapters/output/json"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/validation"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// PlanConfig defines the parameters for assessing readiness.
type PlanConfig struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	Now             string
	Format          ui.OutputFormat
	Quiet           bool
	Sanitize        bool
	Stdout          io.Writer
	Stderr          io.Writer

	ControlsFlagSet bool
	HasEnabledPacks bool
	PrereqChecks    []validation.PrereqCheck
}

// ValidatorFactory creates the validation function used during assessment.
type ValidatorFactory func(ctlDir, obsDir string, sanitize bool) func(time.Duration, time.Time) (validation.ValidationResult, error)

// Planner orchestrates the "plan/readiness" workflow.
type Planner struct {
	CreateValidator ValidatorFactory
}

// NewPlanner returns a planner with default dependencies.
func NewPlanner(factory ValidatorFactory) *Planner {
	return &Planner{
		CreateValidator: factory,
	}
}

// Execute performs the readiness assessment and writes the report.
func (p *Planner) Execute(cfg PlanConfig) error {
	ctlDir := fsutil.CleanUserPath(cfg.ControlsDir)
	obsDir := fsutil.CleanUserPath(cfg.ObservationsDir)

	maxUnsafe, err := timeutil.ParseDurationFlag(cfg.MaxUnsafe, "--max-unsafe")
	if err != nil {
		return ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)
	}
	now, err := compose.ResolveNow(cfg.Now)
	if err != nil {
		return err
	}

	report, err := service.AssessReadiness(validation.ReadinessInput{
		ControlsDir:           ctlDir,
		ObservationsDir:       obsDir,
		MaxUnsafe:             maxUnsafe,
		Now:                   now,
		ControlsFlagSet:       cfg.ControlsFlagSet,
		HasEnabledControlPack: cfg.HasEnabledPacks,
		PrereqChecks:          cfg.PrereqChecks,
		Validate:              p.CreateValidator(ctlDir, obsDir, cfg.Sanitize),
	})
	if err != nil {
		return err
	}

	if !cfg.Quiet {
		if err := p.writeReport(cfg, report); err != nil {
			return err
		}
	}

	if !report.Ready {
		return ui.ErrValidationFailed
	}
	return nil
}

func (p *Planner) writeReport(cfg PlanConfig, report validation.ReadinessReport) error {
	if cfg.Format.IsJSON() {
		return jsonout.WriteReadinessJSON(cfg.Stdout, report)
	}
	rep := &Reporter{Stdout: cfg.Stdout, Stderr: cfg.Stderr}
	return rep.ReportPlan(report)
}

// runDryRun performs only readiness checks (replacing the removed plan command).
// It is invoked by apply --dry-run.
func runDryRun(p *compose.Provider, cfg PlanConfig) error {
	factory := func(ctlDir, obsDir string, sanitize bool) func(time.Duration, time.Time) (validation.ValidationResult, error) {
		return applyvalidate.NewReadinessValidator(p, ctlDir, obsDir, sanitize)
	}
	planner := NewPlanner(factory)
	return planner.Execute(cfg)
}

func doctorPrereqs() []validation.PrereqCheck {
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	return cmdutil.DoctorPrereqChecks(cwd, exe)
}
