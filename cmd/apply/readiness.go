package apply

import (
	"errors"
	"io"
	"os"
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

	report, err := service.AssessReadiness(validation.ReadinessInput{
		ControlsDir:           ctlDir,
		ObservationsDir:       obsDir,
		MaxUnsafe:             cfg.MaxUnsafe,
		Now:                   cfg.Now,
		ControlsFlagSet:       cfg.ControlsFlagSet,
		HasEnabledControlPack: cfg.HasEnabledPacks,
		PrereqChecks:          cfg.PrereqChecks,
		Validate:              p.CreateValidator(ctlDir, obsDir, cfg.Sanitize),
	})
	if err != nil {
		if errors.Is(err, service.ErrInvalidMaxUnsafe) {
			return ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)
		}
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
func runDryRun(cmd *cobra.Command, opts *ApplyOptions) error {
	format, err := compose.ResolveFormatValue(cmd, opts.Format)
	if err != nil {
		return err
	}

	resolver, err := projctx.NewResolver()
	if err != nil {
		return err
	}
	engine := projctx.NewInferenceEngine(resolver)
	ctlDir := fsutil.CleanUserPath(opts.ControlsDir)
	if !cmd.Flags().Changed("controls") {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			ctlDir = inferred
		}
	}
	obsDir := fsutil.CleanUserPath(opts.ObservationsDir)
	if !cmd.Flags().Changed("observations") {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			obsDir = inferred
		}
	}

	hasPacks := false
	if cfg, ok := projconfig.FindProjectConfig(); ok && len(cfg.EnabledControlPacks) > 0 {
		hasPacks = true
	}

	gf := cmdutil.GetGlobalFlags(cmd)
	planner := NewPlanner(applyvalidate.NewReadinessValidator)

	return planner.Execute(PlanConfig{
		ControlsDir:     ctlDir,
		ObservationsDir: obsDir,
		MaxUnsafe:       opts.MaxUnsafe,
		Now:             opts.NowTime,
		Format:          format,
		Quiet:           gf.Quiet,
		Sanitize:        gf.Sanitize,
		Stdout:          cmd.OutOrStdout(),
		Stderr:          cmd.ErrOrStderr(),
		ControlsFlagSet: opts.ControlsSet,
		HasEnabledPacks: hasPacks,
		PrereqChecks:    doctorPrereqs(),
	})
}

func doctorPrereqs() []validation.PrereqCheck {
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	return cmdutil.DoctorPrereqChecks(cwd, exe)
}
