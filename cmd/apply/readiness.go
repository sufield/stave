package apply

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/prereq"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/app/readiness"
	"github.com/sufield/stave/internal/cli/ui"
	validation "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// ReadinessValidator evaluates controls against observations and returns a result.
type ReadinessValidator func(maxUnsafe time.Duration, now time.Time) (validation.Result, error)

// ReadinessValidatorFactory creates the validation function used during assessment.
type ReadinessValidatorFactory func(ctlDir, obsDir string, sanitize bool) ReadinessValidator

// ReadinessConfig defines the parsed, validated parameters for readiness assessment.
// All fields are native types — flag string parsing happens before construction.
type ReadinessConfig struct {
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration time.Duration
	Now               time.Time
	Format            appcontracts.OutputFormat
	Quiet             bool
	Sanitize          bool
	Stdout            io.Writer
	Stderr            io.Writer

	ControlsFlagSet        bool
	HasEnabledControlPacks bool
	PrereqChecks           []validation.Issue
}

// ReadinessRunner orchestrates the readiness assessment workflow.
// Invoked by apply --dry-run.
type ReadinessRunner struct {
	CreateValidator ReadinessValidatorFactory
}

// NewReadinessRunner returns a runner with the given validator factory.
func NewReadinessRunner(factory ReadinessValidatorFactory) *ReadinessRunner {
	return &ReadinessRunner{
		CreateValidator: factory,
	}
}

// Execute performs the readiness assessment and writes the report.
func (r *ReadinessRunner) Execute(cfg ReadinessConfig) error {
	report, err := readiness.AssessReadiness(validation.Input{
		ControlsDir:            cfg.ControlsDir,
		ObservationsDir:        cfg.ObservationsDir,
		MaxUnsafeDuration:      cfg.MaxUnsafeDuration,
		Now:                    cfg.Now,
		ControlsFlagSet:        cfg.ControlsFlagSet,
		HasEnabledControlPacks: cfg.HasEnabledControlPacks,
		PrereqChecks:           cfg.PrereqChecks,
		Validate:               r.CreateValidator(cfg.ControlsDir, cfg.ObservationsDir, cfg.Sanitize),
	})
	if err != nil {
		return err
	}

	if !cfg.Quiet {
		if err := r.writeReport(cfg, report); err != nil {
			return err
		}
	}

	if !report.Ready {
		return ui.ErrValidationFailed
	}
	return nil
}

func (r *ReadinessRunner) writeReport(cfg ReadinessConfig, report validation.Report) error {
	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(cfg.Stdout, readinessJSONReport{
			Report:      report,
			NextCommand: readinessNextCommand(report),
		})
	}
	rep := &Reporter{Stdout: cfg.Stdout, Stderr: cfg.Stderr}
	return rep.ReportPlan(report)
}

// readinessJSONReport enriches the domain Report with the CLI-specific
// next_command field for JSON output. The domain type intentionally omits this
// field because CLI command names are a presentation concern.
type readinessJSONReport struct {
	validation.Report
	NextCommand string `json:"next_command"`
}

// runDryRun performs only readiness checks (replacing the removed plan command).
// It is invoked by apply --dry-run.
func runDryRun(ctx context.Context, p *compose.Provider, cfg ReadinessConfig) error {
	factory := func(ctlDir, obsDir string, sanitize bool) ReadinessValidator {
		return applyvalidate.NewReadinessValidator(ctx, p.NewObservationRepo, p.NewControlRepo, ctlDir, obsDir, sanitize, applyvalidate.PackConfigIssues)
	}
	runner := NewReadinessRunner(factory)
	return runner.Execute(cfg)
}

func doctorPrereqs() ([]validation.Issue, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	return prereq.DoctorPrereqChecks(cwd, exe), nil
}
