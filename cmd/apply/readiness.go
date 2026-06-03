package apply

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	"github.com/sufield/stave/cmd/cmdutil/prereq"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/app/readiness"
	"github.com/sufield/stave/internal/cli/ui"
	validation "github.com/sufield/stave/internal/core/schemaval"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// ReadinessValidator evaluates controls against observations and returns a result.
type ReadinessValidator func(maxUnsafe time.Duration, now time.Time) (validation.EvaluationState, error)

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
	PrereqChecks           []validation.ValidationFinding
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
	report, err := readiness.AssessReadiness(validation.AssessmentContext{
		ControlSource:          cfg.ControlsDir,
		ObservationSource:      cfg.ObservationsDir,
		SLAThreshold:           cfg.MaxUnsafeDuration,
		CurrentTime:            cfg.Now,
		ControlFlagsSet:        cfg.ControlsFlagSet,
		HasEnabledControlPacks: cfg.HasEnabledControlPacks,
		PreflightChecks:        cfg.PrereqChecks,
		RunEvaluation:          r.CreateValidator(cfg.ControlsDir, cfg.ObservationsDir, cfg.Sanitize),
	})
	if err != nil {
		return fmt.Errorf("assess readiness: %w", err)
	}

	if err := r.writeReport(cfg, report); err != nil {
		return err
	}

	if !report.IsReady() {
		return ui.ErrValidationFailed
	}
	return nil
}

// writeReport renders the readiness report in the requested format.
// The cfg.Quiet gate lives here (rather than at the caller) so the
// "stay silent in quiet mode" rule is bound to the writer rather
// than to the call site — the report renderer itself decides
// whether the configuration permits emitting output.
func (r *ReadinessRunner) writeReport(cfg ReadinessConfig, report validation.ReadinessAssessment) error {
	if cfg.Quiet {
		return nil
	}
	if cfg.Format.IsJSON() {
		if err := jsonutil.WriteIndented(cfg.Stdout, readinessJSONReport{
			ReadinessAssessment: report,
			NextCommand:         report.NextCommand(),
		}); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		return nil
	}
	rep := &Reporter{Stdout: cfg.Stdout, Stderr: cfg.Stderr}
	return rep.ReportPlan(report)
}

// readinessJSONReport enriches the domain Report with the CLI-specific
// next_command field for JSON output. The domain type intentionally omits this
// field because CLI command names are a presentation concern.
type readinessJSONReport struct {
	validation.ReadinessAssessment
	NextCommand string `json:"next_command"`
}

// runDryRun performs only readiness checks (replacing the removed plan command).
// It is invoked by apply --dry-run.
func runDryRun(ctx context.Context, deps Deps, cfg ReadinessConfig) error {
	factory := func(ctlDir, obsDir string, sanitize bool) ReadinessValidator {
		return applyvalidate.NewReadinessValidator(ctx, deps.NewObsRepo, deps.NewCtlRepo, ctlDir, obsDir, sanitize, applyvalidate.PackConfigIssues)
	}
	runner := NewReadinessRunner(factory)
	return runner.Execute(cfg)
}

func doctorPrereqs() ([]validation.ValidationFinding, error) {
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
