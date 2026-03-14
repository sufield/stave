package gate

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/enforce/shared"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// Config defines the parameters for enforcing a CI failure policy.
type Config struct {
	Policy          projconfig.GatePolicy
	InPath          string
	BaselinePath    string
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       time.Duration
	Format          ui.OutputFormat
	Quiet           bool
}

// Runner orchestrates CI policy enforcement.
type Runner struct {
	Provider  *compose.Provider
	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
	Stdout    io.Writer
}

// NewRunner initializes a gate runner with required dependencies.
func NewRunner(p *compose.Provider, clock ports.Clock) *Runner {
	return &Runner{
		Provider: p,
		Clock:    clock,
	}
}

// Result represents the structured output of a gate evaluation.
type Result struct {
	SchemaVersion kernel.Schema         `json:"schema_version"`
	Kind          kernel.OutputKind     `json:"kind"`
	CheckedAt     time.Time             `json:"checked_at"`
	Policy        projconfig.GatePolicy `json:"policy"`
	Pass          bool                  `json:"pass"`
	Reason        string                `json:"reason"`

	EvaluationPath   string `json:"evaluation_path,omitempty"`
	BaselinePath     string `json:"baseline_path,omitempty"`
	ControlsPath     string `json:"controls_path,omitempty"`
	ObservationsPath string `json:"observations_path,omitempty"`

	CurrentViolations int `json:"current_violations,omitempty"`
	NewViolations     int `json:"new_violations,omitempty"`
	OverdueUpcoming   int `json:"overdue_upcoming,omitempty"`
}

// Run executes the configured gate policy.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	var (
		res Result
		err error
	)

	switch cfg.Policy {
	case projconfig.GatePolicyAny:
		res, err = r.runPolicyAny(cfg.InPath)
	case projconfig.GatePolicyNew:
		res, err = r.runPolicyNew(cfg.InPath, cfg.BaselinePath)
	case projconfig.GatePolicyOverdue:
		res, err = r.runPolicyOverdue(ctx, cfg.ControlsDir, cfg.ObservationsDir, cfg.MaxUnsafe)
	default:
		return fmt.Errorf("unsupported gate policy: %q", cfg.Policy)
	}
	if err != nil {
		return err
	}

	if r.Sanitizer != nil {
		res.EvaluationPath = r.Sanitizer.Path(res.EvaluationPath)
		res.BaselinePath = r.Sanitizer.Path(res.BaselinePath)
		res.ControlsPath = r.Sanitizer.Path(res.ControlsPath)
		res.ObservationsPath = r.Sanitizer.Path(res.ObservationsPath)
	}

	if err := r.report(cfg, res); err != nil {
		return err
	}
	if !res.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

func (r *Runner) runPolicyAny(evaluationPath string) (Result, error) {
	eval, err := shared.LoadEvaluationEnvelope(evaluationPath)
	if err != nil {
		return Result{}, fmt.Errorf("loading evaluation: %w", err)
	}
	count := len(eval.Findings)
	pass := count == 0
	reason := fmt.Sprintf("current findings=%d", count)
	if pass {
		reason = "no current findings"
	}
	return Result{
		SchemaVersion:     kernel.SchemaGate,
		Kind:              kernel.KindGateCheck,
		CheckedAt:         r.Clock.Now().UTC(),
		Policy:            projconfig.GatePolicyAny,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    evaluationPath,
		CurrentViolations: count,
	}, nil
}

func (r *Runner) runPolicyNew(evaluationPath, baselinePath string) (Result, error) {
	eval, err := shared.LoadEvaluationEnvelope(evaluationPath)
	if err != nil {
		return Result{}, fmt.Errorf("loading evaluation: %w", err)
	}
	base, err := shared.LoadBaselineFile(baselinePath, kernel.KindBaseline)
	if err != nil {
		return Result{}, fmt.Errorf("loading baseline: %w", err)
	}
	bc := shared.CompareAgainstBaseline(r.Sanitizer, base.Findings, eval.Findings)
	newCount := len(bc.Comparison.New)
	pass := newCount == 0
	reason := fmt.Sprintf("new findings=%d", newCount)
	if pass {
		reason = "no new findings compared to baseline"
	}
	return Result{
		SchemaVersion:     kernel.SchemaGate,
		Kind:              kernel.KindGateCheck,
		CheckedAt:         r.Clock.Now().UTC(),
		Policy:            projconfig.GatePolicyNew,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    evaluationPath,
		BaselinePath:      baselinePath,
		CurrentViolations: len(bc.Current),
		NewViolations:     newCount,
	}, nil
}

func (r *Runner) runPolicyOverdue(ctx context.Context, controlsDir, observationsDir string, maxUnsafe time.Duration) (Result, error) {
	loaded, err := r.Provider.LoadAssets(ctx, observationsDir, controlsDir)
	if err != nil {
		return Result{}, err
	}
	now := r.Clock.Now().UTC()
	items := risk.ComputeItems(risk.Request{
		Controls:        loaded.Controls,
		Snapshots:       loaded.Snapshots,
		GlobalMaxUnsafe: maxUnsafe,
		Now:             now,
		PredicateParser: ctlyaml.YAMLPredicateParser,
	})
	overdueCount := items.CountOverdue()
	pass := overdueCount == 0
	reason := fmt.Sprintf("overdue upcoming actions=%d", overdueCount)
	if pass {
		reason = "no overdue upcoming actions"
	}
	return Result{
		SchemaVersion:    kernel.SchemaGate,
		Kind:             kernel.KindGateCheck,
		CheckedAt:        now,
		Policy:           projconfig.GatePolicyOverdue,
		Pass:             pass,
		Reason:           reason,
		ControlsPath:     controlsDir,
		ObservationsPath: observationsDir,
		OverdueUpcoming:  overdueCount,
	}, nil
}

func (r *Runner) report(cfg Config, res Result) error {
	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(r.Stdout, res)
	}
	if cfg.Quiet {
		return nil
	}
	status := "PASS"
	if !res.Pass {
		status = "FAIL"
	}
	_, err := fmt.Fprintf(r.Stdout, "Gate %s (%s): %s\n", status, res.Policy, res.Reason)
	return err
}
