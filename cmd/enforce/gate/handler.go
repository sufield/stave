package gate

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/shared"
	appconfig "github.com/sufield/stave/internal/app/config"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// Config defines the parameters for enforcing a CI failure policy.
type Config struct {
	Policy          appconfig.GatePolicy
	InPath          string
	BaselinePath    string
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       time.Duration
	Format          ui.OutputFormat
	Quiet           bool

	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
	Stdout    io.Writer
	Stderr    io.Writer
}

// Runner orchestrates CI policy enforcement.
type Runner struct {
	Provider *compose.Provider
}

// NewRunner initializes a gate runner with required dependencies.
func NewRunner(p *compose.Provider) *Runner {
	return &Runner{
		Provider: p,
	}
}

// Result represents the structured output of a gate evaluation.
type Result struct {
	SchemaVersion kernel.Schema         `json:"schema_version"`
	Kind          kernel.OutputKind     `json:"kind"`
	CheckedAt     time.Time             `json:"checked_at"`
	Policy        appconfig.GatePolicy `json:"policy"`
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
	case appconfig.GatePolicyAny:
		res, err = r.runPolicyAny(cfg)
	case appconfig.GatePolicyNew:
		res, err = r.runPolicyNew(cfg)
	case appconfig.GatePolicyOverdue:
		res, err = r.runPolicyOverdue(ctx, cfg)
	default:
		return fmt.Errorf("unsupported gate policy: %q", cfg.Policy)
	}
	if err != nil {
		return err
	}

	if cfg.Sanitizer != nil {
		res.EvaluationPath = cfg.Sanitizer.Path(res.EvaluationPath)
		res.BaselinePath = cfg.Sanitizer.Path(res.BaselinePath)
		res.ControlsPath = cfg.Sanitizer.Path(res.ControlsPath)
		res.ObservationsPath = cfg.Sanitizer.Path(res.ObservationsPath)
	}

	if err := r.report(cfg, res); err != nil {
		return err
	}
	if !res.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

func (r *Runner) runPolicyAny(cfg Config) (Result, error) {
	eval, err := shared.NewLoader().Evaluation(cfg.InPath)
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
		CheckedAt:         cfg.Clock.Now().UTC(),
		Policy:            appconfig.GatePolicyAny,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    cfg.InPath,
		CurrentViolations: count,
	}, nil
}

func (r *Runner) runPolicyNew(cfg Config) (Result, error) {
	eval, err := shared.NewLoader().Evaluation(cfg.InPath)
	if err != nil {
		return Result{}, fmt.Errorf("loading evaluation: %w", err)
	}
	base, err := shared.NewLoader().Baseline(cfg.BaselinePath, kernel.KindBaseline)
	if err != nil {
		return Result{}, fmt.Errorf("loading baseline: %w", err)
	}
	bc := shared.CompareAgainstBaseline(cfg.Sanitizer, base.Findings, eval.Findings)
	newCount := len(bc.Comparison.New)
	pass := newCount == 0
	reason := fmt.Sprintf("new findings=%d", newCount)
	if pass {
		reason = "no new findings compared to baseline"
	}
	return Result{
		SchemaVersion:     kernel.SchemaGate,
		Kind:              kernel.KindGateCheck,
		CheckedAt:         cfg.Clock.Now().UTC(),
		Policy:            appconfig.GatePolicyNew,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    cfg.InPath,
		BaselinePath:      cfg.BaselinePath,
		CurrentViolations: len(bc.Current),
		NewViolations:     newCount,
	}, nil
}

func (r *Runner) runPolicyOverdue(ctx context.Context, cfg Config) (Result, error) {
	loaded, err := r.Provider.LoadAssets(ctx, cfg.ObservationsDir, cfg.ControlsDir)
	if err != nil {
		return Result{}, err
	}
	now := cfg.Clock.Now().UTC()
	items := risk.ComputeItems(risk.Request{
		Controls:        loaded.Controls,
		Snapshots:       loaded.Snapshots,
		GlobalMaxUnsafe: cfg.MaxUnsafe,
		Now:             now,
		PredicateParser: ctlyaml.ParsePredicate,
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
		Policy:           appconfig.GatePolicyOverdue,
		Pass:             pass,
		Reason:           reason,
		ControlsPath:     cfg.ControlsDir,
		ObservationsPath: cfg.ObservationsDir,
		OverdueUpcoming:  overdueCount,
	}, nil
}

func (r *Runner) report(cfg Config, res Result) error {
	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(cfg.Stdout, res)
	}
	if cfg.Quiet {
		return nil
	}
	status := "PASS"
	if !res.Pass {
		status = "FAIL"
	}
	_, err := fmt.Fprintf(cfg.Stdout, "Gate %s (%s): %s\n", status, res.Policy, res.Reason)
	return err
}
