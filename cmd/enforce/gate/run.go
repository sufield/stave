package gate

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/enforce/artifact"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// config defines the parameters for enforcing a CI failure policy.
type config struct {
	Policy            appconfig.GatePolicy
	InPath            string
	BaselinePath      string
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration time.Duration
	Format            ui.OutputFormat
	Quiet             bool

	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
	Stdout    io.Writer
	Stderr    io.Writer
}

// runner orchestrates CI policy enforcement.
type runner struct {
	LoadAssets      compose.AssetLoaderFunc
	NewCELEvaluator compose.CELEvaluatorFactory
}

// newRunner initializes a gate runner with required dependencies.
func newRunner(loadAssets compose.AssetLoaderFunc, newCELEvaluator compose.CELEvaluatorFactory) *runner {
	return &runner{
		LoadAssets:      loadAssets,
		NewCELEvaluator: newCELEvaluator,
	}
}

// result represents the structured output of a gate evaluation.
type result struct {
	SchemaVersion kernel.Schema        `json:"schema_version"`
	Kind          kernel.OutputKind    `json:"kind"`
	CheckedAt     time.Time            `json:"checked_at"`
	Policy        appconfig.GatePolicy `json:"policy"`
	Passed        bool                 `json:"pass"`
	Reason        string               `json:"reason"`

	EvaluationPath   string `json:"evaluation_path,omitempty"`
	BaselinePath     string `json:"baseline_path,omitempty"`
	ControlsPath     string `json:"controls_path,omitempty"`
	ObservationsPath string `json:"observations_path,omitempty"`

	CurrentViolations int `json:"current_violations,omitempty"`
	NewViolations     int `json:"new_violations,omitempty"`
	OverdueUpcoming   int `json:"overdue_upcoming,omitempty"`
}

// Run executes the configured gate policy.
func (r *runner) Run(ctx context.Context, cfg config) error {
	var (
		res result
		err error
	)

	switch cfg.Policy {
	case appconfig.GatePolicyAny:
		res, err = r.runPolicyAny(ctx, cfg)
	case appconfig.GatePolicyNew:
		res, err = r.runPolicyNew(ctx, cfg)
	case appconfig.GatePolicyOverdue:
		res, err = r.runPolicyOverdue(ctx, cfg)
	default:
		return fmt.Errorf("unsupported gate policy: %q", cfg.Policy)
	}
	if err != nil {
		return fmt.Errorf("gate execution: %w", err)
	}

	if cfg.Sanitizer != nil {
		res.sanitize(cfg.Sanitizer)
	}

	if err := r.report(cfg, res); err != nil {
		return err
	}
	if !res.Passed {
		return ui.ErrViolationsFound
	}
	return nil
}

func newBaseResult(cfg config) result {
	return result{
		SchemaVersion: kernel.SchemaGate,
		Kind:          kernel.KindGateCheck,
		CheckedAt:     cfg.Clock.Now().UTC(),
	}
}

func (res *result) sanitize(s kernel.Sanitizer) {
	res.EvaluationPath = s.Path(res.EvaluationPath)
	res.BaselinePath = s.Path(res.BaselinePath)
	res.ControlsPath = s.Path(res.ControlsPath)
	res.ObservationsPath = s.Path(res.ObservationsPath)
}

func (r *runner) runPolicyAny(ctx context.Context, cfg config) (result, error) {
	eval, err := artifact.NewLoader().Evaluation(ctx, cfg.InPath)
	if err != nil {
		return result{}, fmt.Errorf("loading evaluation: %w", err)
	}
	count := len(eval.Findings)
	pass := count == 0
	reason := fmt.Sprintf("current findings=%d", count)
	if pass {
		reason = "no current findings"
	}
	res := newBaseResult(cfg)
	res.Policy = appconfig.GatePolicyAny
	res.Passed = pass
	res.Reason = reason
	res.EvaluationPath = cfg.InPath
	res.CurrentViolations = count
	return res, nil
}

func (r *runner) runPolicyNew(ctx context.Context, cfg config) (result, error) {
	loader := artifact.NewLoader()
	eval, err := loader.Evaluation(ctx, cfg.InPath)
	if err != nil {
		return result{}, fmt.Errorf("loading evaluation: %w", err)
	}
	base, err := loader.Baseline(ctx, cfg.BaselinePath, kernel.KindBaseline)
	if err != nil {
		return result{}, fmt.Errorf("loading baseline: %w", err)
	}
	bc := artifact.CompareAgainstBaseline(cfg.Sanitizer, base.Findings, eval.Findings)
	pass := !bc.HasNewViolations()
	reason := fmt.Sprintf("new findings=%d", len(bc.Comparison.New))
	if pass {
		reason = "no new findings compared to baseline"
	}
	res := newBaseResult(cfg)
	res.Policy = appconfig.GatePolicyNew
	res.Passed = pass
	res.Reason = reason
	res.EvaluationPath = cfg.InPath
	res.BaselinePath = cfg.BaselinePath
	res.CurrentViolations = len(bc.Current)
	res.NewViolations = len(bc.Comparison.New)
	return res, nil
}

func (r *runner) runPolicyOverdue(ctx context.Context, cfg config) (result, error) {
	loaded, err := r.LoadAssets(ctx, cfg.ObservationsDir, cfg.ControlsDir)
	if err != nil {
		return result{}, fmt.Errorf("loading assets: %w", err)
	}
	celEval, err := r.NewCELEvaluator()
	if err != nil {
		return result{}, fmt.Errorf("init CEL evaluator: %w", err)
	}
	now := cfg.Clock.Now().UTC()
	items := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                loaded.Controls,
		Snapshots:               loaded.Snapshots,
		GlobalMaxUnsafeDuration: cfg.MaxUnsafeDuration,
		Now:                     now,
		PredicateParser:         ctlyaml.ParsePredicate,
		PredicateEval:           celEval,
	})
	overdueCount := items.CountOverdue()
	pass := overdueCount == 0
	reason := fmt.Sprintf("overdue upcoming actions=%d", overdueCount)
	if pass {
		reason = "no overdue upcoming actions"
	}
	res := newBaseResult(cfg)
	res.CheckedAt = now
	res.Policy = appconfig.GatePolicyOverdue
	res.Passed = pass
	res.Reason = reason
	res.ControlsPath = cfg.ControlsDir
	res.ObservationsPath = cfg.ObservationsDir
	res.OverdueUpcoming = overdueCount
	return res, nil
}

func (r *runner) report(cfg config, res result) error {
	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(cfg.Stdout, res)
	}
	if cfg.Quiet {
		return nil
	}
	status := "PASS"
	if !res.Passed {
		status = "FAIL"
	}
	_, err := fmt.Fprintf(cfg.Stdout, "Gate %s (%s): %s\n", status, res.Policy, res.Reason)
	return err
}
