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
	Stdout          io.Writer
	Stderr          io.Writer
}

// Runner orchestrates the evaluation of compliance gates.
type Runner struct {
	Provider  *compose.Provider
	Clock     ports.Clock
	Sanitizer kernel.Sanitizer
}

// NewRunner initializes a gate runner with required dependencies.
func NewRunner(p *compose.Provider, clock ports.Clock) *Runner {
	return &Runner{
		Provider: p,
		Clock:    clock,
	}
}

type gateResult struct {
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

// Run executes the gating logic and returns ui.ErrViolationsFound if the policy fails.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	now := r.Clock.Now().UTC()

	result, err := r.executePolicy(ctx, cfg, now)
	if err != nil {
		return err
	}

	result = sanitizeGateResult(r.Sanitizer, result)

	if err := writeOutput(cfg, result); err != nil {
		return err
	}
	if !result.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

func (r *Runner) executePolicy(ctx context.Context, cfg Config, now time.Time) (gateResult, error) {
	switch cfg.Policy {
	case projconfig.GatePolicyAny:
		return runPolicyAny(now, cfg.InPath)
	case projconfig.GatePolicyNew:
		return runPolicyNew(now, cfg.InPath, cfg.BaselinePath)
	case projconfig.GatePolicyOverdue:
		return r.runPolicyOverdue(ctx, now, cfg.ControlsDir, cfg.ObservationsDir, cfg.MaxUnsafe)
	default:
		return gateResult{}, fmt.Errorf("unsupported --policy %q", cfg.Policy)
	}
}

func writeOutput(cfg Config, result gateResult) error {
	if cfg.Format.IsJSON() {
		if err := jsonutil.WriteIndented(cfg.Stdout, result); err != nil {
			return fmt.Errorf("write gate output: %w", err)
		}
		return nil
	}
	if cfg.Quiet {
		return nil
	}
	if result.Pass {
		_, err := fmt.Fprintf(cfg.Stdout, "Gate PASS (%s): %s\n", result.Policy, result.Reason)
		return err
	}
	_, err := fmt.Fprintf(cfg.Stdout, "Gate FAIL (%s): %s\n", result.Policy, result.Reason)
	return err
}

func runPolicyAny(now time.Time, evaluationPath string) (gateResult, error) {
	eval, err := shared.LoadEvaluationEnvelope(evaluationPath)
	if err != nil {
		return gateResult{}, err
	}
	count := len(eval.Findings)
	pass := count == 0
	reason := fmt.Sprintf("current findings=%d", count)
	if pass {
		reason = "no current findings"
	}
	return gateResult{
		SchemaVersion:     kernel.SchemaGate,
		Kind:              kernel.KindGateCheck,
		CheckedAt:         now,
		Policy:            projconfig.GatePolicyAny,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    evaluationPath,
		CurrentViolations: count,
	}, nil
}

func runPolicyNew(now time.Time, evaluationPath, baselinePath string) (gateResult, error) {
	eval, err := shared.LoadEvaluationEnvelope(evaluationPath)
	if err != nil {
		return gateResult{}, err
	}
	base, err := shared.LoadBaselineFile(baselinePath, "baseline")
	if err != nil {
		return gateResult{}, err
	}
	bc := shared.CompareBaseline(base.Findings, eval.Findings)
	pass := !bc.Comparison.HasNewFindings()
	reason := fmt.Sprintf("new findings=%d", len(bc.Comparison.New))
	if pass {
		reason = "no new findings compared to baseline"
	}
	return gateResult{
		SchemaVersion:     kernel.SchemaGate,
		Kind:              kernel.KindGateCheck,
		CheckedAt:         now,
		Policy:            projconfig.GatePolicyNew,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    evaluationPath,
		BaselinePath:      baselinePath,
		CurrentViolations: len(bc.Current),
		NewViolations:     len(bc.Comparison.New),
	}, nil
}

func sanitizeGateResult(s kernel.Sanitizer, r gateResult) gateResult {
	if s == nil {
		return r
	}
	r.EvaluationPath = s.Path(r.EvaluationPath)
	r.BaselinePath = s.Path(r.BaselinePath)
	r.ControlsPath = s.Path(r.ControlsPath)
	r.ObservationsPath = s.Path(r.ObservationsPath)
	return r
}

func (r *Runner) runPolicyOverdue(ctx context.Context, now time.Time, controlsDir, observationsDir string, maxUnsafe time.Duration) (gateResult, error) {
	loaded, err := r.Provider.LoadAssets(ctx, observationsDir, controlsDir)
	if err != nil {
		return gateResult{}, err
	}
	items := risk.ComputeItems(risk.Request{
		Controls:        loaded.Controls,
		Snapshots:       loaded.Snapshots,
		GlobalMaxUnsafe: maxUnsafe,
		Now:             now,
		PredicateParser: ctlyaml.YAMLPredicateParser,
	})
	overdue := items.CountOverdue()
	pass := overdue == 0
	reason := fmt.Sprintf("overdue upcoming actions=%d", overdue)
	if pass {
		reason = "no overdue upcoming actions"
	}
	return gateResult{
		SchemaVersion:    kernel.SchemaGate,
		Kind:             kernel.KindGateCheck,
		CheckedAt:        now,
		Policy:           projconfig.GatePolicyOverdue,
		Pass:             pass,
		Reason:           reason,
		ControlsPath:     controlsDir,
		ObservationsPath: observationsDir,
		OverdueUpcoming:  overdue,
	}, nil
}
