package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

// EvaluateRequest is the input for the CI gate evaluation.
type EvaluateRequest struct {
	Policy            string        `json:"policy"`
	EvaluationPath    string        `json:"evaluation_path,omitempty"`
	BaselinePath      string        `json:"baseline_path,omitempty"`
	ControlsDir       string        `json:"controls_dir,omitempty"`
	ObservationsDir   string        `json:"observations_dir,omitempty"`
	MaxUnsafeDuration time.Duration `json:"max_unsafe_duration,omitempty"`
	EvalTime          *time.Time    `json:"eval_time,omitempty"`
}

// EvaluateResponse is the output of the CI gate evaluation.
type EvaluateResponse struct {
	Policy            string    `json:"policy"`
	Passed            bool      `json:"pass"`
	Reason            string    `json:"reason"`
	CheckedAt         time.Time `json:"checked_at"`
	EvaluationPath    string    `json:"evaluation_path,omitempty"`
	BaselinePath      string    `json:"baseline_path,omitempty"`
	ControlsPath      string    `json:"controls_path,omitempty"`
	ObservationsPath  string    `json:"observations_path,omitempty"`
	CurrentViolations int       `json:"current_violations,omitempty"`
	NewViolations     int       `json:"new_violations,omitempty"`
	OverdueUpcoming   int       `json:"overdue_upcoming,omitempty"`
}

// FindingsCounterPort counts findings in an evaluation artifact.
type FindingsCounterPort interface {
	CountFindings(ctx context.Context, path string) (int, error)
}

// BaselineComparerPort compares evaluation findings against a baseline.
type BaselineComparerPort interface {
	CompareAgainstBaseline(ctx context.Context, evalPath, baselinePath string) (currentCount, newCount int, err error)
}

// OverdueCounterPort counts overdue upcoming actions.
type OverdueCounterPort interface {
	CountOverdue(ctx context.Context, controlsDir, observationsDir string, maxUnsafe time.Duration, now time.Time) (int, error)
}

// EvaluateDeps groups the port interfaces for the gate evaluation.
type EvaluateDeps struct {
	FindingsCounter  FindingsCounterPort
	BaselineComparer BaselineComparerPort
	OverdueCounter   OverdueCounterPort
	Clock            ports.Clock
}

const (
	policyAny     = "fail_on_any_violation"
	policyNew     = "fail_on_new_violation"
	policyOverdue = "fail_on_overdue_upcoming"
)

// Evaluate enforces a CI failure policy and returns the gate result.
func Evaluate(ctx context.Context, req EvaluateRequest, deps EvaluateDeps) (EvaluateResponse, error) {
	if err := ctx.Err(); err != nil {
		return EvaluateResponse{}, fmt.Errorf("gate: %w", err)
	}

	var now time.Time
	switch {
	case req.EvalTime != nil:
		now = req.EvalTime.UTC()
	case deps.Clock != nil:
		now = deps.Clock.Now().UTC()
	default:
		now = ports.RealClock{}.Now().UTC()
	}

	switch req.Policy {
	case policyAny:
		return evaluateAny(ctx, req, deps, now)
	case policyNew:
		return evaluateNew(ctx, req, deps, now)
	case policyOverdue:
		return evaluateOverdue(ctx, req, deps, now)
	default:
		return EvaluateResponse{}, fmt.Errorf("gate: unsupported policy %q", req.Policy)
	}
}

func evaluateAny(ctx context.Context, req EvaluateRequest, deps EvaluateDeps, now time.Time) (EvaluateResponse, error) {
	if deps.FindingsCounter == nil {
		return EvaluateResponse{}, fmt.Errorf("gate: %s policy requires %s dependency", req.Policy, "FindingsCounter")
	}
	count, err := deps.FindingsCounter.CountFindings(ctx, req.EvaluationPath)
	if err != nil {
		return EvaluateResponse{}, fmt.Errorf("gate: load evaluation %s: %w", req.EvaluationPath, err)
	}

	pass := count == 0
	reason := fmt.Sprintf("current findings=%d", count)
	if pass {
		reason = "no current findings"
	}

	return EvaluateResponse{
		Policy:            req.Policy,
		Passed:            pass,
		Reason:            reason,
		CheckedAt:         now,
		EvaluationPath:    req.EvaluationPath,
		CurrentViolations: count,
	}, nil
}

func evaluateNew(ctx context.Context, req EvaluateRequest, deps EvaluateDeps, now time.Time) (EvaluateResponse, error) {
	if deps.BaselineComparer == nil {
		return EvaluateResponse{}, fmt.Errorf("gate: %s policy requires %s dependency", req.Policy, "BaselineComparer")
	}
	currentCount, newCount, err := deps.BaselineComparer.CompareAgainstBaseline(ctx, req.EvaluationPath, req.BaselinePath)
	if err != nil {
		return EvaluateResponse{}, fmt.Errorf("gate: compare against baseline: %w", err)
	}

	pass := newCount == 0
	reason := fmt.Sprintf("new findings=%d", newCount)
	if pass {
		reason = "no new findings compared to baseline"
	}

	return EvaluateResponse{
		Policy:            req.Policy,
		Passed:            pass,
		Reason:            reason,
		CheckedAt:         now,
		EvaluationPath:    req.EvaluationPath,
		BaselinePath:      req.BaselinePath,
		CurrentViolations: currentCount,
		NewViolations:     newCount,
	}, nil
}

func evaluateOverdue(ctx context.Context, req EvaluateRequest, deps EvaluateDeps, now time.Time) (EvaluateResponse, error) {
	if deps.OverdueCounter == nil {
		return EvaluateResponse{}, fmt.Errorf("gate: %s policy requires %s dependency", req.Policy, "OverdueCounter")
	}
	overdueCount, err := deps.OverdueCounter.CountOverdue(ctx, req.ControlsDir, req.ObservationsDir, req.MaxUnsafeDuration, now)
	if err != nil {
		return EvaluateResponse{}, fmt.Errorf("gate: count overdue: %w", err)
	}

	pass := overdueCount == 0
	reason := fmt.Sprintf("overdue upcoming actions=%d", overdueCount)
	if pass {
		reason = "no overdue upcoming actions"
	}

	return EvaluateResponse{
		Policy:           req.Policy,
		Passed:           pass,
		Reason:           reason,
		CheckedAt:        now,
		ControlsPath:     req.ControlsDir,
		ObservationsPath: req.ObservationsDir,
		OverdueUpcoming:  overdueCount,
	}, nil
}
