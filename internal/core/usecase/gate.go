package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

// --- Gate ---

// GateRequest is the input for the CI gate use case.
type GateRequest struct {
	Policy            string        `json:"policy"`
	EvaluationPath    string        `json:"evaluation_path,omitempty"`
	BaselinePath      string        `json:"baseline_path,omitempty"`
	ControlsDir       string        `json:"controls_dir,omitempty"`
	ObservationsDir   string        `json:"observations_dir,omitempty"`
	MaxUnsafeDuration time.Duration `json:"max_unsafe_duration,omitempty"`
	Now               *time.Time    `json:"now,omitempty"`
}

// GateResponse is the output of the CI gate use case.
type GateResponse struct {
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

// GateDeps groups the port interfaces for the gate use case.
type GateDeps struct {
	FindingsCounter  FindingsCounterPort
	BaselineComparer BaselineComparerPort
	OverdueCounter   OverdueCounterPort
	Clock            ports.Clock
}

const (
	gatePolicyAny     = "fail_on_any_violation"
	gatePolicyNew     = "fail_on_new_violation"
	gatePolicyOverdue = "fail_on_overdue_upcoming"
)

// Gate enforces a CI failure policy and returns the gate result.
func Gate(ctx context.Context, req GateRequest, deps GateDeps) (GateResponse, error) {
	if err := ctx.Err(); err != nil {
		return GateResponse{}, fmt.Errorf("gate: %w", err)
	}

	// req.Now overrides everything (tests and reproducible runs);
	// otherwise use the injected Clock; if neither is supplied, fall
	// back to ports.RealClock so a nil Clock dependency doesn't panic
	// while keeping wall-clock access behind the ports interface.
	var now time.Time
	switch {
	case req.Now != nil:
		now = req.Now.UTC()
	case deps.Clock != nil:
		now = deps.Clock.Now().UTC()
	default:
		now = ports.RealClock{}.Now().UTC()
	}

	switch req.Policy {
	case gatePolicyAny:
		return gateAny(ctx, req, deps, now)
	case gatePolicyNew:
		return gateNew(ctx, req, deps, now)
	case gatePolicyOverdue:
		return gateOverdue(ctx, req, deps, now)
	default:
		return GateResponse{}, fmt.Errorf("gate: unsupported policy %q", req.Policy)
	}
}

func gateAny(ctx context.Context, req GateRequest, deps GateDeps, now time.Time) (GateResponse, error) {
	if deps.FindingsCounter == nil {
		return GateResponse{}, fmt.Errorf("gate: %s policy requires %s dependency", req.Policy, "FindingsCounter")
	}
	count, err := deps.FindingsCounter.CountFindings(ctx, req.EvaluationPath)
	if err != nil {
		return GateResponse{}, fmt.Errorf("gate: load evaluation %s: %w", req.EvaluationPath, err)
	}

	pass := count == 0
	reason := fmt.Sprintf("current findings=%d", count)
	if pass {
		reason = "no current findings"
	}

	return GateResponse{
		Policy:            req.Policy,
		Passed:            pass,
		Reason:            reason,
		CheckedAt:         now,
		EvaluationPath:    req.EvaluationPath,
		CurrentViolations: count,
	}, nil
}

func gateNew(ctx context.Context, req GateRequest, deps GateDeps, now time.Time) (GateResponse, error) {
	if deps.BaselineComparer == nil {
		return GateResponse{}, fmt.Errorf("gate: %s policy requires %s dependency", req.Policy, "BaselineComparer")
	}
	currentCount, newCount, err := deps.BaselineComparer.CompareAgainstBaseline(ctx, req.EvaluationPath, req.BaselinePath)
	if err != nil {
		return GateResponse{}, fmt.Errorf("gate: compare against baseline: %w", err)
	}

	pass := newCount == 0
	reason := fmt.Sprintf("new findings=%d", newCount)
	if pass {
		reason = "no new findings compared to baseline"
	}

	return GateResponse{
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

func gateOverdue(ctx context.Context, req GateRequest, deps GateDeps, now time.Time) (GateResponse, error) {
	if deps.OverdueCounter == nil {
		return GateResponse{}, fmt.Errorf("gate: %s policy requires %s dependency", req.Policy, "OverdueCounter")
	}
	overdueCount, err := deps.OverdueCounter.CountOverdue(ctx, req.ControlsDir, req.ObservationsDir, req.MaxUnsafeDuration, now)
	if err != nil {
		return GateResponse{}, fmt.Errorf("gate: count overdue: %w", err)
	}

	pass := overdueCount == 0
	reason := fmt.Sprintf("overdue upcoming actions=%d", overdueCount)
	if pass {
		reason = "no overdue upcoming actions"
	}

	return GateResponse{
		Policy:           req.Policy,
		Passed:           pass,
		Reason:           reason,
		CheckedAt:        now,
		ControlsPath:     req.ControlsDir,
		ObservationsPath: req.ObservationsDir,
		OverdueUpcoming:  overdueCount,
	}, nil
}
