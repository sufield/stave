package eval

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

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

	now := deps.Clock.Now().UTC()
	if req.Now != nil {
		now = req.Now.UTC()
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
