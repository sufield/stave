package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

// Policy represents a CI gate failure policy rule.
type Policy string

const (
	PolicyAny     Policy = "fail_on_any_violation"
	PolicyNew     Policy = "fail_on_new_violation"
	PolicyOverdue Policy = "fail_on_overdue_upcoming"

	policyAny     = PolicyAny
	policyNew     = PolicyNew
	policyOverdue = PolicyOverdue
)

// String returns the raw string value of the policy.
func (p Policy) String() string {
	return string(p)
}

// IsValid reports whether the policy is a recognized gate policy.
func (p Policy) IsValid() bool {
	switch p {
	case PolicyAny, PolicyNew, PolicyOverdue:
		return true
	default:
		return false
	}
}

// IsAny reports whether the policy fails on any violation.
func (p Policy) IsAny() bool {
	return p == PolicyAny
}

// IsNew reports whether the policy fails on new violations compared to baseline.
func (p Policy) IsNew() bool {
	return p == PolicyNew
}

// IsOverdue reports whether the policy fails on overdue upcoming actions.
func (p Policy) IsOverdue() bool {
	return p == PolicyOverdue
}

// EvaluateRequest is the input for the CI gate evaluation.
type EvaluateRequest struct {
	Policy            Policy        `json:"policy"`
	EvaluationPath    string        `json:"evaluation_path,omitempty"`
	BaselinePath      string        `json:"baseline_path,omitempty"`
	ControlsDir       string        `json:"controls_dir,omitempty"`
	ObservationsDir   string        `json:"observations_dir,omitempty"`
	MaxUnsafeDuration time.Duration `json:"max_unsafe_duration,omitempty"`
	EvalTime          *time.Time    `json:"eval_time,omitempty"`
}

// HasEvaluationPath reports whether an evaluation path is specified.
func (r EvaluateRequest) HasEvaluationPath() bool {
	return r.EvaluationPath != ""
}

// HasBaselinePath reports whether a baseline path is specified.
func (r EvaluateRequest) HasBaselinePath() bool {
	return r.BaselinePath != ""
}

// HasControlsDir reports whether a controls directory is specified.
func (r EvaluateRequest) HasControlsDir() bool {
	return r.ControlsDir != ""
}

// HasObservationsDir reports whether an observations directory is specified.
func (r EvaluateRequest) HasObservationsDir() bool {
	return r.ObservationsDir != ""
}

// HasMaxUnsafeDuration reports whether a non-zero max unsafe duration is configured.
func (r EvaluateRequest) HasMaxUnsafeDuration() bool {
	return r.MaxUnsafeDuration > 0
}

// HasEvalTime reports whether an explicit evaluation time override is set.
func (r EvaluateRequest) HasEvalTime() bool {
	return r.EvalTime != nil && !r.EvalTime.IsZero()
}

// EvaluateResponse is the output of the CI gate evaluation.
type EvaluateResponse struct {
	Policy            Policy    `json:"policy"`
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

// IsPassing reports whether the gate evaluation passed policy.
func (r EvaluateResponse) IsPassing() bool {
	return r.Passed
}

// IsFailing reports whether the gate evaluation failed policy.
func (r EvaluateResponse) IsFailing() bool {
	return !r.Passed
}

// HasCurrentViolations reports whether any current violations were found.
func (r EvaluateResponse) HasCurrentViolations() bool {
	return r.CurrentViolations > 0
}

// HasNewViolations reports whether any new violations were introduced compared to baseline.
func (r EvaluateResponse) HasNewViolations() bool {
	return r.NewViolations > 0
}

// HasOverdueUpcoming reports whether any upcoming actions are overdue.
func (r EvaluateResponse) HasOverdueUpcoming() bool {
	return r.OverdueUpcoming > 0
}

// TotalBreaches returns the primary count of violations or overdue items driving the gate verdict.
func (r EvaluateResponse) TotalBreaches() int {
	switch r.Policy {
	case PolicyAny:
		return r.CurrentViolations
	case PolicyNew:
		return r.NewViolations
	case PolicyOverdue:
		return r.OverdueUpcoming
	default:
		return r.CurrentViolations + r.NewViolations + r.OverdueUpcoming
	}
}

// PassLabel returns "PASS" if the evaluation passed, or "FAIL" otherwise.
func (r EvaluateResponse) PassLabel() string {
	if r.Passed {
		return "PASS"
	}
	return "FAIL"
}

// IsClean reports whether the evaluation passed and has zero violations across all metrics.
func (r EvaluateResponse) IsClean() bool {
	return r.Passed && r.CurrentViolations == 0 && r.NewViolations == 0 && r.OverdueUpcoming == 0
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
