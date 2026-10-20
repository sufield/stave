package gate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

type mockFindingsCounter struct {
	count int
	err   error
}

func (m *mockFindingsCounter) CountFindings(_ context.Context, _ string) (int, error) {
	return m.count, m.err
}

type mockBaselineComparer struct {
	current, new int
	err          error
}

func (m *mockBaselineComparer) CompareAgainstBaseline(_ context.Context, _, _ string) (int, int, error) {
	return m.current, m.new, m.err
}

type mockOverdueCounter struct {
	count int
	err   error
}

func (m *mockOverdueCounter) CountOverdue(_ context.Context, _, _ string, _ time.Duration, _ time.Time) (int, error) {
	return m.count, m.err
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	clock := ports.FixedClock(now)

	t.Run("any pass", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_any_violation", EvaluationPath: "e.json"}, EvaluateDeps{FindingsCounter: &mockFindingsCounter{count: 0}, Clock: clock})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Passed {
			t.Error("expected pass")
		}
	})
	t.Run("any fail", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_any_violation", EvaluationPath: "e.json"}, EvaluateDeps{FindingsCounter: &mockFindingsCounter{count: 3}, Clock: clock})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Passed {
			t.Error("expected fail")
		}
	})
	t.Run("new pass", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_new_violation"}, EvaluateDeps{BaselineComparer: &mockBaselineComparer{current: 2, new: 0}, Clock: clock})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Passed {
			t.Error("expected pass")
		}
	})
	t.Run("overdue pass", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_overdue_upcoming"}, EvaluateDeps{OverdueCounter: &mockOverdueCounter{count: 0}, Clock: clock})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Passed {
			t.Error("expected pass")
		}
	})
	t.Run("bad policy", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{Policy: "unknown"}, EvaluateDeps{Clock: clock})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("any error", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_any_violation"}, EvaluateDeps{FindingsCounter: &mockFindingsCounter{err: errors.New("fail")}, Clock: clock})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("new error", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_new_violation"}, EvaluateDeps{BaselineComparer: &mockBaselineComparer{err: errors.New("fail")}, Clock: clock})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("overdue error", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_overdue_upcoming"}, EvaluateDeps{OverdueCounter: &mockOverdueCounter{err: errors.New("fail")}, Clock: clock})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("explicit now", func(t *testing.T) {
		explicit := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		resp, err := Evaluate(context.Background(), EvaluateRequest{Policy: "fail_on_any_violation", EvalTime: &explicit}, EvaluateDeps{FindingsCounter: &mockFindingsCounter{}, Clock: clock})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.CheckedAt.Equal(explicit) {
			t.Errorf("CheckedAt: got %v, want %v", resp.CheckedAt, explicit)
		}
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Evaluate(canceled(), EvaluateRequest{Policy: "fail_on_any_violation"}, EvaluateDeps{Clock: clock})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
	})
}

func TestPolicy_DomainMethods(t *testing.T) {
	pAny := PolicyAny
	if pAny.String() != "fail_on_any_violation" {
		t.Errorf("String() = %v, want fail_on_any_violation", pAny.String())
	}
	if !pAny.IsValid() {
		t.Error("PolicyAny.IsValid() = false, want true")
	}
	if !pAny.IsAny() {
		t.Error("PolicyAny.IsAny() = false, want true")
	}
	if pAny.IsNew() || pAny.IsOverdue() {
		t.Error("PolicyAny should only be IsAny")
	}

	pNew := PolicyNew
	if !pNew.IsValid() || !pNew.IsNew() {
		t.Error("PolicyNew.IsNew() = false, want true")
	}
	if pNew.IsAny() || pNew.IsOverdue() {
		t.Error("PolicyNew should only be IsNew")
	}

	pOverdue := PolicyOverdue
	if !pOverdue.IsValid() || !pOverdue.IsOverdue() {
		t.Error("PolicyOverdue.IsOverdue() = false, want true")
	}
	if pOverdue.IsAny() || pOverdue.IsNew() {
		t.Error("PolicyOverdue should only be IsOverdue")
	}

	invalid := Policy("unsupported_policy")
	if invalid.IsValid() {
		t.Error("invalid.IsValid() = true, want false")
	}
}

func TestEvaluateRequest_DomainMethods(t *testing.T) {
	now := time.Now()
	req := EvaluateRequest{
		EvaluationPath:    "eval.json",
		BaselinePath:      "base.json",
		ControlsDir:       "controls",
		ObservationsDir:   "obs",
		MaxUnsafeDuration: 24 * time.Hour,
		EvalTime:          &now,
	}

	if !req.HasEvaluationPath() {
		t.Error("HasEvaluationPath() = false, want true")
	}
	if !req.HasBaselinePath() {
		t.Error("HasBaselinePath() = false, want true")
	}
	if !req.HasControlsDir() {
		t.Error("HasControlsDir() = false, want true")
	}
	if !req.HasObservationsDir() {
		t.Error("HasObservationsDir() = false, want true")
	}
	if !req.HasMaxUnsafeDuration() {
		t.Error("HasMaxUnsafeDuration() = false, want true")
	}
	if !req.HasEvalTime() {
		t.Error("HasEvalTime() = false, want true")
	}

	empty := EvaluateRequest{}
	if empty.HasEvaluationPath() || empty.HasBaselinePath() || empty.HasControlsDir() ||
		empty.HasObservationsDir() || empty.HasMaxUnsafeDuration() || empty.HasEvalTime() {
		t.Error("empty request should return false for all Has* methods")
	}
}

func TestEvaluateResponse_DomainMethods(t *testing.T) {
	passingClean := EvaluateResponse{
		Policy:            PolicyAny,
		Passed:            true,
		CurrentViolations: 0,
		NewViolations:     0,
		OverdueUpcoming:   0,
	}

	if !passingClean.IsPassing() {
		t.Error("IsPassing() = false, want true")
	}
	if passingClean.IsFailing() {
		t.Error("IsFailing() = true, want false")
	}
	if !passingClean.IsClean() {
		t.Error("IsClean() = false, want true")
	}
	if passingClean.HasCurrentViolations() || passingClean.HasNewViolations() || passingClean.HasOverdueUpcoming() {
		t.Error("expected zero violations")
	}
	if passingClean.TotalBreaches() != 0 {
		t.Errorf("TotalBreaches() = %d, want 0", passingClean.TotalBreaches())
	}
	if passingClean.PassLabel() != "PASS" {
		t.Errorf("PassLabel() = %q, want PASS", passingClean.PassLabel())
	}

	failingAny := EvaluateResponse{
		Policy:            PolicyAny,
		Passed:            false,
		CurrentViolations: 4,
	}
	if !failingAny.IsFailing() || failingAny.IsPassing() {
		t.Error("failingAny IsFailing / IsPassing failed")
	}
	if !failingAny.HasCurrentViolations() {
		t.Error("HasCurrentViolations() = false, want true")
	}
	if failingAny.IsClean() {
		t.Error("IsClean() = true, want false")
	}
	if failingAny.TotalBreaches() != 4 {
		t.Errorf("TotalBreaches() = %d, want 4", failingAny.TotalBreaches())
	}
	if failingAny.PassLabel() != "FAIL" {
		t.Errorf("PassLabel() = %q, want FAIL", failingAny.PassLabel())
	}

	failingNew := EvaluateResponse{
		Policy:            PolicyNew,
		Passed:            false,
		CurrentViolations: 10,
		NewViolations:     2,
	}
	if !failingNew.HasNewViolations() {
		t.Error("HasNewViolations() = false, want true")
	}
	if failingNew.TotalBreaches() != 2 {
		t.Errorf("TotalBreaches() = %d, want 2 for PolicyNew", failingNew.TotalBreaches())
	}

	failingOverdue := EvaluateResponse{
		Policy:          PolicyOverdue,
		Passed:          false,
		OverdueUpcoming: 3,
	}
	if !failingOverdue.HasOverdueUpcoming() {
		t.Error("HasOverdueUpcoming() = false, want true")
	}
	if failingOverdue.TotalBreaches() != 3 {
		t.Errorf("TotalBreaches() = %d, want 3 for PolicyOverdue", failingOverdue.TotalBreaches())
	}
}

