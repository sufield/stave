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
