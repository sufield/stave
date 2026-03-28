package usecases

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/domain"
)

type mockFindingsCounter struct {
	count int
	err   error
}

func (m *mockFindingsCounter) CountFindings(_ context.Context, _ string) (int, error) {
	return m.count, m.err
}

type mockBaselineComparer struct {
	currentCount int
	newCount     int
	err          error
}

func (m *mockBaselineComparer) CompareAgainstBaseline(_ context.Context, _, _ string) (int, int, error) {
	return m.currentCount, m.newCount, m.err
}

type mockOverdueCounter struct {
	count int
	err   error
}

func (m *mockOverdueCounter) CountOverdue(_ context.Context, _, _ string, _ time.Duration, _ time.Time) (int, error) {
	return m.count, m.err
}

func defaultGateDeps() GateDeps {
	return GateDeps{
		FindingsCounter:  &mockFindingsCounter{},
		BaselineComparer: &mockBaselineComparer{},
		OverdueCounter:   &mockOverdueCounter{},
		Clock:            fixedClock,
	}
}

func TestGate_PolicyAny(t *testing.T) {
	tests := []struct {
		name     string
		counter  *mockFindingsCounter
		wantPass bool
		wantErr  bool
	}{
		{
			name:     "no findings passes",
			counter:  &mockFindingsCounter{count: 0},
			wantPass: true,
		},
		{
			name:     "findings fails",
			counter:  &mockFindingsCounter{count: 3},
			wantPass: false,
		},
		{
			name:    "loader error",
			counter: &mockFindingsCounter{err: errors.New("not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := defaultGateDeps()
			deps.FindingsCounter = tc.counter

			resp, err := Gate(context.Background(), domain.GateRequest{
				Policy:         "fail_on_any_violation",
				EvaluationPath: "eval.json",
			}, deps)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Passed != tc.wantPass {
				t.Errorf("Passed: got %v, want %v", resp.Passed, tc.wantPass)
			}
			if resp.Policy != "fail_on_any_violation" {
				t.Errorf("Policy: got %q", resp.Policy)
			}
		})
	}
}

func TestGate_PolicyNew(t *testing.T) {
	tests := []struct {
		name     string
		comparer *mockBaselineComparer
		wantPass bool
		wantErr  bool
	}{
		{
			name:     "no new findings passes",
			comparer: &mockBaselineComparer{currentCount: 2, newCount: 0},
			wantPass: true,
		},
		{
			name:     "new findings fails",
			comparer: &mockBaselineComparer{currentCount: 3, newCount: 1},
			wantPass: false,
		},
		{
			name:     "comparer error",
			comparer: &mockBaselineComparer{err: errors.New("load failed")},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := defaultGateDeps()
			deps.BaselineComparer = tc.comparer

			resp, err := Gate(context.Background(), domain.GateRequest{
				Policy:         "fail_on_new_violation",
				EvaluationPath: "eval.json",
				BaselinePath:   "baseline.json",
			}, deps)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Passed != tc.wantPass {
				t.Errorf("Passed: got %v, want %v", resp.Passed, tc.wantPass)
			}
			if resp.EvaluationPath != "eval.json" {
				t.Errorf("EvaluationPath: got %q", resp.EvaluationPath)
			}
		})
	}
}

func TestGate_PolicyOverdue(t *testing.T) {
	tests := []struct {
		name     string
		counter  *mockOverdueCounter
		wantPass bool
		wantErr  bool
	}{
		{
			name:     "no overdue passes",
			counter:  &mockOverdueCounter{count: 0},
			wantPass: true,
		},
		{
			name:     "overdue fails",
			counter:  &mockOverdueCounter{count: 2},
			wantPass: false,
		},
		{
			name:    "counter error",
			counter: &mockOverdueCounter{err: errors.New("load failed")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := defaultGateDeps()
			deps.OverdueCounter = tc.counter

			resp, err := Gate(context.Background(), domain.GateRequest{
				Policy:            "fail_on_overdue_upcoming",
				ControlsDir:       "controls",
				ObservationsDir:   "observations",
				MaxUnsafeDuration: 24 * time.Hour,
			}, deps)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Passed != tc.wantPass {
				t.Errorf("Passed: got %v, want %v", resp.Passed, tc.wantPass)
			}
			if resp.ControlsPath != "controls" {
				t.Errorf("ControlsPath: got %q", resp.ControlsPath)
			}
		})
	}
}

func TestGate_UnsupportedPolicy(t *testing.T) {
	deps := defaultGateDeps()
	_, err := Gate(context.Background(), domain.GateRequest{
		Policy: "invalid_policy",
	}, deps)
	if err == nil {
		t.Fatal("expected error for unsupported policy")
	}
}

func TestGate_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := defaultGateDeps()
	_, err := Gate(ctx, domain.GateRequest{
		Policy:         "fail_on_any_violation",
		EvaluationPath: "eval.json",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
