package eval

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

// --- Mocks ---

type mockEvalRunner struct {
	resp ApplyResponse
	err  error
}

func (m *mockEvalRunner) RunEvaluation(_ context.Context, _ ApplyRequest) (ApplyResponse, error) {
	return m.resp, m.err
}

type mockFindingLoader struct {
	data any
	err  error
}

func (m *mockFindingLoader) LoadFindingWithPlan(_ context.Context, _, _ string) (any, error) {
	return m.data, m.err
}

type mockFixLoopRunner struct {
	resp FixLoopResponse
	err  error
}

func (m *mockFixLoopRunner) RunFixLoop(_ context.Context, _ FixLoopRequest) (FixLoopResponse, error) {
	return m.resp, m.err
}

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

type mockTraceEvaluator struct {
	data any
	err  error
}

func (m *mockTraceEvaluator) TraceEvaluation(_ context.Context, _, _, _, _ string) (any, error) {
	return m.data, m.err
}

type mockVerifyRunner struct {
	resp VerifyResponse
	err  error
}

func (m *mockVerifyRunner) RunVerification(_ context.Context, _ Request) (VerifyResponse, error) {
	return m.resp, m.err
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// --- Apply ---

func TestApply(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Apply(context.Background(), ApplyRequest{}, ApplyDeps{Runner: &mockEvalRunner{resp: ApplyResponse{}}})
		assertNoErr(t, err)
	})
	t.Run("profile without input", func(t *testing.T) {
		_, err := Apply(context.Background(), ApplyRequest{Profile: "aws-s3"}, ApplyDeps{Runner: &mockEvalRunner{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Apply(context.Background(), ApplyRequest{}, ApplyDeps{Runner: &mockEvalRunner{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Apply(canceled(), ApplyRequest{}, ApplyDeps{Runner: &mockEvalRunner{}})
		assertCanceled(t, err)
	})
}

// --- Fix ---

func TestFix(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Fix(context.Background(), FixRequest{InputPath: "e.json", FindingRef: "CTL.A@b"}, FixDeps{Loader: &mockFindingLoader{data: "ok"}})
		assertNoErr(t, err)
	})
	t.Run("empty ref", func(t *testing.T) {
		_, err := Fix(context.Background(), FixRequest{InputPath: "e.json"}, FixDeps{Loader: &mockFindingLoader{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Fix(context.Background(), FixRequest{FindingRef: "x"}, FixDeps{Loader: &mockFindingLoader{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Fix(canceled(), FixRequest{FindingRef: "x"}, FixDeps{Loader: &mockFindingLoader{}})
		assertCanceled(t, err)
	})
}

// --- FixLoop ---

func TestFixLoop(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := FixLoop(context.Background(), FixLoopRequest{BeforeDir: "a", AfterDir: "b"}, LoopDeps{Runner: &mockFixLoopRunner{}})
		assertNoErr(t, err)
	})
	t.Run("empty before", func(t *testing.T) {
		_, err := FixLoop(context.Background(), FixLoopRequest{AfterDir: "b"}, LoopDeps{Runner: &mockFixLoopRunner{}})
		assertErr(t, err)
	})
	t.Run("empty after", func(t *testing.T) {
		_, err := FixLoop(context.Background(), FixLoopRequest{BeforeDir: "a"}, LoopDeps{Runner: &mockFixLoopRunner{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := FixLoop(context.Background(), FixLoopRequest{BeforeDir: "a", AfterDir: "b"}, LoopDeps{Runner: &mockFixLoopRunner{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := FixLoop(canceled(), FixLoopRequest{BeforeDir: "a", AfterDir: "b"}, LoopDeps{Runner: &mockFixLoopRunner{}})
		assertCanceled(t, err)
	})
}

// --- Gate ---

func TestGate(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	clock := ports.FixedClock(now)

	t.Run("any pass", func(t *testing.T) {
		resp, err := Gate(context.Background(), GateRequest{Policy: "fail_on_any_violation", EvaluationPath: "e.json"}, GateDeps{FindingsCounter: &mockFindingsCounter{count: 0}, Clock: clock})
		assertNoErr(t, err)
		if !resp.Passed {
			t.Error("expected pass")
		}
	})
	t.Run("any fail", func(t *testing.T) {
		resp, err := Gate(context.Background(), GateRequest{Policy: "fail_on_any_violation", EvaluationPath: "e.json"}, GateDeps{FindingsCounter: &mockFindingsCounter{count: 3}, Clock: clock})
		assertNoErr(t, err)
		if resp.Passed {
			t.Error("expected fail")
		}
	})
	t.Run("new pass", func(t *testing.T) {
		resp, err := Gate(context.Background(), GateRequest{Policy: "fail_on_new_violation"}, GateDeps{BaselineComparer: &mockBaselineComparer{current: 2, new: 0}, Clock: clock})
		assertNoErr(t, err)
		if !resp.Passed {
			t.Error("expected pass")
		}
	})
	t.Run("overdue pass", func(t *testing.T) {
		resp, err := Gate(context.Background(), GateRequest{Policy: "fail_on_overdue_upcoming"}, GateDeps{OverdueCounter: &mockOverdueCounter{count: 0}, Clock: clock})
		assertNoErr(t, err)
		if !resp.Passed {
			t.Error("expected pass")
		}
	})
	t.Run("bad policy", func(t *testing.T) {
		_, err := Gate(context.Background(), GateRequest{Policy: "unknown"}, GateDeps{Clock: clock})
		assertErr(t, err)
	})
	t.Run("any error", func(t *testing.T) {
		_, err := Gate(context.Background(), GateRequest{Policy: "fail_on_any_violation"}, GateDeps{FindingsCounter: &mockFindingsCounter{err: errors.New("fail")}, Clock: clock})
		assertErr(t, err)
	})
	t.Run("new error", func(t *testing.T) {
		_, err := Gate(context.Background(), GateRequest{Policy: "fail_on_new_violation"}, GateDeps{BaselineComparer: &mockBaselineComparer{err: errors.New("fail")}, Clock: clock})
		assertErr(t, err)
	})
	t.Run("overdue error", func(t *testing.T) {
		_, err := Gate(context.Background(), GateRequest{Policy: "fail_on_overdue_upcoming"}, GateDeps{OverdueCounter: &mockOverdueCounter{err: errors.New("fail")}, Clock: clock})
		assertErr(t, err)
	})
	t.Run("explicit now", func(t *testing.T) {
		explicit := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		resp, err := Gate(context.Background(), GateRequest{Policy: "fail_on_any_violation", Now: &explicit}, GateDeps{FindingsCounter: &mockFindingsCounter{}, Clock: clock})
		assertNoErr(t, err)
		if !resp.CheckedAt.Equal(explicit) {
			t.Errorf("CheckedAt: got %v, want %v", resp.CheckedAt, explicit)
		}
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Gate(canceled(), GateRequest{Policy: "fail_on_any_violation"}, GateDeps{Clock: clock})
		assertCanceled(t, err)
	})
}

// --- Trace ---

func TestTrace(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := Trace(context.Background(), TraceRequest{ControlID: "CTL.A", AssetID: "b"}, TraceDeps{Evaluator: &mockTraceEvaluator{data: "ok"}})
		assertNoErr(t, err)
		if resp.TraceData == nil {
			t.Error("TraceData: got nil")
		}
	})
	t.Run("empty control", func(t *testing.T) {
		_, err := Trace(context.Background(), TraceRequest{AssetID: "b"}, TraceDeps{Evaluator: &mockTraceEvaluator{}})
		assertErr(t, err)
	})
	t.Run("empty asset", func(t *testing.T) {
		_, err := Trace(context.Background(), TraceRequest{ControlID: "CTL.A"}, TraceDeps{Evaluator: &mockTraceEvaluator{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Trace(context.Background(), TraceRequest{ControlID: "CTL.A", AssetID: "b"}, TraceDeps{Evaluator: &mockTraceEvaluator{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Trace(canceled(), TraceRequest{ControlID: "CTL.A", AssetID: "b"}, TraceDeps{Evaluator: &mockTraceEvaluator{}})
		assertCanceled(t, err)
	})
}

// --- Verify ---

func TestVerify(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Verify(context.Background(), Request{BeforeDir: "a", AfterDir: "b"}, VerifyDeps{Runner: &mockVerifyRunner{}})
		assertNoErr(t, err)
	})
	t.Run("empty before", func(t *testing.T) {
		_, err := Verify(context.Background(), Request{AfterDir: "b"}, VerifyDeps{Runner: &mockVerifyRunner{}})
		assertErr(t, err)
	})
	t.Run("empty after", func(t *testing.T) {
		_, err := Verify(context.Background(), Request{BeforeDir: "a"}, VerifyDeps{Runner: &mockVerifyRunner{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Verify(context.Background(), Request{BeforeDir: "a", AfterDir: "b"}, VerifyDeps{Runner: &mockVerifyRunner{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Verify(canceled(), Request{BeforeDir: "a", AfterDir: "b"}, VerifyDeps{Runner: &mockVerifyRunner{}})
		assertCanceled(t, err)
	})
}

// --- Helpers ---

func assertNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func assertCanceled(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
