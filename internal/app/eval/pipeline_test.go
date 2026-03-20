package eval

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

func TestPipeline_ShortCircuitsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	called := false
	step := func(_ context.Context, _ *PipelineData) error {
		called = true
		return nil
	}

	err := NewPipeline(ctx, &PipelineData{}).
		Then(step).
		Error()

	if err == nil {
		t.Fatal("expected context.Canceled error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if called {
		t.Fatal("step should not have been called after context cancellation")
	}
}

func TestPipeline_ShortCircuitsOnPriorError(t *testing.T) {
	boom := errors.New("boom")
	called := false

	err := NewPipeline(context.Background(), &PipelineData{}).
		Then(func(_ context.Context, _ *PipelineData) error { return boom }).
		Then(func(_ context.Context, _ *PipelineData) error {
			called = true
			return nil
		}).
		Error()

	if !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
	if called {
		t.Fatal("second step should not run after first error")
	}
}

func TestWriteStep_RejectsEmptyBytes(t *testing.T) {
	data := &PipelineData{
		Bytes:  nil,
		Output: &bytes.Buffer{},
	}

	err := WriteStep()(context.Background(), data)
	if err == nil || !strings.Contains(err.Error(), "no bytes to write") {
		t.Fatalf("expected 'no bytes to write' error, got %v", err)
	}
}

func TestWriteStep_WritesBytes(t *testing.T) {
	var buf bytes.Buffer
	data := &PipelineData{
		Bytes:  []byte(`{"ok":true}`),
		Output: &buf,
	}

	err := WriteStep()(context.Background(), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != `{"ok":true}` {
		t.Fatalf("got %q, want %q", buf.String(), `{"ok":true}`)
	}
}

func TestMarshalStep_WrapsError(t *testing.T) {
	sentinel := errors.New("codec failure")
	m := &pipelineMarshalerStub{err: sentinel}
	data := &PipelineData{Enriched: appcontracts.EnrichedResult{}}

	err := MarshalStep(m)(context.Background(), data)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("errors.Is should find sentinel through wrapping, got %v", err)
	}
	if !strings.Contains(err.Error(), "marshal findings") {
		t.Fatalf("expected 'marshal findings' prefix, got %v", err)
	}
}

type pipelineMarshalerStub struct {
	err error
}

func (s *pipelineMarshalerStub) MarshalFindings(_ appcontracts.EnrichedResult) ([]byte, error) {
	return nil, s.err
}

func TestEnrichStep_SetsEnrichedResult(t *testing.T) {
	enrichFn := func(result evaluation.Result) appcontracts.EnrichedResult {
		return appcontracts.EnrichedResult{
			Result: result,
			Run:    result.Run,
		}
	}

	data := &PipelineData{
		Result: evaluation.Result{
			Run: evaluation.RunInfo{ToolVersion: "test"},
		},
	}

	err := EnrichStep(enrichFn)(context.Background(), data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Enriched.Run.ToolVersion != "test" {
		t.Fatalf("enriched run not set, got %v", data.Enriched.Run)
	}
}

func TestWithRecovery_CatchesPanic(t *testing.T) {
	panicking := func(_ context.Context, _ *PipelineData) error {
		panic("boom")
	}

	wrapped := WithRecovery("test-step", panicking)
	err := wrapped(context.Background(), &PipelineData{})

	if err == nil {
		t.Fatal("expected error from panic, got nil")
	}
	want := `panic in pipeline step "test-step": boom`
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestWithRecovery_PassesThroughNormalError(t *testing.T) {
	sentinel := errors.New("normal error")
	step := func(_ context.Context, _ *PipelineData) error {
		return sentinel
	}

	wrapped := WithRecovery("test-step", step)
	err := wrapped(context.Background(), &PipelineData{})

	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestWithRecovery_PassesThroughSuccess(t *testing.T) {
	step := func(_ context.Context, _ *PipelineData) error {
		return nil
	}

	wrapped := WithRecovery("test-step", step)
	err := wrapped(context.Background(), &PipelineData{})

	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestWithLogging_NilLoggerPassesThrough(t *testing.T) {
	called := false
	step := func(_ context.Context, _ *PipelineData) error {
		called = true
		return nil
	}

	wrapped := WithLogging(nil, "test-step", step)
	err := wrapped(context.Background(), &PipelineData{})

	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if !called {
		t.Error("expected step to be called")
	}
}

func TestWithLogging_PropagatesError(t *testing.T) {
	sentinel := errors.New("step failed")
	step := func(_ context.Context, _ *PipelineData) error {
		return sentinel
	}

	// WithLogging with nil logger returns the step unchanged.
	wrapped := WithLogging(nil, "test-step", step)
	err := wrapped(context.Background(), &PipelineData{})

	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}
