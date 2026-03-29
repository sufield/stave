package eval

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

func TestOutputPipeline_Success(t *testing.T) {
	var buf bytes.Buffer

	p := &OutputPipeline{
		Marshaler: &outputMarshalerStub{data: []byte(`{"ok":true}`)},
		Enricher: func(r evaluation.Result) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{Result: r, Run: r.Run}, nil
		},
	}
	err := p.Run(context.Background(), &buf, evaluation.Result{Run: evaluation.RunInfo{StaveVersion: "test"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != `{"ok":true}` {
		t.Fatalf("got %q, want %q", buf.String(), `{"ok":true}`)
	}
}

func TestOutputPipeline_MarshalError(t *testing.T) {
	sentinel := errors.New("codec failure")

	p := &OutputPipeline{
		Marshaler: &outputMarshalerStub{err: sentinel},
		Enricher: func(r evaluation.Result) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{}, nil
		},
	}
	err := p.Run(context.Background(), &bytes.Buffer{}, evaluation.Result{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel through wrapping, got %v", err)
	}
	if !strings.Contains(err.Error(), "marshal") {
		t.Fatalf("expected 'marshal' in error, got %v", err)
	}
}

func TestOutputPipeline_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := &OutputPipeline{
		Marshaler: &outputMarshalerStub{data: []byte(`{}`)},
		Enricher: func(r evaluation.Result) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{}, nil
		},
	}
	err := p.Run(ctx, &bytes.Buffer{}, evaluation.Result{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestRunStep_PropagatesError(t *testing.T) {
	sentinel := errors.New("step failed")
	_, err := runStep[int](nil, "test", func() (int, error) {
		return 0, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

func TestRunStep_WithNilLogger(t *testing.T) {
	val, err := runStep(nil, "test", func() (string, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "ok" {
		t.Fatalf("got %q, want %q", val, "ok")
	}
}

func TestRunStep_WithLogger(t *testing.T) {
	logger := slog.Default()
	val, err := runStep(logger, "test", func() (int, error) {
		return 42, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 42 {
		t.Fatalf("got %d, want 42", val)
	}
}

type outputMarshalerStub struct {
	data []byte
	err  error
}

func (s *outputMarshalerStub) MarshalFindings(_ appcontracts.EnrichedResult) ([]byte, error) {
	return s.data, s.err
}
