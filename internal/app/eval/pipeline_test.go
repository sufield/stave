package eval

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

func TestRunOutputPipeline_Success(t *testing.T) {
	var buf bytes.Buffer

	err := RunOutputPipeline(
		context.Background(),
		&buf,
		evaluation.Result{Run: evaluation.RunInfo{StaveVersion: "test"}},
		&outputMarshalerStub{data: []byte(`{"ok":true}`)},
		func(r evaluation.Result) appcontracts.EnrichedResult {
			return appcontracts.EnrichedResult{Result: r, Run: r.Run}
		},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != `{"ok":true}` {
		t.Fatalf("got %q, want %q", buf.String(), `{"ok":true}`)
	}
}

func TestRunOutputPipeline_MarshalError(t *testing.T) {
	sentinel := errors.New("codec failure")

	err := RunOutputPipeline(
		context.Background(),
		&bytes.Buffer{},
		evaluation.Result{},
		&outputMarshalerStub{err: sentinel},
		func(r evaluation.Result) appcontracts.EnrichedResult {
			return appcontracts.EnrichedResult{}
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel through wrapping, got %v", err)
	}
	if !strings.Contains(err.Error(), "marshal findings") {
		t.Fatalf("expected 'marshal findings' in error, got %v", err)
	}
}

func TestRunOutputPipeline_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := RunOutputPipeline(
		ctx,
		&bytes.Buffer{},
		evaluation.Result{},
		&outputMarshalerStub{data: []byte(`{}`)},
		func(r evaluation.Result) appcontracts.EnrichedResult {
			return appcontracts.EnrichedResult{}
		},
		nil,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestRunStep_CatchesPanic(t *testing.T) {
	_, err := runStep[int](nil, "boom", func() (int, error) {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected error from panic")
	}
	if !strings.Contains(err.Error(), `panic in step "boom"`) {
		t.Fatalf("got %q", err.Error())
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
