package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockTraceEvaluator struct {
	data any
	err  error
}

func (m *mockTraceEvaluator) TraceEvaluation(_ context.Context, _, _, _, _ string) (any, error) {
	return m.data, m.err
}

func TestTrace(t *testing.T) {
	sampleTrace := map[string]any{"clauses": 3, "result": "UNSAFE"}

	tests := []struct {
		name    string
		req     domain.TraceRequest
		eval    *mockTraceEvaluator
		wantErr bool
	}{
		{
			name: "happy path",
			req:  domain.TraceRequest{ControlID: "CTL.A", ObservationPath: "obs.json", AssetID: "bucket-a"},
			eval: &mockTraceEvaluator{data: sampleTrace},
		},
		{
			name:    "empty control ID",
			req:     domain.TraceRequest{ControlID: "", ObservationPath: "obs.json", AssetID: "bucket-a"},
			eval:    &mockTraceEvaluator{},
			wantErr: true,
		},
		{
			name:    "empty asset ID",
			req:     domain.TraceRequest{ControlID: "CTL.A", ObservationPath: "obs.json", AssetID: ""},
			eval:    &mockTraceEvaluator{},
			wantErr: true,
		},
		{
			name:    "evaluator error",
			req:     domain.TraceRequest{ControlID: "CTL.A", ObservationPath: "obs.json", AssetID: "bucket-a"},
			eval:    &mockTraceEvaluator{err: errors.New("control not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := TraceDeps{Evaluator: tc.eval}
			resp, err := Trace(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.TraceData == nil {
				t.Error("TraceData: got nil")
			}
		})
	}
}

func TestTrace_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := TraceDeps{Evaluator: &mockTraceEvaluator{}}
	_, err := Trace(ctx, domain.TraceRequest{ControlID: "CTL.A", AssetID: "bucket-a"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
