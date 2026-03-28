package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockReportEvalLoader struct {
	data any
	err  error
}

func (m *mockReportEvalLoader) LoadEvaluation(_ context.Context, _ string) (any, error) {
	return m.data, m.err
}

func TestReport(t *testing.T) {
	sampleEval := map[string]any{"summary": map[string]any{"violations": 2}}

	tests := []struct {
		name    string
		req     domain.ReportRequest
		loader  *mockReportEvalLoader
		wantNil bool
		wantErr bool
	}{
		{
			name:   "happy path",
			req:    domain.ReportRequest{InputFile: "eval.json"},
			loader: &mockReportEvalLoader{data: sampleEval},
		},
		{
			name:    "loader error",
			req:     domain.ReportRequest{InputFile: "missing.json"},
			loader:  &mockReportEvalLoader{err: errors.New("not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := ReportDeps{Loader: tc.loader}
			resp, err := Report(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.EvaluationData == nil {
				t.Error("EvaluationData: got nil")
			}
		})
	}
}

func TestReport_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := ReportDeps{Loader: &mockReportEvalLoader{}}
	_, err := Report(ctx, domain.ReportRequest{InputFile: "eval.json"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
