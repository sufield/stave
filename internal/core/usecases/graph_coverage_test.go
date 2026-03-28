package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockGraphCoverageComputer struct {
	data any
	err  error
}

func (m *mockGraphCoverageComputer) ComputeCoverage(_ context.Context, _, _ string) (any, error) {
	return m.data, m.err
}

func TestGraphCoverage(t *testing.T) {
	sampleGraph := map[string]any{"controls": 5, "assets": 10, "edges": 15}

	tests := []struct {
		name    string
		comp    *mockGraphCoverageComputer
		wantErr bool
	}{
		{
			name: "happy path",
			comp: &mockGraphCoverageComputer{data: sampleGraph},
		},
		{
			name:    "computer error",
			comp:    &mockGraphCoverageComputer{err: errors.New("no snapshots")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := GraphCoverageDeps{Computer: tc.comp}
			resp, err := GraphCoverage(context.Background(), domain.GraphCoverageRequest{
				ControlsDir:     "controls",
				ObservationsDir: "observations",
			}, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.GraphData == nil {
				t.Error("GraphData: got nil")
			}
		})
	}
}

func TestGraphCoverage_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := GraphCoverageDeps{Computer: &mockGraphCoverageComputer{}}
	_, err := GraphCoverage(ctx, domain.GraphCoverageRequest{
		ControlsDir:     "controls",
		ObservationsDir: "observations",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
