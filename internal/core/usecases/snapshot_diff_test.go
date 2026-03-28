package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockDeltaComputer struct {
	data any
	err  error
}

func (m *mockDeltaComputer) ComputeDelta(_ context.Context, _ string, _, _ []string, _ string) (any, error) {
	return m.data, m.err
}

func TestSnapshotDiff(t *testing.T) {
	sampleDelta := map[string]any{
		"from_captured": "2026-01-09T00:00:00Z",
		"to_captured":   "2026-01-10T00:00:00Z",
		"changes":       []any{"bucket-a added"},
	}

	tests := []struct {
		name    string
		req     domain.SnapshotDiffRequest
		comp    *mockDeltaComputer
		wantNil bool
		wantErr bool
	}{
		{
			name:    "happy path",
			req:     domain.SnapshotDiffRequest{ObservationsDir: "observations"},
			comp:    &mockDeltaComputer{data: sampleDelta},
			wantNil: false,
		},
		{
			name: "with filters",
			req: domain.SnapshotDiffRequest{
				ObservationsDir: "observations",
				ChangeTypes:     []string{"added"},
				AssetTypes:      []string{"aws_s3_bucket"},
				AssetID:         "bucket",
			},
			comp: &mockDeltaComputer{data: sampleDelta},
		},
		{
			name:    "computer error",
			req:     domain.SnapshotDiffRequest{ObservationsDir: "missing"},
			comp:    &mockDeltaComputer{err: errors.New("need at least 2 snapshots")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := SnapshotDiffDeps{DeltaComputer: tc.comp}
			resp, err := SnapshotDiff(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.DeltaData == nil {
				t.Error("DeltaData: got nil")
			}
		})
	}
}

func TestSnapshotDiff_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := SnapshotDiffDeps{DeltaComputer: &mockDeltaComputer{}}
	_, err := SnapshotDiff(ctx, domain.SnapshotDiffRequest{ObservationsDir: "obs"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
