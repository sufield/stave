package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockUpcomingComputer struct {
	data any
	err  error
}

func (m *mockUpcomingComputer) ComputeUpcoming(_ context.Context, _ domain.SnapshotUpcomingRequest) (any, error) {
	return m.data, m.err
}

func TestSnapshotUpcoming(t *testing.T) {
	tests := []struct {
		name    string
		comp    *mockUpcomingComputer
		wantErr bool
	}{
		{
			name: "happy path",
			comp: &mockUpcomingComputer{data: map[string]any{"items": 3}},
		},
		{
			name:    "computer error",
			comp:    &mockUpcomingComputer{err: errors.New("no snapshots")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := SnapshotUpcomingDeps{Computer: tc.comp}
			resp, err := SnapshotUpcoming(context.Background(), domain.SnapshotUpcomingRequest{
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
			if resp.ItemsData == nil {
				t.Error("ItemsData: got nil")
			}
		})
	}
}

func TestSnapshotUpcoming_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := SnapshotUpcomingDeps{Computer: &mockUpcomingComputer{}}
	_, err := SnapshotUpcoming(ctx, domain.SnapshotUpcomingRequest{
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
