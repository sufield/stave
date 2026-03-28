package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockControlsLister struct {
	rows []domain.ControlRow
	err  error
}

func (m *mockControlsLister) ListControls(_ context.Context, _ string, _ bool, _ []string) ([]domain.ControlRow, error) {
	return m.rows, m.err
}

func TestControlsList(t *testing.T) {
	sampleRows := []domain.ControlRow{
		{ID: "CTL.S3.PUBLIC.001", Name: "No Public Read", Type: "unsafe_duration", Severity: "critical"},
		{ID: "CTL.S3.ENCRYPT.001", Name: "SSE Enabled", Type: "unsafe_state", Severity: "high"},
	}

	tests := []struct {
		name      string
		req       domain.ControlsListRequest
		lister    *mockControlsLister
		wantCount int
		wantErr   bool
	}{
		{
			name:      "list from directory",
			req:       domain.ControlsListRequest{ControlsDir: "controls"},
			lister:    &mockControlsLister{rows: sampleRows},
			wantCount: 2,
		},
		{
			name:      "list built-in",
			req:       domain.ControlsListRequest{BuiltIn: true},
			lister:    &mockControlsLister{rows: sampleRows},
			wantCount: 2,
		},
		{
			name:      "empty result",
			req:       domain.ControlsListRequest{ControlsDir: "empty"},
			lister:    &mockControlsLister{rows: nil},
			wantCount: 0,
		},
		{
			name:    "lister error",
			req:     domain.ControlsListRequest{ControlsDir: "missing"},
			lister:  &mockControlsLister{err: errors.New("directory not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := ControlsListDeps{Lister: tc.lister}
			resp, err := ControlsList(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.Controls) != tc.wantCount {
				t.Errorf("Controls count: got %d, want %d", len(resp.Controls), tc.wantCount)
			}
		})
	}
}

func TestControlsList_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := ControlsListDeps{Lister: &mockControlsLister{}}
	_, err := ControlsList(ctx, domain.ControlsListRequest{ControlsDir: "controls"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
