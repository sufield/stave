package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockFmtRunner struct {
	processed int
	changed   int
	err       error
}

func (m *mockFmtRunner) FormatPath(_ context.Context, _ string, _ bool) (int, int, error) {
	return m.processed, m.changed, m.err
}

func TestFmt(t *testing.T) {
	tests := []struct {
		name          string
		req           domain.FmtRequest
		runner        *mockFmtRunner
		wantProcessed int
		wantChanged   int
		wantErr       bool
	}{
		{
			name:          "format in place",
			req:           domain.FmtRequest{Target: "controls"},
			runner:        &mockFmtRunner{processed: 10, changed: 3},
			wantProcessed: 10,
			wantChanged:   3,
		},
		{
			name:          "check only",
			req:           domain.FmtRequest{Target: "controls", CheckOnly: true},
			runner:        &mockFmtRunner{processed: 10, changed: 0},
			wantProcessed: 10,
			wantChanged:   0,
		},
		{
			name:    "empty target",
			req:     domain.FmtRequest{Target: ""},
			runner:  &mockFmtRunner{},
			wantErr: true,
		},
		{
			name:    "runner error",
			req:     domain.FmtRequest{Target: "missing"},
			runner:  &mockFmtRunner{err: errors.New("path not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := FmtDeps{Runner: tc.runner}
			resp, err := Fmt(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.FilesProcessed != tc.wantProcessed {
				t.Errorf("FilesProcessed: got %d, want %d", resp.FilesProcessed, tc.wantProcessed)
			}
			if resp.FilesChanged != tc.wantChanged {
				t.Errorf("FilesChanged: got %d, want %d", resp.FilesChanged, tc.wantChanged)
			}
		})
	}
}

func TestFmt_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := FmtDeps{Runner: &mockFmtRunner{}}
	_, err := Fmt(ctx, domain.FmtRequest{Target: "controls"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
