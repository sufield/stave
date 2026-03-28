package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockStatusScanner struct {
	stateData   any
	nextCommand string
	err         error
}

func (m *mockStatusScanner) ScanProject(_ context.Context, _ string) (any, string, error) {
	return m.stateData, m.nextCommand, m.err
}

func TestStatus(t *testing.T) {
	tests := []struct {
		name        string
		scanner     *mockStatusScanner
		wantNextCmd string
		wantErr     bool
	}{
		{
			name:        "project found",
			scanner:     &mockStatusScanner{stateData: map[string]any{"ok": true}, nextCommand: "stave apply"},
			wantNextCmd: "stave apply",
		},
		{
			name:        "no project",
			scanner:     &mockStatusScanner{stateData: map[string]any{}, nextCommand: "stave init"},
			wantNextCmd: "stave init",
		},
		{
			name:    "scanner error",
			scanner: &mockStatusScanner{err: errors.New("cannot detect root")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := StatusDeps{Scanner: tc.scanner}
			resp, err := Status(context.Background(), domain.StatusRequest{Dir: "."}, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.NextCommand != tc.wantNextCmd {
				t.Errorf("NextCommand: got %q, want %q", resp.NextCommand, tc.wantNextCmd)
			}
			if resp.StateData == nil {
				t.Error("StateData: got nil")
			}
		})
	}
}

func TestStatus_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := StatusDeps{Scanner: &mockStatusScanner{}}
	_, err := Status(ctx, domain.StatusRequest{Dir: "."}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
