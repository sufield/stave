package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockControlGenerator struct {
	outputPath string
	err        error
}

func (m *mockControlGenerator) GenerateControl(_ context.Context, _, _ string) (string, error) {
	return m.outputPath, m.err
}

func TestGenerateControl(t *testing.T) {
	tests := []struct {
		name     string
		req      domain.GenerateControlRequest
		gen      *mockControlGenerator
		wantPath string
		wantErr  bool
	}{
		{
			name:     "happy path",
			req:      domain.GenerateControlRequest{Name: "No Public Read"},
			gen:      &mockControlGenerator{outputPath: "controls/CTL.S3.PUBLIC.001.yaml"},
			wantPath: "controls/CTL.S3.PUBLIC.001.yaml",
		},
		{
			name:     "with custom out path",
			req:      domain.GenerateControlRequest{Name: "No Public Read", OutPath: "custom/ctl.yaml"},
			gen:      &mockControlGenerator{outputPath: "custom/ctl.yaml"},
			wantPath: "custom/ctl.yaml",
		},
		{
			name:    "empty name",
			req:     domain.GenerateControlRequest{Name: ""},
			gen:     &mockControlGenerator{},
			wantErr: true,
		},
		{
			name:    "generator error",
			req:     domain.GenerateControlRequest{Name: "Test"},
			gen:     &mockControlGenerator{err: errors.New("write failed")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := GenerateControlDeps{Generator: tc.gen}
			resp, err := GenerateControl(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.OutputPath != tc.wantPath {
				t.Errorf("OutputPath: got %q, want %q", resp.OutputPath, tc.wantPath)
			}
		})
	}
}

func TestGenerateControl_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := GenerateControlDeps{Generator: &mockControlGenerator{}}
	_, err := GenerateControl(ctx, domain.GenerateControlRequest{Name: "Test"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
