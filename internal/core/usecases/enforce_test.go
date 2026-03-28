package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockEnforceGenerator struct {
	outputFile string
	targets    []string
	err        error
}

func (m *mockEnforceGenerator) GenerateTemplate(_ context.Context, _, _, _ string, _ bool) (string, []string, error) {
	return m.outputFile, m.targets, m.err
}

func TestEnforce(t *testing.T) {
	tests := []struct {
		name        string
		req         domain.EnforceRequest
		gen         *mockEnforceGenerator
		wantFile    string
		wantTargets int
		wantDryRun  bool
		wantErr     bool
	}{
		{
			name:        "pab mode",
			req:         domain.EnforceRequest{InputPath: "eval.json", OutDir: "output", Mode: "pab"},
			gen:         &mockEnforceGenerator{outputFile: "output/enforcement/aws/pab.tf", targets: []string{"bucket-a", "bucket-b"}},
			wantFile:    "output/enforcement/aws/pab.tf",
			wantTargets: 2,
		},
		{
			name:        "dry run",
			req:         domain.EnforceRequest{InputPath: "eval.json", Mode: "scp", DryRun: true},
			gen:         &mockEnforceGenerator{outputFile: "output/enforcement/aws/scp.json", targets: []string{"bucket-a"}},
			wantFile:    "output/enforcement/aws/scp.json",
			wantTargets: 1,
			wantDryRun:  true,
		},
		{
			name:    "generator error",
			req:     domain.EnforceRequest{InputPath: "missing.json", Mode: "pab"},
			gen:     &mockEnforceGenerator{err: errors.New("input not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := EnforceDeps{Generator: tc.gen}
			resp, err := Enforce(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.OutputFile != tc.wantFile {
				t.Errorf("OutputFile: got %q, want %q", resp.OutputFile, tc.wantFile)
			}
			if len(resp.Targets) != tc.wantTargets {
				t.Errorf("Targets count: got %d, want %d", len(resp.Targets), tc.wantTargets)
			}
			if resp.DryRun != tc.wantDryRun {
				t.Errorf("DryRun: got %v, want %v", resp.DryRun, tc.wantDryRun)
			}
		})
	}
}

func TestEnforce_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := EnforceDeps{Generator: &mockEnforceGenerator{}}
	_, err := Enforce(ctx, domain.EnforceRequest{InputPath: "eval.json", Mode: "pab"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
