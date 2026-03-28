package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockLintRunner struct {
	diags      []domain.LintDiagnostic
	errorCount int
	err        error
}

func (m *mockLintRunner) LintPath(_ context.Context, _ string) ([]domain.LintDiagnostic, int, error) {
	return m.diags, m.errorCount, m.err
}

func TestLint(t *testing.T) {
	sampleDiags := []domain.LintDiagnostic{
		{Path: "ctl.yaml", Line: 10, Col: 5, RuleID: "CTL_ID_NAMESPACE", Message: "bad id", Severity: "error"},
		{Path: "ctl.yaml", Line: 15, Col: 3, RuleID: "CTL_ORDERING_HINT", Message: "unordered", Severity: "warn"},
	}

	tests := []struct {
		name           string
		req            domain.LintRequest
		runner         *mockLintRunner
		wantDiags      int
		wantErrorCount int
		wantErr        bool
	}{
		{
			name:           "clean lint",
			req:            domain.LintRequest{Target: "controls"},
			runner:         &mockLintRunner{diags: nil, errorCount: 0},
			wantDiags:      0,
			wantErrorCount: 0,
		},
		{
			name:           "with diagnostics",
			req:            domain.LintRequest{Target: "controls"},
			runner:         &mockLintRunner{diags: sampleDiags, errorCount: 1},
			wantDiags:      2,
			wantErrorCount: 1,
		},
		{
			name:    "empty target",
			req:     domain.LintRequest{Target: ""},
			runner:  &mockLintRunner{},
			wantErr: true,
		},
		{
			name:    "runner error",
			req:     domain.LintRequest{Target: "missing"},
			runner:  &mockLintRunner{err: errors.New("path not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := LintDeps{Runner: tc.runner}
			resp, err := Lint(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.Diagnostics) != tc.wantDiags {
				t.Errorf("Diagnostics count: got %d, want %d", len(resp.Diagnostics), tc.wantDiags)
			}
			if resp.ErrorCount != tc.wantErrorCount {
				t.Errorf("ErrorCount: got %d, want %d", resp.ErrorCount, tc.wantErrorCount)
			}
		})
	}
}

func TestLint_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := LintDeps{Runner: &mockLintRunner{}}
	_, err := Lint(ctx, domain.LintRequest{Target: "controls"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
