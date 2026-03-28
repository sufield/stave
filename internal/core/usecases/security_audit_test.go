package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockSecurityAuditRunner struct {
	reportData any
	summary    domain.SecurityAuditSummary
	gated      bool
	err        error
}

func (m *mockSecurityAuditRunner) RunAudit(_ context.Context, _ domain.SecurityAuditRequest) (any, domain.SecurityAuditSummary, bool, error) {
	return m.reportData, m.summary, m.gated, m.err
}

func TestSecurityAudit(t *testing.T) {
	tests := []struct {
		name      string
		runner    *mockSecurityAuditRunner
		wantGated bool
		wantErr   bool
	}{
		{
			name: "audit passes",
			runner: &mockSecurityAuditRunner{
				reportData: map[string]any{"ok": true},
				summary:    domain.SecurityAuditSummary{Total: 5, Pass: 5, Threshold: "HIGH"},
				gated:      false,
			},
			wantGated: false,
		},
		{
			name: "audit gated",
			runner: &mockSecurityAuditRunner{
				reportData: map[string]any{"findings": 2},
				summary:    domain.SecurityAuditSummary{Total: 5, Pass: 3, Fail: 2, Threshold: "HIGH"},
				gated:      true,
			},
			wantGated: true,
		},
		{
			name:    "runner error",
			runner:  &mockSecurityAuditRunner{err: errors.New("govulncheck failed")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := SecurityAuditDeps{Runner: tc.runner}
			resp, err := SecurityAudit(context.Background(), domain.SecurityAuditRequest{
				Format: "json",
				FailOn: "HIGH",
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
			if resp.Gated != tc.wantGated {
				t.Errorf("Gated: got %v, want %v", resp.Gated, tc.wantGated)
			}
			if resp.ReportData == nil {
				t.Error("ReportData: got nil")
			}
		})
	}
}

func TestSecurityAudit_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := SecurityAuditDeps{Runner: &mockSecurityAuditRunner{}}
	_, err := SecurityAudit(ctx, domain.SecurityAuditRequest{}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
