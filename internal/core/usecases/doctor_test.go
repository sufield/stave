package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockDoctorCheckRunner struct {
	checks    []domain.DoctorCheck
	allPassed bool
	err       error
}

func (m *mockDoctorCheckRunner) RunChecks(_ context.Context, _, _ string) ([]domain.DoctorCheck, bool, error) {
	return m.checks, m.allPassed, m.err
}

func TestDoctor(t *testing.T) {
	passChecks := []domain.DoctorCheck{
		{Name: "git", Status: "pass", Message: "/usr/bin/git"},
		{Name: "workspace-writable", Status: "pass", Message: "/home/user"},
	}
	warnChecks := []domain.DoctorCheck{
		{Name: "git", Status: "pass", Message: "/usr/bin/git"},
		{Name: "jq", Status: "warn", Message: "not found", Fix: "brew install jq"},
	}

	tests := []struct {
		name       string
		runner     *mockDoctorCheckRunner
		wantCount  int
		wantPassed bool
		wantErr    bool
	}{
		{
			name:       "all pass",
			runner:     &mockDoctorCheckRunner{checks: passChecks, allPassed: true},
			wantCount:  2,
			wantPassed: true,
		},
		{
			name:       "with warnings",
			runner:     &mockDoctorCheckRunner{checks: warnChecks, allPassed: true},
			wantCount:  2,
			wantPassed: true,
		},
		{
			name:       "with failure",
			runner:     &mockDoctorCheckRunner{checks: passChecks, allPassed: false},
			wantCount:  2,
			wantPassed: false,
		},
		{
			name:    "runner error",
			runner:  &mockDoctorCheckRunner{err: errors.New("system error")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := DoctorDeps{CheckRunner: tc.runner}
			resp, err := Doctor(context.Background(), domain.DoctorRequest{Cwd: "/tmp"}, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.Checks) != tc.wantCount {
				t.Errorf("Checks count: got %d, want %d", len(resp.Checks), tc.wantCount)
			}
			if resp.AllPassed != tc.wantPassed {
				t.Errorf("AllPassed: got %v, want %v", resp.AllPassed, tc.wantPassed)
			}
		})
	}
}

func TestDoctor_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := DoctorDeps{CheckRunner: &mockDoctorCheckRunner{}}
	_, err := Doctor(ctx, domain.DoctorRequest{Cwd: "/tmp"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
