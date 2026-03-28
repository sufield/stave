package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockBundleGenerator struct {
	bundlePath string
	warnings   []string
	err        error
}

func (m *mockBundleGenerator) GenerateBundle(_ context.Context, _ string, _ int, _ bool) (string, []string, error) {
	return m.bundlePath, m.warnings, m.err
}

func TestBugReport(t *testing.T) {
	tests := []struct {
		name    string
		req     domain.BugReportRequest
		gen     *mockBundleGenerator
		wantErr bool
	}{
		{
			name: "happy path",
			req:  domain.BugReportRequest{TailLines: 1000, IncludeConfig: true},
			gen:  &mockBundleGenerator{bundlePath: "/tmp/stave-diag.zip"},
		},
		{
			name: "with custom out path",
			req:  domain.BugReportRequest{OutPath: "/tmp/custom.zip", TailLines: 500},
			gen:  &mockBundleGenerator{bundlePath: "/tmp/custom.zip"},
		},
		{
			name: "with warnings",
			req:  domain.BugReportRequest{TailLines: 100, IncludeConfig: true},
			gen:  &mockBundleGenerator{bundlePath: "/tmp/diag.zip", warnings: []string{"skipped config"}},
		},
		{
			name:    "negative tail lines",
			req:     domain.BugReportRequest{TailLines: -1},
			gen:     &mockBundleGenerator{},
			wantErr: true,
		},
		{
			name:    "generator error",
			req:     domain.BugReportRequest{TailLines: 1000},
			gen:     &mockBundleGenerator{err: errors.New("write failed")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := BugReportDeps{Generator: tc.gen}
			resp, err := BugReport(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.BundlePath != tc.gen.bundlePath {
				t.Errorf("BundlePath: got %q, want %q", resp.BundlePath, tc.gen.bundlePath)
			}
		})
	}
}

func TestBugReport_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := BugReportDeps{Generator: &mockBundleGenerator{}}
	_, err := BugReport(ctx, domain.BugReportRequest{TailLines: 1000}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
