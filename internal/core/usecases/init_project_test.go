package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockProjectScaffolder struct {
	resp domain.InitProjectResponse
	err  error
}

func (m *mockProjectScaffolder) ScaffoldProject(_ context.Context, _ domain.InitProjectRequest) (domain.InitProjectResponse, error) {
	return m.resp, m.err
}

func TestInitProject(t *testing.T) {
	tests := []struct {
		name    string
		req     domain.InitProjectRequest
		scaff   *mockProjectScaffolder
		wantErr bool
	}{
		{
			name: "happy path",
			req:  domain.InitProjectRequest{Dir: "/tmp/proj", CaptureCadence: "daily"},
			scaff: &mockProjectScaffolder{resp: domain.InitProjectResponse{
				BaseDir: "/tmp/proj",
				Dirs:    []string{"controls", "observations"},
				Created: []string{"stave.yaml"},
			}},
		},
		{
			name: "with aws-s3 profile",
			req:  domain.InitProjectRequest{Dir: "/tmp/proj", Profile: "aws-s3", CaptureCadence: "daily"},
			scaff: &mockProjectScaffolder{resp: domain.InitProjectResponse{
				BaseDir: "/tmp/proj",
				Created: []string{"stave.yaml", "controls/s3.yaml"},
			}},
		},
		{
			name: "dry run",
			req:  domain.InitProjectRequest{Dir: "/tmp/proj", DryRun: true, CaptureCadence: "daily"},
			scaff: &mockProjectScaffolder{resp: domain.InitProjectResponse{
				BaseDir: "/tmp/proj",
				DryRun:  true,
			}},
		},
		{
			name: "hourly cadence",
			req:  domain.InitProjectRequest{Dir: "/tmp/proj", CaptureCadence: "hourly"},
			scaff: &mockProjectScaffolder{resp: domain.InitProjectResponse{
				BaseDir: "/tmp/proj",
			}},
		},
		{
			name: "empty cadence allowed",
			req:  domain.InitProjectRequest{Dir: "/tmp/proj"},
			scaff: &mockProjectScaffolder{resp: domain.InitProjectResponse{
				BaseDir: "/tmp/proj",
			}},
		},
		{
			name:    "empty dir",
			req:     domain.InitProjectRequest{Dir: ""},
			scaff:   &mockProjectScaffolder{},
			wantErr: true,
		},
		{
			name:    "unsupported profile",
			req:     domain.InitProjectRequest{Dir: "/tmp/proj", Profile: "gcp-gcs"},
			scaff:   &mockProjectScaffolder{},
			wantErr: true,
		},
		{
			name:    "unsupported cadence",
			req:     domain.InitProjectRequest{Dir: "/tmp/proj", CaptureCadence: "weekly"},
			scaff:   &mockProjectScaffolder{},
			wantErr: true,
		},
		{
			name:    "scaffolder error",
			req:     domain.InitProjectRequest{Dir: "/tmp/proj", CaptureCadence: "daily"},
			scaff:   &mockProjectScaffolder{err: errors.New("permission denied")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := InitProjectDeps{Scaffolder: tc.scaff}
			resp, err := InitProject(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.BaseDir != tc.scaff.resp.BaseDir {
				t.Errorf("BaseDir: got %q, want %q", resp.BaseDir, tc.scaff.resp.BaseDir)
			}
		})
	}
}

func TestInitProject_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := InitProjectDeps{Scaffolder: &mockProjectScaffolder{}}
	_, err := InitProject(ctx, domain.InitProjectRequest{Dir: "/tmp/proj"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
