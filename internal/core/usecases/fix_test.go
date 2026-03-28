package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockFixFindingLoader struct {
	data any
	err  error
}

func (m *mockFixFindingLoader) LoadFindingWithPlan(_ context.Context, _, _ string) (any, error) {
	return m.data, m.err
}

func TestFix(t *testing.T) {
	sampleData := map[string]any{
		"control_id": "CTL.S3.PUBLIC.001",
		"asset_id":   "bucket-a",
		"fix_plan":   map[string]any{"id": "fix-abc123"},
	}

	tests := []struct {
		name    string
		req     domain.FixRequest
		loader  *mockFixFindingLoader
		wantNil bool
		wantErr bool
	}{
		{
			name: "happy path",
			req: domain.FixRequest{
				InputPath:  "eval.json",
				FindingRef: "CTL.S3.PUBLIC.001@bucket-a",
			},
			loader: &mockFixFindingLoader{data: sampleData},
		},
		{
			name: "empty finding ref",
			req: domain.FixRequest{
				InputPath:  "eval.json",
				FindingRef: "",
			},
			loader:  &mockFixFindingLoader{},
			wantErr: true,
		},
		{
			name: "loader error",
			req: domain.FixRequest{
				InputPath:  "eval.json",
				FindingRef: "CTL.MISSING@bucket-x",
			},
			loader:  &mockFixFindingLoader{err: errors.New("finding not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := FixDeps{Loader: tc.loader}
			resp, err := Fix(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Data == nil {
				t.Error("Data: got nil, want non-nil")
			}
		})
	}
}

func TestFix_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := FixDeps{Loader: &mockFixFindingLoader{}}
	_, err := Fix(ctx, domain.FixRequest{
		InputPath:  "eval.json",
		FindingRef: "CTL.A@res-1",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
