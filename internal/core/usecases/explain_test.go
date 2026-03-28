package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockExplainFinder struct {
	resp domain.ExplainResponse
	err  error
}

func (m *mockExplainFinder) ExplainControl(_ context.Context, _, _ string) (domain.ExplainResponse, error) {
	return m.resp, m.err
}

func TestExplain(t *testing.T) {
	sampleResp := domain.ExplainResponse{
		ControlID:     "CTL.S3.PUBLIC.001",
		Name:          "No Public Read",
		Type:          "unsafe_duration",
		MatchedFields: []string{"properties.storage.access.public_read"},
		Rules: []domain.ExplainRule{
			{Path: "properties.storage.access.public_read", Op: "eq", Value: true, From: "all[0]"},
		},
	}

	tests := []struct {
		name    string
		req     domain.ExplainRequest
		finder  *mockExplainFinder
		wantID  string
		wantErr bool
	}{
		{
			name:   "happy path",
			req:    domain.ExplainRequest{ControlID: "CTL.S3.PUBLIC.001", ControlsDir: "controls"},
			finder: &mockExplainFinder{resp: sampleResp},
			wantID: "CTL.S3.PUBLIC.001",
		},
		{
			name:    "empty control ID",
			req:     domain.ExplainRequest{ControlID: "", ControlsDir: "controls"},
			finder:  &mockExplainFinder{},
			wantErr: true,
		},
		{
			name:    "finder error",
			req:     domain.ExplainRequest{ControlID: "CTL.MISSING", ControlsDir: "controls"},
			finder:  &mockExplainFinder{err: errors.New("control not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := ExplainDeps{Finder: tc.finder}
			resp, err := Explain(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.ControlID != tc.wantID {
				t.Errorf("ControlID: got %q, want %q", resp.ControlID, tc.wantID)
			}
		})
	}
}

func TestExplain_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := ExplainDeps{Finder: &mockExplainFinder{}}
	_, err := Explain(ctx, domain.ExplainRequest{ControlID: "CTL.A", ControlsDir: "controls"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
