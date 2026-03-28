package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

func TestCIDiff(t *testing.T) {
	baseline := []domain.BaselineFinding{
		{ControlID: "CTL.A", ControlName: "A", AssetID: "res-1", AssetType: "bucket"},
		{ControlID: "CTL.B", ControlName: "B", AssetID: "res-2", AssetType: "bucket"},
	}
	current := []domain.BaselineFinding{
		{ControlID: "CTL.B", ControlName: "B", AssetID: "res-2", AssetType: "bucket"},
		{ControlID: "CTL.C", ControlName: "C", AssetID: "res-3", AssetType: "bucket"},
	}

	tests := []struct {
		name         string
		req          domain.CIDiffRequest
		curLoader    *mockEvalLoader
		baseLoader   *mockEvalLoader
		wantNew      int
		wantResolved int
		wantHasNew   bool
		wantErr      bool
	}{
		{
			name: "new and resolved",
			req: domain.CIDiffRequest{
				CurrentPath:  "current.json",
				BaselinePath: "baseline.json",
				FailOnNew:    true,
			},
			curLoader:    &mockEvalLoader{findings: current},
			baseLoader:   &mockEvalLoader{findings: baseline},
			wantNew:      1,
			wantResolved: 1,
			wantHasNew:   true,
		},
		{
			name: "no changes",
			req: domain.CIDiffRequest{
				CurrentPath:  "current.json",
				BaselinePath: "baseline.json",
			},
			curLoader:    &mockEvalLoader{findings: baseline},
			baseLoader:   &mockEvalLoader{findings: baseline},
			wantNew:      0,
			wantResolved: 0,
			wantHasNew:   false,
		},
		{
			name: "all new",
			req: domain.CIDiffRequest{
				CurrentPath:  "current.json",
				BaselinePath: "baseline.json",
			},
			curLoader:    &mockEvalLoader{findings: current},
			baseLoader:   &mockEvalLoader{findings: nil},
			wantNew:      2,
			wantResolved: 0,
			wantHasNew:   true,
		},
		{
			name: "all resolved",
			req: domain.CIDiffRequest{
				CurrentPath:  "current.json",
				BaselinePath: "baseline.json",
			},
			curLoader:    &mockEvalLoader{findings: nil},
			baseLoader:   &mockEvalLoader{findings: baseline},
			wantNew:      0,
			wantResolved: 2,
			wantHasNew:   false,
		},
		{
			name: "current loader error",
			req: domain.CIDiffRequest{
				CurrentPath:  "missing.json",
				BaselinePath: "baseline.json",
			},
			curLoader:  &mockEvalLoader{err: errors.New("not found")},
			baseLoader: &mockEvalLoader{findings: baseline},
			wantErr:    true,
		},
		{
			name: "baseline loader error",
			req: domain.CIDiffRequest{
				CurrentPath:  "current.json",
				BaselinePath: "missing.json",
			},
			curLoader:  &mockEvalLoader{findings: current},
			baseLoader: &mockEvalLoader{err: errors.New("not found")},
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := CIDiffDeps{
				CurrentLoader:  tc.curLoader,
				BaselineLoader: tc.baseLoader,
				Clock:          fixedClock,
			}
			resp, err := CIDiff(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.NewFindings) != tc.wantNew {
				t.Errorf("NewFindings: got %d, want %d", len(resp.NewFindings), tc.wantNew)
			}
			if len(resp.ResolvedFindings) != tc.wantResolved {
				t.Errorf("ResolvedFindings: got %d, want %d", len(resp.ResolvedFindings), tc.wantResolved)
			}
			if resp.HasNew != tc.wantHasNew {
				t.Errorf("HasNew: got %v, want %v", resp.HasNew, tc.wantHasNew)
			}
			if resp.Summary.NewFindings != tc.wantNew {
				t.Errorf("Summary.NewFindings: got %d, want %d", resp.Summary.NewFindings, tc.wantNew)
			}
			if resp.CurrentEvaluation != tc.req.CurrentPath {
				t.Errorf("CurrentEvaluation: got %q, want %q", resp.CurrentEvaluation, tc.req.CurrentPath)
			}
			if resp.BaselineEvaluation != tc.req.BaselinePath {
				t.Errorf("BaselineEvaluation: got %q, want %q", resp.BaselineEvaluation, tc.req.BaselinePath)
			}
		})
	}
}

func TestCIDiff_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := CIDiffDeps{
		CurrentLoader:  &mockEvalLoader{},
		BaselineLoader: &mockEvalLoader{},
		Clock:          fixedClock,
	}
	_, err := CIDiff(ctx, domain.CIDiffRequest{
		CurrentPath:  "current.json",
		BaselinePath: "baseline.json",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestCIDiff_ContextCancelledBetweenLoads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	deps := CIDiffDeps{
		CurrentLoader: &cancelAfterLoadEvalLoader{
			inner:  &mockEvalLoader{findings: []domain.BaselineFinding{{ControlID: "CTL.A", AssetID: "res-1"}}},
			cancel: cancel,
		},
		BaselineLoader: &mockEvalLoader{},
		Clock:          fixedClock,
	}
	_, err := CIDiff(ctx, domain.CIDiffRequest{
		CurrentPath:  "current.json",
		BaselinePath: "baseline.json",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error between loads")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
