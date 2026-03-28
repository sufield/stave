package usecases

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/domain"
)

// --- Mock implementations ---

type mockEvalLoader struct {
	findings []domain.BaselineFinding
	err      error
}

func (m *mockEvalLoader) LoadFindings(_ context.Context, _ string) ([]domain.BaselineFinding, error) {
	return m.findings, m.err
}

type mockBaselineLoader struct {
	findings []domain.BaselineFinding
	err      error
}

func (m *mockBaselineLoader) LoadBaseline(_ context.Context, _ string) ([]domain.BaselineFinding, error) {
	return m.findings, m.err
}

type mockBaselineWriter struct {
	writtenPath     string
	writtenFindings []domain.BaselineFinding
	err             error
}

func (m *mockBaselineWriter) WriteBaseline(_ context.Context, path string, findings []domain.BaselineFinding, _ time.Time, _ string) error {
	m.writtenPath = path
	m.writtenFindings = findings
	return m.err
}

var fixedTime = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

func fixedClock() time.Time { return fixedTime }

// --- BaselineSave tests ---

func TestBaselineSave(t *testing.T) {
	findings := []domain.BaselineFinding{
		{ControlID: "CTL.S3.PUBLIC.001", ControlName: "No Public Read", AssetID: "bucket-a", AssetType: "aws_s3_bucket"},
		{ControlID: "CTL.S3.ENCRYPT.001", ControlName: "SSE Enabled", AssetID: "bucket-b", AssetType: "aws_s3_bucket"},
	}

	tests := []struct {
		name      string
		req       domain.BaselineSaveRequest
		loader    *mockEvalLoader
		writer    *mockBaselineWriter
		wantCount int
		wantErr   bool
	}{
		{
			name: "happy path",
			req: domain.BaselineSaveRequest{
				EvaluationPath: "eval.json",
				OutputPath:     "baseline.json",
			},
			loader:    &mockEvalLoader{findings: findings},
			writer:    &mockBaselineWriter{},
			wantCount: 2,
		},
		{
			name: "zero findings",
			req: domain.BaselineSaveRequest{
				EvaluationPath: "eval.json",
				OutputPath:     "baseline.json",
			},
			loader:    &mockEvalLoader{findings: nil},
			writer:    &mockBaselineWriter{},
			wantCount: 0,
		},
		{
			name: "loader error",
			req: domain.BaselineSaveRequest{
				EvaluationPath: "missing.json",
				OutputPath:     "baseline.json",
			},
			loader:  &mockEvalLoader{err: errors.New("file not found")},
			writer:  &mockBaselineWriter{},
			wantErr: true,
		},
		{
			name: "writer error",
			req: domain.BaselineSaveRequest{
				EvaluationPath: "eval.json",
				OutputPath:     "/readonly/baseline.json",
			},
			loader:  &mockEvalLoader{findings: findings},
			writer:  &mockBaselineWriter{err: errors.New("permission denied")},
			wantErr: true,
		},
		{
			name: "custom now",
			req: domain.BaselineSaveRequest{
				EvaluationPath: "eval.json",
				OutputPath:     "baseline.json",
				Now:            new(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)),
			},
			loader:    &mockEvalLoader{findings: findings},
			writer:    &mockBaselineWriter{},
			wantCount: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := BaselineSaveDeps{
				Loader: tc.loader,
				Writer: tc.writer,
				Clock:  fixedClock,
			}
			resp, err := BaselineSave(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.FindingsCount != tc.wantCount {
				t.Errorf("FindingsCount: got %d, want %d", resp.FindingsCount, tc.wantCount)
			}
			if resp.OutputPath != tc.req.OutputPath {
				t.Errorf("OutputPath: got %q, want %q", resp.OutputPath, tc.req.OutputPath)
			}
			if tc.req.Now != nil && !resp.CreatedAt.Equal(*tc.req.Now) {
				t.Errorf("CreatedAt: got %v, want %v", resp.CreatedAt, *tc.req.Now)
			}
		})
	}
}

func TestBaselineSave_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := BaselineSaveDeps{
		Loader: &mockEvalLoader{},
		Writer: &mockBaselineWriter{},
		Clock:  fixedClock,
	}
	_, err := BaselineSave(ctx, domain.BaselineSaveRequest{
		EvaluationPath: "eval.json",
		OutputPath:     "baseline.json",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// --- BaselineCheck tests ---

func TestBaselineCheck(t *testing.T) {
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
		req          domain.BaselineCheckRequest
		evalLoader   *mockEvalLoader
		baseLoader   *mockBaselineLoader
		wantNew      int
		wantResolved int
		wantHasNew   bool
		wantErr      bool
	}{
		{
			name: "new and resolved findings",
			req: domain.BaselineCheckRequest{
				EvaluationPath: "eval.json",
				BaselinePath:   "baseline.json",
				FailOnNew:      true,
			},
			evalLoader:   &mockEvalLoader{findings: current},
			baseLoader:   &mockBaselineLoader{findings: baseline},
			wantNew:      1,
			wantResolved: 1,
			wantHasNew:   true,
		},
		{
			name: "no changes",
			req: domain.BaselineCheckRequest{
				EvaluationPath: "eval.json",
				BaselinePath:   "baseline.json",
				FailOnNew:      true,
			},
			evalLoader:   &mockEvalLoader{findings: baseline},
			baseLoader:   &mockBaselineLoader{findings: baseline},
			wantNew:      0,
			wantResolved: 0,
			wantHasNew:   false,
		},
		{
			name: "all resolved",
			req: domain.BaselineCheckRequest{
				EvaluationPath: "eval.json",
				BaselinePath:   "baseline.json",
			},
			evalLoader:   &mockEvalLoader{findings: nil},
			baseLoader:   &mockBaselineLoader{findings: baseline},
			wantNew:      0,
			wantResolved: 2,
			wantHasNew:   false,
		},
		{
			name: "eval loader error",
			req: domain.BaselineCheckRequest{
				EvaluationPath: "missing.json",
				BaselinePath:   "baseline.json",
			},
			evalLoader: &mockEvalLoader{err: errors.New("not found")},
			baseLoader: &mockBaselineLoader{findings: baseline},
			wantErr:    true,
		},
		{
			name: "baseline loader error",
			req: domain.BaselineCheckRequest{
				EvaluationPath: "eval.json",
				BaselinePath:   "missing.json",
			},
			evalLoader: &mockEvalLoader{findings: current},
			baseLoader: &mockBaselineLoader{err: errors.New("not found")},
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := BaselineCheckDeps{
				EvalLoader:     tc.evalLoader,
				BaselineLoader: tc.baseLoader,
				Clock:          fixedClock,
			}
			resp, err := BaselineCheck(context.Background(), tc.req, deps)
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
			if resp.Summary.ResolvedFindings != tc.wantResolved {
				t.Errorf("Summary.ResolvedFindings: got %d, want %d", resp.Summary.ResolvedFindings, tc.wantResolved)
			}
		})
	}
}

func TestBaselineCheck_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := BaselineCheckDeps{
		EvalLoader:     &mockEvalLoader{},
		BaselineLoader: &mockBaselineLoader{},
		Clock:          fixedClock,
	}
	_, err := BaselineCheck(ctx, domain.BaselineCheckRequest{
		EvaluationPath: "eval.json",
		BaselinePath:   "baseline.json",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestBaselineCheck_ContextCancelledBetweenLoads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Loader that cancels the context after returning successfully
	loader := &mockEvalLoader{
		findings: []domain.BaselineFinding{
			{ControlID: "CTL.A", ControlName: "A", AssetID: "res-1", AssetType: "bucket"},
		},
	}

	deps := BaselineCheckDeps{
		EvalLoader: &cancelAfterLoadEvalLoader{
			inner:  loader,
			cancel: cancel,
		},
		BaselineLoader: &mockBaselineLoader{},
		Clock:          fixedClock,
	}
	_, err := BaselineCheck(ctx, domain.BaselineCheckRequest{
		EvaluationPath: "eval.json",
		BaselinePath:   "baseline.json",
	}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error between loads")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// cancelAfterLoadEvalLoader delegates to inner, then cancels the context.
type cancelAfterLoadEvalLoader struct {
	inner  EvaluationLoaderPort
	cancel context.CancelFunc
}

func (c *cancelAfterLoadEvalLoader) LoadFindings(ctx context.Context, path string) ([]domain.BaselineFinding, error) {
	findings, err := c.inner.LoadFindings(ctx, path)
	c.cancel()
	return findings, err
}
