package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockDiagnoseRunner struct {
	data any
	err  error
}

func (m *mockDiagnoseRunner) RunDiagnosis(_ context.Context, _ domain.DiagnoseRequest) (any, error) {
	return m.data, m.err
}

type mockDiagnoseDetailRunner struct {
	data any
	err  error
}

func (m *mockDiagnoseDetailRunner) RunDetail(_ context.Context, _, _, _, _ string) (any, error) {
	return m.data, m.err
}

func TestDiagnose_StandardMode(t *testing.T) {
	sampleReport := map[string]any{"issues": []any{"finding-1"}}

	tests := []struct {
		name    string
		runner  *mockDiagnoseRunner
		wantErr bool
	}{
		{
			name:   "happy path",
			runner: &mockDiagnoseRunner{data: sampleReport},
		},
		{
			name:    "runner error",
			runner:  &mockDiagnoseRunner{err: errors.New("load failed")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := DiagnoseDeps{Runner: tc.runner}
			resp, err := Diagnose(context.Background(), domain.DiagnoseRequest{
				ControlsDir:     "controls",
				ObservationsDir: "observations",
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
			if resp.ReportData == nil {
				t.Error("ReportData: got nil")
			}
			if resp.IsDetailMode {
				t.Error("IsDetailMode: got true, want false")
			}
		})
	}
}

func TestDiagnose_DetailMode(t *testing.T) {
	tests := []struct {
		name    string
		detail  *mockDiagnoseDetailRunner
		wantErr bool
	}{
		{
			name:   "happy path",
			detail: &mockDiagnoseDetailRunner{data: map[string]any{"trace": "ok"}},
		},
		{
			name:    "detail error",
			detail:  &mockDiagnoseDetailRunner{err: errors.New("not found")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := DiagnoseDeps{
				Runner:       &mockDiagnoseRunner{},
				DetailRunner: tc.detail,
			}
			resp, err := Diagnose(context.Background(), domain.DiagnoseRequest{
				ControlsDir:     "controls",
				ObservationsDir: "observations",
				ControlID:       "CTL.A",
				AssetID:         "bucket-a",
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
			if !resp.IsDetailMode {
				t.Error("IsDetailMode: got false, want true")
			}
		})
	}
}

func TestDiagnose_DetailModeNilRunner(t *testing.T) {
	deps := DiagnoseDeps{Runner: &mockDiagnoseRunner{}}
	_, err := Diagnose(context.Background(), domain.DiagnoseRequest{
		ControlID: "CTL.A",
		AssetID:   "bucket-a",
	}, deps)
	if err == nil {
		t.Fatal("expected error for nil detail runner")
	}
}

func TestDiagnose_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := DiagnoseDeps{Runner: &mockDiagnoseRunner{}}
	_, err := Diagnose(ctx, domain.DiagnoseRequest{ControlsDir: "controls"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
