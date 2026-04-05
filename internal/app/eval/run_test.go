package eval

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
)

type runMockRunner struct {
	returnStatus evaluation.Posture
	returnErr    error
}

func (m *runMockRunner) Execute(_ context.Context, _ EvaluateConfig) (evaluation.Posture, error) {
	return m.returnStatus, m.returnErr
}

func TestRunnerExecute(t *testing.T) {
	tests := []struct {
		name       string
		status     evaluation.Posture
		config     EvaluateConfig
		wantStatus evaluation.Posture
	}{
		{
			name:   "clean run",
			status: evaluation.PostureSafe,
			config: EvaluateConfig{
				LoadConfig: LoadConfig{
					ControlsDir:     "/tmp/ctl",
					ObservationsDir: "/tmp/obs",
				},
			},
			wantStatus: evaluation.PostureSafe,
		},
		{
			name:   "violations found",
			status: evaluation.PostureUnsafe,
			config: EvaluateConfig{
				LoadConfig: LoadConfig{
					ControlsDir:     "./s3-controls",
					ObservationsDir: "./aws-snapshots",
				},
			},
			wantStatus: evaluation.PostureUnsafe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &runMockRunner{returnStatus: tt.status}

			status, err := runner.Execute(context.Background(), tt.config)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if status != tt.wantStatus {
				t.Errorf("expected status=%v, got %v", tt.wantStatus, status)
			}
		})
	}
}

func TestRunnerExecute_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	runner := &runMockRunner{returnStatus: evaluation.PostureSafe, returnErr: wantErr}

	_, err := runner.Execute(context.Background(), EvaluateConfig{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
}
