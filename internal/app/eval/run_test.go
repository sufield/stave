package eval

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
)

type runMockRunner struct {
	returnStatus evaluation.SecurityState
	returnErr    error
}

func (m *runMockRunner) PerformAssessment(_ context.Context, _ AssessmentConfig) (evaluation.SecurityState, error) {
	return m.returnStatus, m.returnErr
}

func TestRunnerExecute(t *testing.T) {
	tests := []struct {
		name       string
		status     evaluation.SecurityState
		config     AssessmentConfig
		wantStatus evaluation.SecurityState
	}{
		{
			name:   "clean run",
			status: evaluation.StateCompliant,
			config: AssessmentConfig{
				InventoryConfig: InventoryConfig{
					PolicySource:    "/tmp/ctl",
					InventorySource: "/tmp/obs",
				},
			},
			wantStatus: evaluation.StateCompliant,
		},
		{
			name:   "violations found",
			status: evaluation.StateNonCompliant,
			config: AssessmentConfig{
				InventoryConfig: InventoryConfig{
					PolicySource:    "./s3-controls",
					InventorySource: "./aws-snapshots",
				},
			},
			wantStatus: evaluation.StateNonCompliant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &runMockRunner{returnStatus: tt.status}

			status, err := runner.PerformAssessment(context.Background(), tt.config)
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
	runner := &runMockRunner{returnStatus: evaluation.StateCompliant, returnErr: wantErr}

	_, err := runner.PerformAssessment(context.Background(), AssessmentConfig{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
}
