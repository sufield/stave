package eval

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation"
)

type runMockRunner struct {
	returnStatus evaluation.SafetyStatus
	returnErr    error
}

func (m *runMockRunner) Execute(_ context.Context, _ EvaluateConfig) (evaluation.SafetyStatus, error) {
	return m.returnStatus, m.returnErr
}

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		status     evaluation.SafetyStatus
		config     EvaluateConfig
		wantStatus evaluation.SafetyStatus
		wantHint   bool
		wantSteps  int
	}{
		{
			name:   "clean run",
			status: evaluation.SafetyStatusSafe,
			config: EvaluateConfig{
				LoadConfig: LoadConfig{
					ControlsDir:     "/tmp/ctl",
					ObservationsDir: "/tmp/obs",
				},
			},
			wantStatus: evaluation.SafetyStatusSafe,
			wantHint:   false,
			wantSteps:  0,
		},
		{
			name:   "violations found",
			status: evaluation.SafetyStatusUnsafe,
			config: EvaluateConfig{
				LoadConfig: LoadConfig{
					ControlsDir:     "./s3-controls",
					ObservationsDir: "./aws-snapshots",
				},
			},
			wantStatus: evaluation.SafetyStatusUnsafe,
			wantHint:   true,
			wantSteps:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &runMockRunner{returnStatus: tt.status}

			res, err := Run(context.Background(), RunInput{
				Runner: runner,
				Config: tt.config,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if res.SafetyStatus != tt.wantStatus {
				t.Errorf("expected status=%v, got %v", tt.wantStatus, res.SafetyStatus)
			}

			if tt.wantHint {
				if res.DiagnoseHint == "" {
					t.Error("expected a diagnose hint but got empty string")
				}
				if !strings.Contains(res.DiagnoseHint, tt.config.ControlsDir) {
					t.Errorf("hint missing controls dir: %s", res.DiagnoseHint)
				}
			} else if res.DiagnoseHint != "" {
				t.Errorf("expected no hint for clean run, got: %s", res.DiagnoseHint)
			}

			if len(res.NextSteps) != tt.wantSteps {
				t.Errorf("expected %d next steps, got %d", tt.wantSteps, len(res.NextSteps))
			}
			if res.NextSteps == nil {
				t.Error("expected NextSteps to be initialized (non-nil)")
			}
		})
	}
}

func TestRun_PropagatesRunnerError(t *testing.T) {
	wantErr := errors.New("boom")
	runner := &runMockRunner{returnStatus: evaluation.SafetyStatusSafe, returnErr: wantErr}

	_, err := Run(context.Background(), RunInput{
		Runner: runner,
		Config: EvaluateConfig{},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
}
