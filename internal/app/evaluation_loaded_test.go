package app

import (
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"

	appworkflow "github.com/sufield/stave/internal/app/workflow"
)

func TestEvaluateLoaded_DefaultsClockWhenNil(t *testing.T) {
	result, err := appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:          nil,
		Snapshots:         nil,
		MaxUnsafeDuration: 24 * time.Hour,
		Clock:             nil,
		StaveVersion:      "test-version",
	})
	if err != nil {
		t.Fatalf("EvaluateLoaded returned error: %v", err)
	}

	if result.Run.StaveVersion != "test-version" {
		t.Fatalf("tool_version=%q, want %q", result.Run.StaveVersion, "test-version")
	}
	if result.Run.Now.IsZero() {
		t.Fatal("expected run.now to be set when clock is nil")
	}
	if result.Run.MaxUnsafeDuration != kernel.Duration(24*time.Hour) {
		t.Fatalf("max_unsafe=%s, want %s", result.Run.MaxUnsafeDuration, kernel.Duration(24*time.Hour))
	}
}
