package evaluate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	appeval "github.com/sufield/stave/internal/app/eval"
	clockadp "github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/testutil"
)

// saveEvaluateFlags captures current flag values and returns a restore function.
func saveEvaluateFlags() func() {
	saved := applyFlags
	return func() {
		applyFlags = saved
	}
}

// testdataDir returns the path to a testdata e2e fixture directory.
func testdataDir(t *testing.T, name string) string {
	t.Helper()
	return testutil.E2EDir(t, name)
}

func TestValidateEvaluateFlags(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")

	t.Run("valid flags with defaults", func(t *testing.T) {
		restore := saveEvaluateFlags()
		defer restore()

		applyFlags.controlsDir = filepath.Join(fixture, "controls")
		applyFlags.observationsDir = filepath.Join(fixture, "observations")
		applyFlags.maxUnsafe = "168h"
		applyFlags.nowTime = ""

		params, err := validateEvaluateFlags(ApplyCmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if params.maxDuration != 168*time.Hour {
			t.Errorf("maxDuration = %v, want 168h", params.maxDuration)
		}
		if params.source.IsStdin() {
			t.Error("source should not be stdin")
		}
		// Clock should be RealClock when --now is empty
		if _, ok := params.clock.(clockadp.RealClock); !ok {
			t.Errorf("clock type = %T, want clockadp.RealClock", params.clock)
		}
	})

	t.Run("valid flags with --now", func(t *testing.T) {
		restore := saveEvaluateFlags()
		defer restore()

		applyFlags.controlsDir = filepath.Join(fixture, "controls")
		applyFlags.observationsDir = filepath.Join(fixture, "observations")
		applyFlags.maxUnsafe = "7d"
		applyFlags.nowTime = "2026-01-15T00:00:00Z"

		params, err := validateEvaluateFlags(ApplyCmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if params.maxDuration != 7*24*time.Hour {
			t.Errorf("maxDuration = %v, want 168h (7d)", params.maxDuration)
		}
		fc, ok := params.clock.(clockadp.FixedClock)
		if !ok {
			t.Fatalf("clock type = %T, want clockadp.FixedClock", params.clock)
		}
		expected := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
		if !fc.Time.Equal(expected) {
			t.Errorf("clock time = %v, want %v", fc.Time, expected)
		}
	})

	t.Run("stdin mode", func(t *testing.T) {
		restore := saveEvaluateFlags()
		defer restore()

		applyFlags.controlsDir = filepath.Join(fixture, "controls")
		applyFlags.observationsDir = "-"
		applyFlags.maxUnsafe = "168h"
		applyFlags.nowTime = ""

		params, err := validateEvaluateFlags(ApplyCmd)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !params.source.IsStdin() {
			t.Error("source should be stdin")
		}
	})

	errorCases := []struct {
		name        string
		setup       func()
		wantContain string
	}{
		{
			name: "controls dir not found",
			setup: func() {
				applyFlags.controlsDir = "/nonexistent/path"
				applyFlags.observationsDir = filepath.Join(fixture, "observations")
				applyFlags.maxUnsafe = "168h"
			},
			wantContain: "--controls not accessible",
		},
		{
			name: "observations dir not found",
			setup: func() {
				applyFlags.controlsDir = filepath.Join(fixture, "controls")
				applyFlags.observationsDir = "/nonexistent/path"
				applyFlags.maxUnsafe = "168h"
			},
			wantContain: "--observations not accessible",
		},
		{
			name: "invalid max-unsafe",
			setup: func() {
				applyFlags.controlsDir = filepath.Join(fixture, "controls")
				applyFlags.observationsDir = filepath.Join(fixture, "observations")
				applyFlags.maxUnsafe = "not-a-duration"
			},
			wantContain: "invalid --max-unsafe",
		},
		{
			name: "invalid --now format",
			setup: func() {
				applyFlags.controlsDir = filepath.Join(fixture, "controls")
				applyFlags.observationsDir = filepath.Join(fixture, "observations")
				applyFlags.maxUnsafe = "168h"
				applyFlags.nowTime = "not-a-time"
			},
			wantContain: "invalid --now",
		},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			restore := saveEvaluateFlags()
			defer restore()
			applyFlags.nowTime = ""
			tc.setup()
			_, err := validateEvaluateFlags(ApplyCmd)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantContain)
			}
			if got := err.Error(); !contains(got, tc.wantContain) {
				t.Errorf("error = %q, want to contain %q", got, tc.wantContain)
			}
		})
	}

	t.Run("controls path is a file", func(t *testing.T) {
		restore := saveEvaluateFlags()
		defer restore()

		files, _ := filepath.Glob(filepath.Join(fixture, "controls", "*.yaml"))
		if len(files) == 0 {
			t.Skip("no control YAML files in fixture")
		}
		applyFlags.controlsDir = files[0]
		applyFlags.observationsDir = filepath.Join(fixture, "observations")
		applyFlags.maxUnsafe = "168h"
		applyFlags.nowTime = ""

		_, err := validateEvaluateFlags(ApplyCmd)
		if err == nil {
			t.Fatal("expected error when controls is a file")
		}
		if got := err.Error(); !contains(got, "--controls must be a directory") {
			t.Errorf("error = %q, want to contain %q", got, "--controls must be a directory")
		}
	})
}

func TestBuildEvaluateDeps(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")
	dummyCmd := &cobra.Command{Use: "test"}

	t.Run("json format produces deps", func(t *testing.T) {
		restore := saveEvaluateFlags()
		defer restore()

		applyFlags.controlsDir = filepath.Join(fixture, "controls")
		applyFlags.observationsDir = filepath.Join(fixture, "observations")

		applyFlags.outputFormat = "json"
		applyFlags.quietMode = false

		params := evaluateParams{
			maxDuration: 168 * time.Hour,
			clock:       clockadp.RealClock{},
			source:      appeval.ObservationSource(applyFlags.observationsDir),
		}

		deps, err := NewFactory(dummyCmd, params).BuildWithNewPlan()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer deps.Close()

		if deps.Config.ControlsDir != applyFlags.controlsDir {
			t.Errorf("ControlsDir = %q, want %q", deps.Config.ControlsDir, applyFlags.controlsDir)
		}
		if deps.Config.MaxUnsafe != 168*time.Hour {
			t.Errorf("MaxUnsafe = %v, want 168h", deps.Config.MaxUnsafe)
		}
		if deps.Runner == nil {
			t.Error("Runner should not be nil")
		}
	})

	t.Run("text format produces deps", func(t *testing.T) {
		restore := saveEvaluateFlags()
		defer restore()

		applyFlags.controlsDir = filepath.Join(fixture, "controls")
		applyFlags.observationsDir = filepath.Join(fixture, "observations")

		applyFlags.outputFormat = "text"
		applyFlags.quietMode = false

		params := evaluateParams{
			maxDuration: 24 * time.Hour,
			clock:       clockadp.FixedClock{Time: time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)},
			source:      appeval.ObservationSource(applyFlags.observationsDir),
		}

		deps, err := NewFactory(dummyCmd, params).BuildWithNewPlan()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer deps.Close()

		if deps.Runner == nil {
			t.Error("Runner should not be nil")
		}
	})

	t.Run("invalid output format", func(t *testing.T) {
		restore := saveEvaluateFlags()
		defer restore()

		applyFlags.controlsDir = filepath.Join(fixture, "controls")
		applyFlags.observationsDir = filepath.Join(fixture, "observations")

		applyFlags.outputFormat = "csv"

		params := evaluateParams{
			maxDuration: 168 * time.Hour,
			clock:       clockadp.RealClock{},
			source:      appeval.ObservationSource(applyFlags.observationsDir),
		}

		_, err := NewFactory(dummyCmd, params).BuildWithNewPlan()
		if err == nil {
			t.Fatal("expected error for invalid output format")
		}
		if got := err.Error(); !contains(got, "invalid --format") {
			t.Errorf("error = %q, want to contain %q", got, "invalid --format")
		}
	})

}

func TestEvaluateDepsClose(t *testing.T) {
	t.Run("close is safe", func(t *testing.T) {
		deps := &EvaluateDeps{}
		deps.Close() // should not panic
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
