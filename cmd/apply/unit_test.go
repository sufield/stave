package apply

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appeval "github.com/sufield/stave/internal/app/eval"
	clockadp "github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/testutil"
)

// testdataDir returns the path to a testdata e2e fixture directory.
func testdataDir(t *testing.T, name string) string {
	t.Helper()
	return testutil.E2EDir(t, name)
}

func TestResolveApplyOptions(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")
	cmd := NewApplyCmd(compose.NewDefaultProvider())
	cs := cobraState{
		Ctx:         cmd.Context(),
		Stdout:      cmd.OutOrStdout(),
		Stderr:      cmd.ErrOrStderr(),
		GlobalFlags: cmdutil.GetGlobalFlags(cmd),
	}

	t.Run("valid flags with defaults", func(t *testing.T) {
		opts := &ApplyOptions{
			SharedOptions: SharedOptions{
				ControlsDir:     filepath.Join(fixture, "controls"),
				ObservationsDir: filepath.Join(fixture, "observations"),
				MaxUnsafe:       "168h",
			},
		}

		cfg, err := opts.Resolve(cs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Params.maxDuration != 168*time.Hour {
			t.Errorf("maxDuration = %v, want 168h", cfg.Params.maxDuration)
		}
		if cfg.Params.source.IsStdin() {
			t.Error("source should not be stdin")
		}
		// Clock should be RealClock when --now is empty
		if _, ok := cfg.Params.clock.(clockadp.RealClock); !ok {
			t.Errorf("clock type = %T, want clockadp.RealClock", cfg.Params.clock)
		}
	})

	t.Run("valid flags with --now", func(t *testing.T) {
		opts := &ApplyOptions{
			SharedOptions: SharedOptions{
				ControlsDir:     filepath.Join(fixture, "controls"),
				ObservationsDir: filepath.Join(fixture, "observations"),
				MaxUnsafe:       "7d",
				NowTime:         "2026-01-15T00:00:00Z",
			},
		}

		cfg, err := opts.Resolve(cs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Params.maxDuration != 7*24*time.Hour {
			t.Errorf("maxDuration = %v, want 168h (7d)", cfg.Params.maxDuration)
		}
		fc, ok := cfg.Params.clock.(clockadp.FixedClock)
		if !ok {
			t.Fatalf("clock type = %T, want clockadp.FixedClock", cfg.Params.clock)
		}
		expected := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
		if !time.Time(fc).Equal(expected) {
			t.Errorf("clock time = %v, want %v", time.Time(fc), expected)
		}
	})

	t.Run("stdin mode", func(t *testing.T) {
		opts := &ApplyOptions{
			SharedOptions: SharedOptions{
				ControlsDir:     filepath.Join(fixture, "controls"),
				ObservationsDir: "-",
				MaxUnsafe:       "168h",
			},
		}

		cfg, err := opts.Resolve(cs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Params.source.IsStdin() {
			t.Error("source should be stdin")
		}
	})

	errorCases := []struct {
		name        string
		opts        ApplyOptions
		wantContain string
	}{
		{
			name: "controls dir not found",
			opts: ApplyOptions{
				SharedOptions: SharedOptions{
					ControlsDir:     "/nonexistent/path",
					ObservationsDir: filepath.Join(fixture, "observations"),
					MaxUnsafe:       "168h",
				},
			},
			wantContain: "--controls path",
		},
		{
			name: "observations dir not found",
			opts: ApplyOptions{
				SharedOptions: SharedOptions{
					ControlsDir:     filepath.Join(fixture, "controls"),
					ObservationsDir: "/nonexistent/path",
					MaxUnsafe:       "168h",
				},
			},
			wantContain: "--observations path",
		},
		{
			name: "invalid max-unsafe",
			opts: ApplyOptions{
				SharedOptions: SharedOptions{
					ControlsDir:     filepath.Join(fixture, "controls"),
					ObservationsDir: filepath.Join(fixture, "observations"),
					MaxUnsafe:       "not-a-duration",
				},
			},
			wantContain: "invalid --max-unsafe",
		},
		{
			name: "invalid --now format",
			opts: ApplyOptions{
				SharedOptions: SharedOptions{
					ControlsDir:     filepath.Join(fixture, "controls"),
					ObservationsDir: filepath.Join(fixture, "observations"),
					MaxUnsafe:       "168h",
					NowTime:         "not-a-time",
				},
			},
			wantContain: "invalid timestamp",
		},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			_, err := o.Resolve(cs)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantContain)
			}
			if got := err.Error(); !contains(got, tc.wantContain) {
				t.Errorf("error = %q, want to contain %q", got, tc.wantContain)
			}
		})
	}

	t.Run("controls path is a file", func(t *testing.T) {
		files, _ := filepath.Glob(filepath.Join(fixture, "controls", "*.yaml"))
		if len(files) == 0 {
			t.Fatal("no control YAML files in fixture: e2e-01-violation/controls must contain at least one *.yaml file")
		}
		opts := &ApplyOptions{
			SharedOptions: SharedOptions{
				ControlsDir:     files[0],
				ObservationsDir: filepath.Join(fixture, "observations"),
				MaxUnsafe:       "168h",
			},
		}

		_, err := opts.Resolve(cs)
		if err == nil {
			t.Fatal("expected error when controls is a file")
		}
		if got := err.Error(); !contains(got, "is not a directory") {
			t.Errorf("error = %q, want to contain %q", got, "is not a directory")
		}
	})
}

func testBuilder(opts *ApplyOptions, params applyParams) *Builder {
	return &Builder{
		Ctx:       context.Background(),
		Stdout:    io.Discard,
		Stderr:    io.Discard,
		Sanitizer: sanitize.New(),
		Opts:      opts,
		Params:    params,
		Provider:  compose.NewDefaultProvider(),
	}
}

func TestBuildApplyDeps(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")

	t.Run("json format produces deps", func(t *testing.T) {
		opts := &ApplyOptions{
			SharedOptions: SharedOptions{
				ControlsDir:     filepath.Join(fixture, "controls"),
				ObservationsDir: filepath.Join(fixture, "observations"),
				Format:          "json",
			},
		}

		params := applyParams{
			maxDuration: 168 * time.Hour,
			clock:       clockadp.RealClock{},
			source:      appeval.ObservationSource(opts.ObservationsDir),
		}

		deps, err := testBuilder(opts, params).BuildWithNewPlan()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer deps.Close()

		if deps.Config.ControlsDir != opts.ControlsDir {
			t.Errorf("ControlsDir = %q, want %q", deps.Config.ControlsDir, opts.ControlsDir)
		}
		if deps.Config.MaxUnsafe != 168*time.Hour {
			t.Errorf("MaxUnsafe = %v, want 168h", deps.Config.MaxUnsafe)
		}
		if deps.Runner == nil {
			t.Error("Runner should not be nil")
		}
	})

	t.Run("text format produces deps", func(t *testing.T) {
		opts := &ApplyOptions{
			SharedOptions: SharedOptions{
				ControlsDir:     filepath.Join(fixture, "controls"),
				ObservationsDir: filepath.Join(fixture, "observations"),
				Format:          "text",
			},
		}

		params := applyParams{
			maxDuration: 24 * time.Hour,
			clock:       clockadp.FixedClock(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)),
			source:      appeval.ObservationSource(opts.ObservationsDir),
		}

		deps, err := testBuilder(opts, params).BuildWithNewPlan()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer deps.Close()

		if deps.Runner == nil {
			t.Error("Runner should not be nil")
		}
	})

	t.Run("invalid output format", func(t *testing.T) {
		opts := &ApplyOptions{
			SharedOptions: SharedOptions{
				ControlsDir:     filepath.Join(fixture, "controls"),
				ObservationsDir: filepath.Join(fixture, "observations"),
				Format:          "csv",
			},
		}

		params := applyParams{
			maxDuration: 168 * time.Hour,
			clock:       clockadp.RealClock{},
			source:      appeval.ObservationSource(opts.ObservationsDir),
		}

		_, err := testBuilder(opts, params).BuildWithNewPlan()
		if err == nil {
			t.Fatal("expected error for invalid output format")
		}
		if got := err.Error(); !contains(got, "invalid --format") {
			t.Errorf("error = %q, want to contain %q", got, "invalid --format")
		}
	})

}

func TestApplyDepsClose(t *testing.T) {
	t.Run("close is safe", func(t *testing.T) {
		deps := &appeval.ApplyDeps{}
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
