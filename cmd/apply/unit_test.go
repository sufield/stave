package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
)

// testdataDir returns the path to a testdata e2e fixture directory.
func testdataDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(findRepoRoot(t), "testdata", "e2e", name)
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod found)")
		}
		dir = parent
	}
}

func TestResolveApplyOptions(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")
	cmd := NewApplyCmd()
	cs := cobraState{
		Stdout:      cmd.OutOrStdout(),
		Stderr:      cmd.ErrOrStderr(),
		Stdin:       cmd.InOrStdin(),
		GlobalFlags: cliflags.GetGlobalFlags(cmd),
	}

	// --max-unsafe / --now parsing moved to the facade; Resolve now only
	// resolves paths + project config, so these assert the resolved dirs.
	t.Run("valid flags with defaults", func(t *testing.T) {
		opts := &Options{
			SharedOptions: SharedOptions{
				ControlsDir:       filepath.Join(fixture, "controls"),
				ObservationsDir:   filepath.Join(fixture, "observations"),
				MaxUnsafeDuration: "168h",
			},
		}
		cfg, err := Resolve(opts, cs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ControlsDir != filepath.Join(fixture, "controls") {
			t.Errorf("ControlsDir = %q, want fixture controls", cfg.ControlsDir)
		}
		if cfg.IsProfileMode() {
			t.Error("expected standard mode")
		}
	})

	t.Run("valid flags with --now", func(t *testing.T) {
		opts := &Options{
			SharedOptions: SharedOptions{
				ControlsDir:       filepath.Join(fixture, "controls"),
				ObservationsDir:   filepath.Join(fixture, "observations"),
				MaxUnsafeDuration: "7d",
				NowTime:           "2026-01-15T00:00:00Z",
			},
		}
		if _, err := Resolve(opts, cs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("stdin mode", func(t *testing.T) {
		opts := &Options{
			SharedOptions: SharedOptions{
				ControlsDir:       filepath.Join(fixture, "controls"),
				ObservationsDir:   "-",
				MaxUnsafeDuration: "168h",
			},
		}
		cfg, err := Resolve(opts, cs)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ObservationsDir != "-" {
			t.Errorf("ObservationsDir = %q, want stdin (-)", cfg.ObservationsDir)
		}
	})

	errorCases := []struct {
		name        string
		opts        Options
		wantContain string
	}{
		{
			// Explicit --controls to a missing path still errors. When
			// --controls is NOT set and the path is absent, apply instead
			// falls back to the built-in catalog (verified separately).
			name: "controls dir not found (explicit flag)",
			opts: Options{
				SharedOptions: SharedOptions{
					ControlsDir:       "/nonexistent/path",
					ObservationsDir:   filepath.Join(fixture, "observations"),
					MaxUnsafeDuration: "168h",
					controlsSet:       true,
				},
			},
			wantContain: "--controls path",
		},
		{
			name: "observations dir not found",
			opts: Options{
				SharedOptions: SharedOptions{
					ControlsDir:       filepath.Join(fixture, "controls"),
					ObservationsDir:   "/nonexistent/path",
					MaxUnsafeDuration: "168h",
				},
			},
			wantContain: "--observations path",
		},
		{
			// Integrity flag validation is restored command-side (it left
			// with the removed appeval.Validate path). The public key needs a
			// manifest.
			name: "integrity public key without manifest",
			opts: Options{
				SharedOptions: SharedOptions{
					ControlsDir:       filepath.Join(fixture, "controls"),
					ObservationsDir:   filepath.Join(fixture, "observations"),
					MaxUnsafeDuration: "168h",
				},
				IntegrityPublicKey: "/some/key.pem",
			},
			wantContain: "integrity-public-key requires integrity-manifest",
		},
		{
			// The manifest is incompatible with stdin observations.
			name: "integrity manifest with stdin",
			opts: Options{
				SharedOptions: SharedOptions{
					ControlsDir:       filepath.Join(fixture, "controls"),
					ObservationsDir:   "-",
					MaxUnsafeDuration: "168h",
				},
				IntegrityManifest: "/some/manifest.json",
			},
			wantContain: "integrity-manifest cannot be used with observations - (stdin mode)",
		},
		// --max-unsafe and --now are parsed in the facade (stave.EvaluateStandard),
		// not in Resolve, so bad values no longer surface here. Their validation
		// is covered by the facade's tests.
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			_, err := Resolve(&o, cs)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantContain)
			}
			if got := err.Error(); !strings.Contains(got, tc.wantContain) {
				t.Errorf("error = %q, want to contain %q", got, tc.wantContain)
			}
		})
	}

	t.Run("controls path is a file", func(t *testing.T) {
		files, _ := filepath.Glob(filepath.Join(fixture, "controls", "*.yaml"))
		if len(files) == 0 {
			t.Fatal("no control YAML files in fixture: e2e-01-violation/controls must contain at least one *.yaml file")
		}
		opts := &Options{
			SharedOptions: SharedOptions{
				ControlsDir:       files[0],
				ObservationsDir:   filepath.Join(fixture, "observations"),
				MaxUnsafeDuration: "168h",
			},
		}

		_, err := Resolve(opts, cs)
		if err == nil {
			t.Fatal("expected error when controls is a file")
		}
		if got := err.Error(); !strings.Contains(got, "is not a directory") {
			t.Errorf("error = %q, want to contain %q", got, "is not a directory")
		}
	})
}
