package gate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

func TestParseGatePolicy(t *testing.T) {
	tests := []struct {
		in      string
		want    appconfig.GatePolicy
		wantErr bool
	}{
		{in: string(appconfig.GatePolicyAny), want: appconfig.GatePolicyAny},
		{in: "  FAIL_ON_NEW_VIOLATION  ", want: appconfig.GatePolicyNew},
		{in: string(appconfig.GatePolicyOverdue), want: appconfig.GatePolicyOverdue},
		{in: "unknown", wantErr: true},
	}
	for _, tc := range tests {
		got, err := appconfig.ParseGatePolicy(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseGatePolicy(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseGatePolicy(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseGatePolicy(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRunGatePolicyAny(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	tmp := t.TempDir()
	p := compose.NewDefaultProvider()
	runner := newRunner(p.LoadAssets, p.NewCELEvaluator)

	withFindings := filepath.Join(tmp, "with-findings.json")
	if err := os.WriteFile(withFindings, []byte(`{
  "kind": "evaluation",
  "findings": [
    {
      "control_id": "CTL.TEST.RULE.001",
      "control_name": "Test control",
      "asset_id": "res:1",
      "asset_type": "storage_bucket"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write eval file: %v", err)
	}
	result, err := runner.runPolicyAny(config{
		InPath: withFindings,
		Clock:  ports.FixedClock(now),
		Stdout: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("runPolicyAny: %v", err)
	}
	if result.Passed {
		t.Fatalf("expected gate fail when findings exist, got pass")
	}
	if result.CurrentViolations != 1 {
		t.Fatalf("expected 1 violation, got %d", result.CurrentViolations)
	}

	noFindings := filepath.Join(tmp, "no-findings.json")
	if writeErr := os.WriteFile(noFindings, []byte(`{"kind":"evaluation","findings":[]}`), 0o644); writeErr != nil {
		t.Fatalf("write eval file: %v", writeErr)
	}
	result, err = runner.runPolicyAny(config{
		InPath: noFindings,
		Clock:  ports.FixedClock(now),
		Stdout: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("runPolicyAny: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected gate pass when no findings exist, got fail")
	}
}

func TestRunGatePolicyNew(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	tmp := t.TempDir()
	p := compose.NewDefaultProvider()
	runner := newRunner(p.LoadAssets, p.NewCELEvaluator)

	evalPath := filepath.Join(tmp, "evaluation.json")
	basePath := filepath.Join(tmp, "baseline.json")

	if err := os.WriteFile(evalPath, []byte(`{
  "kind": "evaluation",
  "findings": [
    {
      "control_id": "CTL.TEST.RULE.001",
      "control_name": "Test control",
      "asset_id": "res:1",
      "asset_type": "storage_bucket"
    },
    {
      "control_id": "CTL.TEST.RULE.002",
      "control_name": "Test control 2",
      "asset_id": "res:2",
      "asset_type": "storage_bucket"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write eval file: %v", err)
	}

	if err := os.WriteFile(basePath, []byte(`{
  "kind": "baseline",
  "findings": [
    {
      "control_id": "CTL.TEST.RULE.001",
      "control_name": "Test control",
      "asset_id": "res:1",
      "asset_type": "storage_bucket"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write baseline file: %v", err)
	}

	result, err := runner.runPolicyNew(config{
		InPath:       evalPath,
		BaselinePath: basePath,
		Clock:        ports.FixedClock(now),
		Stdout:       &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("runPolicyNew: %v", err)
	}
	if result.Passed {
		t.Fatalf("expected fail when new findings exist")
	}
	if result.NewViolations != 1 {
		t.Fatalf("expected 1 new finding, got %d", result.NewViolations)
	}
}

func TestRunGatePolicyOverdue(t *testing.T) {
	fixture := testdataDir(t, "e2e-01-violation")
	tmp := t.TempDir()
	controlsDir := filepath.Join(tmp, "controls")
	if err := os.MkdirAll(controlsDir, 0o755); err != nil {
		t.Fatalf("mkdir controls dir: %v", err)
	}
	controlData, err := os.ReadFile(filepath.Join(fixture, "controls", "CTL.EXP.DURATION.001.yaml"))
	if err != nil {
		t.Fatalf("read fixture control: %v", err)
	}
	// Remove per-control threshold so the test can drive max-unsafe via gate input.
	trimmedControl := strings.ReplaceAll(string(controlData), "params:\n  max_unsafe_duration: \"168h\"\n", "")
	if writeErr := os.WriteFile(filepath.Join(controlsDir, "CTL.EXP.DURATION.001.yaml"), []byte(trimmedControl), 0o644); writeErr != nil {
		t.Fatalf("write temp control: %v", writeErr)
	}
	observationsDir := filepath.Join(fixture, "observations")

	now := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)
	p := compose.NewDefaultProvider()
	runner := newRunner(p.LoadAssets, p.NewCELEvaluator)

	result, err := runner.runPolicyOverdue(context.Background(), config{
		ControlsDir:       controlsDir,
		ObservationsDir:   observationsDir,
		MaxUnsafeDuration: 500 * time.Hour,
		Clock:             ports.FixedClock(now),
		Stdout:            &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("runPolicyOverdue: %v", err)
	}
	if !result.Passed {
		t.Fatalf("expected pass at high threshold before overdue, got fail with reason: %s", result.Reason)
	}

	result, err = runner.runPolicyOverdue(context.Background(), config{
		ControlsDir:       controlsDir,
		ObservationsDir:   observationsDir,
		MaxUnsafeDuration: 24 * time.Hour,
		Clock:             ports.FixedClock(now),
		Stdout:            &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("runPolicyOverdue: %v", err)
	}
	if result.Passed {
		t.Fatalf("expected fail when overdue upcoming exists")
	}
	if result.OverdueUpcoming == 0 {
		t.Fatalf("expected overdue count > 0")
	}
}

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
