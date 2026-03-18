package diagnose

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	clockadp "github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type diagnoseObsRepoStub struct {
	snapshots []asset.Snapshot
}

func (s diagnoseObsRepoStub) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{Snapshots: s.snapshots}, nil
}

type diagnoseInvRepoStub struct {
	controls []policy.ControlDefinition
}

func (s diagnoseInvRepoStub) LoadControls(context.Context, string) ([]policy.ControlDefinition, error) {
	return s.controls, nil
}

func TestDiagnosePathNormalization(t *testing.T) {
	ctlDir := filepath.Join(t.TempDir(), "ctl")
	obsDir := filepath.Join(t.TempDir(), "obs")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cleaned := fsutil.CleanUserPath(ctlDir + string(os.PathSeparator) + ".")
	if cleaned != ctlDir {
		t.Fatalf("CleanUserPath = %q, want %q", cleaned, ctlDir)
	}

	if err := cmdutil.CheckDir(ctlDir); err != nil {
		t.Fatalf("CheckDir(%q) error = %v", ctlDir, err)
	}
}

func TestDiagnosePathNormalization_DirErrors(t *testing.T) {
	tmp := t.TempDir()
	notDir := filepath.Join(tmp, "file.txt")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cmdutil.CheckDir(notDir); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("expected directory error, got %v", err)
	}
}

func TestDiagnoseParseHelpers(t *testing.T) {
	maxDur, err := timeutil.ParseDurationFlag("7d", "--max-unsafe")
	if err != nil || maxDur != 7*24*time.Hour {
		t.Fatalf("ParseDurationFlag() = (%s, %v), want (168h, nil)", maxDur, err)
	}
	if _, parseErr := timeutil.ParseDurationFlag("bad", "--max-unsafe"); parseErr == nil {
		t.Fatal("expected max-unsafe parse error")
	}

	clock, err := compose.ResolveClock("")
	if err != nil {
		t.Fatalf("ResolveClock() default error = %v", err)
	}
	if _, ok := clock.(clockadp.RealClock); !ok {
		t.Fatalf("default clock type = %T, want clockadp.RealClock", clock)
	}

	clock, err = compose.ResolveClock("2026-01-15T00:00:00Z")
	if err != nil {
		t.Fatalf("ResolveClock() fixed error = %v", err)
	}
	fixed, ok := clock.(clockadp.FixedClock)
	if !ok || !time.Time(fixed).Equal(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("fixed clock = %#v", clock)
	}

	if _, err := compose.ResolveClock("bad"); err == nil {
		t.Fatal("expected now parse error")
	}
}

func TestRunnerBuildAppConfig(t *testing.T) {
	runner := NewRunner(compose.NewDefaultProvider(), clockadp.RealClock{})

	fakeStdin := strings.NewReader(`{"findings":[]}`)
	cfg := Config{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
		PreviousOutput:  "-",
		Stdin:           fakeStdin,
	}
	appCfg, err := runner.buildAppConfig(cfg, 24*time.Hour)
	if err != nil {
		t.Fatalf("buildAppConfig(stdin) error = %v", err)
	}
	if appCfg.PreviousResult == nil {
		t.Fatal("expected PreviousResult to be set from stdin")
	}

	cfg = Config{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
	}
	appCfg, err = runner.buildAppConfig(cfg, 24*time.Hour)
	if err != nil {
		t.Fatalf("buildAppConfig(no previous) error = %v", err)
	}
	if appCfg.PreviousResult != nil {
		t.Fatalf("expected PreviousResult nil, got %#v", appCfg.PreviousResult)
	}

	var buf bytes.Buffer
	if compose.ResolveStdout(&buf, true, "text") != io.Discard {
		t.Fatal("ResolveStdout(quiet=true, text) should return io.Discard")
	}
	if compose.ResolveStdout(&buf, true, "json") == io.Discard {
		t.Fatal("ResolveStdout(quiet=true, json) should preserve stdout for piping")
	}
}

func TestPresenterRenderReport_EnvelopeMode(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: diagnosis.ScenarioEmptyFindings, Signal: "s", Evidence: "e", Action: "a"},
		},
		Summary: diagnosis.Summary{
			TotalSnapshots:     1,
			TotalAssets:        1,
			TotalControls:      1,
			TimeSpan:           kernel.Duration(time.Hour),
			MinCapturedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxCapturedAt:      time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
			EvaluationTime:     time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC),
			MaxUnsafeThreshold: kernel.Duration(time.Hour),
			ViolationsFound:    1,
			AttackSurface:      1,
		},
	}

	var buf bytes.Buffer
	p := &Presenter{Stdout: &buf, Format: ui.OutputFormatJSON, EnvelopeMode: true}
	if err := p.RenderReport(report); err != nil {
		t.Fatalf("RenderReport() error = %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal diagnose json: %v", err)
	}
	if _, ok := out["ok"]; !ok {
		t.Fatalf("expected envelope output, got %s", buf.String())
	}

	buf.Reset()
	p.EnvelopeMode = false
	if err := p.RenderReport(report); err != nil {
		t.Fatalf("RenderReport() no-envelope error = %v", err)
	}
	if strings.Contains(buf.String(), "\"ok\"") {
		t.Fatalf("did not expect envelope in non-envelope mode: %s", buf.String())
	}
}

func TestRunDiagnose_EarlyValidationAndLoaderError(t *testing.T) {
	ctlDir := filepath.Join(t.TempDir(), "ctl")
	obsDir := filepath.Join(t.TempDir(), "obs")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Test observation loader error.
	cfg := Config{
		ControlsDir:     ctlDir,
		ObservationsDir: obsDir,
		MaxUnsafe:       24 * time.Hour,
		Format:          ui.OutputFormatText,
		Stdout:          &bytes.Buffer{},
		Stderr:          &bytes.Buffer{},
	}
	badProvider := &compose.Provider{
		ObsRepoFunc: func() (appcontracts.ObservationRepository, error) {
			return nil, os.ErrPermission
		},
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) {
			return nil, nil
		},
	}
	runner := NewRunner(badProvider, clockadp.RealClock{})
	if err := runner.Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "create observation loader") {
		t.Fatalf("expected observation loader error, got %v", err)
	}
}

func TestPresenterRenderReport_Branches(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{},
		Summary: diagnosis.Summary{
			TotalSnapshots:     1,
			TotalAssets:        1,
			TotalControls:      1,
			TimeSpan:           kernel.Duration(time.Hour),
			MinCapturedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			MaxCapturedAt:      time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
			EvaluationTime:     time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC),
			MaxUnsafeThreshold: kernel.Duration(time.Hour),
		},
	}

	var out bytes.Buffer
	p := &Presenter{Stdout: &out, Format: ui.OutputFormatText}
	if err := p.RenderReport(report); err != nil {
		t.Fatalf("text report error = %v", err)
	}
	if !strings.Contains(out.String(), "Summary") {
		t.Fatalf("expected text summary output, got %s", out.String())
	}

	out.Reset()
	p.Format = ui.OutputFormatJSON
	if err := p.RenderReport(report); err != nil {
		t.Fatalf("json report error = %v", err)
	}
	if !strings.Contains(out.String(), "\"schema_version\"") {
		t.Fatalf("expected json output, got %s", out.String())
	}
}
