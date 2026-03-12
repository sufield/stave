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

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	clockadp "github.com/sufield/stave/internal/domain/ports"
)

// testCmdWithOutputMode builds a cobra command tree where the root has an
// --output persistent flag set to mode ("json" or "text"). This mirrors the
// real root command setup that cmdutil.IsJSONMode inspects.
func testCmdWithOutputMode(mode string) *cobra.Command {
	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("output", "text", "")
	_ = root.PersistentFlags().Set("output", mode)
	child := &cobra.Command{Use: "diagnose-test"}
	root.AddCommand(child)
	return child
}

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

type diagnoseEvalRepoStub struct {
	result *evaluation.Result
}

func (s diagnoseEvalRepoStub) LoadFromFile(string) (*evaluation.Result, error) {
	return s.result, nil
}

func (s diagnoseEvalRepoStub) LoadFromReader(_ io.Reader, _ string) (*evaluation.Result, error) {
	return s.result, nil
}

func TestDiagnoseOptionsNormalizeAndValidate(t *testing.T) {
	ctlDir := filepath.Join(t.TempDir(), "ctl")
	obsDir := filepath.Join(t.TempDir(), "obs")
	if err := os.MkdirAll(ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("controls", "", "")
	cmd.Flags().String("observations", "", "")
	if err := cmd.Flags().Set("controls", ctlDir); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("observations", obsDir); err != nil {
		t.Fatal(err)
	}

	opts, inferLog := (diagnoseOptions{
		ControlsDir:     ctlDir + string(os.PathSeparator) + ".",
		ObservationsDir: obsDir + string(os.PathSeparator) + ".",
	}).normalizePaths(cmd)
	if err := opts.validateDirs(inferLog); err != nil {
		t.Fatalf("normalizePaths+validateDirs() error = %v", err)
	}
	if opts.ControlsDir != ctlDir || opts.ObservationsDir != obsDir {
		t.Fatalf("normalized dirs = (%q, %q), want (%q, %q)", opts.ControlsDir, opts.ObservationsDir, ctlDir, obsDir)
	}
}

func TestDiagnoseOptionsNormalizeAndValidate_DirErrors(t *testing.T) {
	tmp := t.TempDir()
	notDir := filepath.Join(tmp, "file.txt")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("controls", "", "")
	cmd.Flags().String("observations", "", "")
	_ = cmd.Flags().Set("controls", notDir)
	_ = cmd.Flags().Set("observations", notDir)

	opts, inferLog := (diagnoseOptions{
		ControlsDir:     notDir,
		ObservationsDir: notDir,
	}).normalizePaths(cmd)
	if err := opts.validateDirs(inferLog); err == nil || !strings.Contains(err.Error(), "--controls must be a directory") {
		t.Fatalf("expected controls directory error, got %v", err)
	}
}

func TestDiagnoseOptionsParseHelpers(t *testing.T) {
	maxDur, err := (diagnoseOptions{MaxUnsafe: "7d"}).parseMaxUnsafe()
	if err != nil || maxDur != 7*24*time.Hour {
		t.Fatalf("parseMaxUnsafe() = (%s, %v), want (168h, nil)", maxDur, err)
	}
	if _, parseErr := (diagnoseOptions{MaxUnsafe: "bad"}).parseMaxUnsafe(); parseErr == nil {
		t.Fatal("expected max-unsafe parse error")
	}

	clock, err := (diagnoseOptions{}).parseClock()
	if err != nil {
		t.Fatalf("parseClock() default error = %v", err)
	}
	if _, ok := clock.(clockadp.RealClock); !ok {
		t.Fatalf("default clock type = %T, want clockadp.RealClock", clock)
	}

	clock, err = (diagnoseOptions{NowTime: "2026-01-15T00:00:00Z"}).parseClock()
	if err != nil {
		t.Fatalf("parseClock() fixed error = %v", err)
	}
	fixed, ok := clock.(clockadp.FixedClock)
	if !ok || !time.Time(fixed).Equal(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("fixed clock = %#v", clock)
	}

	if _, err := (diagnoseOptions{NowTime: "bad"}).parseClock(); err == nil {
		t.Fatal("expected now parse error")
	}
}

func TestBuildDiagnoseConfigAndOutputHelpers(t *testing.T) {
	opts := diagnoseOptions{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
		PreviousOutput:  "-",
	}
	cfg := buildDiagnoseConfig(opts, 24*time.Hour, clockadp.RealClock{})
	if cfg.OutputReader != os.Stdin || cfg.OutputFile != "" {
		t.Fatalf("stdin config mismatch: %#v", cfg)
	}

	cfg = buildDiagnoseConfig(diagnoseOptions{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
		PreviousOutput:  "out.json",
	}, 24*time.Hour, clockadp.RealClock{})
	if cfg.OutputFile != "out.json" || cfg.OutputReader != nil {
		t.Fatalf("file config mismatch: %#v", cfg)
	}

	testCmd := &cobra.Command{}
	if compose.ResolveStdout(testCmd, true, "text") != io.Discard {
		t.Fatal("ResolveStdout(quiet=true, text) should return io.Discard")
	}
	if compose.ResolveStdout(testCmd, true, "json") == io.Discard {
		t.Fatal("ResolveStdout(quiet=true, json) should preserve stdout for piping")
	}
}

func TestWriteDiagnoseJSON_EnvelopeMode(t *testing.T) {
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

	jsonCmd := testCmdWithOutputMode("json")

	var buf bytes.Buffer
	if err := writeDiagnoseJSON(jsonCmd, &buf, report); err != nil {
		t.Fatalf("writeDiagnoseJSON() error = %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal diagnose json: %v", err)
	}
	if _, ok := out["ok"]; !ok {
		t.Fatalf("expected envelope output, got %s", buf.String())
	}

	textCmd := testCmdWithOutputMode("text")
	buf.Reset()
	if err := writeDiagnoseJSON(textCmd, &buf, report); err != nil {
		t.Fatalf("writeDiagnoseJSON() text mode error = %v", err)
	}
	if strings.Contains(buf.String(), "\"ok\"") {
		t.Fatalf("did not expect envelope in text mode json output: %s", buf.String())
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

	cmd := &cobra.Command{Use: "diagnose-test"}
	cmd.Flags().String("controls", "", "")
	cmd.Flags().String("observations", "", "")
	_ = cmd.Flags().Set("controls", ctlDir)
	_ = cmd.Flags().Set("observations", obsDir)

	opts := &diagnoseOptions{
		ControlsDir:     ctlDir,
		ObservationsDir: obsDir,
		MaxUnsafe:       "bad-duration",
		Format:          "text",
	}
	if err := runDiagnose(cmd, opts); err == nil || !strings.Contains(err.Error(), "invalid --max-unsafe") {
		t.Fatalf("expected max-unsafe validation error, got %v", err)
	}

	opts.MaxUnsafe = "24h"
	compose.OverrideForTest(t, compose.Composition{
		NewObservationRepository: func() (appcontracts.ObservationRepository, error) {
			return nil, os.ErrPermission
		},
		NewControlRepository: func() (appcontracts.ControlRepository, error) {
			return nil, nil
		},
	})
	if err := runDiagnose(cmd, opts); err == nil || !strings.Contains(err.Error(), "create observation loader") {
		t.Fatalf("expected observation loader error, got %v", err)
	}
}

func TestWriteDiagnoseReport_Branches(t *testing.T) {
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

	cmd := testCmdWithOutputMode("text")

	var out bytes.Buffer
	if err := writeDiagnoseReport(cmd, &out, ui.OutputFormatText, report); err != nil {
		t.Fatalf("text report error = %v", err)
	}
	if !strings.Contains(out.String(), "Summary") {
		t.Fatalf("expected text summary output, got %s", out.String())
	}

	out.Reset()
	if err := writeDiagnoseReport(cmd, &out, ui.OutputFormatJSON, report); err != nil {
		t.Fatalf("json report error = %v", err)
	}
	if !strings.Contains(out.String(), "\"schema_version\"") {
		t.Fatalf("expected json output, got %s", out.String())
	}
}
