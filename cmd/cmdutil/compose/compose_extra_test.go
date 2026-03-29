package compose

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
)

// --- ResolveClock ---

func TestResolveClock_Empty(t *testing.T) {
	c, err := ResolveClock("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(ports.RealClock); !ok {
		t.Fatalf("expected RealClock, got %T", c)
	}
}

func TestResolveClock_Valid(t *testing.T) {
	c, err := ResolveClock("2026-01-15T00:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fc, ok := c.(ports.FixedClock)
	if !ok {
		t.Fatalf("expected FixedClock, got %T", c)
	}
	want := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !time.Time(fc).Equal(want) {
		t.Fatalf("FixedClock = %v, want %v", time.Time(fc), want)
	}
}

func TestResolveClock_Invalid(t *testing.T) {
	_, err := ResolveClock("not-a-time")
	if err == nil {
		t.Fatal("expected error for invalid time")
	}
	if !strings.Contains(err.Error(), "--now") {
		t.Fatalf("error should mention --now, got: %v", err)
	}
}

// --- ResolveNow ---

func TestResolveNow_Empty(t *testing.T) {
	now, err := ResolveNow("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be approximately now
	if time.Since(now) > 5*time.Second {
		t.Fatalf("ResolveNow('') returned %v, expected approximately now", now)
	}
}

func TestResolveNow_Valid(t *testing.T) {
	now, err := ResolveNow("2026-06-15T12:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if !now.Equal(want) {
		t.Fatalf("ResolveNow = %v, want %v", now, want)
	}
}

func TestResolveNow_Invalid(t *testing.T) {
	_, err := ResolveNow("bad-format")
	if err == nil {
		t.Fatal("expected error for invalid time format")
	}
}

// --- EmptyDash ---

func TestEmptyDash(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "-"},
		{"  ", "-"},
		{"\t\n", "-"},
		{"hello", "hello"},
		{" hello ", " hello "},
	}
	for _, tt := range tests {
		got := EmptyDash(tt.input)
		if got != tt.want {
			t.Errorf("EmptyDash(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- ResolveStdout ---

func TestResolveStdout_QuietText(t *testing.T) {
	var buf bytes.Buffer
	w := ResolveStdout(&buf, true, ui.OutputFormatText)
	if w != io.Discard {
		t.Fatal("expected io.Discard for quiet+text")
	}
}

func TestResolveStdout_QuietJSON(t *testing.T) {
	var buf bytes.Buffer
	w := ResolveStdout(&buf, true, ui.OutputFormatJSON)
	if w == io.Discard {
		t.Fatal("quiet+json should preserve writer for piping")
	}
}

func TestResolveStdout_NotQuiet(t *testing.T) {
	var buf bytes.Buffer
	w := ResolveStdout(&buf, false, ui.OutputFormatText)
	if w != &buf {
		t.Fatal("non-quiet should return original writer")
	}
}

func TestResolveStdout_NilWriter(t *testing.T) {
	w := ResolveStdout(nil, false, ui.OutputFormatText)
	if w == nil {
		t.Fatal("nil writer should be replaced with os.Stdout")
	}
}

// --- ResolveFormatValuePure ---

func TestResolveFormatValuePure_Text(t *testing.T) {
	f, err := ResolveFormatValuePure("text", false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != ui.OutputFormatText {
		t.Fatalf("format = %q, want text", f)
	}
}

func TestResolveFormatValuePure_JSON(t *testing.T) {
	f, err := ResolveFormatValuePure("json", true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != ui.OutputFormatJSON {
		t.Fatalf("format = %q, want json", f)
	}
}

func TestResolveFormatValuePure_SARIF(t *testing.T) {
	f, err := ResolveFormatValuePure("sarif", true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != ui.OutputFormatSARIF {
		t.Fatalf("format = %q, want sarif", f)
	}
}

func TestResolveFormatValuePure_Invalid(t *testing.T) {
	_, err := ResolveFormatValuePure("xml", true, false)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestResolveFormatValuePure_CaseInsensitive(t *testing.T) {
	f, err := ResolveFormatValuePure("JSON", true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != ui.OutputFormatJSON {
		t.Fatalf("format = %q, want json", f)
	}
}

// --- DefaultFindingWriter ---

func TestDefaultFindingWriter_Text(t *testing.T) {
	fw, err := DefaultFindingWriter(ui.OutputFormatText, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestDefaultFindingWriter_JSON(t *testing.T) {
	fw, err := DefaultFindingWriter(ui.OutputFormatJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestDefaultFindingWriter_SARIF(t *testing.T) {
	fw, err := DefaultFindingWriter(ui.OutputFormatSARIF, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestDefaultFindingWriter_Invalid(t *testing.T) {
	_, err := DefaultFindingWriter("xml", false)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "invalid --format") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// --- Provider nil checks ---

func TestProvider_NewObservationRepo_NilFunc(t *testing.T) {
	p := &Provider{}
	_, err := p.NewObservationRepo()
	if err == nil {
		t.Fatal("expected error for nil ObsRepoFunc")
	}
}

func TestProvider_NewControlRepo_NilFunc(t *testing.T) {
	p := &Provider{}
	_, err := p.NewControlRepo()
	if err == nil {
		t.Fatal("expected error for nil ControlRepoFunc")
	}
}

func TestProvider_NewStdinObsRepo_NilFunc(t *testing.T) {
	p := &Provider{}
	_, err := p.NewStdinObsRepo(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for nil StdinObsRepoFunc")
	}
}

func TestProvider_NewSnapshotRepo_NilFunc(t *testing.T) {
	p := &Provider{}
	_, err := p.NewSnapshotRepo()
	if err == nil {
		t.Fatal("expected error for nil SnapshotRepoFunc")
	}
}

func TestProvider_NewFindingWriter_NilFunc(t *testing.T) {
	p := &Provider{}
	_, err := p.NewFindingWriter(ui.OutputFormatJSON, false)
	if err == nil {
		t.Fatal("expected error for nil FindingWriterFunc")
	}
}

func TestProvider_NewCELEvaluator_DefaultFunc(t *testing.T) {
	p := &Provider{}
	eval, err := p.NewCELEvaluator()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval == nil {
		t.Fatal("expected non-nil evaluator")
	}
}

func TestProvider_NewCELEvaluator_CustomFunc(t *testing.T) {
	called := false
	p := &Provider{
		CELEvalFunc: func() (policy.PredicateEval, error) {
			called = true
			return nil, nil
		},
	}
	_, _ = p.NewCELEvaluator()
	if !called {
		t.Fatal("expected custom CELEvalFunc to be called")
	}
}

// --- NewDefaultProvider ---

func TestNewDefaultProvider_NotNil(t *testing.T) {
	p := NewDefaultProvider()
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
	if p.ObsRepoFunc == nil {
		t.Fatal("ObsRepoFunc should not be nil")
	}
	if p.ControlRepoFunc == nil {
		t.Fatal("ControlRepoFunc should not be nil")
	}
	if p.StdinObsRepoFunc == nil {
		t.Fatal("StdinObsRepoFunc should not be nil")
	}
	if p.FindingWriterFunc == nil {
		t.Fatal("FindingWriterFunc should not be nil")
	}
	if p.CELEvalFunc == nil {
		t.Fatal("CELEvalFunc should not be nil")
	}
	if p.SnapshotRepoFunc == nil {
		t.Fatal("SnapshotRepoFunc should not be nil")
	}
}

// --- LoadSnapshots nil ObsRepoFunc ---

func TestProvider_LoadSnapshots_NilObsRepoFunc(t *testing.T) {
	p := &Provider{}
	_, err := p.LoadSnapshots(t.Context(), "some-dir")
	if err == nil {
		t.Fatal("expected error for nil ObsRepoFunc")
	}
}

// --- resolveFlags with SkipAll ---

func TestPrepareEvaluationContext_AllSkipped(t *testing.T) {
	ec, err := PrepareEvaluationContext(EvalContextRequest{
		ControlsDir:                "/tmp/ctl",
		ObservationsDir:            "/tmp/obs",
		SkipPathInference:          true,
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
		SkipMaxUnsafe:              true,
		SkipClock:                  true,
		SkipFormat:                 true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ec.ControlsDir != "/tmp/ctl" {
		t.Fatalf("ControlsDir = %q, want /tmp/ctl", ec.ControlsDir)
	}
	if ec.ObservationsDir != "/tmp/obs" {
		t.Fatalf("ObservationsDir = %q, want /tmp/obs", ec.ObservationsDir)
	}
}

func TestPrepareEvaluationContext_FlagParsing(t *testing.T) {
	ec, err := PrepareEvaluationContext(EvalContextRequest{
		ControlsDir:                "/tmp/ctl",
		ObservationsDir:            "/tmp/obs",
		MaxUnsafeDuration:          "7d",
		NowTime:                    "2026-01-15T00:00:00Z",
		Format:                     "json",
		FormatChanged:              true,
		SkipPathInference:          true,
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ec.MaxUnsafe != 7*24*time.Hour {
		t.Fatalf("MaxUnsafe = %v, want 168h", ec.MaxUnsafe)
	}
	if ec.Format != ui.OutputFormatJSON {
		t.Fatalf("Format = %q, want json", ec.Format)
	}
	want := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !ec.Now.Equal(want) {
		t.Fatalf("Now = %v, want %v", ec.Now, want)
	}
	if ec.Clock == nil {
		t.Fatal("Clock should not be nil")
	}
}

func TestPrepareEvaluationContext_BadMaxUnsafe(t *testing.T) {
	_, err := PrepareEvaluationContext(EvalContextRequest{
		ControlsDir:                "/tmp/ctl",
		ObservationsDir:            "/tmp/obs",
		MaxUnsafeDuration:          "bad",
		SkipPathInference:          true,
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
		SkipClock:                  true,
		SkipFormat:                 true,
	})
	if err == nil {
		t.Fatal("expected error for invalid max-unsafe")
	}
}

func TestPrepareEvaluationContext_BadClock(t *testing.T) {
	_, err := PrepareEvaluationContext(EvalContextRequest{
		ControlsDir:                "/tmp/ctl",
		ObservationsDir:            "/tmp/obs",
		NowTime:                    "bad",
		SkipPathInference:          true,
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
		SkipMaxUnsafe:              true,
		SkipFormat:                 true,
	})
	if err == nil {
		t.Fatal("expected error for invalid clock value")
	}
}

func TestPrepareEvaluationContext_BadFormat(t *testing.T) {
	_, err := PrepareEvaluationContext(EvalContextRequest{
		ControlsDir:                "/tmp/ctl",
		ObservationsDir:            "/tmp/obs",
		Format:                     "xml",
		FormatChanged:              true,
		SkipPathInference:          true,
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
		SkipMaxUnsafe:              true,
		SkipClock:                  true,
	})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

// --- WarnGitDirty ---

func TestWarnGitDirty_NilGit(t *testing.T) {
	// Should not panic
	WarnGitDirty(io.Discard, nil, "test", false)
}

func TestWarnGitDirty_NotDirty(t *testing.T) {
	// Should not panic or write
	var buf bytes.Buffer
	WarnGitDirty(&buf, &evaluation.GitInfo{Dirty: false}, "test", false)
}

func TestWarnGitDirty_Quiet(t *testing.T) {
	WarnGitDirty(io.Discard, &evaluation.GitInfo{Dirty: true}, "test", true)
}

// --- isManifestArtifact (via output) ---

func TestEvalContextRequest_Defaults(t *testing.T) {
	req := EvalContextRequest{}
	if req.ControlsDir != "" {
		t.Fatalf("default ControlsDir should be empty, got %q", req.ControlsDir)
	}
	if req.SkipPathInference {
		t.Fatal("default SkipPathInference should be false")
	}
}
