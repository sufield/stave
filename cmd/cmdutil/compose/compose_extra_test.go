package compose

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
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
	if !strings.Contains(err.Error(), "--eval-time") {
		t.Fatalf("error should mention --eval-time, got: %v", err)
	}
}

// --- ResolveEvalTime ---

func TestResolveNow_Empty(t *testing.T) {
	now, err := ResolveEvalTime("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be approximately now
	if time.Since(now) > 5*time.Second {
		t.Fatalf("ResolveEvalTime('') returned %v, expected approximately now", now)
	}
}

func TestResolveNow_Valid(t *testing.T) {
	now, err := ResolveEvalTime("2026-06-15T12:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if !now.Equal(want) {
		t.Fatalf("ResolveEvalTime = %v, want %v", now, want)
	}
}

func TestResolveNow_Invalid(t *testing.T) {
	_, err := ResolveEvalTime("bad-format")
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
	w := ResolveStdout(&buf, true, appcontracts.FormatText)
	if w != io.Discard {
		t.Fatal("expected io.Discard for quiet+text")
	}
}

func TestResolveStdout_QuietJSON(t *testing.T) {
	var buf bytes.Buffer
	w := ResolveStdout(&buf, true, appcontracts.FormatJSON)
	if w == io.Discard {
		t.Fatal("quiet+json should preserve writer for piping")
	}
}

func TestResolveStdout_NotQuiet(t *testing.T) {
	var buf bytes.Buffer
	w := ResolveStdout(&buf, false, appcontracts.FormatText)
	if w != &buf {
		t.Fatal("non-quiet should return original writer")
	}
}

func TestResolveStdout_NilWriter(t *testing.T) {
	w := ResolveStdout(nil, false, appcontracts.FormatText)
	if w == nil {
		t.Fatal("nil writer should be replaced with os.Stdout")
	}
}

// --- ResolveFormatValue ---

func TestResolveFormatValue_Text(t *testing.T) {
	f, err := ResolveFormatValue("text")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != appcontracts.FormatText {
		t.Fatalf("format = %q, want text", f)
	}
}

func TestResolveFormatValue_JSON(t *testing.T) {
	f, err := ResolveFormatValue("json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != appcontracts.FormatJSON {
		t.Fatalf("format = %q, want json", f)
	}
}

func TestResolveFormatValue_SARIF(t *testing.T) {
	f, err := ResolveFormatValue("sarif")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != appcontracts.FormatSARIF {
		t.Fatalf("format = %q, want sarif", f)
	}
}

func TestResolveFormatValue_Invalid(t *testing.T) {
	_, err := ResolveFormatValue("xml")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestResolveFormatValue_CaseInsensitive(t *testing.T) {
	f, err := ResolveFormatValue("JSON")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != appcontracts.FormatJSON {
		t.Fatalf("format = %q, want json", f)
	}
}

// --- DefaultFindingWriter ---

func TestDefaultFindingWriter_Text(t *testing.T) {
	fw, err := DefaultFindingWriter(appcontracts.FormatText, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestDefaultFindingWriter_JSON(t *testing.T) {
	fw, err := DefaultFindingWriter(appcontracts.FormatJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestDefaultFindingWriter_SARIF(t *testing.T) {
	fw, err := DefaultFindingWriter(appcontracts.FormatSARIF, false)
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

// --- DefaultFactories ---

func TestDefaultFactories_NotNil(t *testing.T) {
	f := DefaultFactories()
	if f.NewObsRepo == nil {
		t.Fatal("NewObsRepo should not be nil")
	}
	if f.NewCtlRepo == nil {
		t.Fatal("NewCtlRepo should not be nil")
	}
	if f.NewStdinObsRepo == nil {
		t.Fatal("NewStdinObsRepo should not be nil")
	}
	if f.NewFindingWriter == nil {
		t.Fatal("NewFindingWriter should not be nil")
	}
	if f.NewCELEvaluator == nil {
		t.Fatal("NewCELEvaluator should not be nil")
	}
	if f.NewSnapshotRepo == nil {
		t.Fatal("NewSnapshotRepo should not be nil")
	}
}

func TestDefaultFactories_Callable(t *testing.T) {
	f := DefaultFactories()

	if _, err := f.NewObsRepo(); err != nil {
		t.Fatalf("NewObsRepo() error: %v", err)
	}
	if _, err := f.NewCtlRepo(); err != nil {
		t.Fatalf("NewCtlRepo() error: %v", err)
	}
	if _, err := f.NewCELEvaluator(); err != nil {
		t.Fatalf("NewCELEvaluator() error: %v", err)
	}
	if _, err := f.NewSnapshotRepo(); err != nil {
		t.Fatalf("NewSnapshotRepo() error: %v", err)
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
		EvalTimeRaw:                "2026-01-15T00:00:00Z",
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
	if ec.Format != appcontracts.FormatJSON {
		t.Fatalf("Format = %q, want json", ec.Format)
	}
	want := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !ec.EvalTime.Equal(want) {
		t.Fatalf("Now = %v, want %v", ec.EvalTime, want)
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
		EvalTimeRaw:                "bad",
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
