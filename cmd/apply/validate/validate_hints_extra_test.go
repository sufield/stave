package validate

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestShellQuote_NoSpecialChars(t *testing.T) {
	if got := shellQuote("simple"); got != "simple" {
		t.Fatalf("got %q, want simple", got)
	}
}

func TestShellQuote_Spaces(t *testing.T) {
	got := shellQuote("has spaces")
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("expected quoted, got: %q", got)
	}
}

func TestShellQuote_SingleQuote(t *testing.T) {
	got := shellQuote("it's")
	if !strings.Contains(got, "\\'") {
		t.Fatalf("expected escaped single quote, got: %q", got)
	}
}

func TestShellQuote_ShellChars(t *testing.T) {
	for _, s := range []string{"$var", "`cmd`", "a|b", "a;b", "a&b"} {
		got := shellQuote(s)
		if !strings.HasPrefix(got, "'") {
			t.Errorf("shellQuote(%q) = %q, expected quoted", s, got)
		}
	}
}

func TestHintGenerateControl(t *testing.T) {
	issue := diag.Diagnostic{
		Code:     diag.CodeNoControls,
		Evidence: kernel.NewSanitizableMap(map[string]string{"control_id": "CTL.TEST.001"}),
	}
	ctx := hintContext{ControlsDir: "controls/s3"}
	got := hintGenerateControl(issue, ctx)
	if !strings.Contains(got, "stave generate control") {
		t.Fatalf("expected generate control command, got: %q", got)
	}
	if !strings.Contains(got, "CTL.TEST.001") {
		t.Fatalf("expected control ID, got: %q", got)
	}
}

func TestHintGenerateControl_EmptyControlsDir(t *testing.T) {
	issue := diag.Diagnostic{Code: diag.CodeNoControls}
	ctx := hintContext{}
	got := hintGenerateControl(issue, ctx)
	if got != "" {
		t.Fatalf("expected empty hint for empty controls dir, got: %q", got)
	}
}

func TestHintGenerateControl_NoControlID(t *testing.T) {
	issue := diag.Diagnostic{Code: diag.CodeNoControls}
	ctx := hintContext{ControlsDir: "controls"}
	got := hintGenerateControl(issue, ctx)
	if !strings.Contains(got, "EXAMPLE.CONTROL.ID") {
		t.Fatalf("expected fallback control ID, got: %q", got)
	}
}

func TestHintDiagnoseObservations(t *testing.T) {
	issue := diag.Diagnostic{Code: diag.CodeSnapshotsUnsorted}
	ctx := hintContext{ControlsDir: "controls", ObservationsDir: "observations"}
	got := hintDiagnoseObservations(issue, ctx)
	if !strings.Contains(got, "stave diagnose") {
		t.Fatalf("expected diagnose command, got: %q", got)
	}
	if !strings.Contains(got, "--controls") {
		t.Fatalf("expected --controls flag, got: %q", got)
	}
}

func TestHintDiagnoseObservations_NoDirs(t *testing.T) {
	issue := diag.Diagnostic{}
	ctx := hintContext{}
	got := hintDiagnoseObservations(issue, ctx)
	if got != "stave diagnose" {
		t.Fatalf("expected bare 'stave diagnose', got: %q", got)
	}
}

func TestHintValidateCoverage(t *testing.T) {
	issue := diag.Diagnostic{Code: diag.CodeSpanLessThanMaxUnsafe}
	ctx := hintContext{ControlsDir: "controls", ObservationsDir: "observations"}
	got := hintValidateCoverage(issue, ctx)
	if !strings.Contains(got, "stave validate") {
		t.Fatalf("expected validate command, got: %q", got)
	}
	if !strings.Contains(got, "--max-unsafe") {
		t.Fatalf("expected --max-unsafe flag, got: %q", got)
	}
}

func TestHintValidateCoverage_NoDirs(t *testing.T) {
	issue := diag.Diagnostic{}
	ctx := hintContext{}
	got := hintValidateCoverage(issue, ctx)
	if got != "stave validate" {
		t.Fatalf("expected bare 'stave validate', got: %q", got)
	}
}

func TestHintExplainControl(t *testing.T) {
	issue := diag.Diagnostic{
		Code:     diag.CodeControlUndefinedParam,
		Evidence: kernel.NewSanitizableMap(map[string]string{"control_id": "CTL.TEST.001"}),
	}
	ctx := hintContext{ControlsDir: "controls/s3"}
	got := hintExplainControl(issue, ctx)
	if !strings.Contains(got, "stave explain") {
		t.Fatalf("expected explain command, got: %q", got)
	}
	if !strings.Contains(got, "CTL.TEST.001") {
		t.Fatalf("expected control ID, got: %q", got)
	}
}

func TestHintExplainControl_FromPath(t *testing.T) {
	issue := diag.Diagnostic{
		Evidence: kernel.NewSanitizableMap(map[string]string{"path": "controls/s3/CTL.S3.PUBLIC.001.yaml"}),
	}
	ctx := hintContext{ControlsDir: "controls/s3"}
	got := hintExplainControl(issue, ctx)
	if !strings.Contains(got, "CTL.S3.PUBLIC.001.yaml") {
		t.Fatalf("expected filename from path, got: %q", got)
	}
}

func TestHintExplainControl_NoID(t *testing.T) {
	issue := diag.Diagnostic{}
	ctx := hintContext{ControlsDir: "controls"}
	got := hintExplainControl(issue, ctx)
	if got != "" {
		t.Fatalf("expected empty hint for no control ID, got: %q", got)
	}
}

func TestHintExplainControl_NoDirs(t *testing.T) {
	issue := diag.Diagnostic{
		Evidence: kernel.NewSanitizableMap(map[string]string{"control_id": "CTL.TEST.001"}),
	}
	ctx := hintContext{}
	got := hintExplainControl(issue, ctx)
	if !strings.Contains(got, "stave explain CTL.TEST.001") {
		t.Fatalf("expected explain command without --controls, got: %q", got)
	}
	if strings.Contains(got, "--controls") {
		t.Fatal("should not have --controls flag")
	}
}

func TestHintForIssue_KnownCode(t *testing.T) {
	issue := diag.Diagnostic{Code: diag.CodeNoControls}
	ctx := hintContext{ControlsDir: "controls"}
	got := hintForIssue(issue, ctx)
	if !strings.Contains(got, "stave generate") {
		t.Fatalf("expected hint for known code, got: %q", got)
	}
}

func TestHintForIssue_UnknownCodeWithPath(t *testing.T) {
	issue := diag.Diagnostic{
		Code:     diag.Code("UNKNOWN"),
		Evidence: kernel.NewSanitizableMap(map[string]string{"path": "controls/test.yaml"}),
	}
	ctx := hintContext{ControlsDir: "controls"}
	got := hintForIssue(issue, ctx)
	if !strings.Contains(got, "stave explain") {
		t.Fatalf("expected fallback to explain for unknown code with path, got: %q", got)
	}
}

func TestHintForIssue_UnknownCodeNoPath(t *testing.T) {
	issue := diag.Diagnostic{Code: diag.Code("UNKNOWN")}
	ctx := hintContext{}
	got := hintForIssue(issue, ctx)
	if got != "" {
		t.Fatalf("expected empty for unknown code without path, got: %q", got)
	}
}

func TestCollectHints_Nil(t *testing.T) {
	got := collectHints(nil, hintContext{})
	if got != nil {
		t.Fatalf("expected nil for nil result, got: %v", got)
	}
}

func TestCollectHints_Empty(t *testing.T) {
	got := collectHints(&diag.Report{}, hintContext{})
	if got != nil {
		t.Fatalf("expected nil for empty result, got: %v", got)
	}
}

func TestCollectHints_Dedupes(t *testing.T) {
	result := &diag.Report{
		Issues: []diag.Diagnostic{
			{Code: diag.CodeNoControls},
			{Code: diag.CodeNoControls},
		},
	}
	ctx := hintContext{ControlsDir: "controls"}
	got := collectHints(result, ctx)
	if len(got) != 1 {
		t.Fatalf("expected 1 unique hint, got %d: %v", len(got), got)
	}
}

func TestCollectHints_UsesExplicitCommand(t *testing.T) {
	result := &diag.Report{
		Issues: []diag.Diagnostic{
			{Command: "stave custom-command"},
		},
	}
	got := collectHints(result, hintContext{})
	if len(got) != 1 || got[0] != "stave custom-command" {
		t.Fatalf("expected explicit command, got: %v", got)
	}
}

func TestCollectHints_Sorted(t *testing.T) {
	result := &diag.Report{
		Issues: []diag.Diagnostic{
			{Command: "z-command"},
			{Command: "a-command"},
			{Command: "m-command"},
		},
	}
	got := collectHints(result, hintContext{})
	if len(got) != 3 {
		t.Fatalf("expected 3 hints, got %d", len(got))
	}
	if got[0] != "a-command" || got[1] != "m-command" || got[2] != "z-command" {
		t.Fatalf("hints not sorted: %v", got)
	}
}
