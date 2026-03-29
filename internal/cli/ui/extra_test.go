package ui

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestErrorInfo_Error_WithTitle(t *testing.T) {
	info := &ErrorInfo{Code: CodeIOError, Title: "Read failed", Message: "file not found"}
	got := info.Error()
	if got != "[IO_ERROR] Read failed: file not found" {
		t.Errorf("Error() = %q", got)
	}
}

func TestErrorInfo_Error_WithoutTitle(t *testing.T) {
	info := &ErrorInfo{Code: CodeIOError, Message: "file not found"}
	got := info.Error()
	if got != "[IO_ERROR] file not found" {
		t.Errorf("Error() = %q", got)
	}
}

func TestErrorInfo_Error_Nil(t *testing.T) {
	var info *ErrorInfo
	if info.Error() != "" {
		t.Errorf("nil ErrorInfo.Error() = %q, want empty", info.Error())
	}
}

func TestUserError(t *testing.T) {
	inner := errors.New("bad flag")
	ue := &UserError{Err: inner}
	if ue.Error() != "bad flag" {
		t.Errorf("UserError.Error() = %q", ue.Error())
	}
	if ue.Unwrap() != inner {
		t.Error("UserError.Unwrap() mismatch")
	}
}

func TestExitCode_UserError(t *testing.T) {
	ue := &UserError{Err: errors.New("bad input")}
	if ExitCode(ue) != ExitInputError {
		t.Errorf("ExitCode(UserError) = %d, want %d", ExitCode(ue), ExitInputError)
	}
}

func TestExitCode_InternalError(t *testing.T) {
	err := ErrInternal
	if ExitCode(err) != ExitInternal {
		t.Errorf("ExitCode(ErrInternal) = %d, want %d", ExitCode(err), ExitInternal)
	}
}

func TestWithEvidence_NilReceiver(t *testing.T) {
	var info *ErrorInfo
	result := info.WithEvidence("k", "v")
	if result != nil {
		t.Error("expected nil from WithEvidence on nil receiver")
	}
}

func TestWithTitle_NilReceiver(t *testing.T) {
	var info *ErrorInfo
	result := info.WithTitle("title")
	if result != nil {
		t.Error("expected nil from WithTitle on nil receiver")
	}
}

func TestWriteErrorText_NilInfo(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteErrorText(&buf, nil); err != nil {
		t.Fatalf("WriteErrorText(nil) error = %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestWriteErrorText_WithEvidence(t *testing.T) {
	var buf bytes.Buffer
	info := NewErrorInfo(CodeIOError, "not found").
		WithEvidence("path", "/tmp/x")
	if err := WriteErrorText(&buf, info); err != nil {
		t.Fatalf("WriteErrorText error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Evidence:") {
		t.Errorf("missing Evidence section in output: %s", out)
	}
	if !strings.Contains(out, "path: /tmp/x") {
		t.Errorf("missing evidence detail: %s", out)
	}
}

func TestWriteErrorText_DefaultTitle(t *testing.T) {
	var buf bytes.Buffer
	info := NewErrorInfo(CodeInternalError, "something went wrong")
	if err := WriteErrorText(&buf, info); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Execution failed") {
		t.Errorf("missing default title: %s", out)
	}
}

func TestDirectoryAccessError_NotExist(t *testing.T) {
	err := DirectoryAccessError("--controls", "/missing/path", os.ErrNotExist, ErrHintControlsNotAccessible)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("unexpected error message: %v", err)
	}
	if !errors.Is(err, ErrHintControlsNotAccessible) {
		t.Error("expected hint sentinel in error chain")
	}
}

func TestDirectoryAccessError_Permission(t *testing.T) {
	err := DirectoryAccessError("--observations", "/secret", os.ErrPermission, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDirectoryAccessError_OtherError(t *testing.T) {
	err := DirectoryAccessError("--controls", "/broken", errors.New("disk error"), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not accessible") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDirectoryAccessError_NilError(t *testing.T) {
	err := DirectoryAccessError("--controls", "/path", nil, nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestParseOutputFormat_ValidFormats(t *testing.T) {
	tests := []struct {
		input string
		want  OutputFormat
	}{
		{"text", OutputFormatText},
		{"json", OutputFormatJSON},
		{"sarif", OutputFormatSARIF},
		{"markdown", OutputFormatMarkdown},
		{"TEXT", OutputFormatText},
		{"JSON", OutputFormatJSON},
		{" json ", OutputFormatJSON},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseOutputFormat(tt.input)
			if err != nil {
				t.Fatalf("ParseOutputFormat(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseOutputFormat(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseOutputFormat_Invalid(t *testing.T) {
	_, err := ParseOutputFormat("xml")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "invalid --format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseOutputFormat_CloseSuggestion(t *testing.T) {
	_, err := ParseOutputFormat("jso")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("expected suggestion, got: %v", err)
	}
}

func TestNormalizeToken(t *testing.T) {
	if got := NormalizeToken(" JSON "); got != "json" {
		t.Errorf("NormalizeToken = %q", got)
	}
}

func TestEnumError_WithSuggestion(t *testing.T) {
	err := EnumError("--severity", "hig", []string{"high", "medium", "low"})
	if !strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("expected suggestion, got: %v", err)
	}
}

func TestEnumError_NoSuggestion(t *testing.T) {
	err := EnumError("--severity", "xyz", []string{"high", "medium", "low"})
	if strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("unexpected suggestion for distant input: %v", err)
	}
}

func TestEnumList(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{nil, ""},
		{[]string{"a"}, "use a"},
		{[]string{"a", "b"}, "use a or b"},
		{[]string{"a", "b", "c"}, "use a, b, or c"},
	}
	for _, tt := range tests {
		got := enumList(tt.input)
		if got != tt.want {
			t.Errorf("enumList(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWithHint_NilErr(t *testing.T) {
	result := WithHint(nil, ErrHintNoControls)
	if result != nil {
		t.Error("WithHint(nil, ...) should return nil")
	}
}

func TestWithHint_NilHint(t *testing.T) {
	err := errors.New("base")
	result := WithHint(err, nil)
	if result != err {
		t.Error("WithHint(err, nil) should return original err")
	}
}

func TestWithHint_AlreadyContainsSentinel(t *testing.T) {
	err := WithHint(errors.New("base"), ErrHintNoControls)
	// Apply same hint again
	result := WithHint(err, ErrHintNoControls)
	if result != err {
		t.Error("WithHint should skip if sentinel already in chain")
	}
}

func TestWithNextCommand_NilErr(t *testing.T) {
	result := WithNextCommand(nil, "stave apply")
	if result != nil {
		t.Error("WithNextCommand(nil, ...) should return nil")
	}
}

func TestWithNextCommand_EmptyCommand(t *testing.T) {
	err := errors.New("base")
	result := WithNextCommand(err, "")
	if result != err {
		t.Error("WithNextCommand(err, '') should return original err")
	}
}

func TestWithNextCommand_AppendsNext(t *testing.T) {
	err := errors.New("base")
	result := WithNextCommand(err, "stave apply")
	if !strings.Contains(result.Error(), "Next: stave apply") {
		t.Errorf("unexpected error: %v", result)
	}
}

func TestHintedError_Error_Nil(t *testing.T) {
	var he *hintedError
	if he.Error() != "" {
		t.Errorf("nil hintedError.Error() = %q", he.Error())
	}
}

func TestHintedError_Unwrap_Nil(t *testing.T) {
	var he *hintedError
	if he.Unwrap() != nil {
		t.Error("nil hintedError.Unwrap() should be nil")
	}
}

func TestHintedError_Is_Nil(t *testing.T) {
	var he *hintedError
	if he.Is(ErrHintNoControls) {
		t.Error("nil hintedError.Is() should be false")
	}
}

func TestHintedError_As_Nil(t *testing.T) {
	var he *hintedError
	var target *UserError
	if he.As(&target) {
		t.Error("nil hintedError.As() should be false")
	}
}

func TestSuggestForError_Nil(t *testing.T) {
	hint := SuggestForError(nil)
	if hint.NextCommand != "" {
		t.Errorf("expected empty hint for nil error, got: %+v", hint)
	}
}

func TestSuggestForError_UnknownError(t *testing.T) {
	hint := SuggestForError(errors.New("completely unknown error message"))
	if hint.Reason != "Unknown error encountered." {
		t.Errorf("expected unknown hint, got: %+v", hint)
	}
}

func TestEvaluateErrorWithHint_Nil(t *testing.T) {
	if err := EvaluateErrorWithHint(nil); err != nil {
		t.Errorf("EvaluateErrorWithHint(nil) = %v", err)
	}
}

func TestBuildSearchQueryFromError_Empty(t *testing.T) {
	got := buildSearchQueryFromError("")
	if got != "troubleshooting" {
		t.Errorf("buildSearchQueryFromError('') = %q", got)
	}
}

func TestSeverityDecor(t *testing.T) {
	tests := []struct {
		level      string
		wantSymbol string
	}{
		{"error", "[ERR]"},
		{"err", "[ERR]"},
		{"warning", "[WARN]"},
		{"warn", "[WARN]"},
		{"success", "[OK]"},
		{"ok", "[OK]"},
		{"info", "[INFO]"},
		{"unknown", "[INFO]"},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			sym, _ := severityDecor(tt.level)
			if sym != tt.wantSymbol {
				t.Errorf("severityDecor(%q) symbol = %q, want %q", tt.level, sym, tt.wantSymbol)
			}
		})
	}
}

func TestRenderSeverityLabel_NoColor(t *testing.T) {
	got := renderSeverityLabel("error", "something broke", false)
	if got != "[ERR] something broke" {
		t.Errorf("got %q", got)
	}
}

func TestRenderSeverityLabel_WithColor(t *testing.T) {
	got := renderSeverityLabel("error", "something broke", true)
	if !strings.Contains(got, "\x1b[31m") {
		t.Errorf("expected ANSI color, got %q", got)
	}
	if !strings.Contains(got, "[ERR]") {
		t.Errorf("expected [ERR], got %q", got)
	}
}

func TestSeverityLabel_NonTTY(t *testing.T) {
	var buf bytes.Buffer
	got := SeverityLabel("error", "test", &buf)
	// buf is not an *os.File, so should not get color
	if strings.Contains(got, "\x1b[") {
		t.Errorf("expected no ANSI for non-file writer, got %q", got)
	}
}
