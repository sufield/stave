package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestExecuteTemplate_SimpleField(t *testing.T) {
	var buf bytes.Buffer
	data := struct{ Name string }{Name: "test"}
	err := ExecuteTemplate(&buf, "Hello {{.Name}}", data)
	if err != nil {
		t.Fatalf("ExecuteTemplate error = %v", err)
	}
	if buf.String() != "Hello test" {
		t.Errorf("got %q", buf.String())
	}
}

func TestExecuteTemplate_JSONFunc(t *testing.T) {
	var buf bytes.Buffer
	data := struct{ Items []string }{Items: []string{"a", "b"}}
	err := ExecuteTemplate(&buf, `{{json .Items}}`, data)
	if err != nil {
		t.Fatalf("ExecuteTemplate error = %v", err)
	}
	if !strings.Contains(buf.String(), `"a"`) {
		t.Errorf("got %q", buf.String())
	}
}

func TestExecuteTemplate_RangeIteration(t *testing.T) {
	var buf bytes.Buffer
	data := struct{ Items []string }{Items: []string{"x", "y"}}
	err := ExecuteTemplate(&buf, `{{range .Items}}{{.}} {{end}}`, data)
	if err != nil {
		t.Fatalf("ExecuteTemplate error = %v", err)
	}
	if buf.String() != "x y " {
		t.Errorf("got %q", buf.String())
	}
}

func TestExecuteTemplate_InvalidTemplate(t *testing.T) {
	var buf bytes.Buffer
	err := ExecuteTemplate(&buf, "{{.Unclosed", nil)
	if err == nil || !strings.Contains(err.Error(), "template parse") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestExecuteTemplate_DisallowedFunction(t *testing.T) {
	var buf bytes.Buffer
	// "template" is disallowed
	err := ExecuteTemplate(&buf, `{{template "x"}}`, nil)
	if err == nil || !strings.Contains(err.Error(), "template security") {
		t.Fatalf("expected security error, got: %v", err)
	}
}

func TestSuggestFlagParseError_EmptyCandidates(t *testing.T) {
	err := errors.New("unknown flag 'x'")
	result := SuggestFlagParseError(err, nil)
	if result != err {
		t.Error("expected original error for empty candidates")
	}
}

func TestSuggestFlagParseError_WithSuggestion(t *testing.T) {
	err := errors.New("unknown flag '--fromat'")
	result := SuggestFlagParseError(err, []string{"--format", "--force", "--file"})
	if result == nil {
		t.Fatal("expected non-nil error")
	}
	if !strings.Contains(result.Error(), "Did you mean") {
		t.Errorf("expected suggestion, got: %v", result)
	}
}

func TestSuggestFlagParseError_NoQuotedToken(t *testing.T) {
	// Error message without quotes, with flag-like last word
	err := errors.New("unknown flag --xyz")
	result := SuggestFlagParseError(err, []string{"--abc"})
	// xyz is far from abc so no suggestion
	if result == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestExtractBetween(t *testing.T) {
	val, ok := extractBetween("foo 'bar' baz", "'")
	if !ok || val != "bar" {
		t.Errorf("extractBetween = (%q, %v)", val, ok)
	}
	_, ok = extractBetween("no quotes", "'")
	if ok {
		t.Error("expected false for no quotes")
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"x", "-x"},
		{"--format", "--format"},
		{"-f", "-f"},
	}
	for _, tt := range tests {
		got := normalize(tt.input)
		if got != tt.want {
			t.Errorf("normalize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewRuntime_NilArgs(t *testing.T) {
	r := NewRuntime(nil, nil)
	if r.Stdout == nil || r.Stderr == nil {
		t.Error("expected non-nil stdout/stderr")
	}
}

func TestDefaultRuntime(t *testing.T) {
	r := DefaultRuntime()
	if r.Stdout == nil || r.Stderr == nil {
		t.Error("expected non-nil stdout/stderr")
	}
}

// WriteHint already tested in runtime_test.go

func TestShouldShowWorkflowHandoff_WithShortFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"short help", []string{"-h"}, false},
		{"mixed flags", []string{"apply", "--format", "json"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldShowWorkflowHandoff(tt.args)
			if got != tt.want {
				t.Errorf("ShouldShowWorkflowHandoff(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestRuntime_PrintNextSteps(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf}
	r.PrintNextSteps("step one", "step two")
	out := buf.String()
	if !strings.Contains(out, "Next steps:") {
		t.Errorf("missing header: %q", out)
	}
	if !strings.Contains(out, "1. step one") {
		t.Errorf("missing step 1: %q", out)
	}
	if !strings.Contains(out, "2. step two") {
		t.Errorf("missing step 2: %q", out)
	}
}

func TestRuntime_PrintNextSteps_Quiet(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf, Quiet: true}
	r.PrintNextSteps("step one")
	if buf.Len() != 0 {
		t.Error("expected no output in quiet mode")
	}
}

func TestRuntime_PrintNextSteps_Empty(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf}
	r.PrintNextSteps()
	if buf.Len() != 0 {
		t.Error("expected no output for empty steps")
	}
}

func TestRuntime_PrintNextSteps_Nil(t *testing.T) {
	var r *Runtime
	r.PrintNextSteps("step") // should not panic
}

func TestRuntime_BeginProgress_Quiet(t *testing.T) {
	r := &Runtime{Quiet: true}
	done := r.BeginProgress("test")
	done() // should not panic
}

func TestRuntime_BeginProgress_Nil(t *testing.T) {
	var r *Runtime
	done := r.BeginProgress("test")
	done() // should not panic
}

func TestRuntime_BeginProgress_NonTTY(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf}
	done := r.BeginProgress("loading")
	done()
	out := buf.String()
	if !strings.Contains(out, "Running: loading") {
		t.Errorf("missing Running message: %q", out)
	}
	if !strings.Contains(out, "Done:    loading") {
		t.Errorf("missing Done message: %q", out)
	}
}

func TestCountedProgress_Nil(t *testing.T) {
	var cp *CountedProgress
	cp.Update(1, 10) // should not panic
	cp.Done()        // should not panic
}

func TestRuntime_BeginCountedProgress_Quiet(t *testing.T) {
	r := &Runtime{Quiet: true}
	cp := r.BeginCountedProgress("test")
	if cp != nil {
		t.Error("expected nil progress in quiet mode")
	}
}

func TestRuntime_BeginCountedProgress_Nil(t *testing.T) {
	var r *Runtime
	cp := r.BeginCountedProgress("test")
	if cp != nil {
		t.Error("expected nil progress for nil runtime")
	}
}

func TestRuntime_BeginCountedProgress_NonTTY(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf}
	cp := r.BeginCountedProgress("loading")
	cp.Update(5, 10)
	cp.Done()
	out := buf.String()
	if !strings.Contains(out, "Running: loading") {
		t.Errorf("missing Running: %q", out)
	}
	if !strings.Contains(out, "Done:    loading") {
		t.Errorf("missing Done: %q", out)
	}
}

func TestRuntime_PrintWorkflowHandoff(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf}
	r.PrintWorkflowHandoff(WorkflowHandoffRequest{
		Args:        []string{"apply"},
		ProjectRoot: "/project",
	})
	out := buf.String()
	if !strings.Contains(out, "Next workflow start:") {
		t.Errorf("missing handoff message: %q", out)
	}
}

func TestRuntime_PrintWorkflowHandoff_Quiet(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf, Quiet: true}
	r.PrintWorkflowHandoff(WorkflowHandoffRequest{
		Args:        []string{"apply"},
		ProjectRoot: "/project",
	})
	if buf.Len() != 0 {
		t.Error("expected no output in quiet mode")
	}
}

func TestRuntime_PrintWorkflowHandoff_NoProjectRoot(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf}
	r.PrintWorkflowHandoff(WorkflowHandoffRequest{
		Args: []string{"apply"},
	})
	if buf.Len() != 0 {
		t.Error("expected no output without project root")
	}
}

func TestRuntime_PrintWorkflowHandoff_WithNextCommand(t *testing.T) {
	var buf bytes.Buffer
	r := &Runtime{Stderr: &buf}
	r.PrintWorkflowHandoff(WorkflowHandoffRequest{
		Args:        []string{"apply"},
		ProjectRoot: "/project",
		NextCommand: func(string) (string, error) {
			return "stave verify", nil
		},
	})
	out := buf.String()
	if !strings.Contains(out, "stave verify") {
		t.Errorf("expected custom next command: %q", out)
	}
}

func TestIsTerminal_NonFile(t *testing.T) {
	var buf bytes.Buffer
	if IsTerminal(&buf) {
		t.Error("non-file writer should not be terminal")
	}
}

func TestPrompter_Confirm_Yes(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("y\n"), &out)
	if !p.Confirm("proceed?") {
		t.Error("expected true for 'y'")
	}
}

func TestPrompter_Confirm_No(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader("n\n"), &out)
	if p.Confirm("proceed?") {
		t.Error("expected false for 'n'")
	}
}

func TestPrompter_Confirm_EOF(t *testing.T) {
	var out bytes.Buffer
	p := NewPrompter(strings.NewReader(""), &out)
	if p.Confirm("proceed?") {
		t.Error("expected false for EOF")
	}
}
