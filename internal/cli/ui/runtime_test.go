package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestShouldShowWorkflowHandoff(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{args: []string{"apply"}, want: true},
		{args: []string{"init", "--dir", "./x"}, want: true},
		{args: []string{"status"}, want: false},
		{args: []string{"help"}, want: false},
		{args: []string{"--help"}, want: false},
		{args: []string{"--version"}, want: false},
	}

	for _, tt := range tests {
		got := ShouldShowWorkflowHandoff(tt.args)
		if got != tt.want {
			t.Fatalf("ShouldShowWorkflowHandoff(%v)=%v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestRuntimeBeginProgress_UsesInjectedStderr(t *testing.T) {
	var stderr bytes.Buffer
	isTTY := true
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.IsTTY = &isTTY

	done := rt.BeginProgress("sync data")
	time.Sleep(120 * time.Millisecond)
	done()

	out := stderr.String()
	if !strings.Contains(out, "Done:    sync data (") {
		t.Fatalf("missing done output: %q", out)
	}
	if !strings.Contains(out, "Running: sync data...") {
		t.Fatalf("missing spinner running output: %q", out)
	}
}

func TestRuntimeBeginProgress_QuietOrNoTTY(t *testing.T) {
	var stderr bytes.Buffer

	isTTY := true
	rtQuiet := NewRuntime(&bytes.Buffer{}, &stderr)
	rtQuiet.IsTTY = &isTTY
	rtQuiet.Quiet = true
	rtQuiet.BeginProgress("quiet mode")()
	if stderr.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got %q", stderr.String())
	}

	isNotTTY := false
	rtNoTTY := NewRuntime(&bytes.Buffer{}, &stderr)
	rtNoTTY.IsTTY = &isNotTTY
	rtNoTTY.BeginProgress("non-tty")()
	out := stderr.String()
	if !strings.Contains(out, "Running: non-tty...") {
		t.Fatalf("expected running output for non-tty, got %q", out)
	}
	if !strings.Contains(out, "Done:    non-tty (") {
		t.Fatalf("expected done output for non-tty, got %q", out)
	}
}

func TestRuntimePrintNextSteps(t *testing.T) {
	var stderr bytes.Buffer
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.PrintNextSteps("Do A", "Do B")

	out := stderr.String()
	if !strings.Contains(out, "Next steps:") {
		t.Fatalf("missing header: %q", out)
	}
	if !strings.Contains(out, "1. Do A") || !strings.Contains(out, "2. Do B") {
		t.Fatalf("missing steps: %q", out)
	}
}

func TestRuntimePrintWorkflowHandoff(t *testing.T) {
	var stderr bytes.Buffer
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.PrintWorkflowHandoff(WorkflowHandoffRequest{
		Args:        []string{"apply"},
		ProjectRoot: "/repo",
		NextCommand: func(string) (string, error) { return "stave diagnose", nil },
	})
	if got := stderr.String(); !strings.Contains(got, "Next workflow start: stave diagnose") {
		t.Fatalf("unexpected output: %q", got)
	}
}
