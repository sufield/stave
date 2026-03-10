package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCountedProgress_TTY(t *testing.T) {
	var stderr bytes.Buffer
	isTTY := true
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.IsTTY = &isTTY

	cp := rt.BeginCountedProgress("loading observations")
	cp.Update(3, 10)
	time.Sleep(150 * time.Millisecond)
	cp.Done()

	out := stderr.String()
	if !strings.Contains(out, "loading observations") {
		t.Fatalf("missing label in output: %q", out)
	}
	if !strings.Contains(out, "Done:    loading observations") {
		t.Fatalf("missing done message: %q", out)
	}
	if !strings.Contains(out, "10 files") {
		t.Fatalf("missing file count in done message: %q", out)
	}
}

func TestCountedProgress_NonTTY(t *testing.T) {
	var stderr bytes.Buffer
	isTTY := false
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.IsTTY = &isTTY

	cp := rt.BeginCountedProgress("loading observations")
	cp.Update(5, 20)
	cp.Done()

	out := stderr.String()
	if !strings.Contains(out, "Running: loading observations...") {
		t.Fatalf("missing running message: %q", out)
	}
	if !strings.Contains(out, "Done:    loading observations (20 files,") {
		t.Fatalf("missing done message with file count: %q", out)
	}
}

func TestCountedProgress_Quiet(t *testing.T) {
	var stderr bytes.Buffer
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.Quiet = true

	cp := rt.BeginCountedProgress("should not appear")
	if cp != nil {
		t.Fatal("expected nil CountedProgress in quiet mode")
	}
	// nil receiver methods should be no-ops
	cp.Update(1, 5)
	cp.Done()

	if stderr.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got %q", stderr.String())
	}
}

func TestCountedProgress_NilRuntime(t *testing.T) {
	var rt *Runtime
	cp := rt.BeginCountedProgress("test")
	if cp != nil {
		t.Fatal("expected nil CountedProgress from nil runtime")
	}
	// nil receiver methods should be no-ops
	cp.Update(1, 5)
	cp.Done()
}

func TestCountedProgress_ZeroTotal(t *testing.T) {
	var stderr bytes.Buffer
	isTTY := false
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.IsTTY = &isTTY

	cp := rt.BeginCountedProgress("loading")
	cp.Done()

	out := stderr.String()
	// With zero total, should not show "0 files"
	if strings.Contains(out, "0 files") {
		t.Fatalf("should not show '0 files' for zero total: %q", out)
	}
}

func TestCountedProgress_SpinnerShowsCounts(t *testing.T) {
	var stderr bytes.Buffer
	isTTY := true
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.IsTTY = &isTTY

	cp := rt.BeginCountedProgress("processing")
	cp.Update(7, 42)
	time.Sleep(150 * time.Millisecond)
	cp.Done()

	out := stderr.String()
	if !strings.Contains(out, "[7/42]") {
		t.Fatalf("spinner should show file counts: %q", out)
	}
}
