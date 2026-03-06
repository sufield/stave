package ui

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestSeverityLabel_NoColorWriter(t *testing.T) {
	var buf bytes.Buffer
	got := SeverityLabel("error", "something failed", &buf)
	if got != "[ERR] something failed" {
		t.Fatalf("unexpected label: %q", got)
	}
}

func TestSeverityLabel_NO_COLOR(t *testing.T) {
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "1")
	got := SeverityLabel("warn", "check this", os.Stdout)
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("expected no ANSI escapes when NO_COLOR is set, got: %q", got)
	}
}

func TestCanColor_TERMDumb(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if CanColor(os.Stdout) {
		t.Fatal("expected color to be disabled for TERM=dumb")
	}
}

func TestCanColor_CachesTTYCheckPerWriter(t *testing.T) {
	origNoColor, hadNoColor := os.LookupEnv("NO_COLOR")
	_ = os.Unsetenv("NO_COLOR")
	t.Cleanup(func() {
		if hadNoColor {
			_ = os.Setenv("NO_COLOR", origNoColor)
			return
		}
		_ = os.Unsetenv("NO_COLOR")
	})
	t.Setenv("TERM", "xterm")

	orig := detectTTY
	resetTTYCacheForTest()
	t.Cleanup(func() {
		detectTTY = orig
		resetTTYCacheForTest()
	})

	calls := 0
	detectTTY = func(f *os.File) bool {
		calls++
		return false
	}

	if CanColor(os.Stdout) {
		t.Fatal("expected false from stubbed tty detector")
	}
	if CanColor(os.Stdout) {
		t.Fatal("expected false from cached tty detector")
	}
	if calls != 1 {
		t.Fatalf("expected detector to be called once, got %d", calls)
	}
}

func TestRuntimeSeverityLabel_RespectsNoColor(t *testing.T) {
	var stderr bytes.Buffer
	rt := NewRuntime(&bytes.Buffer{}, &stderr)
	rt.NoColor = true
	got := rt.SeverityLabel("error", "failed")
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("expected no ANSI escapes when runtime NoColor=true, got: %q", got)
	}
	if got != "[ERR] failed" {
		t.Fatalf("unexpected label: %q", got)
	}
}

func TestRuntimeCanColor_UsesIsTTYOverride(t *testing.T) {
	var out bytes.Buffer
	rt := NewRuntime(&bytes.Buffer{}, &out)
	isTTY := true
	rt.IsTTY = &isTTY
	rt.NoColor = false

	t.Setenv("TERM", "xterm")
	origNoColor, hadNoColor := os.LookupEnv("NO_COLOR")
	_ = os.Unsetenv("NO_COLOR")
	t.Cleanup(func() {
		if hadNoColor {
			_ = os.Setenv("NO_COLOR", origNoColor)
			return
		}
		_ = os.Unsetenv("NO_COLOR")
	})

	if !rt.CanColor(&out) {
		t.Fatal("expected color to be enabled via IsTTY override")
	}
}
