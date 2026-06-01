package alert

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

func TestFormatCEF_Basic(t *testing.T) {
	a := ports.WatchAlert{
		Timestamp:     time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC),
		Transition:    ports.TransitionRegression,
		SecurityState: "NON_COMPLIANT",
		Violations:    5,
		NewViolations: 2,
	}

	line := FormatCEF(a)

	if !strings.HasPrefix(line, "CEF:0|Stave|stave-watch|") {
		t.Errorf("CEF header wrong: %s", line)
	}
	if !strings.Contains(line, "REGRESSION") {
		t.Error("should contain transition REGRESSION")
	}
	if !strings.Contains(line, "cn1=5") {
		t.Error("should contain cn1=5 (violations)")
	}
	if !strings.Contains(line, "cn2=2") {
		t.Error("should contain cn2=2 (new violations)")
	}
	if !strings.Contains(line, "|8|") {
		t.Error("REGRESSION should have CEF severity 8")
	}
}

func TestFormatCEF_WithSLA(t *testing.T) {
	a := ports.WatchAlert{
		Timestamp:         time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC),
		Transition:        ports.TransitionDegradation,
		SecurityState:     "AT_RISK",
		Violations:        10,
		NewViolations:     3,
		ActiveSLABreaches: 2,
		MaxDwellTimeHours: 480,
	}

	line := FormatCEF(a)
	if !strings.Contains(line, "cn3=2") {
		t.Error("should contain SLA breaches")
	}
	if !strings.Contains(line, "cfp1=480.0") {
		t.Error("should contain max dwell hours")
	}
	if !strings.Contains(line, "|6|") {
		t.Error("DEGRADATION should have CEF severity 6")
	}
}

func TestFormatCEF_Error(t *testing.T) {
	a := ports.WatchAlert{
		Timestamp:    time.Date(2025, 11, 15, 14, 0, 0, 0, time.UTC),
		Transition:   ports.TransitionError,
		ErrorMessage: "snapshot parse failed",
	}

	line := FormatCEF(a)
	if !strings.Contains(line, "|10|") {
		t.Error("ERROR should have CEF severity 10")
	}
	if !strings.Contains(line, "msg=snapshot parse failed") {
		t.Error("should contain error message")
	}
}

func TestCEFEscape(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`hello`, `hello`},
		{`back\slash`, `back\\slash`},
		{`pipe|char`, `pipe\|char`},
		{`eq=sign`, `eq\=sign`},
		{"new\nline", `new\nline`},
		{`all\|=` + "\n", `all\\\|\=\n`},
	}
	for _, tt := range tests {
		got := cefEscape(tt.input)
		if got != tt.want {
			t.Errorf("cefEscape(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCEFFileSink_WritesToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.cef")
	sink, err := NewCEFFileSink(path)
	if err != nil {
		t.Fatal(err)
	}

	a := ports.WatchAlert{
		Timestamp:     time.Now(),
		Transition:    ports.TransitionStable,
		SecurityState: "COMPLIANT",
		Violations:    0,
	}
	if emitErr := sink.Emit(context.Background(), a); emitErr != nil {
		t.Fatal(emitErr)
	}
	if closeErr := sink.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "CEF:0|") {
		t.Errorf("file should start with CEF header, got: %s", string(data)[:40])
	}
}

func TestCEFFileSink_ConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.cef")
	sink, err := NewCEFFileSink(path)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			a := ports.WatchAlert{
				Timestamp:     time.Now(),
				Transition:    ports.TransitionStable,
				SecurityState: "COMPLIANT",
				Violations:    n,
			}
			_ = sink.Emit(context.Background(), a)
		}(i)
	}
	wg.Wait()
	sink.Close()

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 20 {
		t.Errorf("expected 20 lines, got %d", len(lines))
	}
	// Verify no interleaved lines.
	for i, line := range lines {
		if !strings.HasPrefix(line, "CEF:0|") {
			t.Errorf("line %d corrupted: %s", i, line[:min(40, len(line))])
		}
	}
}

func TestCEFTransitionSeverity(t *testing.T) {
	tests := []struct {
		transition ports.WatchTransition
		want       int
	}{
		{ports.TransitionRegression, 8},
		{ports.TransitionDegradation, 6},
		{ports.TransitionError, 10},
		{ports.TransitionRecovery, 3},
		{ports.TransitionStable, 1},
		{ports.TransitionInitial, 1},
	}
	for _, tt := range tests {
		got := tt.transition.CEFSeverity()
		if got != tt.want {
			t.Errorf("CEFSeverity(%s) = %d, want %d", tt.transition, got, tt.want)
		}
	}
}
