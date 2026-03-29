package status

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestFormatText_Basic(t *testing.T) {
	var buf bytes.Buffer
	result := Result{
		State: ProjectState{
			Root:         "/project",
			Controls:     Summary{Count: 5},
			RawSnapshots: Summary{Count: 3},
			Observations: Summary{Count: 2},
			HasEval:      true,
		},
		NextCommand: "stave apply",
	}
	err := FormatText(&buf, result)
	if err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Summary") {
		t.Fatal("missing Summary header")
	}
	if !strings.Contains(out, "/project") {
		t.Fatal("missing project root")
	}
	if !strings.Contains(out, "controls: 5") {
		t.Fatal("missing controls count")
	}
	if !strings.Contains(out, "snapshots/raw: 3") {
		t.Fatal("missing raw count")
	}
	if !strings.Contains(out, "observations: 2") {
		t.Fatal("missing observations count")
	}
	if !strings.Contains(out, "evaluation.json: true") {
		t.Fatal("missing eval status")
	}
	if !strings.Contains(out, "stave apply") {
		t.Fatal("missing next command")
	}
}

func TestFormatText_WithLastCommand(t *testing.T) {
	var buf bytes.Buffer
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	result := Result{
		State: ProjectState{
			Root:            "/project",
			LastCommand:     "stave validate",
			LastCommandTime: ts,
		},
		NextCommand: "stave apply",
	}
	err := FormatText(&buf, result)
	if err != nil {
		t.Fatalf("FormatText: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Last command: stave validate") {
		t.Fatal("missing last command")
	}
	if !strings.Contains(out, "2026-01-15T10:00:00Z") {
		t.Fatal("missing last command time")
	}
}
