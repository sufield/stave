package monitor

import (
	"bytes"
	"strings"
	"testing"
)

func TestSparkline(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   int // expected length in runes
	}{
		{"empty", nil, 0},
		{"single", []float64{50}, 1},
		{"ascending", []float64{10, 20, 30, 40, 50, 60, 70, 80}, 8},
		{"flat", []float64{50, 50, 50}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sparkline(tt.values)
			runes := []rune(got)
			if len(runes) != tt.want {
				t.Errorf("Sparkline len = %d runes, want %d (got %q)", len(runes), tt.want, got)
			}
		})
	}
}

func TestSparkline_AscendingOrder(t *testing.T) {
	s := Sparkline([]float64{0, 25, 50, 75, 100})
	runes := []rune(s)
	// First should be lowest block, last should be highest.
	if runes[0] >= runes[len(runes)-1] {
		t.Errorf("ascending values should produce ascending blocks: %q", s)
	}
}

func TestBar_Proportional(t *testing.T) {
	c := colorFuncs(false)
	b := bar(5, 10, "", c)
	filled := strings.Count(b, "█")
	empty := strings.Count(b, "░")
	if filled != 10 {
		t.Errorf("bar filled = %d, want 10", filled)
	}
	if empty != 10 {
		t.Errorf("bar empty = %d, want 10", empty)
	}
}

func TestGauge(t *testing.T) {
	g := gauge(0.5, 10)
	if strings.Count(g, "█") != 5 {
		t.Errorf("gauge at 50%%: filled = %d, want 5", strings.Count(g, "█"))
	}
	if strings.Count(g, "░") != 5 {
		t.Errorf("gauge at 50%%: empty = %d, want 5", strings.Count(g, "░"))
	}
}

func TestRenderPlain_NoANSI(t *testing.T) {
	state := &State{
		GeneratedAt: "2026-01-15 12:00:00",
		Score:       81.2,
		ScoreDelta:  4.1,
		ScoreTrend:  "IMPROVING",
		Findings:    FindingSummary{Total: 10, Critical: 2, High: 3, Medium: 3, Low: 2},
	}
	var buf bytes.Buffer
	RenderPlain(&buf, state, false)
	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Error("plain output should not contain ANSI escape codes")
	}
	if !strings.Contains(out, "81.2") {
		t.Error("should contain posture score")
	}
	if !strings.Contains(out, "IMPROVING") {
		t.Error("should contain trend direction")
	}
}

func TestRenderPlain_WithColor(t *testing.T) {
	state := &State{
		GeneratedAt: "2026-01-15 12:00:00",
		Score:       45.0,
		ScoreTrend:  "REGRESSING",
		Findings:    FindingSummary{Total: 5, Critical: 5},
	}
	var buf bytes.Buffer
	RenderPlain(&buf, state, true)
	out := buf.String()
	if !strings.Contains(out, "\033[31m") {
		t.Error("score < 60 should be red")
	}
}

func TestColorThresholds(t *testing.T) {
	c := colorFuncs(true)
	// Green >= 80.
	if c.green == "" {
		t.Error("green should not be empty when color enabled")
	}
}
