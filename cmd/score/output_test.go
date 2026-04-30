package score

import (
	"strings"
	"testing"
)

func TestScoreBar_BoundsAndShape(t *testing.T) {
	const filled = "█"
	const empty = "░"
	cases := []struct {
		name      string
		score     float64
		wantWidth int
		wantFill  int
	}{
		{"zero", 0, 20, 0},
		{"hundred", 100, 20, 20},
		{"fifty", 50, 20, 10},
		{"negative", -5, 20, 0},
		{"above 100", 250, 20, 20}, // clamp guard — used to overflow past 20 cells
		{"way above 100", 1e6, 20, 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bar := scoreBar(tc.score)
			width := strings.Count(bar, filled) + strings.Count(bar, empty)
			if width != tc.wantWidth {
				t.Errorf("bar width = %d, want %d (bar=%q)", width, tc.wantWidth, bar)
			}
			gotFill := strings.Count(bar, filled)
			if gotFill != tc.wantFill {
				t.Errorf("fill count = %d, want %d (bar=%q)", gotFill, tc.wantFill, bar)
			}
		})
	}
}
