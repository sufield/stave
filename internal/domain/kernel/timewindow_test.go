package kernel

import (
	"testing"
	"time"
)

func TestTimeWindow_Contains(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := TimeWindow{Start: base, End: base.Add(2 * time.Hour)}

	tests := []struct {
		name string
		t    time.Time
		want bool
	}{
		{"before window", base.Add(-1 * time.Hour), false},
		{"at start (inclusive)", base, true},
		{"inside window", base.Add(1 * time.Hour), true},
		{"at end (exclusive)", base.Add(2 * time.Hour), false},
		{"after window", base.Add(3 * time.Hour), false},
	}
	for _, tt := range tests {
		if got := w.Contains(tt.t); got != tt.want {
			t.Errorf("Contains(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTimeWindow_ContainsExclusive(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := TimeWindow{Start: base, End: base.Add(2 * time.Hour)}

	tests := []struct {
		name string
		t    time.Time
		want bool
	}{
		{"at start (exclusive)", base, false},
		{"inside window", base.Add(1 * time.Hour), true},
		{"at end (exclusive)", base.Add(2 * time.Hour), false},
	}
	for _, tt := range tests {
		if got := w.ContainsExclusive(tt.t); got != tt.want {
			t.Errorf("ContainsExclusive(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTimeWindow_Overlaps(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		a, b TimeWindow
		want bool
	}{
		{
			"disjoint before",
			TimeWindow{base, base.Add(1 * time.Hour)},
			TimeWindow{base.Add(2 * time.Hour), base.Add(3 * time.Hour)},
			false,
		},
		{
			"touching boundaries",
			TimeWindow{base, base.Add(1 * time.Hour)},
			TimeWindow{base.Add(1 * time.Hour), base.Add(2 * time.Hour)},
			false,
		},
		{
			"overlapping",
			TimeWindow{base, base.Add(2 * time.Hour)},
			TimeWindow{base.Add(1 * time.Hour), base.Add(3 * time.Hour)},
			true,
		},
		{
			"contained",
			TimeWindow{base, base.Add(4 * time.Hour)},
			TimeWindow{base.Add(1 * time.Hour), base.Add(2 * time.Hour)},
			true,
		},
	}
	for _, tt := range tests {
		if got := tt.a.Overlaps(tt.b); got != tt.want {
			t.Errorf("Overlaps(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTimeWindow_Span(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := TimeWindow{Start: base, End: base.Add(3 * time.Hour)}
	if got := w.Span(); got != 3*time.Hour {
		t.Errorf("Span() = %v, want 3h", got)
	}
}
