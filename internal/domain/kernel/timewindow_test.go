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
		{
			"invalid window returns false",
			TimeWindow{},
			TimeWindow{base, base.Add(1 * time.Hour)},
			false,
		},
	}
	for _, tt := range tests {
		if got := tt.a.Overlaps(tt.b); got != tt.want {
			t.Errorf("Overlaps(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTimeWindow_Duration(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := TimeWindow{Start: base, End: base.Add(3 * time.Hour)}
	if got := w.Duration(); got != 3*time.Hour {
		t.Errorf("Duration() = %v, want 3h", got)
	}
}

func TestTimeWindow_Duration_Inverted(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := TimeWindow{Start: base.Add(3 * time.Hour), End: base}
	if got := w.Duration(); got != 0 {
		t.Errorf("Duration() on inverted window = %v, want 0", got)
	}
}

func TestNewTimeWindow_SwapsIfInverted(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := base.Add(2 * time.Hour)
	w := NewTimeWindow(end, base) // inverted
	if w.Start != base || w.End != end {
		t.Errorf("NewTimeWindow should swap inverted times, got Start=%v End=%v", w.Start, w.End)
	}
}

func TestTimeWindow_IsValid(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		w    TimeWindow
		want bool
	}{
		{"valid", TimeWindow{base, base.Add(1 * time.Hour)}, true},
		{"equal start and end", TimeWindow{base, base}, true},
		{"zero start", TimeWindow{time.Time{}, base}, false},
		{"zero end", TimeWindow{base, time.Time{}}, false},
		{"both zero", TimeWindow{}, false},
		{"inverted", TimeWindow{base.Add(1 * time.Hour), base}, false},
	}
	for _, tt := range tests {
		if got := tt.w.IsValid(); got != tt.want {
			t.Errorf("IsValid(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTimeWindow_IsZero(t *testing.T) {
	if !(TimeWindow{}).IsZero() {
		t.Error("zero-value TimeWindow should be IsZero")
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if (TimeWindow{Start: base}).IsZero() {
		t.Error("non-zero Start should not be IsZero")
	}
}

func TestTimeWindow_String(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w := TimeWindow{Start: base, End: base.Add(2 * time.Hour)}
	want := "[2026-01-01T00:00:00Z, 2026-01-01T02:00:00Z)"
	if got := w.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestTimeWindow_String_Invalid(t *testing.T) {
	w := TimeWindow{}
	if got := w.String(); got != "[invalid window]" {
		t.Errorf("String() on zero window = %q, want [invalid window]", got)
	}
}
