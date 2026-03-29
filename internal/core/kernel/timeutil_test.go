package kernel

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0h"},
		{"one hour", time.Hour, "1h"},
		{"24 hours = 1 day", 24 * time.Hour, "1d"},
		{"48 hours = 2 days", 48 * time.Hour, "2d"},
		{"168 hours = 7 days", 168 * time.Hour, "7d"},
		{"36 hours (not day-aligned)", 36 * time.Hour, "36h"},
		{"12 hours", 12 * time.Hour, "12h"},
		{"1.5 hours", 90 * time.Minute, "1.5h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatDuration(tt.d); got != tt.want {
				t.Errorf("FormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestFormatDurationHuman(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"zero", 0, "0h"},
		{"one hour", time.Hour, "1h"},
		{"24 hours = 1 day", 24 * time.Hour, "1d"},
		{"30 hours compound", 30 * time.Hour, "1d6h"},
		{"49 hours compound", 49 * time.Hour, "2d1h"},
		{"48 hours even", 48 * time.Hour, "2d"},
		{"5 hours", 5 * time.Hour, "5h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatDurationHuman(tt.d); got != tt.want {
				t.Errorf("FormatDurationHuman(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"simple hours", "168h", 168 * time.Hour, false},
		{"simple days", "7d", 168 * time.Hour, false},
		{"fractional days", "1.5d", 36 * time.Hour, false},
		{"compound days+hours", "1d12h", 36 * time.Hour, false},
		{"whitespace trimmed", "  24h  ", 24 * time.Hour, false},
		{"empty string", "", 0, true},
		{"whitespace only", "   ", 0, true},
		{"negative rejected", "-24h", 0, true},
		{"minutes", "30m", 30 * time.Minute, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseDuration(%q) error = nil, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDuration_Std(t *testing.T) {
	d := Duration(24 * time.Hour)
	if got := d.Std(); got != 24*time.Hour {
		t.Errorf("Std() = %v, want %v", got, 24*time.Hour)
	}
}

func TestDuration_String(t *testing.T) {
	d := Duration(168 * time.Hour)
	if got := d.String(); got != "7d" {
		t.Errorf("String() = %q, want %q", got, "7d")
	}
}

func TestDuration_MarshalJSON(t *testing.T) {
	d := Duration(24 * time.Hour)
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != `"1d"` {
		t.Errorf("MarshalJSON = %s, want %q", data, `"1d"`)
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"7d"`), &d); err != nil {
		t.Fatalf("UnmarshalJSON error: %v", err)
	}
	if d.Std() != 168*time.Hour {
		t.Errorf("UnmarshalJSON result = %v, want %v", d.Std(), 168*time.Hour)
	}
}

func TestDuration_UnmarshalJSON_Error(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`123`), &d); err == nil {
		t.Fatal("expected error for non-string JSON")
	}
}

func TestDuration_MarshalYAML(t *testing.T) {
	d := Duration(48 * time.Hour)
	got, err := d.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML error: %v", err)
	}
	if got != "2d" {
		t.Errorf("MarshalYAML = %v, want %q", got, "2d")
	}
}

func TestDuration_UnmarshalYAML(t *testing.T) {
	var d Duration
	// Simulate YAML unmarshal by calling the method directly.
	err := d.UnmarshalYAML(func(v any) error {
		ptr := v.(*string)
		*ptr = "3d"
		return nil
	})
	if err != nil {
		t.Fatalf("UnmarshalYAML error: %v", err)
	}
	if d.Std() != 72*time.Hour {
		t.Errorf("UnmarshalYAML result = %v, want %v", d.Std(), 72*time.Hour)
	}
}

func TestNormalizeDaysToHours(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no days", "24h", "24h"},
		{"simple days", "7d", "168h"},
		{"compound", "1d12h", "24h12h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeDaysToHours(tt.in)
			if err != nil {
				t.Fatalf("normalizeDaysToHours(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("normalizeDaysToHours(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
