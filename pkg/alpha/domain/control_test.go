package domain

import (
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// TestParseDuration tests ParseDuration with various duration formats.
func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"168h", 168 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"1d12h", 36 * time.Hour, false},                  // combined format
		{"2d6h30m", 54*time.Hour + 30*time.Minute, false}, // combined format
		{"1d2m", 24*time.Hour + 2*time.Minute, false},
		{"1d1.5h", 25*time.Hour + 30*time.Minute, false},
		{"-7d", 0, true},  // negative days
		{"-24h", 0, true}, // negative hours
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := kernel.ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("kernel.ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("kernel.ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
