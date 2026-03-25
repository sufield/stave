package cliflags

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/sanitize"
)

func TestParsePathMode(t *testing.T) {
	tests := []struct {
		input string
		want  sanitize.PathMode
	}{
		{"base", sanitize.PathBase},
		{"full", sanitize.PathFull},
		{" FULL ", sanitize.PathFull},
		{"", sanitize.PathBase},
		{"other", sanitize.PathBase},
	}
	for _, tt := range tests {
		got := ParsePathMode(tt.input)
		if got != tt.want {
			t.Errorf("ParsePathMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseDurationFlag(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		flag    string
		want    time.Duration
		wantErr string
	}{
		{name: "hours", val: "168h", flag: "--max-unsafe", want: 168 * time.Hour},
		{name: "days", val: "7d", flag: "--max-unsafe", want: 7 * 24 * time.Hour},
		{name: "mixed", val: "1d12h", flag: "--lookback", want: 36 * time.Hour},
		{name: "invalid", val: "bogus", flag: "--max-unsafe", wantErr: "invalid --max-unsafe"},
		{name: "empty", val: "", flag: "--due-soon", wantErr: "invalid --due-soon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDurationFlag(tt.val, tt.flag)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want to contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}
