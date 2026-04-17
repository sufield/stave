package strutil

import "testing"

func TestTitleCase(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"critical", "Critical"},
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"", ""},
		{"ALREADY", "Already"},
	}
	for _, tt := range tests {
		got := TitleCase(tt.input)
		if got != tt.want {
			t.Errorf("TitleCase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
