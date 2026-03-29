package reporter

import "testing"

func TestRedactAccountID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"123456789012", "********9012"},
		{"9012", "9012"},
		{"12", "12"},
		{"", ""},
		{"ABCDE", "*BCDE"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := RedactAccountID(tc.input)
			if got != tc.want {
				t.Errorf("RedactAccountID(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
