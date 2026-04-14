package evidence

import "testing"

func TestMapVerdict(t *testing.T) {
	tests := []struct {
		input string
		want  EvidenceVerdict
	}{
		{"VIOLATION", VerdictFail},
		{"PASS", VerdictPass},
		{"INCONCLUSIVE", VerdictIncomplete},
		{"NOT_APPLICABLE", VerdictNotApplicable},
		{"SKIPPED", VerdictNotApplicable},
		{"UNKNOWN", VerdictNotApplicable},
		{"", VerdictNotApplicable},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := MapVerdict(tt.input)
			if got != tt.want {
				t.Errorf("MapVerdict(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
