package evidence

import "testing"

func TestParsePassThreshold(t *testing.T) {
	tests := []struct {
		input   string
		mode    ThresholdMode
		percent float64
		wantErr bool
	}{
		{"all", ThresholdAll, 0, false},
		{"", ThresholdAll, 0, false},
		{"any", ThresholdAny, 0, false},
		{"percent:80", ThresholdPercent, 80, false},
		{"percent:100", ThresholdPercent, 100, false},
		{"percent:0", ThresholdPercent, 0, false},
		{"percent:90.5", ThresholdPercent, 90.5, false},
		{"percent:abc", 0, 0, true},
		{"percent:-1", 0, 0, true},
		{"percent:101", 0, 0, true},
		{"bogus", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParsePassThreshold(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Mode != tt.mode {
				t.Errorf("Mode = %v, want %v", got.Mode, tt.mode)
			}
			if got.Percent != tt.percent {
				t.Errorf("Percent = %v, want %v", got.Percent, tt.percent)
			}
		})
	}
}

func TestRequirementStatus_String(t *testing.T) {
	tests := []struct {
		status RequirementStatus
		want   string
	}{
		{RequirementMet, "met"},
		{RequirementNotMet, "not_met"},
		{RequirementNotEvaluated, "not_evaluated"},
		{RequirementIncomplete, "incomplete"},
		{RequirementStatus(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestThresholdMode_String(t *testing.T) {
	if ThresholdAll.String() != "all" {
		t.Errorf("ThresholdAll = %q", ThresholdAll.String())
	}
	if ThresholdAny.String() != "any" {
		t.Errorf("ThresholdAny = %q", ThresholdAny.String())
	}
	if ThresholdPercent.String() != "percent" {
		t.Errorf("ThresholdPercent = %q", ThresholdPercent.String())
	}
}
