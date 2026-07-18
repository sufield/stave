package risk

import "testing"

func TestEnvironmentMultiplier(t *testing.T) {
	tests := []struct {
		tier EnvironmentTier
		want float64
	}{
		{TierUnknown, 1.0},
		{TierDev, 0.5},
		{TierStaging, 0.75},
		{TierProduction, 1.0},
		{TierCritical, 2.0},
	}
	for _, tt := range tests {
		got := EnvironmentMultiplier(tt.tier)
		if got != tt.want {
			t.Errorf("EnvironmentMultiplier(%d) = %v, want %v", tt.tier, got, tt.want)
		}
	}
}

func TestParseEnvironmentTier(t *testing.T) {
	tests := []struct {
		input string
		want  EnvironmentTier
	}{
		{"dev", TierDev},
		{"development", TierDev},
		{"sandbox", TierDev},
		{"staging", TierStaging},
		{"stage", TierStaging},
		{"qa", TierStaging},
		{"uat", TierStaging},
		{"prod", TierProduction},
		{"production", TierProduction},
		{"critical", TierCritical},
		{"pci", TierCritical},
		{"hipaa", TierCritical},
		{"pii", TierCritical},
		{"financial", TierCritical},
		{"unknown", TierUnknown},
		{"", TierUnknown},
	}
	for _, tt := range tests {
		got := ParseEnvironmentTier(tt.input)
		if got != tt.want {
			t.Errorf("ParseEnvironmentTier(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
