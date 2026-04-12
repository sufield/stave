package risk

import (
	"math"
	"testing"
)

func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < 0.001
}

func TestEnvironmental(t *testing.T) {
	tests := []struct {
		name        string
		baseImpact  int
		sensitivity float64
		exposure    float64
		want        float64
	}{
		{"PHI public", 10, 3.0, 2.0, 60.0},
		{"internal vpc", 10, 1.0, 1.0, 10.0},
		{"dev sandbox", 5, 0.5, 0.5, 1.25},
		{"zero impact", 0, 3.0, 2.0, 0.0},
		{"production cross-account", 7, 2.0, 1.5, 21.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Environmental(tt.baseImpact, tt.sensitivity, tt.exposure)
			if !approxEqual(got, tt.want) {
				t.Errorf("Environmental(%d, %f, %f) = %f, want %f",
					tt.baseImpact, tt.sensitivity, tt.exposure, got, tt.want)
			}
		})
	}
}

func TestCompound(t *testing.T) {
	tests := []struct {
		name       string
		envScore   float64
		escalation float64
		blast      float64
		want       float64
	}{
		{"single control", 60.0, 1.0, 1.0, 60.0},
		{"two controls", 60.0, 1.8, 1.0, 108.0},
		{"three controls with detection blast", 60.0, 2.5, 2.5, 375.0},
		{"no blast", 42.0, 1.8, 1.0, 75.6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compound(tt.envScore, tt.escalation, tt.blast)
			if !approxEqual(got, tt.want) {
				t.Errorf("Compound(%f, %f, %f) = %f, want %f",
					tt.envScore, tt.escalation, tt.blast, got, tt.want)
			}
		})
	}
}

func TestChainEscalation(t *testing.T) {
	tests := []struct {
		count int
		want  float64
	}{
		{0, 1.0},
		{1, 1.0},
		{2, 1.8},
		{3, 2.5},
		{5, 2.5},
		{10, 2.5},
	}
	for _, tt := range tests {
		got := ChainEscalation(tt.count)
		if got != tt.want {
			t.Errorf("ChainEscalation(%d) = %f, want %f", tt.count, got, tt.want)
		}
	}
}

func TestLookupSensitivity(t *testing.T) {
	if got := LookupSensitivity("phi"); got != 3.0 {
		t.Errorf("phi = %f, want 3.0", got)
	}
	if got := LookupSensitivity("unknown"); got != 1.0 {
		t.Errorf("unknown = %f, want 1.0", got)
	}
}

func TestLookupExposure(t *testing.T) {
	if got := LookupExposure("public_internet"); got != 2.0 {
		t.Errorf("public = %f, want 2.0", got)
	}
	if got := LookupExposure("unknown"); got != 1.0 {
		t.Errorf("unknown = %f, want 1.0", got)
	}
}
