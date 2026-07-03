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
	// Compound output is capped at ScoreCatastrophic (=100). Inputs
	// that would otherwise multiply to a higher value get clamped so
	// the score frame stays in [0, ScoreCatastrophic] regardless of
	// chain depth or blast multiplier. The clamp prevents one
	// catastrophic outlier from compressing every other finding into
	// a sub-1% bar in the report renderer.
	tests := []struct {
		name       string
		envScore   float64
		escalation float64
		blast      float64
		want       float64
	}{
		{"single control", 60.0, 1.0, 1.0, 60.0},
		{"two controls clamped at ceiling", 60.0, 1.8, 1.0, 100.0},
		{"three controls with detection blast clamped", 60.0, 2.5, 2.5, 100.0},
		{"no blast clamped", 42.0, 1.8, 1.0, 75.6},
		{"below ceiling", 30.0, 1.8, 1.0, 54.0},
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

// TestEnvironmental_CappedAtCeiling pins that extreme inputs do not
// produce uncapped raw values. The earlier shape returned values up
// to baseImpact*9 (3.0 sensitivity × 3.0 exposure) which made the
// scoring frame unstable for catastrophic findings.
func TestEnvironmental_CappedAtCeiling(t *testing.T) {
	got := Environmental(100, 3.0, 3.0)
	if got != float64(ScoreCatastrophic) {
		t.Errorf("Environmental extreme = %f, want %d", got, ScoreCatastrophic)
	}
}

// TestCompound_CappedAtCeiling pins the symmetric cap on Compound.
func TestCompound_CappedAtCeiling(t *testing.T) {
	got := Compound(100.0, 2.5, 2.5)
	if got != float64(ScoreCatastrophic) {
		t.Errorf("Compound extreme = %f, want %d", got, ScoreCatastrophic)
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

func TestLookupExposure(t *testing.T) {
	if got := LookupExposure("public_internet"); got != 2.0 {
		t.Errorf("public = %f, want 2.0", got)
	}
	if got := LookupExposure("unknown"); got != 1.0 {
		t.Errorf("unknown = %f, want 1.0", got)
	}
}
