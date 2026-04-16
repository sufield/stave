package forecast

import (
	"math"
	"testing"
)

func TestLinearFit_Ascending(t *testing.T) {
	slope, _ := linearFit([]float64{10, 20, 30, 40, 50})
	if math.Abs(slope-10) > 0.01 {
		t.Errorf("slope = %f, want 10", slope)
	}
}

func TestLinearFit_Flat(t *testing.T) {
	slope, intercept := linearFit([]float64{50, 50, 50, 50})
	if math.Abs(slope) > 0.01 {
		t.Errorf("slope = %f, want 0", slope)
	}
	if math.Abs(intercept-50) > 0.01 {
		t.Errorf("intercept = %f, want 50", intercept)
	}
}

func TestCompute_InsufficientHistory(t *testing.T) {
	_, err := Compute(Input{ScoreHistory: []float64{80, 81, 82}})
	if err == nil {
		t.Fatal("expected error for < 7 days")
	}
}

func TestCompute_ProjectionExtends(t *testing.T) {
	history := make([]float64, 30)
	for i := range history {
		history[i] = 70 + float64(i)*0.2 // improving trend
	}

	result, err := Compute(Input{
		ScoreHistory: history,
		HorizonDays:  90,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Projected.PostureScore <= history[29] {
		t.Errorf("projected %.1f should be > current %.1f (improving trend)",
			result.Projected.PostureScore, history[29])
	}
	if result.ModelNote == "" {
		t.Error("model_note should not be empty")
	}
}

func TestCompute_SLAProjection(t *testing.T) {
	history := make([]float64, 14)
	for i := range history {
		history[i] = 70 + float64(i)*0.1
	}
	mttrHistory := map[string][]float64{
		"critical": {48, 45, 42, 40, 38, 36, 34},
	}

	result, err := Compute(Input{
		ScoreHistory: history,
		HorizonDays:  30,
		SLADeadlines: map[string]float64{"critical": 24},
		MTTRHistory:  mttrHistory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SLAProj) != 1 {
		t.Fatalf("sla projections = %d, want 1", len(result.SLAProj))
	}
}
