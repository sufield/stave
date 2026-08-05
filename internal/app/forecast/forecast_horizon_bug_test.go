package forecast

import (
	"testing"
)

func TestCompute_NegativeHorizonDaysRejected(t *testing.T) {
	input := Input{
		ScoreHistory: []float64{80, 81, 82, 83, 84, 85, 86},
		HorizonDays:  -10, // negative horizon days
	}

	res, err := Compute(input)
	if err == nil || res != nil {
		t.Errorf("expected error from Compute with negative HorizonDays, got result: %v", res)
	}
}
