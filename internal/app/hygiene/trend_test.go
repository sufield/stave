package hygiene

import (
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestCalculateTrend(t *testing.T) {
	current := appcontracts.SLAPosture{
		ActiveFindings:  4,
		SLABreaches:     1,
		BreachingNow:    1,
		NearBreach:      2,
		CompliantWindow: 0,
	}
	previous := appcontracts.SLAPosture{
		ActiveFindings:  6,
		SLABreaches:     2,
		BreachingNow:    0,
		NearBreach:      1,
		CompliantWindow: 1,
	}

	got := CalculateTrend(current, previous)

	if len(got) != 4 {
		t.Fatalf("len(trend) = %d, want 4", len(got))
	}
	expect := []struct {
		name     string
		current  int
		previous int
	}{
		{"Current violations", 4, 6},
		{"Upcoming overdue", 1, 2},
		{"Upcoming due soon", 2, 1},
		{"Upcoming total", 4, 4},
	}
	for i, e := range expect {
		if got[i].Name != e.name || got[i].Current != e.current || got[i].Previous != e.previous {
			t.Errorf("trend[%d] = %+v, want Name=%q Current=%d Previous=%d",
				i, got[i], e.name, e.current, e.previous)
		}
	}
}
