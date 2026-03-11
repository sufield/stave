package hygiene

import (
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestCalculateTrend(t *testing.T) {
	current := appcontracts.RiskStats{
		CurrentViolations: 4,
		Overdue:           1,
		DueNow:            1,
		DueSoon:           2,
		Later:             0,
		UpcomingTotal:     4,
	}
	previous := appcontracts.RiskStats{
		CurrentViolations: 6,
		Overdue:           2,
		DueNow:            0,
		DueSoon:           1,
		Later:             1,
		UpcomingTotal:     4,
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
