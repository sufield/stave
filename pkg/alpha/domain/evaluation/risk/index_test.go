package risk

import "testing"

func TestCalculateRiskIndex(t *testing.T) {
	cases := []struct {
		name   string
		scores []int
		want   int
	}{
		{"empty", nil, 0},
		{"single low", []int{3}, 3},
		{"single high", []int{10}, 11},
		{"multiple", []int{9, 6, 3}, 10},
		{"capped at 100", []int{90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90}, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CalculateRiskIndex(tc.scores)
			if got != tc.want {
				t.Errorf("CalculateRiskIndex(%v) = %d, want %d", tc.scores, got, tc.want)
			}
		})
	}
}

func TestGetRiskLevel(t *testing.T) {
	cases := []struct {
		index int
		want  string
	}{
		{0, "SAFE"},
		{1, "LOW"},
		{39, "LOW"},
		{40, "MEDIUM"},
		{69, "MEDIUM"},
		{70, "HIGH"},
		{89, "HIGH"},
		{90, "CRITICAL"},
		{100, "CRITICAL"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := GetRiskLevel(tc.index)
			if got != tc.want {
				t.Errorf("GetRiskLevel(%d) = %q, want %q", tc.index, got, tc.want)
			}
		})
	}
}
