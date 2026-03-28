package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/risk"
)

func TestClassifySafetyStatus(t *testing.T) {
	tests := []struct {
		name       string
		violations int
		risks      []risk.ThresholdItem
		want       SafetyStatus
	}{
		{
			name:       "no violations nil risks",
			violations: 0,
			risks:      nil,
			want:       StatusSafe,
		},
		{
			name:       "no violations empty risks",
			violations: 0,
			risks:      []risk.ThresholdItem{},
			want:       StatusSafe,
		},
		{
			name:       "no violations upcoming risk",
			violations: 0,
			risks:      []risk.ThresholdItem{{Status: risk.StatusUpcoming}},
			want:       StatusBorderline,
		},
		{
			name:       "no violations due now risk",
			violations: 0,
			risks:      []risk.ThresholdItem{{Status: risk.StatusDueNow}},
			want:       StatusBorderline,
		},
		{
			name:       "no violations overdue risk",
			violations: 0,
			risks:      []risk.ThresholdItem{{Status: risk.StatusOverdue}},
			want:       StatusBorderline,
		},
		{
			name:       "violations with risks",
			violations: 3,
			risks:      []risk.ThresholdItem{{Status: risk.StatusUpcoming}},
			want:       StatusUnsafe,
		},
		{
			name:       "violations nil risks",
			violations: 1,
			risks:      nil,
			want:       StatusUnsafe,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifySafetyStatus(tt.violations, tt.risks)
			if got != tt.want {
				t.Fatalf("ClassifySafetyStatus(%d, %v) = %q, want %q", tt.violations, tt.risks, got, tt.want)
			}
		})
	}
}
