package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
)

func TestClassifySafetyStatus(t *testing.T) {
	tests := []struct {
		name       string
		violations int
		risks      []risk.Item
		want       SafetyStatus
	}{
		{
			name:       "no violations nil risks",
			violations: 0,
			risks:      nil,
			want:       SafetyStatusSafe,
		},
		{
			name:       "no violations empty risks",
			violations: 0,
			risks:      []risk.Item{},
			want:       SafetyStatusSafe,
		},
		{
			name:       "no violations upcoming risk",
			violations: 0,
			risks:      []risk.Item{{Status: risk.StatusUpcoming}},
			want:       SafetyStatusBorderline,
		},
		{
			name:       "no violations due now risk",
			violations: 0,
			risks:      []risk.Item{{Status: risk.StatusDueNow}},
			want:       SafetyStatusBorderline,
		},
		{
			name:       "no violations overdue risk",
			violations: 0,
			risks:      []risk.Item{{Status: risk.StatusOverdue}},
			want:       SafetyStatusBorderline,
		},
		{
			name:       "violations with risks",
			violations: 3,
			risks:      []risk.Item{{Status: risk.StatusUpcoming}},
			want:       SafetyStatusUnsafe,
		},
		{
			name:       "violations nil risks",
			violations: 1,
			risks:      nil,
			want:       SafetyStatusUnsafe,
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
