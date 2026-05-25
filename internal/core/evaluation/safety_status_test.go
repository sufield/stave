package evaluation

import (
	"testing"

	"github.com/sufield/stave/internal/core/findings"
)

func TestDeriveSecurityState(t *testing.T) {
	tests := []struct {
		name       string
		violations int
		risks      []findings.ThresholdItem
		want       SecurityState
	}{
		{
			name:       "no violations nil risks",
			violations: 0,
			risks:      nil,
			want:       StateCompliant,
		},
		{
			name:       "no violations empty risks",
			violations: 0,
			risks:      []findings.ThresholdItem{},
			want:       StateCompliant,
		},
		{
			name:       "no violations upcoming risk",
			violations: 0,
			risks:      []findings.ThresholdItem{{Status: findings.StatusUpcoming}},
			want:       StateAtRisk,
		},
		{
			name:       "no violations due now risk",
			violations: 0,
			risks:      []findings.ThresholdItem{{Status: findings.StatusDueNow}},
			want:       StateAtRisk,
		},
		{
			name:       "no violations overdue risk",
			violations: 0,
			risks:      []findings.ThresholdItem{{Status: findings.StatusOverdue}},
			want:       StateAtRisk,
		},
		{
			name:       "violations with risks",
			violations: 3,
			risks:      []findings.ThresholdItem{{Status: findings.StatusUpcoming}},
			want:       StateNonCompliant,
		},
		{
			name:       "violations nil risks",
			violations: 1,
			risks:      nil,
			want:       StateNonCompliant,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveSecurityState(tt.violations, tt.risks)
			if got != tt.want {
				t.Fatalf("DeriveSecurityState(%d, %v) = %q, want %q", tt.violations, tt.risks, got, tt.want)
			}
		})
	}
}
