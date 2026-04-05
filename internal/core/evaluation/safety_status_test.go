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
		want       Posture
	}{
		{
			name:       "no violations nil risks",
			violations: 0,
			risks:      nil,
			want:       PostureSafe,
		},
		{
			name:       "no violations empty risks",
			violations: 0,
			risks:      []risk.ThresholdItem{},
			want:       PostureSafe,
		},
		{
			name:       "no violations upcoming risk",
			violations: 0,
			risks:      []risk.ThresholdItem{{Status: risk.StatusUpcoming}},
			want:       PostureBorderline,
		},
		{
			name:       "no violations due now risk",
			violations: 0,
			risks:      []risk.ThresholdItem{{Status: risk.StatusDueNow}},
			want:       PostureBorderline,
		},
		{
			name:       "no violations overdue risk",
			violations: 0,
			risks:      []risk.ThresholdItem{{Status: risk.StatusOverdue}},
			want:       PostureBorderline,
		},
		{
			name:       "violations with risks",
			violations: 3,
			risks:      []risk.ThresholdItem{{Status: risk.StatusUpcoming}},
			want:       PostureUnsafe,
		},
		{
			name:       "violations nil risks",
			violations: 1,
			risks:      nil,
			want:       PostureUnsafe,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DerivePosture(tt.violations, tt.risks)
			if got != tt.want {
				t.Fatalf("DerivePosture(%d, %v) = %q, want %q", tt.violations, tt.risks, got, tt.want)
			}
		})
	}
}
