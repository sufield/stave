package rank

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestBuildRoadmap_ChainMembersSortFirst(t *testing.T) {
	now := time.Now()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID:       "CTL.ISOLATED",
				AssetID:         "asset-1",
				ControlSeverity: policy.SeverityCritical,
				Evidence: evaluation.Evidence{
					FirstUnsafeAt:       now.Add(-480 * time.Hour),
					LastSeenUnsafeAt:    now,
					UnsafeDurationHours: 480,
					ThresholdHours:      168,
				},
			},
			RemediationSpec: policy.RemediationSpec{Action: "fix isolated"},
		},
		{
			Finding: evaluation.Finding{
				ControlID:       "CTL.CHAIN",
				AssetID:         "asset-2",
				ControlSeverity: policy.SeverityMedium,
				Evidence: evaluation.Evidence{
					FirstUnsafeAt:       now.Add(-48 * time.Hour),
					LastSeenUnsafeAt:    now,
					UnsafeDurationHours: 48,
					ThresholdHours:      168,
				},
				ChainMembership: []evaluation.ChainMembershipEntry{
					{
						ChainID:       "data_exfiltration_path",
						ChainSeverity: "critical",
						StageSpan:     []string{"initial_access", "exfiltration"},
						Narrative:     "test chain",
					},
				},
			},
			RemediationSpec: policy.RemediationSpec{Action: "fix chain member"},
		},
	}

	roadmap := BuildRoadmap(findings, nil, 0)

	if len(roadmap.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(roadmap.Entries))
	}

	// Chain-member finding should be ranked first even though isolated
	// finding has higher severity and longer duration.
	if roadmap.Entries[0].ControlID != "CTL.CHAIN" {
		t.Errorf("rank 1 = %s, want CTL.CHAIN (chain member sorts first)", roadmap.Entries[0].ControlID)
	}
	if !roadmap.Entries[0].IsChainMember {
		t.Error("rank 1 should have IsChainMember=true")
	}
	if roadmap.Entries[0].ChainID != "data_exfiltration_path" {
		t.Errorf("rank 1 ChainID = %q, want data_exfiltration_path", roadmap.Entries[0].ChainID)
	}
	if roadmap.Entries[1].ControlID != "CTL.ISOLATED" {
		t.Errorf("rank 2 = %s, want CTL.ISOLATED", roadmap.Entries[1].ControlID)
	}
	if roadmap.Entries[1].IsChainMember {
		t.Error("rank 2 should have IsChainMember=false")
	}
}

func TestBuildRoadmap_NoChainFindings(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID:       "CTL.A",
				AssetID:         "asset-1",
				ControlSeverity: policy.SeverityHigh,
				Evidence: evaluation.Evidence{
					UnsafeDurationHours: 100,
					ThresholdHours:      168,
				},
			},
		},
	}

	roadmap := BuildRoadmap(findings, nil, 0)
	if roadmap.Entries[0].IsChainMember {
		t.Error("non-chain finding should have IsChainMember=false")
	}
}

func TestSLAUrgencyMultiplier(t *testing.T) {
	tests := []struct {
		remaining float64
		overdue   bool
		want      float64
	}{
		{-10, true, 3.0},
		{12, false, 2.5},
		{48, false, 2.0},
		{100, false, 1.5},
		{200, false, 1.0},
	}
	for _, tt := range tests {
		got := SLAUrgencyMultiplier(tt.remaining, tt.overdue)
		if got != tt.want {
			t.Errorf("SLAUrgencyMultiplier(%f, %v) = %f, want %f", tt.remaining, tt.overdue, got, tt.want)
		}
	}
}

func TestBuildRoadmap_ExposureScores(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID:       "CTL.A",
				AssetID:         "asset-1",
				ControlSeverity: policy.SeverityHigh,
				Evidence: evaluation.Evidence{
					UnsafeDurationHours: 100,
					ThresholdHours:      168,
				},
			},
		},
	}
	exposures := []risk.ExposureRank{
		{
			ControlID:     "CTL.A",
			AssetID:       "asset-1",
			ExposureScore: 200,
			Breakdown:     risk.ScoreBreakdown{BaseScore: 10, DurationFactor: 2, BlastMultiplier: 1, ExposureMultiplier: 1},
		},
	}

	roadmap := BuildRoadmap(findings, exposures, 0)
	if roadmap.Entries[0].PriorityScore < 200 {
		t.Errorf("expected exposure score to be used, got %f", roadmap.Entries[0].PriorityScore)
	}
}
