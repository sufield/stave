package text

import (
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

// TestBugHunt_TrendChangeSign proves that the trend Change column renders an
// improving metric as "↓ -3" (down arrow followed by a minus sign) instead of
// "↓ 3" (arrow plus magnitude), mirroring the "↑ 5" form used for declining
// metrics.
//
// Symbol() already encodes direction: "↓ " for improving, "↑ " for declining.
// Change() returns Current-Previous, which is negative when improving. The
// renderer prints Change() raw with %d, so the magnitude is signed in one
// direction and unsigned in the other.
func TestBugHunt_TrendChangeSign(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	previous := now.Add(-7 * 24 * time.Hour)

	// Improving metric: Current(2) < Previous(5) => Change() == -3, Symbol() == "↓ ".
	trends := []evaluation.TrendMetric{
		{Name: "Current violations", Current: 2, Previous: 5},
	}

	req := appcontracts.HygieneAssessment{
		AuditContext: appcontracts.AuditContext{
			EvalTime:        now,
			PreviousAuditAt: previous,
			LookbackWindow:  7 * 24 * time.Hour,
			SLAWarning:      24 * time.Hour,
		},
		Evidence: appcontracts.SnapshotSummary{
			ActiveSnapshots:    3,
			HistoricalEvidence: 1,
			PurgeCandidates:    0,
			ComplianceTier:     "critical",
			RetentionPolicy:    30 * 24 * time.Hour,
			MinEvidenceCount:   2,
		},
		SLAPosture:      appcontracts.SLAPosture{ActiveFindings: 2},
		ExposureHistory: trends,
	}

	var b strings.Builder
	if err := WriteHygieneReport(&b, req); err != nil {
		t.Fatalf("WriteHygieneReport: %v", err)
	}
	out := b.String()

	// Correct behavior: arrow plus the magnitude of the change.
	const want = "| Current violations | 2 | 5 | ↓ 3 |"
	if !strings.Contains(out, want) {
		// Surface the buggy line for a readable failure message.
		var got string
		for line := range strings.SplitSeq(out, "\n") {
			if strings.Contains(line, "Current violations") && strings.Contains(line, "↓") {
				got = strings.TrimSpace(line)
				break
			}
		}
		t.Fatalf("improving trend change should render arrow + magnitude.\n  want substring: %q\n  got line:       %q", want, got)
	}

	// Guard against the specific buggy rendering "↓ -3".
	if strings.Contains(out, "↓ -3") {
		t.Fatalf("improving trend renders down-arrow followed by a negative sign %q; should be \"↓ 3\"", "↓ -3")
	}
}
