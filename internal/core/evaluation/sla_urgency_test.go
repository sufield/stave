package evaluation

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Bug 7: SLAUrgencyFactor must compute "remaining" against the SLA policy
// deadline (slaDeadlineHours), not the control threshold. The old code
// used Evidence.ThresholdHours − UnsafeDurationHours, which is always
// negative for a finding (a finding exists because dwell > threshold),
// pinning every finding at maximum urgency.
func TestSLAUrgencyFactor_UsesSLADeadlineNotControlThreshold(t *testing.T) {
	deadline := 72.0

	// Capture what the urgency function receives.
	var gotRemaining float64
	var gotOverdue bool
	urgencyFn := func(remainingHours float64, isOverdue bool) float64 {
		gotRemaining = remainingHours
		gotOverdue = isOverdue
		return 1.0
	}

	t.Run("within SLA deadline", func(t *testing.T) {
		f := &Finding{
			// Control threshold (ThresholdHours) is small and already
			// exceeded by dwell — the OLD math would force remaining
			// negative / overdue here. The SLA policy deadline (72h) is
			// not yet reached, so urgency must see positive remaining.
			Evidence: Evidence{ThresholdHours: 1, UnsafeDurationHours: 24},
		}
		f.RehydrateSLA(&deadline, false, nil, policy.SeverityNone, kernel.SLAPolicySource(""))

		f.SLAUrgencyFactor(urgencyFn)
		if gotOverdue {
			t.Error("finding within SLA deadline must not be reported overdue")
		}
		if gotRemaining != deadline-24 { // 48
			t.Errorf("remaining = %v, want %v (deadline − dwell, not threshold-based)", gotRemaining, deadline-24)
		}
	})

	t.Run("past SLA deadline", func(t *testing.T) {
		overdue := 28.0 // dwell 100 − deadline 72
		f := &Finding{
			Evidence: Evidence{ThresholdHours: 1, UnsafeDurationHours: 100},
		}
		f.RehydrateSLA(&deadline, true, &overdue, policy.SeverityNone, kernel.SLAPolicySource(""))

		f.SLAUrgencyFactor(urgencyFn)
		if !gotOverdue {
			t.Error("finding past SLA deadline must be reported overdue")
		}
		if gotRemaining != deadline-100 { // -28
			t.Errorf("remaining = %v, want %v", gotRemaining, deadline-100)
		}
	})

	t.Run("no SLA annotation returns neutral 1.0", func(t *testing.T) {
		f := &Finding{Evidence: Evidence{ThresholdHours: 1, UnsafeDurationHours: 100}}
		// No RehydrateSLA/AnnotateSLA → no deadline.
		called := false
		got := f.SLAUrgencyFactor(func(float64, bool) float64 { called = true; return 2.0 })
		if called {
			t.Error("urgencyFn must not be called when there is no SLA deadline")
		}
		if got != 1.0 {
			t.Errorf("unannotated finding must return neutral 1.0, got %v", got)
		}
	})
}
