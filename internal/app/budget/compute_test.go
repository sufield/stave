package budget

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func makeFinding(sev policy.Severity, dwellHours float64, deadlineHours float64) remediation.Finding {
	var deadline *float64
	if deadlineHours > 0 {
		deadline = &deadlineHours
	}
	ev := evaluation.Finding{
		ControlSeverity: sev,
		Evidence:        evaluation.Evidence{UnsafeDurationHours: dwellHours},
	}
	ev.RehydrateSLA(deadline, false, nil, 0, "")
	return remediation.Finding{Finding: ev}
}

func TestCompute_BurnRateEqualsConsumedOverAllowed(t *testing.T) {
	findings := []remediation.Finding{
		makeFinding(policy.SeverityCritical, 2, 4),
		makeFinding(policy.SeverityCritical, 3, 4),
	}
	// Period 30 days, critical deadline 4h → allowed = 30*4 = 120h
	// Consumed = 2 + 3 = 5h (both under deadline cap)
	// BurnRate = 5/120 * 100 ≈ 4.2%
	r := Compute(Input{
		Findings:      findings,
		Period:        30 * 24 * time.Hour,
		DeadlineHours: map[string]float64{"critical": 4},
		PeriodStart:   time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
	})

	if len(r.BurnRates) != 1 {
		t.Fatalf("burn_rates count = %d, want 1", len(r.BurnRates))
	}
	br := r.BurnRates[0]
	if br.AllowedHours != 120 {
		t.Errorf("allowed = %.1f, want 120", br.AllowedHours)
	}
	if br.ConsumedHours != 5 {
		t.Errorf("consumed = %.1f, want 5", br.ConsumedHours)
	}
	if br.BurnRatePercent < 4.1 || br.BurnRatePercent > 4.3 {
		t.Errorf("burn_rate = %.1f%%, want ~4.2%%", br.BurnRatePercent)
	}
	if br.Status != "within_budget" {
		t.Errorf("status = %q, want within_budget", br.Status)
	}
}

func TestCompute_DwellCappedAtSLADeadline(t *testing.T) {
	// Finding with 48h dwell against 4h SLA should contribute 4h, not 48h.
	findings := []remediation.Finding{
		makeFinding(policy.SeverityCritical, 48, 4),
	}
	r := Compute(Input{
		Findings:      findings,
		Period:        30 * 24 * time.Hour,
		DeadlineHours: map[string]float64{"critical": 4},
		PeriodStart:   time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
	})

	br := r.BurnRates[0]
	if br.ConsumedHours != 4 {
		t.Errorf("consumed = %.1f, want 4 (capped at SLA deadline)", br.ConsumedHours)
	}
	if br.OverrunHours != 44 {
		t.Errorf("overrun = %.1f, want 44", br.OverrunHours)
	}
}

func TestCompute_BurnRateExceeds100OnBreach(t *testing.T) {
	// 40 critical findings, each at 4h dwell, 4h deadline
	// Consumed = 40*4 = 160h, Allowed = 30*4 = 120h → 133%
	findings := make([]remediation.Finding, 40)
	for i := range findings {
		findings[i] = makeFinding(policy.SeverityCritical, 4, 4)
	}
	r := Compute(Input{
		Findings:      findings,
		Period:        30 * 24 * time.Hour,
		DeadlineHours: map[string]float64{"critical": 4},
		PeriodStart:   time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
	})

	br := r.BurnRates[0]
	if br.BurnRatePercent <= 100 {
		t.Errorf("burn_rate = %.1f%%, want > 100%% (budget exhausted)", br.BurnRatePercent)
	}
	if br.Status != "budget_exhausted" {
		t.Errorf("status = %q, want budget_exhausted", br.Status)
	}
}

func TestEvaluateGate_FailsAtThreshold(t *testing.T) {
	findings := make([]remediation.Finding, 30)
	for i := range findings {
		findings[i] = makeFinding(policy.SeverityCritical, 4, 4)
	}
	// 30*4 = 120h consumed, 120h allowed → 100% burn rate
	r := Compute(Input{
		Findings:      findings,
		Period:        30 * 24 * time.Hour,
		DeadlineHours: map[string]float64{"critical": 4},
		PeriodStart:   time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
	})

	gate := EvaluateGate(&r, 80, []string{"critical"})
	if gate.Passed {
		t.Error("gate should fail: burn rate 100% > threshold 80%")
	}
}

func TestEvaluateGate_PassesBelowThreshold(t *testing.T) {
	findings := []remediation.Finding{
		makeFinding(policy.SeverityCritical, 2, 4),
	}
	r := Compute(Input{
		Findings:      findings,
		Period:        30 * 24 * time.Hour,
		DeadlineHours: map[string]float64{"critical": 4},
		PeriodStart:   time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
	})

	gate := EvaluateGate(&r, 80, []string{"critical"})
	if !gate.Passed {
		t.Errorf("gate should pass: burn rate %.1f%% < threshold 80%%", r.BurnRates[0].BurnRatePercent)
	}
}

func TestCompute_WeeklyVelocity(t *testing.T) {
	start := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)

	findings := []remediation.Finding{
		makeFinding(policy.SeverityCritical, 3, 4),
	}
	// Set first unsafe to start of period
	findings[0].Evidence.FirstUnsafeAt = start

	r := Compute(Input{
		Findings:      findings,
		Period:        30 * 24 * time.Hour,
		DeadlineHours: map[string]float64{"critical": 4},
		PeriodStart:   start,
		PeriodEnd:     end,
	})

	br := r.BurnRates[0]
	if len(br.WeeklyConsumption) == 0 {
		t.Error("weekly_consumption should not be empty")
	}
	// First week should have the consumption
	if br.WeeklyConsumption[0] <= 0 {
		t.Errorf("week 1 consumption = %.1f, want > 0", br.WeeklyConsumption[0])
	}
}
