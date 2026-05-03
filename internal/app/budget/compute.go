// Package budget computes security SLA burn rates for deployment gating.
package budget

import (
	"fmt"
	"math"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// Input holds data for burn rate computation.
type Input struct {
	Findings []remediation.Finding
	Period   time.Duration
	// DeadlineHours maps severity (lowercase) to SLA deadline in hours.
	DeadlineHours map[string]float64
	PeriodStart   time.Time
	PeriodEnd     time.Time
	ProfileID     string
}

// SeverityBurnRate holds burn rate for a single severity tier.
// Recognised SeverityBurnRate.Status values. Centralised so callers
// stop comparing the field against magic strings.
const (
	StatusWithinBudget    = "within_budget"
	StatusBudgetExhausted = "budget_exhausted"
)

type SeverityBurnRate struct {
	Severity          string    `json:"severity"`
	SLADeadlineHours  float64   `json:"sla_deadline_hours"`
	AllowedHours      float64   `json:"allowed_hours"`
	ConsumedHours     float64   `json:"consumed_hours"`
	OverrunHours      float64   `json:"overrun_hours"`
	RemainingHours    float64   `json:"remaining_hours"`
	BurnRatePercent   float64   `json:"burn_rate_percent"`
	Status            string    `json:"status"`
	FindingCount      int       `json:"finding_count"`
	WeeklyConsumption []float64 `json:"weekly_consumption"`
}

// IsExhausted reports whether the severity has consumed its full
// SLA budget. Replaces the br.Status == "budget_exhausted"
// comparison sites in cmd/budget so a future status-vocabulary
// change is one edit on the type.
func (br *SeverityBurnRate) IsExhausted() bool {
	return br != nil && br.Status == StatusBudgetExhausted
}

// SeverityLabel returns the canonical severity label this burn-rate
// row reports against. Mirrors the SeverityLabel() shape on Finding
// and ChainFinding so renderers can ask either type for its label
// without knowing which variant is in hand. Pointer-receiver-safe:
// returns "" on a nil receiver.
func (br *SeverityBurnRate) SeverityLabel() string {
	if br == nil {
		return ""
	}
	return br.Severity
}

// StatusLabel returns the human-readable label renderers (text,
// markdown) display for this severity's burn-rate state. Centralises
// the (IsExhausted ? "EXHAUSTED" : "WITHIN BUDGET") branch the
// budget command used to repeat in writeText and writeMarkdown so a
// future label change is one edit on the type.
func (br *SeverityBurnRate) StatusLabel() string {
	if br.IsExhausted() {
		return "EXHAUSTED"
	}
	return "WITHIN BUDGET"
}

// IsCritical reports whether this burn-rate row tracks the critical
// severity tier. Replaces the (br.Severity == "critical") probe in
// the velocity-section guard at cmd/budget/cmd.go so the comparison
// stays on the type that owns the Severity field.
func (br *SeverityBurnRate) IsCritical() bool {
	return br != nil && br.Severity == "critical"
}

// BurnRateRatio returns the burn rate as a 0..1 ratio (i.e.
// BurnRatePercent / 100). Used by Prometheus / OpenMetrics
// gauge writers that want the ratio rather than the percentage —
// keeping the /100 normalisation on the type so renderer sites
// stop dividing by 100 inline.
func (br *SeverityBurnRate) BurnRateRatio() float64 {
	if br == nil {
		return 0
	}
	return br.BurnRatePercent / 100
}

// GateResult holds the deployment gate decision.
type GateResult struct {
	ThresholdPercent float64  `json:"threshold_percent"`
	GatedSeverities  []string `json:"gated_severities"`
	Passed           bool     `json:"passed"`
	Reason           string   `json:"reason"`
}

// GateFailedError carries a deployment-gate failure reason.
// Returned by GateResult.ExitError so cmd-side callers receive a
// typed error instead of open-coding the wrap.
type GateFailedError struct {
	Reason string
}

// Error formats in the shape cmd/budget previously emitted
// ("deployment gate failed: <reason>") so wire behaviour is
// preserved.
func (e *GateFailedError) Error() string {
	return "deployment gate failed: " + e.Reason
}

// IsPassed reports whether the gate passed. Wraps the bare
// Passed field so cmd-side callers stop reading the field
// directly. nil receiver returns false (a missing gate result
// counts as "not passed" — fail-safe for gate logic).
func (g *GateResult) IsPassed() bool {
	return g != nil && g.Passed
}

// PassLabel returns the canonical "PASS" / "FAIL" string used by
// CLI renderers. Centralised so cmd/budget doesn't open-code the
// ternary at every render site. Mirrors pkg/stave.GateResult.PassLabel.
func (g *GateResult) PassLabel() string {
	if !g.IsPassed() {
		return "FAIL"
	}
	return "PASS"
}

// ExitError returns nil when the gate passed, or a GateFailedError
// wrapping the gate's reason when it failed. Mirrors
// pkg/stave.GateResult.ExitError so the cmd-side runner returns
// this directly.
func (g *GateResult) ExitError() error {
	if g.IsPassed() {
		return nil
	}
	return &GateFailedError{Reason: g.Reason}
}

// Report is the complete burn rate output.
type Report struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Period      PeriodInfo         `json:"period"`
	SLAProfile  string             `json:"sla_profile"`
	BurnRates   []SeverityBurnRate `json:"burn_rates"`
	Gate        *GateResult        `json:"gate_result,omitempty"`
}

// PeriodInfo describes the budget window.
type PeriodInfo struct {
	From         time.Time `json:"from"`
	To           time.Time `json:"to"`
	DurationDays int       `json:"duration_days"`
}

// Compute produces a burn rate report from assessment findings.
func Compute(input Input) Report {
	periodDays := input.Period.Hours() / 24
	if periodDays <= 0 {
		periodDays = 30
	}

	severities := []string{"critical", "high", "medium", "low"}
	var rates []SeverityBurnRate

	for _, sev := range severities {
		deadline, ok := input.DeadlineHours[sev]
		if !ok || deadline <= 0 {
			continue
		}

		allowedHours := periodDays * deadline

		var consumed, overrun float64
		var count int

		for i := range input.Findings {
			f := &input.Findings[i]
			if f.SeverityLabel() != sev {
				continue
			}
			count++

			dwell := f.DwellHours()
			if dwell <= 0 {
				continue
			}

			// Cap contribution at SLA deadline.
			capped := math.Min(dwell, deadline)
			consumed += capped

			// Track overrun separately.
			if dwell > deadline {
				overrun += dwell - deadline
			}
		}

		remaining := math.Max(allowedHours-consumed, 0)
		burnPct := 0.0
		if allowedHours > 0 {
			burnPct = consumed / allowedHours * 100
		}

		status := "within_budget"
		if burnPct >= 100 {
			status = "budget_exhausted"
		}

		weekly := computeWeekly(input.Findings, sev, deadline, input.PeriodStart, input.PeriodEnd)

		rates = append(rates, SeverityBurnRate{
			Severity:          sev,
			SLADeadlineHours:  deadline,
			AllowedHours:      round1(allowedHours),
			ConsumedHours:     round1(consumed),
			OverrunHours:      round1(overrun),
			RemainingHours:    round1(remaining),
			BurnRatePercent:   round1(burnPct),
			Status:            status,
			FindingCount:      count,
			WeeklyConsumption: weekly,
		})
	}

	return Report{
		GeneratedAt: input.PeriodEnd,
		Period: PeriodInfo{
			From:         input.PeriodStart,
			To:           input.PeriodEnd,
			DurationDays: int(periodDays),
		},
		SLAProfile: input.ProfileID,
		BurnRates:  rates,
	}
}

// EvaluateGate checks burn rates against a threshold for specific severities.
func EvaluateGate(report *Report, threshold float64, severities []string) GateResult {
	allowed := make(map[string]bool, len(severities))
	for _, s := range severities {
		allowed[s] = true
	}

	gate := GateResult{
		ThresholdPercent: threshold,
		GatedSeverities:  severities,
		Passed:           true,
	}

	for i := range report.BurnRates {
		br := &report.BurnRates[i]
		if !allowed[br.Severity] {
			continue
		}
		if br.BurnRatePercent >= threshold {
			gate.Passed = false
			gate.Reason = br.SeverityLabel() + " burn rate " +
				formatPct(br.BurnRatePercent) + "% exceeds threshold " +
				formatPct(threshold) + "%"
			break
		}
	}

	if gate.Passed {
		for i := range report.BurnRates {
			br := &report.BurnRates[i]
			if allowed[br.Severity] {
				gate.Reason = br.SeverityLabel() + " burn rate " +
					formatPct(br.BurnRatePercent) + "% is below threshold " +
					formatPct(threshold) + "%"
				break
			}
		}
	}

	report.Gate = &gate
	return gate
}

func computeWeekly(findings []remediation.Finding, sev string, deadline float64, start, end time.Time) []float64 {
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return nil
	}

	dur := end.Sub(start)
	weeks := int(math.Ceil(dur.Hours() / (7 * 24)))
	if weeks <= 0 {
		weeks = 1
	}
	if weeks > 12 {
		weeks = 12
	}

	buckets := make([]float64, weeks)
	weekDur := dur / time.Duration(weeks)

	for i := range findings {
		f := &findings[i]
		if f.SeverityLabel() != sev {
			continue
		}
		dwell := math.Min(f.DwellHours(), deadline)
		if dwell <= 0 {
			continue
		}

		// Assign to a week bucket based on when the finding started.
		firstUnsafe := f.Evidence.FirstUnsafeAt
		if firstUnsafe.IsZero() || firstUnsafe.Before(start) {
			buckets[0] += dwell
			continue
		}
		weekIdx := int(firstUnsafe.Sub(start) / weekDur)
		if weekIdx >= weeks {
			weekIdx = weeks - 1
		}
		buckets[weekIdx] += dwell
	}

	for i := range buckets {
		buckets[i] = round1(buckets[i])
	}
	return buckets
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func formatPct(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}
