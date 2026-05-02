package evaluation

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func defaultSLAConfig() *SLAConfig {
	return &SLAConfig{
		ProfileID: "default",
		DeadlineBySeverity: map[string]float64{
			"critical": 72,
			"high":     336,
			"medium":   1440,
			"low":      4320,
		},
		EscalationFactor: 1.5,
	}
}

func TestAnnotateFindingSLA_WithinDeadline(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 48}, // 48h < 72h deadline
	}
	AnnotateFindingSLA(&f, nil, defaultSLAConfig())

	if f.SLADeadlineHours == nil || *f.SLADeadlineHours != 72 {
		t.Errorf("deadline = %v, want 72", f.SLADeadlineHours)
	}
	if f.SLABreached {
		t.Error("should not be breached (48h < 72h)")
	}
	if f.SLAOverdueHours != nil {
		t.Error("overdue hours should be nil when not breached")
	}
	if f.SLAEscalatedSeverity != policy.SeverityNone {
		t.Error("escalated severity should be empty when not breached")
	}
	if f.SLAPolicySource != kernel.SLAPolicySourceProfile("default") {
		t.Errorf("policy source = %q, want profile:default", f.SLAPolicySource)
	}
}

func TestAnnotateFindingSLA_Breached_OneTier(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityHigh,
		Evidence:        Evidence{UnsafeDurationHours: 500}, // 500h, deadline 336h, 1× overdue
	}
	AnnotateFindingSLA(&f, nil, defaultSLAConfig())

	if !f.SLABreached {
		t.Fatal("should be breached")
	}
	if f.SLAOverdueHours == nil || *f.SLAOverdueHours != 164 {
		t.Errorf("overdue = %v, want 164", f.SLAOverdueHours)
	}
	// 164h overdue / 336h deadline < 1 period → 1 tier escalation
	// high → critical
	if f.SLAEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("escalated = %q, want critical", f.SLAEscalatedSeverity)
	}
}

func TestAnnotateFindingSLA_Breached_ThreeTiers(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityLow,
		Evidence:        Evidence{UnsafeDurationHours: 20000}, // way overdue
	}
	AnnotateFindingSLA(&f, nil, defaultSLAConfig())

	if !f.SLABreached {
		t.Fatal("should be breached")
	}
	// Capped at critical regardless of how many tiers.
	if f.SLAEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("escalated = %q, want critical (capped)", f.SLAEscalatedSeverity)
	}
}

func TestAnnotateFindingSLA_ControlOverride(t *testing.T) {
	ctl := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{"sla_deadline": "4h"}),
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatal(err)
	}

	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 10}, // 10h > 4h
	}
	AnnotateFindingSLA(&f, ctl, defaultSLAConfig())

	if f.SLADeadlineHours == nil || *f.SLADeadlineHours != 4 {
		t.Errorf("deadline = %v, want 4 (control override)", f.SLADeadlineHours)
	}
	if f.SLAPolicySource != kernel.SLAPolicySourceControlOverride {
		t.Errorf("policy source = %q, want control_override", f.SLAPolicySource)
	}
	if !f.SLABreached {
		t.Error("should be breached (10h > 4h)")
	}
}

func TestAnnotateFindingSLA_NilConfig(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 100},
	}
	AnnotateFindingSLA(&f, nil, nil)

	if f.SLADeadlineHours != nil {
		t.Error("should have no SLA data with nil config")
	}
}

func TestAnnotateFindingSLA_NoEscalationWhenAlreadyCritical(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 200}, // 200h, deadline 72h
	}
	AnnotateFindingSLA(&f, nil, defaultSLAConfig())

	if !f.SLABreached {
		t.Fatal("should be breached")
	}
	// Already critical — no escalation possible.
	if f.SLAEscalatedSeverity != policy.SeverityNone {
		t.Errorf("escalated = %q, want empty (already critical)", f.SLAEscalatedSeverity)
	}
}

func TestEscalateSeverity(t *testing.T) {
	tests := []struct {
		base  policy.Severity
		tiers int
		want  policy.Severity
	}{
		{policy.SeverityLow, 1, policy.SeverityMedium},
		{policy.SeverityLow, 2, policy.SeverityHigh},
		{policy.SeverityLow, 3, policy.SeverityCritical},
		{policy.SeverityLow, 10, policy.SeverityCritical}, // capped
		{policy.SeverityMedium, 1, policy.SeverityHigh},
		{policy.SeverityMedium, 2, policy.SeverityCritical},
		{policy.SeverityHigh, 1, policy.SeverityCritical},
		{policy.SeverityCritical, 1, policy.SeverityCritical}, // already max
		{policy.SeverityInfo, 1, policy.SeverityInfo},         // not in escalation table
	}
	for _, tt := range tests {
		got := escalateSeverity(tt.base, tt.tiers)
		if got != tt.want {
			t.Errorf("escalateSeverity(%v, %d) = %v, want %v", tt.base, tt.tiers, got, tt.want)
		}
	}
}

// TestAnnotateFindingSLA_2xDwellEscalates_2Tiers pins the off-by-one
// fix: a finding sitting at exactly 2× the deadline must escalate by
// 2 tiers, and 3× by 3 tiers. The earlier formula divided overdue
// (= dwell - deadline) by deadline and floored, so 2× dwell gave +1
// (off by one) and 3× gave +2.
func TestAnnotateFindingSLA_2xDwellEscalates_2Tiers(t *testing.T) {
	cfg := defaultSLAConfig()
	deadline := cfg.DeadlineBySeverity["medium"]
	if deadline == 0 {
		t.Fatal("test fixture relies on medium having a non-zero deadline")
	}
	f := Finding{
		ControlSeverity: policy.SeverityMedium,
		Evidence:        Evidence{UnsafeDurationHours: 2 * deadline},
	}
	AnnotateFindingSLA(&f, nil, cfg)
	if !f.SLABreached {
		t.Fatal("2× dwell must be breached")
	}
	// medium + 2 tiers should escalate to critical (low→medium→high→critical;
	// medium + 2 = critical at index 3).
	if f.SLAEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("2× dwell from medium: escalated = %q, want critical", f.SLAEscalatedSeverity)
	}
}

func TestAnnotateFindingSLA_3xDwellEscalates_3Tiers(t *testing.T) {
	cfg := defaultSLAConfig()
	deadline := cfg.DeadlineBySeverity["low"]
	if deadline == 0 {
		t.Fatal("test fixture relies on low having a non-zero deadline")
	}
	f := Finding{
		ControlSeverity: policy.SeverityLow,
		Evidence:        Evidence{UnsafeDurationHours: 3 * deadline},
	}
	AnnotateFindingSLA(&f, nil, cfg)
	if !f.SLABreached {
		t.Fatal("3× dwell must be breached")
	}
	// low + 3 tiers = critical (index 0 + 3 = 3, which is critical).
	if f.SLAEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("3× dwell from low: escalated = %q, want critical", f.SLAEscalatedSeverity)
	}
}

// Ensure kernel.ParseDuration handles the "4h" and "30d" formats used in SLA.
func TestSLADurationParsing(t *testing.T) {
	tests := []struct {
		input string
		hours float64
	}{
		{"4h", 4},
		{"72h", 72},
		{"30d", 720},
		{"168h", 168},
	}
	for _, tt := range tests {
		d, err := kernel.ParseDuration(tt.input)
		if err != nil {
			t.Errorf("ParseDuration(%q) error: %v", tt.input, err)
			continue
		}
		if got := d.Hours(); got != tt.hours {
			t.Errorf("ParseDuration(%q).Hours() = %f, want %f", tt.input, got, tt.hours)
		}
	}
}

// Acknowledged findings never reach AnnotateFindingSLA because
// applyAcknowledgments() removes them from the active findings slice
// before SLA annotation runs. This test documents that calling
// AnnotateFindingSLA with nil config (the acknowledged path) is a no-op.
func TestAnnotateFindingSLA_AcknowledgedExclusion(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 9999},
	}
	// Acknowledged findings are excluded from the SLA annotation loop
	// (workflow.go:119-122 iterates only report.Findings, which excludes
	// acknowledged findings). Calling with nil config simulates this.
	AnnotateFindingSLA(&f, nil, nil)

	if f.SLABreached {
		t.Error("acknowledged finding should not have SLA breach annotation")
	}
	if f.SLADeadlineHours != nil {
		t.Error("acknowledged finding should not have SLA deadline")
	}
}

// Verify that the SLA field is set on the finding when it's non-zero.
func TestAnnotateFindingSLA_FieldsPopulated(t *testing.T) {
	now := time.Now()
	f := Finding{
		ControlSeverity: policy.SeverityMedium,
		Evidence: Evidence{
			FirstUnsafeAt:       now.Add(-2000 * time.Hour),
			LastSeenUnsafeAt:    now,
			UnsafeDurationHours: 2000,
			ThresholdHours:      168,
		},
	}
	AnnotateFindingSLA(&f, nil, defaultSLAConfig())

	if f.SLADeadlineHours == nil {
		t.Fatal("deadline should be set")
	}
	if *f.SLADeadlineHours != 1440 {
		t.Errorf("deadline = %f, want 1440", *f.SLADeadlineHours)
	}
	if !f.SLABreached {
		t.Fatal("should be breached")
	}
	if f.SLAOverdueHours == nil {
		t.Fatal("overdue should be set")
	}
	// 2000 - 1440 = 560 hours overdue
	if *f.SLAOverdueHours != 560 {
		t.Errorf("overdue = %f, want 560", *f.SLAOverdueHours)
	}
	// medium → high (1 tier at 560/1440 < 1 period)
	if f.SLAEscalatedSeverity != policy.SeverityHigh {
		t.Errorf("escalated = %q, want high", f.SLAEscalatedSeverity)
	}
}
