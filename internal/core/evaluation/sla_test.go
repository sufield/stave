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

func TestFindingAnnotateSLA_WithinDeadline(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 48}, // 48h < 72h deadline
	}
	f.AnnotateSLA(nil, defaultSLAConfig())

	if f.slaDeadlineHours == nil || *f.slaDeadlineHours != 72 {
		t.Errorf("deadline = %v, want 72", f.slaDeadlineHours)
	}
	if f.slaBreached {
		t.Error("should not be breached (48h < 72h)")
	}
	if f.slaOverdueHours != nil {
		t.Error("overdue hours should be nil when not breached")
	}
	if f.slaEscalatedSeverity != policy.SeverityNone {
		t.Error("escalated severity should be empty when not breached")
	}
	if f.slaPolicySource != kernel.SLAPolicySourceProfile("default") {
		t.Errorf("policy source = %q, want profile:default", f.slaPolicySource)
	}
}

func TestFindingAnnotateSLA_Breached_OneTier(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityHigh,
		Evidence:        Evidence{UnsafeDurationHours: 500}, // 500h, deadline 336h, 1× overdue
	}
	f.AnnotateSLA(nil, defaultSLAConfig())

	if !f.slaBreached {
		t.Fatal("should be breached")
	}
	if f.slaOverdueHours == nil || *f.slaOverdueHours != 164 {
		t.Errorf("overdue = %v, want 164", f.slaOverdueHours)
	}
	// 164h overdue / 336h deadline < 1 period → 1 tier escalation
	// high → critical
	if f.slaEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("escalated = %q, want critical", f.slaEscalatedSeverity)
	}
}

func TestFindingAnnotateSLA_Breached_ThreeTiers(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityLow,
		Evidence:        Evidence{UnsafeDurationHours: 20000}, // way overdue
	}
	f.AnnotateSLA(nil, defaultSLAConfig())

	if !f.slaBreached {
		t.Fatal("should be breached")
	}
	// Capped at critical regardless of how many tiers.
	if f.slaEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("escalated = %q, want critical (capped)", f.slaEscalatedSeverity)
	}
}

func TestFindingAnnotateSLA_ControlOverride(t *testing.T) {
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
	f.AnnotateSLA(ctl, defaultSLAConfig())

	if f.slaDeadlineHours == nil || *f.slaDeadlineHours != 4 {
		t.Errorf("deadline = %v, want 4 (control override)", f.slaDeadlineHours)
	}
	if f.slaPolicySource != kernel.SLAPolicySourceControlOverride {
		t.Errorf("policy source = %q, want control_override", f.slaPolicySource)
	}
	if !f.slaBreached {
		t.Error("should be breached (10h > 4h)")
	}
}

func TestFindingAnnotateSLA_NilConfig(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 100},
	}
	f.AnnotateSLA(nil, nil)

	if f.slaDeadlineHours != nil {
		t.Error("should have no SLA data with nil config")
	}
}

func TestFindingAnnotateSLA_NoEscalationWhenAlreadyCritical(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 200}, // 200h, deadline 72h
	}
	f.AnnotateSLA(nil, defaultSLAConfig())

	if !f.slaBreached {
		t.Fatal("should be breached")
	}
	// Already critical — no escalation possible.
	if f.slaEscalatedSeverity != policy.SeverityNone {
		t.Errorf("escalated = %q, want empty (already critical)", f.slaEscalatedSeverity)
	}
}

func TestSeverityBump(t *testing.T) {
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
		{policy.SeverityInfo, 1, policy.SeverityLow},         // Info is now in the escalation table
	}
	for _, tt := range tests {
		got := tt.base.Bump(tt.tiers)
		if got != tt.want {
			t.Errorf("%v.Bump(%d) = %v, want %v", tt.base, tt.tiers, got, tt.want)
		}
	}
}

// TestFindingAnnotateSLA_2xDwellEscalates_2Tiers pins the off-by-one
// fix: a finding sitting at exactly 2× the deadline must escalate by
// 2 tiers, and 3× by 3 tiers. The earlier formula divided overdue
// (= dwell - deadline) by deadline and floored, so 2× dwell gave +1
// (off by one) and 3× gave +2.
func TestFindingAnnotateSLA_2xDwellEscalates_2Tiers(t *testing.T) {
	cfg := defaultSLAConfig()
	deadline := cfg.DeadlineBySeverity["medium"]
	if deadline == 0 {
		t.Fatal("test fixture relies on medium having a non-zero deadline")
	}
	// EscalationFactor=1 makes "2× dwell" equal "2 periods", producing
	// the +2 tier bump this test name documents. The package default
	// (1.5) is a more lenient real-world setting; isolate this test
	// with factor=1 so the tier-count assertion stays meaningful.
	cfg.EscalationFactor = 1
	f := Finding{
		ControlSeverity: policy.SeverityMedium,
		Evidence:        Evidence{UnsafeDurationHours: 2 * deadline},
	}
	f.AnnotateSLA(nil, cfg)
	if !f.slaBreached {
		t.Fatal("2× dwell must be breached")
	}
	// medium + 2 tiers should escalate to critical (low→medium→high→critical;
	// medium + 2 = critical at index 3).
	if f.slaEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("2× dwell from medium: escalated = %q, want critical", f.slaEscalatedSeverity)
	}
}

func TestFindingAnnotateSLA_3xDwellEscalates_3Tiers(t *testing.T) {
	cfg := defaultSLAConfig()
	deadline := cfg.DeadlineBySeverity["low"]
	if deadline == 0 {
		t.Fatal("test fixture relies on low having a non-zero deadline")
	}
	cfg.EscalationFactor = 1 // see TestFindingAnnotateSLA_2x for rationale
	f := Finding{
		ControlSeverity: policy.SeverityLow,
		Evidence:        Evidence{UnsafeDurationHours: 3 * deadline},
	}
	f.AnnotateSLA(nil, cfg)
	if !f.slaBreached {
		t.Fatal("3× dwell must be breached")
	}
	// low + 3 tiers = critical (index 0 + 3 = 3, which is critical).
	if f.slaEscalatedSeverity != policy.SeverityCritical {
		t.Errorf("3× dwell from low: escalated = %q, want critical", f.slaEscalatedSeverity)
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
func TestFindingAnnotateSLA_AcknowledgedExclusion(t *testing.T) {
	f := Finding{
		ControlSeverity: policy.SeverityCritical,
		Evidence:        Evidence{UnsafeDurationHours: 9999},
	}
	// Acknowledged findings are excluded from the SLA annotation loop
	// (workflow.go:119-122 iterates only report.Findings, which excludes
	// acknowledged findings). Calling with nil config simulates this.
	f.AnnotateSLA(nil, nil)

	if f.slaBreached {
		t.Error("acknowledged finding should not have SLA breach annotation")
	}
	if f.slaDeadlineHours != nil {
		t.Error("acknowledged finding should not have SLA deadline")
	}
}

// Verify that the SLA field is set on the finding when it's non-zero.
func TestFindingAnnotateSLA_FieldsPopulated(t *testing.T) {
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
	f.AnnotateSLA(nil, defaultSLAConfig())

	if f.slaDeadlineHours == nil {
		t.Fatal("deadline should be set")
	}
	if *f.slaDeadlineHours != 1440 {
		t.Errorf("deadline = %f, want 1440", *f.slaDeadlineHours)
	}
	if !f.slaBreached {
		t.Fatal("should be breached")
	}
	if f.slaOverdueHours == nil {
		t.Fatal("overdue should be set")
	}
	// 2000 - 1440 = 560 hours overdue
	if *f.slaOverdueHours != 560 {
		t.Errorf("overdue = %f, want 560", *f.slaOverdueHours)
	}
	// medium → high (1 tier at 560/1440 < 1 period)
	if f.slaEscalatedSeverity != policy.SeverityHigh {
		t.Errorf("escalated = %q, want high", f.slaEscalatedSeverity)
	}
}
