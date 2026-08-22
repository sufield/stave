package evaluation

import (
	"strings"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func sunsetControl(deadline string) *policy.ControlDefinition {
	return &policy.ControlDefinition{
		Severity: policy.SeverityLow,
		Lifecycle: policy.ControlLifecycle{
			Status:   policy.LifecycleSunset,
			Deadline: deadline,
		},
	}
}

func TestAnnotateLifecycleDeadline_NoDeadline(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityLow}
	ctl := &policy.ControlDefinition{
		Lifecycle: policy.ControlLifecycle{Status: policy.LifecycleSunset},
	}
	f.AnnotateLifecycleDeadline(ctl, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if f.lifecycleEscalatedSeverity != policy.SeverityNone {
		t.Fatalf("expected no escalation, got %v", f.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_ActiveStatus(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityLow}
	ctl := &policy.ControlDefinition{
		Lifecycle: policy.ControlLifecycle{
			Status:   policy.LifecycleActive,
			Deadline: "2026-09-01",
		},
	}
	f.AnnotateLifecycleDeadline(ctl, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if f.lifecycleEscalatedSeverity != policy.SeverityNone {
		t.Fatalf("expected no escalation for active control, got %v", f.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_FarAway(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityLow}
	ctl := sunsetControl("2027-06-01")
	evalTime := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	days, ok := f.LifecycleDaysRemaining()
	if !ok {
		t.Fatal("expected days remaining to be set")
	}
	if days <= 180 {
		t.Fatalf("expected >180 days, got %d", days)
	}
	if f.lifecycleEscalatedSeverity != policy.SeverityNone {
		t.Fatalf("expected no escalation for >180 days, got %v", f.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_91to180Days(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityLow}
	ctl := sunsetControl("2027-01-15")
	evalTime := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	if f.lifecycleEscalatedSeverity != policy.SeverityMedium {
		t.Fatalf("expected +1 tier (low→medium), got %v", f.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_31to90Days(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityLow}
	ctl := sunsetControl("2026-10-15")
	evalTime := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	if f.lifecycleEscalatedSeverity != policy.SeverityHigh {
		t.Fatalf("expected +2 tiers (low→high), got %v", f.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_Under30Days(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityLow}
	ctl := sunsetControl("2026-09-15")
	evalTime := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	if f.lifecycleEscalatedSeverity != policy.SeverityCritical {
		t.Fatalf("expected +3 tiers (low→critical), got %v", f.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_PastDeadline(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityMedium}
	ctl := sunsetControl("2026-07-01")
	evalTime := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	if f.lifecycleEscalatedSeverity != policy.SeverityCritical {
		t.Fatalf("expected max escalation for past deadline, got %v", f.lifecycleEscalatedSeverity)
	}
	days, _ := f.LifecycleDaysRemaining()
	if days >= 0 {
		t.Fatalf("expected negative days remaining, got %d", days)
	}
}

func TestAnnotateLifecycleDeadline_AlreadyCritical(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityCritical}
	ctl := sunsetControl("2026-09-01")
	evalTime := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	if f.lifecycleEscalatedSeverity != policy.SeverityNone {
		t.Fatalf("expected no escalation when already critical, got %v", f.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_JSONRoundtrip(t *testing.T) {
	f := &Finding{ControlID: "CTL.TEST.001", AssetID: "arn:aws:test:us-east-1:111:thing/1", ControlSeverity: policy.SeverityLow}
	ctl := sunsetControl("2026-10-15")
	evalTime := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	data, err := f.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"lifecycle_deadline":"2026-10-15"`) {
		t.Fatalf("expected lifecycle_deadline in JSON, got: %s", s)
	}
	if !strings.Contains(s, `"lifecycle_days_remaining":55`) {
		t.Fatalf("expected lifecycle_days_remaining in JSON, got: %s", s)
	}
	if !strings.Contains(s, `"lifecycle_escalated_severity":"high"`) {
		t.Fatalf("expected lifecycle_escalated_severity in JSON, got: %s", s)
	}

	var f2 Finding
	if err := f2.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	if f2.lifecycleDeadline != "2026-10-15" {
		t.Fatalf("roundtrip deadline: got %q", f2.lifecycleDeadline)
	}
	days, ok := f2.LifecycleDaysRemaining()
	if !ok || days != 55 {
		t.Fatalf("roundtrip days: got %d ok=%v", days, ok)
	}
	if f2.lifecycleEscalatedSeverity != policy.SeverityHigh {
		t.Fatalf("roundtrip severity: got %v", f2.lifecycleEscalatedSeverity)
	}
}

func TestAnnotateLifecycleDeadline_EOLStatus(t *testing.T) {
	f := &Finding{ControlSeverity: policy.SeverityLow}
	ctl := &policy.ControlDefinition{
		Severity: policy.SeverityLow,
		Lifecycle: policy.ControlLifecycle{
			Status:   policy.LifecycleEOL,
			Deadline: "2026-10-01",
		},
	}
	evalTime := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	f.AnnotateLifecycleDeadline(ctl, evalTime)

	if f.lifecycleEscalatedSeverity != policy.SeverityHigh {
		t.Fatalf("expected +2 tiers for eol within 31-90 days, got %v", f.lifecycleEscalatedSeverity)
	}
}
