package eval

import (
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

func TestFilterControls_BySeverity(t *testing.T) {
	invs := []policy.ControlDefinition{
		{ID: "CTL.A", Severity: policy.SeverityCritical},
		{ID: "CTL.B", Severity: policy.SeverityLow},
	}
	got, err := FilterControls(invs, ControlFilter{MinSeverity: policy.SeverityHigh})
	if err != nil {
		t.Fatalf("FilterControls() error = %v", err)
	}
	if len(got) != 1 || got[0].ID != "CTL.A" {
		t.Fatalf("filtered controls = %#v", got)
	}
}

func TestFilterControls_PassesThroughWhenDisabled(t *testing.T) {
	invs := []policy.ControlDefinition{
		{ID: "CTL.A", Severity: policy.SeverityCritical},
	}
	got, err := FilterControls(invs, ControlFilter{})
	if err != nil {
		t.Fatalf("FilterControls() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected controls unchanged, got %d", len(got))
	}
}

func TestFilterControls_ByID(t *testing.T) {
	invs := []policy.ControlDefinition{
		{ID: "CTL.A", Severity: policy.SeverityCritical},
		{ID: "CTL.B", Severity: policy.SeverityLow},
	}
	got, err := FilterControls(invs, ControlFilter{ControlID: kernel.ControlID("CTL.B")})
	if err != nil {
		t.Fatalf("FilterControls() error = %v", err)
	}
	if len(got) != 1 || got[0].ID != "CTL.B" {
		t.Fatalf("filtered controls = %#v", got)
	}
}
