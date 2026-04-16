package overlay

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestApply_ControlLevelOverride(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Severity: policy.SeverityCritical, Domain: "exposure"},
	}
	cfg := &Config{
		Name: "dev",
		Overrides: []Override{
			{ControlID: "CTL.A.001", Severity: "medium", Rationale: "dev env"},
		},
	}

	results := Apply(controls, cfg)
	if controls[0].Severity != policy.SeverityMedium {
		t.Errorf("severity = %v, want medium", controls[0].Severity)
	}
	r := results[kernel.ControlID("CTL.A.001")]
	if r.OriginalSeverity != policy.SeverityCritical {
		t.Errorf("original = %v, want critical", r.OriginalSeverity)
	}
}

func TestApply_Suppressed(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Severity: policy.SeverityHigh},
	}
	cfg := &Config{
		Overrides: []Override{
			{ControlID: "CTL.A.001", Severity: "suppressed", Rationale: "not needed in dev"},
		},
	}

	results := Apply(controls, cfg)
	if !results[kernel.ControlID("CTL.A.001")].Suppressed {
		t.Error("expected suppressed")
	}
}

func TestApply_DomainOverride(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Severity: policy.SeverityHigh, Domain: "resilience"},
		{ID: "CTL.B.001", Severity: policy.SeverityHigh, Domain: "exposure"},
	}
	cfg := &Config{
		Overrides: []Override{
			{Domain: "resilience", Severity: "low", Rationale: "resilience is low in dev"},
		},
	}

	Apply(controls, cfg)
	if controls[0].Severity != policy.SeverityLow {
		t.Errorf("resilience control should be low, got %v", controls[0].Severity)
	}
	if controls[1].Severity != policy.SeverityHigh {
		t.Errorf("exposure control should be unchanged at high, got %v", controls[1].Severity)
	}
}

func TestApply_ControlLevelBeadsDomainLevel(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Severity: policy.SeverityCritical, Domain: "resilience"},
	}
	cfg := &Config{
		Overrides: []Override{
			{Domain: "resilience", Severity: "low"},
			{ControlID: "CTL.A.001", Severity: "medium"},
		},
	}

	Apply(controls, cfg)
	if controls[0].Severity != policy.SeverityMedium {
		t.Errorf("control-level should beat domain-level: got %v, want medium", controls[0].Severity)
	}
}

func TestMatchesFilter_NoFilter(t *testing.T) {
	if !MatchesFilter(nil, nil) {
		t.Error("nil config should match")
	}
	if !MatchesFilter(&Config{}, nil) {
		t.Error("no filter should match")
	}
}

func TestMatchesFilter_TagMatch(t *testing.T) {
	cfg := &Config{
		AssetFilter: &AssetFilter{Tags: map[string]string{"env": "dev"}},
	}
	if !MatchesFilter(cfg, map[string]string{"env": "dev"}) {
		t.Error("matching tags should match")
	}
	if MatchesFilter(cfg, map[string]string{"env": "prod"}) {
		t.Error("non-matching tags should not match")
	}
}

func TestApply_NoOverlay(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.A.001", Severity: policy.SeverityCritical},
	}
	results := Apply(controls, nil)
	if results != nil {
		t.Error("nil overlay should return nil results")
	}
	if controls[0].Severity != policy.SeverityCritical {
		t.Error("severity should be unchanged")
	}
}
