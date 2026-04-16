package evidence

import (
	"testing"
)

func TestParseProfile_SectionsFormat(t *testing.T) {
	yaml := `
id: dora_test
name: DORA Test Profile
version: "2025-01"
description: Test DORA profile

sections:
  - id: dora.art5
    title: "Article 5 — ICT Risk Management"
    priority: critical
    required_controls:
      - control_id: CTL.CLOUDTRAIL.ENABLED.001
        rationale: "Audit logging for risk management"
      - control_id: CTL.GUARDDUTY.ENABLED.001
        rationale: "Threat detection"

  - id: dora.art9
    title: "Article 9 — Data Protection"
    priority: high
    required_controls:
      - control_id: CTL.S3.ENCRYPT.001
        rationale: "Data at rest encryption"
`

	profile, err := parseProfile([]byte(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if profile.ID != "dora_test" {
		t.Errorf("id = %q, want dora_test", profile.ID)
	}
	if len(profile.Requirements) != 2 {
		t.Fatalf("requirements = %d, want 2", len(profile.Requirements))
	}

	// First section should have 2 controls.
	r := profile.Requirements[0]
	if r.ID != "dora.art5" {
		t.Errorf("requirement[0].id = %q, want dora.art5", r.ID)
	}
	if len(r.ControlIDs) != 2 {
		t.Errorf("requirement[0].controls = %d, want 2", len(r.ControlIDs))
	}
	if r.ControlIDs[0] != "CTL.CLOUDTRAIL.ENABLED.001" {
		t.Errorf("control[0] = %q, want CTL.CLOUDTRAIL.ENABLED.001", r.ControlIDs[0])
	}
}

func TestParseProfile_MixedFormat(t *testing.T) {
	yaml := `
id: mixed_test
name: Mixed Format Test
version: "1"

requirements:
  - id: req.1
    description: "Existing requirement"
    controls:
      - CTL.A.001

sections:
  - id: sec.1
    title: "New section"
    required_controls:
      - control_id: CTL.B.001
`

	profile, err := parseProfile([]byte(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(profile.Requirements) != 2 {
		t.Fatalf("requirements = %d, want 2 (1 from requirements + 1 from sections)", len(profile.Requirements))
	}
}

func TestParseProfile_UnknownControlID_NoError(t *testing.T) {
	yaml := `
id: test_unknown
name: Test Unknown Controls

sections:
  - id: sec.1
    title: "Section with unknown control"
    required_controls:
      - control_id: CTL.NONEXISTENT.999
        rationale: "This control does not exist"
`

	profile, err := parseProfile([]byte(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("unknown control ID should not cause parse error: %v", err)
	}
	if profile.Requirements[0].ControlIDs[0] != "CTL.NONEXISTENT.999" {
		t.Error("unknown control ID should be preserved for runtime warning")
	}
}

func TestParseProfile_SectionsFormat_MissingID(t *testing.T) {
	yaml := `
name: No ID Profile
sections:
  - id: sec.1
    title: "Section"
    required_controls:
      - control_id: CTL.A.001
`

	_, err := parseProfile([]byte(yaml), "test.yaml")
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}
